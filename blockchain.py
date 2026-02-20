"""
GFC Blockchain Core Module
Hybrid SQLite blockchain with Treasury, grants, and PoDT rewards.

Architecture inspired by GFCoin.sol (ERC-20, 2 decimals) and TreasuryBank.sol
(oracle-gated rewards), implemented in SQLite for desktop P2P deployment.

All financial amounts are stored as INTEGER cents (100 = 1.00 GFC).
"""

import hashlib
import json
import sqlite3
import time
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from config import DB_PATH

# ============================================================================
# CONSTANTS
# ============================================================================

TREASURY_WALLET_ID = "GFC-TREASURY-GENESIS-001"
TREASURY_WALLET_NAME = "GFC Treasury"
PREMINE_CENTS = 100_000_000_000_000_00  # 100 trillion GFC * 100 cents = 10 quadrillion cents
NEW_USER_GRANT_CENTS = 10_000           # 100.00 GFC in cents
CREDITS_PER_MB_CENTS = 10              # 0.10 GFC per MB = 10 cents
MIN_TRANSFER_BYTES = 1024              # Minimum 1 KB for PoDT credit eligibility
GENESIS_PREV_HASH = "0" * 64          # 64 zeros for genesis block

# Transaction types
TX_TYPE_PREMINE  = "PREMINE"   # Genesis: SYSTEM -> Treasury
TX_TYPE_GRANT    = "GRANT"     # Treasury -> new user (first wallet)
TX_TYPE_TRANSFER = "TRANSFER"  # User -> User
TX_TYPE_REWARD   = "REWARD"    # Treasury -> Seeder (PoDT)


# ============================================================================
# SCHEMA INITIALIZATION
# ============================================================================

def init_blockchain_tables(db_path: str = DB_PATH):
    """
    Create blockchain-specific tables and add new columns to existing tables.
    Safe to call multiple times (idempotent).
    """
    conn = sqlite3.connect(db_path)

    # --- New tables ---

    # Blocks table: chain of blocks with prev_hash linkage
    conn.execute('''CREATE TABLE IF NOT EXISTS blocks (
        block_index INTEGER PRIMARY KEY,
        prev_hash TEXT NOT NULL,
        merkle_root TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        tx_count INTEGER NOT NULL DEFAULT 0
    )''')

    # User grants: tracks one-time 100 GFC grant per username
    conn.execute('''CREATE TABLE IF NOT EXISTS user_grants (
        username TEXT PRIMARY KEY,
        wallet_id TEXT NOT NULL,
        granted_at TEXT NOT NULL
    )''')

    # PoDT proofs: tracks completed file transfer proofs (prevents double-claiming)
    conn.execute('''CREATE TABLE IF NOT EXISTS podt_proofs (
        proof_id TEXT PRIMARY KEY,
        seeder_wallet TEXT NOT NULL,
        receiver_wallet TEXT NOT NULL,
        file_hash TEXT NOT NULL,
        file_size_bytes INTEGER NOT NULL,
        reward_cents INTEGER NOT NULL,
        tx_id TEXT,
        created_at TEXT NOT NULL
    )''')

    # Add seed_id column to podt_proofs (safe to re-run)
    try:
        conn.execute("ALTER TABLE podt_proofs ADD COLUMN seed_id TEXT DEFAULT ''")
    except Exception:
        pass  # Column already exists

    # --- Alter existing tables (add new columns, safe to re-run) ---

    # Transactions: add blockchain fields
    for col, coldef in [
        ("amount_cents", "INTEGER DEFAULT 0"),
        ("tx_hash", "TEXT DEFAULT ''"),
        ("block_index", "INTEGER"),
        ("tx_type", "TEXT DEFAULT 'TRANSFER'"),
    ]:
        try:
            conn.execute(f"ALTER TABLE transactions ADD COLUMN {col} {coldef}")
        except Exception:
            pass  # Column already exists

    # Wallets: add blockchain fields
    for col, coldef in [
        ("gfc_balance_cents", "INTEGER DEFAULT 0"),
        ("is_treasury", "INTEGER DEFAULT 0"),
    ]:
        try:
            conn.execute(f"ALTER TABLE wallets ADD COLUMN {col} {coldef}")
        except Exception:
            pass

    conn.commit()
    conn.close()


# ============================================================================
# GENESIS BLOCK
# ============================================================================

def create_genesis_block(db_path: str = DB_PATH):
    """
    Create the genesis block with the 100T GFC premine transaction.
    Idempotent: does nothing if genesis block already exists.
    """
    conn = sqlite3.connect(db_path)

    # Check if genesis block already exists
    existing = conn.execute("SELECT block_index FROM blocks WHERE block_index = 0").fetchone()
    if existing:
        conn.close()
        return  # Already created

    now_iso = datetime.now(timezone.utc).isoformat()

    # 1. Create Treasury wallet if it doesn't exist
    existing_treasury = conn.execute(
        "SELECT id FROM wallets WHERE id = ?", (TREASURY_WALLET_ID,)
    ).fetchone()

    if not existing_treasury:
        conn.execute(
            "INSERT INTO wallets (id, name, owner, gfc_balance, created_at, gfc_balance_cents, is_treasury) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (TREASURY_WALLET_ID, TREASURY_WALLET_NAME, "SYSTEM", 0.0, now_iso, PREMINE_CENTS, 1)
        )
    else:
        # Update existing treasury wallet
        conn.execute(
            "UPDATE wallets SET gfc_balance_cents = ?, is_treasury = 1, name = ? WHERE id = ?",
            (PREMINE_CENTS, TREASURY_WALLET_NAME, TREASURY_WALLET_ID)
        )

    # 2. Create premine transaction
    premine_tx_id = "GENESIS-PREMINE-TX-001"
    premine_tx = {
        "id": premine_tx_id,
        "sender": "SYSTEM",
        "recipient": TREASURY_WALLET_ID,
        "amount": PREMINE_CENTS / 100.0,
        "amount_cents": PREMINE_CENTS,
        "reason": "Genesis premine: 100 trillion GFC",
        "timestamp": now_iso,
        "tx_type": TX_TYPE_PREMINE,
    }
    premine_tx["tx_hash"] = compute_tx_hash(premine_tx)

    conn.execute(
        "INSERT INTO transactions (id, sender, recipient, amount, reason, timestamp, "
        "amount_cents, tx_hash, block_index, tx_type) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (premine_tx["id"], premine_tx["sender"], premine_tx["recipient"],
         premine_tx["amount"], premine_tx["reason"], premine_tx["timestamp"],
         premine_tx["amount_cents"], premine_tx["tx_hash"], 0, premine_tx["tx_type"])
    )

    # 3. Create genesis block (block_index = 0)
    merkle_root = compute_merkle_root([premine_tx["tx_hash"]])
    conn.execute(
        "INSERT INTO blocks (block_index, prev_hash, merkle_root, timestamp, tx_count) "
        "VALUES (?, ?, ?, ?, ?)",
        (0, GENESIS_PREV_HASH, merkle_root, now_iso, 1)
    )

    conn.commit()
    conn.close()
    print(f"[Blockchain] Genesis block created. Treasury: {TREASURY_WALLET_ID}, Premine: {PREMINE_CENTS / 100:.2f} GFC")


# ============================================================================
# HASHING & MERKLE
# ============================================================================

def compute_tx_hash(tx_dict: dict) -> str:
    """Compute SHA-256 hash of a transaction's canonical fields."""
    canonical = {
        "sender": tx_dict.get("sender", ""),
        "recipient": tx_dict.get("recipient", ""),
        "amount_cents": tx_dict.get("amount_cents", 0),
        "timestamp": tx_dict.get("timestamp", ""),
        "tx_type": tx_dict.get("tx_type", TX_TYPE_TRANSFER),
        "reason": tx_dict.get("reason", ""),
    }
    canonical_json = json.dumps(canonical, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(canonical_json.encode()).hexdigest()


def compute_merkle_root(tx_hashes: List[str]) -> str:
    """
    Compute Merkle root from a list of transaction hashes.
    Simple binary tree: pair up hashes, hash pairs, repeat.
    """
    if not tx_hashes:
        return hashlib.sha256(b"empty").hexdigest()

    # Work with a copy
    level = list(tx_hashes)

    while len(level) > 1:
        next_level = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if (i + 1) < len(level) else left  # Duplicate last if odd
            combined = hashlib.sha256((left + right).encode()).hexdigest()
            next_level.append(combined)
        level = next_level

    return level[0]


def _compute_block_hash(block_index: int, prev_hash: str, merkle_root: str, timestamp: str) -> str:
    """Compute the hash of a block header."""
    header = f"{block_index}:{prev_hash}:{merkle_root}:{timestamp}"
    return hashlib.sha256(header.encode()).hexdigest()


# ============================================================================
# BLOCK CREATION
# ============================================================================

def create_block(db_path: str, tx_ids: List[str]) -> dict:
    """
    Create a new block containing the specified transactions.
    Updates each transaction's block_index.
    Returns the block dict.
    """
    conn = sqlite3.connect(db_path)

    # Get the latest block
    last_block = conn.execute(
        "SELECT block_index, prev_hash, merkle_root, timestamp FROM blocks ORDER BY block_index DESC LIMIT 1"
    ).fetchone()

    if last_block:
        prev_block_index = last_block[0]
        prev_hash = _compute_block_hash(last_block[0], last_block[1], last_block[2], last_block[3])
        new_index = prev_block_index + 1
    else:
        # No blocks yet — this shouldn't happen if genesis was created, but handle gracefully
        prev_hash = GENESIS_PREV_HASH
        new_index = 0

    # Get tx hashes for the transactions in this block
    placeholders = ",".join("?" * len(tx_ids))
    rows = conn.execute(
        f"SELECT tx_hash FROM transactions WHERE id IN ({placeholders})", tx_ids
    ).fetchall()
    tx_hashes = [r[0] for r in rows if r[0]]

    if not tx_hashes:
        conn.close()
        raise ValueError("No valid transaction hashes found for block creation")

    now_iso = datetime.now(timezone.utc).isoformat()
    merkle_root = compute_merkle_root(tx_hashes)

    # Insert the block
    conn.execute(
        "INSERT INTO blocks (block_index, prev_hash, merkle_root, timestamp, tx_count) "
        "VALUES (?, ?, ?, ?, ?)",
        (new_index, prev_hash, merkle_root, now_iso, len(tx_ids))
    )

    # Update transactions with their block_index
    conn.execute(
        f"UPDATE transactions SET block_index = ? WHERE id IN ({placeholders})",
        [new_index] + tx_ids
    )

    conn.commit()
    conn.close()

    return {
        "block_index": new_index,
        "prev_hash": prev_hash,
        "merkle_root": merkle_root,
        "timestamp": now_iso,
        "tx_count": len(tx_ids),
    }


# ============================================================================
# BALANCE CALCULATION
# ============================================================================

def get_balance_cents(db_path: str, wallet_id: str) -> int:
    """
    Calculate wallet balance from confirmed (blocked) transactions.
    Returns balance in cents (integer).
    """
    conn = sqlite3.connect(db_path)

    # Sum of all amount_cents received (where block_index IS NOT NULL = confirmed)
    received = conn.execute(
        "SELECT COALESCE(SUM(amount_cents), 0) FROM transactions "
        "WHERE recipient = ? AND block_index IS NOT NULL",
        (wallet_id,)
    ).fetchone()[0]

    # Sum of all amount_cents sent
    sent = conn.execute(
        "SELECT COALESCE(SUM(amount_cents), 0) FROM transactions "
        "WHERE sender = ? AND block_index IS NOT NULL",
        (wallet_id,)
    ).fetchone()[0]

    conn.close()
    return received - sent


def get_balance(db_path: str, wallet_id: str) -> float:
    """Get wallet balance as a float (for display). E.g., 100.00"""
    return get_balance_cents(db_path, wallet_id) / 100.0


# ============================================================================
# USER GRANT (First Wallet)
# ============================================================================

def process_user_grant(db_path: str, username: str, wallet_id: str) -> Optional[dict]:
    """
    Grant 100 GFC to a user's first wallet.
    Returns the transaction dict if grant was issued, None if user already received grant.
    Thread-safe via SQLite's built-in locking.
    """
    conn = sqlite3.connect(db_path)

    # Check if this username already received a grant
    existing = conn.execute(
        "SELECT username FROM user_grants WHERE username = ?", (username,)
    ).fetchone()

    if existing:
        conn.close()
        return None  # Already granted

    now_iso = datetime.now(timezone.utc).isoformat()
    tx_id = str(uuid.uuid4())

    tx = {
        "id": tx_id,
        "sender": TREASURY_WALLET_ID,
        "recipient": wallet_id,
        "amount": NEW_USER_GRANT_CENTS / 100.0,
        "amount_cents": NEW_USER_GRANT_CENTS,
        "reason": f"New user grant: {username}",
        "timestamp": now_iso,
        "tx_type": TX_TYPE_GRANT,
    }
    tx["tx_hash"] = compute_tx_hash(tx)

    # Insert transaction
    conn.execute(
        "INSERT INTO transactions (id, sender, recipient, amount, reason, timestamp, "
        "amount_cents, tx_hash, tx_type) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (tx["id"], tx["sender"], tx["recipient"], tx["amount"], tx["reason"],
         tx["timestamp"], tx["amount_cents"], tx["tx_hash"], tx["tx_type"])
    )

    # Record grant
    conn.execute(
        "INSERT INTO user_grants (username, wallet_id, granted_at) VALUES (?, ?, ?)",
        (username, wallet_id, now_iso)
    )

    conn.commit()
    conn.close()

    # Create block for this transaction
    block = create_block(db_path, [tx_id])
    tx["block_index"] = block["block_index"]

    print(f"[Blockchain] Grant: {NEW_USER_GRANT_CENTS / 100:.2f} GFC -> {wallet_id} (user: {username}, block: {block['block_index']})")
    return tx


# ============================================================================
# TRANSFER (User -> User)
# ============================================================================

def process_transfer(db_path: str, sender_wallet: str, recipient_wallet: str,
                     amount_cents: int, reason: str = "") -> dict:
    """
    Process a GFC transfer between wallets.
    Validates sender has sufficient balance.
    Raises ValueError on insufficient balance.
    Returns the transaction dict.
    """
    if amount_cents <= 0:
        raise ValueError("Amount must be positive")

    if sender_wallet == recipient_wallet:
        raise ValueError("Cannot send to yourself")

    # Check sender balance
    sender_balance = get_balance_cents(db_path, sender_wallet)
    if sender_balance < amount_cents:
        raise ValueError(
            f"Insufficient balance: {sender_balance / 100:.2f} GFC available, "
            f"{amount_cents / 100:.2f} GFC required"
        )

    now_iso = datetime.now(timezone.utc).isoformat()
    tx_id = str(uuid.uuid4())

    tx = {
        "id": tx_id,
        "sender": sender_wallet,
        "recipient": recipient_wallet,
        "amount": amount_cents / 100.0,
        "amount_cents": amount_cents,
        "reason": reason,
        "timestamp": now_iso,
        "tx_type": TX_TYPE_TRANSFER,
    }
    tx["tx_hash"] = compute_tx_hash(tx)

    conn = sqlite3.connect(db_path)
    conn.execute(
        "INSERT INTO transactions (id, sender, recipient, amount, reason, timestamp, "
        "amount_cents, tx_hash, tx_type) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (tx["id"], tx["sender"], tx["recipient"], tx["amount"], tx["reason"],
         tx["timestamp"], tx["amount_cents"], tx["tx_hash"], tx["tx_type"])
    )
    conn.commit()
    conn.close()

    # Create block
    block = create_block(db_path, [tx_id])
    tx["block_index"] = block["block_index"]

    return tx


# ============================================================================
# PoDT REWARD (Treasury -> Seeder)
# ============================================================================

def process_podt_reward(db_path: str, seeder_wallet: str, proof_id: str,
                        bytes_transferred: int, file_hash: str = "",
                        receiver_wallet: str = "", seed_id: str = "") -> Optional[dict]:
    """
    Award PoDT credits to a seeder for a verified file transfer.
    Returns the transaction dict, or None if reward is too small or duplicate.
    """
    if bytes_transferred < MIN_TRANSFER_BYTES:
        return None  # Too small for credit

    # Calculate reward: bytes -> MB -> cents
    mb_transferred = bytes_transferred / (1024 * 1024)
    reward_cents = int(mb_transferred * CREDITS_PER_MB_CENTS)

    if reward_cents <= 0:
        return None  # Round-down to zero

    conn = sqlite3.connect(db_path)

    # Check for duplicate proof (prevents double-claiming)
    existing_proof = conn.execute(
        "SELECT proof_id FROM podt_proofs WHERE proof_id = ?", (proof_id,)
    ).fetchone()

    if existing_proof:
        conn.close()
        return None  # Already claimed

    # Check Treasury balance
    treasury_balance = get_balance_cents(db_path, TREASURY_WALLET_ID)
    if treasury_balance < reward_cents:
        conn.close()
        print(f"[Blockchain] WARNING: Treasury depleted, cannot award {reward_cents / 100:.2f} GFC")
        return None

    now_iso = datetime.now(timezone.utc).isoformat()
    tx_id = str(uuid.uuid4())

    tx = {
        "id": tx_id,
        "sender": TREASURY_WALLET_ID,
        "recipient": seeder_wallet,
        "amount": reward_cents / 100.0,
        "amount_cents": reward_cents,
        "reason": f"PoDT reward: {bytes_transferred} bytes ({mb_transferred:.2f} MB)",
        "timestamp": now_iso,
        "tx_type": TX_TYPE_REWARD,
    }
    tx["tx_hash"] = compute_tx_hash(tx)

    # Insert transaction
    conn.execute(
        "INSERT INTO transactions (id, sender, recipient, amount, reason, timestamp, "
        "amount_cents, tx_hash, tx_type) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (tx["id"], tx["sender"], tx["recipient"], tx["amount"], tx["reason"],
         tx["timestamp"], tx["amount_cents"], tx["tx_hash"], tx["tx_type"])
    )

    # Record proof
    conn.execute(
        "INSERT INTO podt_proofs (proof_id, seeder_wallet, receiver_wallet, file_hash, "
        "file_size_bytes, reward_cents, tx_id, created_at, seed_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (proof_id, seeder_wallet, receiver_wallet, file_hash,
         bytes_transferred, reward_cents, tx_id, now_iso, seed_id)
    )

    conn.commit()
    conn.close()

    # Create block
    block = create_block(db_path, [tx_id])
    tx["block_index"] = block["block_index"]

    print(f"[Blockchain] PoDT: {reward_cents / 100:.2f} GFC -> {seeder_wallet} "
          f"({bytes_transferred} bytes, block: {block['block_index']})")
    return tx


# ============================================================================
# CHAIN VALIDATION
# ============================================================================

def validate_chain(db_path: str = DB_PATH) -> Tuple[bool, str]:
    """
    Walk the entire blockchain and verify:
    1. prev_hash linkage is correct
    2. Merkle roots match transaction hashes in each block
    Returns (is_valid, message).
    """
    conn = sqlite3.connect(db_path)

    blocks = conn.execute(
        "SELECT block_index, prev_hash, merkle_root, timestamp, tx_count "
        "FROM blocks ORDER BY block_index ASC"
    ).fetchall()

    if not blocks:
        conn.close()
        return False, "No blocks found"

    for i, block in enumerate(blocks):
        block_index, prev_hash, merkle_root, timestamp, tx_count = block

        # Check block_index is sequential
        if block_index != i:
            conn.close()
            return False, f"Block index gap: expected {i}, got {block_index}"

        # Check prev_hash linkage
        if i == 0:
            if prev_hash != GENESIS_PREV_HASH:
                conn.close()
                return False, f"Genesis block has wrong prev_hash: {prev_hash}"
        else:
            prev_block = blocks[i - 1]
            expected_prev_hash = _compute_block_hash(
                prev_block[0], prev_block[1], prev_block[2], prev_block[3]
            )
            if prev_hash != expected_prev_hash:
                conn.close()
                return False, f"Block {block_index}: prev_hash mismatch"

        # Verify Merkle root
        tx_rows = conn.execute(
            "SELECT tx_hash FROM transactions WHERE block_index = ? ORDER BY id",
            (block_index,)
        ).fetchall()
        tx_hashes = [r[0] for r in tx_rows if r[0]]

        if tx_hashes:
            expected_merkle = compute_merkle_root(tx_hashes)
            if merkle_root != expected_merkle:
                conn.close()
                return False, f"Block {block_index}: merkle root mismatch"

    conn.close()
    total_blocks = len(blocks)
    return True, f"Chain valid: {total_blocks} blocks verified"


# ============================================================================
# STATISTICS
# ============================================================================

def get_blockchain_stats(db_path: str = DB_PATH) -> dict:
    """Get blockchain statistics."""
    conn = sqlite3.connect(db_path)

    block_count = conn.execute("SELECT COUNT(*) FROM blocks").fetchone()[0]
    tx_count = conn.execute(
        "SELECT COUNT(*) FROM transactions WHERE block_index IS NOT NULL"
    ).fetchone()[0]

    # Total GFC in circulation (all balances except Treasury)
    # = Total granted + rewarded
    granted = conn.execute(
        "SELECT COALESCE(SUM(amount_cents), 0) FROM transactions "
        "WHERE tx_type = ? AND block_index IS NOT NULL",
        (TX_TYPE_GRANT,)
    ).fetchone()[0]

    rewarded = conn.execute(
        "SELECT COALESCE(SUM(amount_cents), 0) FROM transactions "
        "WHERE tx_type = ? AND block_index IS NOT NULL",
        (TX_TYPE_REWARD,)
    ).fetchone()[0]

    circulation_cents = granted + rewarded

    treasury_balance_cents = get_balance_cents(db_path, TREASURY_WALLET_ID)

    # Chain validation (quick check)
    is_valid, validation_msg = validate_chain(db_path)

    # PoDT stats
    podt_count = conn.execute("SELECT COUNT(*) FROM podt_proofs").fetchone()[0]
    podt_total_bytes = conn.execute(
        "SELECT COALESCE(SUM(file_size_bytes), 0) FROM podt_proofs"
    ).fetchone()[0]
    podt_total_reward = conn.execute(
        "SELECT COALESCE(SUM(reward_cents), 0) FROM podt_proofs"
    ).fetchone()[0]

    # User grants count
    grants_issued = conn.execute("SELECT COUNT(*) FROM user_grants").fetchone()[0]

    conn.close()

    return {
        "block_count": block_count,
        "transaction_count": tx_count,
        "gfc_in_circulation": circulation_cents / 100.0,
        "gfc_in_circulation_cents": circulation_cents,
        "treasury_balance": treasury_balance_cents / 100.0,
        "treasury_balance_cents": treasury_balance_cents,
        "premine_total": PREMINE_CENTS / 100.0,
        "chain_valid": is_valid,
        "chain_validation_msg": validation_msg,
        "grants_issued": grants_issued,
        "podt_transfers": podt_count,
        "podt_total_bytes": podt_total_bytes,
        "podt_total_bytes_mb": podt_total_bytes / (1024 * 1024) if podt_total_bytes else 0.0,
        "podt_total_reward": podt_total_reward / 100.0 if podt_total_reward else 0.0,
    }


# ============================================================================
# UTILITY
# ============================================================================

def cents_to_display(cents: int) -> str:
    """Format cents as display string: 10000 -> '100.00'"""
    return f"{cents / 100:.2f}"


# ============================================================================
# STANDALONE TEST
# ============================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("GFC Blockchain Core - Test")
    print("=" * 60)

    test_db = "data/test_blockchain.db"

    # Initialize
    import os
    os.makedirs("data", exist_ok=True)

    # Create tables
    init_blockchain_tables(test_db)
    create_genesis_block(test_db)

    # Check Treasury
    treasury_bal = get_balance_cents(test_db, TREASURY_WALLET_ID)
    print(f"\nTreasury balance: {cents_to_display(treasury_bal)} GFC")

    # Simulate user grant
    grant_result = process_user_grant(test_db, "testuser", "wallet_test_001")
    if grant_result:
        print(f"\nGrant issued: {grant_result['amount']} GFC to wallet_test_001")
        print(f"  TX hash: {grant_result['tx_hash']}")
        print(f"  Block: {grant_result['block_index']}")

    # Check balances
    user_bal = get_balance_cents(test_db, "wallet_test_001")
    treasury_after = get_balance_cents(test_db, TREASURY_WALLET_ID)
    print(f"\nUser balance: {cents_to_display(user_bal)} GFC")
    print(f"Treasury balance: {cents_to_display(treasury_after)} GFC")

    # Try duplicate grant
    dup = process_user_grant(test_db, "testuser", "wallet_test_002")
    print(f"\nDuplicate grant: {'Rejected (correct)' if dup is None else 'ERROR: should have been rejected'}")

    # Validate chain
    is_valid, msg = validate_chain(test_db)
    print(f"\nChain validation: {msg}")

    # Stats
    stats = get_blockchain_stats(test_db)
    print(f"\nBlockchain stats:")
    print(json.dumps(stats, indent=2))

    # Cleanup test DB
    os.remove(test_db)
    print("\nTest complete. Cleaned up test DB.")
