"""
GFC Blockchain Core Module
Hybrid SQLite blockchain with Treasury, grants, and PoDT rewards.

Architecture inspired by GFCoin.sol (ERC-20, 2 decimals) and TreasuryBank.sol
(oracle-gated rewards), implemented in SQLite for desktop P2P deployment.

All financial amounts are stored as INTEGER cents (100 = 1.00 GFC).
"""

import hashlib
import json
import re
import sqlite3
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple

import config as _config
from config import DB_PATH
import phone_verify
import signing

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
TX_TYPE_REFERRAL = "REFERRAL"  # Treasury -> inviter (friend became active) or invited friend (bonus)
TX_TYPE_REPOST   = "REPOST"    # Treasury -> original creator (a verified user reposted their content)
TX_TYPE_FIRST_POST = "FIRST_POST"  # Treasury -> creator's first original post (see first_post.py)
TX_TYPE_OPERATOR = "OPERATOR"      # Treasury -> hackathon prizes, node hosts, ... (see treasury_grants.py)
MINT_TX_TYPES = (TX_TYPE_GRANT, TX_TYPE_REWARD, TX_TYPE_REFERRAL, TX_TYPE_REPOST, TX_TYPE_FIRST_POST,
                 TX_TYPE_OPERATOR)

# Invite rewards: the only two amounts a REFERRAL mint may carry (see referrals.py)
REFERRAL_REWARD_CENTS = 100_000         # 1,000 GFC to the inviter per friend who becomes active
REFERRAL_BONUS_CENTS = 10_000           # 100 GFC extra to the invited friend

# Repost credit: the only amount a REPOST mint may carry (see reposts.py)
REPOST_CREDIT_CENTS = 1_500             # 15 GFC to the original creator per verified reposter

# First post bonus: the amount is node config (first_post.py), but a FIRST_POST mint may
# carry at most this, and each wallet may receive only one
FIRST_POST_BONUS_MAX_CENTS = 100_000    # 1,000 GFC

# Operator grants (treasury_grants.py): every node checks the cap and the purpose/memo
# format, so even a leaked treasury key can't mint more than this per transaction.
OPERATOR_GRANT_MAX_CENTS = 1_000_000    # 10,000 GFC
NODE_HOST_GRANT_CENTS = 1_000_000       # a node host's one-time grant: exactly 10,000 GFC
OPERATOR_PURPOSES = ("hackathon", "node-host", "other")
OPERATOR_REASON_RE = re.compile(r"^Operator grant \((hackathon|node-host|other)\): \S.{2,}$", re.S)

# Bridge escrow wallets (config.BRIDGE_ESCROWS: one per EVM chain; see docs/bridge-service.md).
# Every node enforces these rules, so a typo can't strand GFC in escrow and escrow funds
# can only leave as bridge payouts or refunds:
# - a deposit is a TRANSFER to an escrow with reason bridge:v1:<that escrow's chain>:<0xaddress>
# - escrow outflows are TRANSFERs with reason bridge-out:v1:<chain>:<nonce>:<evm tx> or
#   bridge-refund:v1:<deposit tx_hash>
# - no mints to an escrow, and no escrow-to-escrow transfers
BRIDGE_DEPOSIT_RE = re.compile(r"^bridge:v1:(\d{1,12}):(0x[0-9a-fA-F]{40})$")
BRIDGE_PAYOUT_RE = re.compile(r"^bridge-out:v1:(\d{1,12}):\d{1,20}:0x[0-9a-fA-F]{64}$")
BRIDGE_REFUND_RE = re.compile(r"^bridge-refund:v1:[0-9a-f]{64}$")

# Limits applied to transactions received from peers
MAX_REASON_LEN = 500
MAX_REWARD_CENTS = 100_000              # 1,000 GFC per reward tx (~10 GB of PoDT)
MAX_CLOCK_SKEW = timedelta(hours=1)     # reject rows timestamped further in the future
PENDING_TTL = timedelta(days=7)         # unfunded synced transfers are retried this long
MAX_PENDING = 5_000

# Play rewards (Sybil friction; enforced by the node that issues the reward)
MIN_VIEWER_ACCOUNT_AGE = timedelta(hours=24)  # viewer accounts younger than this earn nobody credit
PLAY_REWARDS_PER_CREATOR_PER_DAY = 1          # per viewer, per creator wallet, per UTC day

TX_INSERT_COLUMNS = ("id", "sender", "recipient", "amount", "reason", "timestamp",
                     "amount_cents", "tx_hash", "tx_type", "signature", "signer")


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
        ("signature", "TEXT DEFAULT ''"),  # Ed25519 signature over tx_hash ('' = local-only)
        ("signer", "TEXT DEFAULT ''"),     # public key that signed (sender, or treasury for mints)
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

    # A tx_hash may only appear once (blocks replays of a signed transaction under a new id)
    try:
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_transactions_tx_hash "
                     "ON transactions(tx_hash) WHERE tx_hash != ''")
    except sqlite3.Error:
        pass  # Legacy duplicates; uniqueness is still checked in code for synced rows

    # Synced transfers with a valid signature but not (yet) enough sender balance on
    # this node, e.g. because the funding transaction hasn't arrived yet. Local only.
    conn.execute('''CREATE TABLE IF NOT EXISTS pending_sync_tx (
        id TEXT PRIMARY KEY,
        tx_json TEXT NOT NULL,
        received_at TEXT NOT NULL
    )''')

    # Paid play rewards per (viewer, creator wallet, UTC day), for the daily cap. Local only.
    conn.execute('''CREATE TABLE IF NOT EXISTS play_reward_slots (
        viewer TEXT NOT NULL,
        seeder_wallet TEXT NOT NULL,
        day TEXT NOT NULL,
        slot INTEGER NOT NULL,
        proof_id TEXT NOT NULL,
        PRIMARY KEY (viewer, seeder_wallet, day, slot)
    )''')

    signing.init_wallet_keys_table(conn)
    phone_verify.init_phone_tables(conn)

    conn.commit()
    conn.close()


def _insert_tx(conn: sqlite3.Connection, tx: dict):
    """Insert a transaction dict (block_index is set later by create_block)."""
    conn.execute(
        f"INSERT INTO transactions ({', '.join(TX_INSERT_COLUMNS)}) "
        f"VALUES ({', '.join('?' * len(TX_INSERT_COLUMNS))})",
        tuple(tx.get(c, "") for c in TX_INSERT_COLUMNS)
    )


def _sign_mint(tx: dict):
    """Sign a GRANT/REWARD with the treasury key if this node holds it."""
    treasury_key = signing.load_treasury_private_key()
    if treasury_key:
        tx["signer"] = signing.public_key_of(treasury_key)
        tx["signature"] = signing.sign_tx_hash(treasury_key, tx["tx_hash"])
    else:
        tx["signer"] = ""
        tx["signature"] = ""  # Local-only: peers will not accept this mint


def bridge_escrow_chain(wallet_id: str) -> Optional[int]:
    """The EVM chain ID whose bridge escrow this wallet is, or None."""
    for chain_id, escrow in _config.BRIDGE_ESCROWS.items():
        if escrow == wallet_id:
            return chain_id
    return None


def bridge_rule_violation(sender: str, recipient: str, reason: str,
                          tx_type: str = TX_TYPE_TRANSFER) -> Optional[str]:
    """Why a transaction breaks the escrow rules above, or None if it doesn't touch an escrow."""
    to_chain = bridge_escrow_chain(recipient)
    from_chain = bridge_escrow_chain(sender)
    if to_chain is None and from_chain is None:
        return None
    if tx_type != TX_TYPE_TRANSFER:
        return "bridge escrow wallets only send and receive transfers"
    if to_chain is not None and from_chain is not None:
        return "escrow-to-escrow transfers aren't allowed"
    if to_chain is not None:
        m = BRIDGE_DEPOSIT_RE.match(reason or "")
        if not m or int(m.group(1)) != to_chain or int(m.group(2), 16) == 0:
            return f"a bridge deposit needs the reason bridge:v1:{to_chain}:<0x EVM address>"
        return None
    m = BRIDGE_PAYOUT_RE.match(reason or "")
    if (m and int(m.group(1)) == from_chain) or BRIDGE_REFUND_RE.match(reason or ""):
        return None
    return "bridge escrow funds only leave as bridge payouts or refunds"


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
    Grant 100 GFC to a user's first wallet, once their phone is verified.
    Returns the transaction dict if grant was issued, None if the user is not
    phone-verified or already received the grant.
    Thread-safe via SQLite's built-in locking.
    """
    conn = sqlite3.connect(db_path)

    if not phone_verify.is_verified(conn, username):
        conn.close()
        return None  # Grants need a verified phone (one per number), see phone_verify.py

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
    _sign_mint(tx)
    _insert_tx(conn, tx)

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
                     amount_cents: int, reason: str = "", data_key: Optional[bytes] = None) -> dict:
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

    if sender_wallet == TREASURY_WALLET_ID or recipient_wallet == TREASURY_WALLET_ID:
        raise ValueError("Treasury funds move only through grants and rewards")
    violation = bridge_rule_violation(sender_wallet, recipient_wallet, reason)
    if violation:
        raise ValueError(violation)

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

    # Sign with the sender's local key. Legacy wallets (created before signed
    # wallets, no key) can still transfer on this node, but peers reject the row.
    # data_key unlocks the key if it is encrypted at rest (see keystore.py)
    private_key = signing.get_wallet_private_key(db_path, sender_wallet, data_key)
    if not private_key and signing.has_wallet_key(db_path, sender_wallet):
        raise ValueError("Wallet key is locked: log in again to sign transfers")
    if private_key:
        tx["signer"] = sender_wallet
        tx["signature"] = signing.sign_tx_hash(private_key, tx["tx_hash"])
    else:
        tx["signer"] = ""
        tx["signature"] = ""

    conn = sqlite3.connect(db_path)
    _insert_tx(conn, tx)
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
    reward_cents = min(int(mb_transferred * CREDITS_PER_MB_CENTS), MAX_REWARD_CENTS)

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
    _sign_mint(tx)
    _insert_tx(conn, tx)

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


def process_referral_mint(db_path: str, wallet_id: str, amount_cents: int, reason: str) -> Optional[dict]:
    """
    Mint an invite reward or bonus (REFERRAL) from the treasury. Callers (referrals.py)
    decide eligibility and make sure each one is paid once. None if the treasury is short.
    """
    if amount_cents not in (REFERRAL_REWARD_CENTS, REFERRAL_BONUS_CENTS):
        raise ValueError("referral mints are REFERRAL_REWARD_CENTS or REFERRAL_BONUS_CENTS")
    if get_balance_cents(db_path, TREASURY_WALLET_ID) < amount_cents:
        print(f"[Blockchain] WARNING: Treasury depleted, cannot pay referral {amount_cents / 100:.2f} GFC")
        return None
    tx = {
        "id": str(uuid.uuid4()),
        "sender": TREASURY_WALLET_ID,
        "recipient": wallet_id,
        "amount": amount_cents / 100.0,
        "amount_cents": amount_cents,
        "reason": reason[:MAX_REASON_LEN],
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tx_type": TX_TYPE_REFERRAL,
    }
    tx["tx_hash"] = compute_tx_hash(tx)
    _sign_mint(tx)
    conn = sqlite3.connect(db_path)
    _insert_tx(conn, tx)
    conn.commit()
    conn.close()
    tx["block_index"] = create_block(db_path, [tx["id"]])["block_index"]
    return tx


def process_repost_mint(db_path: str, wallet_id: str, reason: str) -> Optional[dict]:
    """
    Mint the repost credit (REPOST, exactly REPOST_CREDIT_CENTS) from the treasury to an
    original creator's wallet. Callers (reposts.py) decide eligibility and make sure each
    (reposter, original) pays once. None if the treasury is short.
    """
    amount_cents = REPOST_CREDIT_CENTS
    if get_balance_cents(db_path, TREASURY_WALLET_ID) < amount_cents:
        print(f"[Blockchain] WARNING: Treasury depleted, cannot pay repost credit {amount_cents / 100:.2f} GFC")
        return None
    tx = {
        "id": str(uuid.uuid4()),
        "sender": TREASURY_WALLET_ID,
        "recipient": wallet_id,
        "amount": amount_cents / 100.0,
        "amount_cents": amount_cents,
        "reason": reason[:MAX_REASON_LEN],
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tx_type": TX_TYPE_REPOST,
    }
    tx["tx_hash"] = compute_tx_hash(tx)
    _sign_mint(tx)
    conn = sqlite3.connect(db_path)
    _insert_tx(conn, tx)
    conn.commit()
    conn.close()
    tx["block_index"] = create_block(db_path, [tx["id"]])["block_index"]
    return tx


def process_first_post_mint(db_path: str, wallet_id: str, amount_cents: int, reason: str) -> Optional[dict]:
    """
    Mint the first post bonus (FIRST_POST, at most FIRST_POST_BONUS_MAX_CENTS) from the
    treasury. The caller (first_post.py) decides eligibility and makes sure each account
    is paid once. None if the treasury is short.
    """
    if not 0 < amount_cents <= FIRST_POST_BONUS_MAX_CENTS:
        raise ValueError("first post mints are 1..FIRST_POST_BONUS_MAX_CENTS")
    if get_balance_cents(db_path, TREASURY_WALLET_ID) < amount_cents:
        print(f"[Blockchain] WARNING: Treasury depleted, cannot pay first post bonus {amount_cents / 100:.2f} GFC")
        return None
    tx = {
        "id": str(uuid.uuid4()),
        "sender": TREASURY_WALLET_ID,
        "recipient": wallet_id,
        "amount": amount_cents / 100.0,
        "amount_cents": amount_cents,
        "reason": reason[:MAX_REASON_LEN],
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tx_type": TX_TYPE_FIRST_POST,
    }
    tx["tx_hash"] = compute_tx_hash(tx)
    _sign_mint(tx)
    conn = sqlite3.connect(db_path)
    _insert_tx(conn, tx)
    conn.commit()
    conn.close()
    tx["block_index"] = create_block(db_path, [tx["id"]])["block_index"]
    return tx


def process_operator_mint(db_path: str, wallet_id: str, amount_cents: int, reason: str) -> Optional[dict]:
    """
    Mint an operator grant (OPERATOR, at most OPERATOR_GRANT_MAX_CENTS) from the treasury.
    treasury_grants.py builds the reason ("Operator grant (<purpose>): <memo>") and checks
    the rules first. None if the treasury is short.
    """
    if not 0 < amount_cents <= OPERATOR_GRANT_MAX_CENTS:
        raise ValueError("operator grants are 1..OPERATOR_GRANT_MAX_CENTS")
    if len(reason) > MAX_REASON_LEN or not OPERATOR_REASON_RE.match(reason):
        raise ValueError("operator grant reason must be 'Operator grant (<purpose>): <memo>'")
    if get_balance_cents(db_path, TREASURY_WALLET_ID) < amount_cents:
        print(f"[Blockchain] WARNING: Treasury depleted, cannot pay operator grant {amount_cents / 100:.2f} GFC")
        return None
    tx = {
        "id": str(uuid.uuid4()),
        "sender": TREASURY_WALLET_ID,
        "recipient": wallet_id,
        "amount": amount_cents / 100.0,
        "amount_cents": amount_cents,
        "reason": reason,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tx_type": TX_TYPE_OPERATOR,
    }
    tx["tx_hash"] = compute_tx_hash(tx)
    _sign_mint(tx)
    conn = sqlite3.connect(db_path)
    _insert_tx(conn, tx)
    conn.commit()
    conn.close()
    tx["block_index"] = create_block(db_path, [tx["id"]])["block_index"]
    return tx


def play_reward_block_reason(conn: sqlite3.Connection, viewer: str) -> Optional[str]:
    """Why `viewer`'s plays can't earn credit for anyone (None if they can)."""
    if not phone_verify.is_verified(conn, viewer):
        return "viewer phone not verified"
    row = conn.execute("SELECT created_at FROM users WHERE username = ?", (viewer,)).fetchone()
    created = _parse_timestamp(row[0]) if row else None
    if created is None or datetime.now(timezone.utc) - created < MIN_VIEWER_ACCOUNT_AGE:
        return "viewer account too new"
    return None


def claim_play_slot(db_path: str, viewer: str, seeder_wallet: str, proof_id: str) -> bool:
    """Reserve one of today's play rewards from viewer to this creator wallet. False if all are used."""
    day = datetime.now(timezone.utc).date().isoformat()
    conn = sqlite3.connect(db_path)
    try:
        for slot in range(PLAY_REWARDS_PER_CREATOR_PER_DAY):
            try:
                conn.execute("INSERT INTO play_reward_slots (viewer, seeder_wallet, day, slot, proof_id) "
                             "VALUES (?, ?, ?, ?, ?)", (viewer, seeder_wallet, day, slot, proof_id))
                conn.commit()
                return True
            except sqlite3.IntegrityError:
                continue
        return False
    finally:
        conn.close()


def release_play_slot(db_path: str, proof_id: str):
    """Give back a slot whose reward was not paid."""
    conn = sqlite3.connect(db_path)
    conn.execute("DELETE FROM play_reward_slots WHERE proof_id = ?", (proof_id,))
    conn.commit()
    conn.close()


# ============================================================================
# SYNCED TRANSACTION VALIDATION
# ============================================================================
#
# Rules for a transaction row received from a peer or the tracker (see
# docs/signed-ledger.md for the reasoning):
#   - tx_hash must equal compute_tx_hash() of the row's contents, and must be new
#   - TRANSFER: sender is an Ed25519 public key and signed the tx_hash, and has
#     enough balance on this node (otherwise the row waits in pending_sync_tx)
#   - GRANT / REWARD / REFERRAL / REPOST / FIRST_POST: sender is the treasury wallet and the
#     signature is from a pinned treasury key; GRANT is exactly NEW_USER_GRANT_CENTS,
#     once per wallet; REFERRAL is exactly REFERRAL_REWARD_CENTS or
#     REFERRAL_BONUS_CENTS; REPOST is exactly REPOST_CREDIT_CENTS; FIRST_POST is at
#     most FIRST_POST_BONUS_MAX_CENTS, once per wallet
#   - PREMINE: never accepted; every node creates its own genesis
# The peer's block_index is ignored: accepted rows go into a new local block.

ACCEPTED, DUPLICATE, PENDING, REJECTED = "accepted", "duplicate", "pending", "rejected"


def _parse_timestamp(value) -> Optional[datetime]:
    if not isinstance(value, str) or not value:
        return None
    try:
        ts = datetime.fromisoformat(value)
    except ValueError:
        return None
    return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)


def check_synced_transaction(db_path: str, tx: dict) -> Tuple[str, str]:
    """
    Decide what to do with a transaction row from a peer, without writing it.
    Returns (status, reason) where status is ACCEPTED, DUPLICATE, PENDING or REJECTED.
    """
    tx_id = tx.get("id")
    sender = tx.get("sender")
    recipient = tx.get("recipient")
    amount_cents = tx.get("amount_cents")
    tx_type = tx.get("tx_type")
    reason = tx.get("reason") or ""
    tx_hash = tx.get("tx_hash") or ""
    signature = tx.get("signature") or ""

    if not isinstance(tx_id, str) or not 0 < len(tx_id) <= 100:
        return REJECTED, "bad id"
    if not isinstance(amount_cents, int) or isinstance(amount_cents, bool) or amount_cents <= 0:
        return REJECTED, "bad amount"
    if tx_type == TX_TYPE_PREMINE:
        return REJECTED, "premine is created locally, never synced"
    if tx_type not in (TX_TYPE_TRANSFER,) + MINT_TX_TYPES:
        return REJECTED, "unknown tx_type"
    if not isinstance(reason, str) or len(reason) > MAX_REASON_LEN:
        return REJECTED, "bad reason"
    if not isinstance(sender, str) or not isinstance(recipient, str) or not recipient \
            or recipient == sender or recipient == TREASURY_WALLET_ID:
        return REJECTED, "bad sender or recipient"
    violation = bridge_rule_violation(sender, recipient, reason, tx_type)
    if violation:
        return REJECTED, violation
    ts = _parse_timestamp(tx.get("timestamp"))
    if ts is None or ts > datetime.now(timezone.utc) + MAX_CLOCK_SKEW:
        return REJECTED, "bad timestamp"
    if tx_hash != compute_tx_hash(tx):
        return REJECTED, "tx_hash does not match contents"
    if not isinstance(signature, str) or not signature:
        return REJECTED, "unsigned"

    if tx_type == TX_TYPE_TRANSFER:
        if not signing.is_public_key(sender):
            return REJECTED, "sender is not a public key"
        if tx.get("signer") not in ("", None, sender):
            return REJECTED, "transfer must be signed by its sender"
        signer = sender
    else:
        signer = tx.get("signer") or ""
        if sender != TREASURY_WALLET_ID:
            return REJECTED, "mint must come from the treasury"
        if not isinstance(signer, str) or signer.lower() not in signing.treasury_pubkeys():
            return REJECTED, "mint not signed by a treasury key"
        if tx_type == TX_TYPE_GRANT and amount_cents != NEW_USER_GRANT_CENTS:
            return REJECTED, "wrong grant amount"
        if tx_type == TX_TYPE_REWARD and amount_cents > MAX_REWARD_CENTS:
            return REJECTED, "reward too large"
        if tx_type == TX_TYPE_REFERRAL and amount_cents not in (REFERRAL_REWARD_CENTS, REFERRAL_BONUS_CENTS):
            return REJECTED, "wrong referral amount"
        if tx_type == TX_TYPE_REPOST and amount_cents != REPOST_CREDIT_CENTS:
            return REJECTED, "wrong repost credit amount"
        if tx_type == TX_TYPE_FIRST_POST and amount_cents > FIRST_POST_BONUS_MAX_CENTS:
            return REJECTED, "first post bonus too large"
        if tx_type == TX_TYPE_OPERATOR:
            if amount_cents > OPERATOR_GRANT_MAX_CENTS:
                return REJECTED, "operator grant too large"
            m = OPERATOR_REASON_RE.match(reason)
            if not m:
                return REJECTED, "operator grant needs a purpose and memo"
            if m.group(1) == "node-host" and amount_cents != NODE_HOST_GRANT_CENTS:
                return REJECTED, "wrong node host grant amount"
    if not signing.verify_tx_signature(signer, tx_hash, signature):
        return REJECTED, "bad signature"

    conn = sqlite3.connect(db_path)
    try:
        if conn.execute("SELECT 1 FROM transactions WHERE id = ?", (tx_id,)).fetchone():
            return DUPLICATE, "already have this id"
        if conn.execute("SELECT 1 FROM transactions WHERE tx_hash = ?", (tx_hash,)).fetchone():
            return REJECTED, "replayed tx_hash"
        if tx_type == TX_TYPE_GRANT and conn.execute(
                "SELECT 1 FROM transactions WHERE tx_type = ? AND recipient = ?",
                (TX_TYPE_GRANT, recipient)).fetchone():
            return REJECTED, "wallet already received a grant"
        if tx_type == TX_TYPE_FIRST_POST and conn.execute(
                "SELECT 1 FROM transactions WHERE tx_type = ? AND recipient = ?",
                (TX_TYPE_FIRST_POST, recipient)).fetchone():
            return REJECTED, "wallet already received a first post bonus"
        if (tx_type == TX_TYPE_OPERATOR and reason.startswith("Operator grant (node-host)")
                and conn.execute("SELECT 1 FROM transactions WHERE tx_type = ? AND recipient = ? "
                                 "AND reason LIKE 'Operator grant (node-host)%'",
                                 (TX_TYPE_OPERATOR, recipient)).fetchone()):
            return REJECTED, "wallet already received a node host grant"
    finally:
        conn.close()

    if get_balance_cents(db_path, sender) < amount_cents:
        return PENDING, "insufficient sender balance"
    return ACCEPTED, ""


def accept_synced_transaction(db_path: str, tx: dict) -> Tuple[str, str]:
    """Validate a synced transaction and, if valid, add it to a new local block."""
    status, reason = check_synced_transaction(db_path, tx)
    if status != ACCEPTED:
        return status, reason
    row = {c: tx.get(c, "") for c in TX_INSERT_COLUMNS}
    row["amount"] = tx["amount_cents"] / 100.0
    row["signer"] = tx.get("signer") or tx["sender"]
    conn = sqlite3.connect(db_path)
    try:
        _insert_tx(conn, row)
        conn.commit()
    except sqlite3.IntegrityError:
        return DUPLICATE, "inserted concurrently"
    finally:
        conn.close()
    create_block(db_path, [tx["id"]])
    return ACCEPTED, ""


def _queue_pending(db_path: str, tx: dict):
    now = datetime.now(timezone.utc)
    conn = sqlite3.connect(db_path)
    conn.execute("INSERT OR IGNORE INTO pending_sync_tx (id, tx_json, received_at) VALUES (?, ?, ?)",
                 (tx["id"], json.dumps(tx), now.isoformat()))
    conn.execute("DELETE FROM pending_sync_tx WHERE received_at < ?", ((now - PENDING_TTL).isoformat(),))
    conn.execute("DELETE FROM pending_sync_tx WHERE id NOT IN "
                 "(SELECT id FROM pending_sync_tx ORDER BY received_at DESC LIMIT ?)", (MAX_PENDING,))
    conn.commit()
    conn.close()


def retry_pending_transactions(db_path: str) -> int:
    """Re-check queued transfers until no more become valid. Returns how many were accepted."""
    accepted_total = 0
    while True:
        conn = sqlite3.connect(db_path)
        pending = [json.loads(r[0]) for r in conn.execute("SELECT tx_json FROM pending_sync_tx")]
        conn.close()
        pending.sort(key=lambda t: t.get("timestamp", ""))
        accepted = 0
        for tx in pending:
            status, _ = accept_synced_transaction(db_path, tx)
            if status == PENDING:
                continue
            accepted += status == ACCEPTED
            conn = sqlite3.connect(db_path)
            conn.execute("DELETE FROM pending_sync_tx WHERE id = ?", (tx["id"],))
            conn.commit()
            conn.close()
        accepted_total += accepted
        if not accepted:
            return accepted_total


def ingest_synced_transactions(db_path: str, columns: List[str], rows: list) -> Dict[str, int]:
    """
    Validate and store transaction rows from a peer or the tracker. Rows that are
    signed correctly but not yet funded are queued and retried as more rows
    arrive. Returns a count per status.
    """
    counts = {ACCEPTED: 0, DUPLICATE: 0, PENDING: 0, REJECTED: 0}
    txs = [dict(zip(columns, row)) for row in rows if len(row) == len(columns)]
    txs.sort(key=lambda t: str(t.get("timestamp", "")))
    for tx in txs:
        status, _ = accept_synced_transaction(db_path, tx)
        if status == PENDING:
            _queue_pending(db_path, tx)
        counts[status] += 1
    counts[ACCEPTED] += retry_pending_transactions(db_path)
    return counts


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
        "WHERE tx_type IN (?, ?, ?, ?, ?) AND block_index IS NOT NULL",
        (TX_TYPE_REWARD, TX_TYPE_REFERRAL, TX_TYPE_REPOST, TX_TYPE_FIRST_POST, TX_TYPE_OPERATOR)
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
