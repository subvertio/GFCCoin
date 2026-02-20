"""
GFC Blockchain Migration Script
Converts existing flat SQLite data to blockchain structure.

Usage:
    cd C:\GFC-Dev\backend
    python migrate_to_blockchain.py

What it does:
1. Backs up the existing gfc_ledger.db
2. Creates blockchain tables and genesis block
3. Migrates existing transactions (adds tx_hash, amount_cents, tx_type, block_index)
4. Creates user grants for existing wallet owners
5. Recalculates all wallet balances from blockchain

Safe to run multiple times (idempotent).
"""

import os
import sys
import shutil
import sqlite3
import json
from datetime import datetime, timezone

# Add backend dir to path so imports work
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import DB_PATH
from blockchain import (
    init_blockchain_tables,
    create_genesis_block,
    compute_tx_hash,
    compute_merkle_root,
    create_block,
    get_balance_cents,
    process_user_grant,
    validate_chain,
    get_blockchain_stats,
    TREASURY_WALLET_ID,
    TX_TYPE_TRANSFER,
    TX_TYPE_GRANT,
)


def migrate():
    """Run the full migration."""
    print("=" * 60)
    print("GFC Blockchain Migration")
    print("=" * 60)
    print(f"Database: {DB_PATH}")
    print()

    if not os.path.exists(DB_PATH):
        print("ERROR: Database not found. Run the backend first to create it.")
        return False

    # Step 1: Backup
    backup_path = DB_PATH + ".pre_blockchain_backup"
    if not os.path.exists(backup_path):
        print(f"[1/5] Backing up database to {backup_path}")
        shutil.copy2(DB_PATH, backup_path)
        print(f"  Backup created: {os.path.getsize(backup_path)} bytes")
    else:
        print(f"[1/5] Backup already exists at {backup_path} (skipping)")

    # Step 2: Create blockchain tables and genesis block
    print("\n[2/5] Creating blockchain tables and genesis block...")
    init_blockchain_tables(DB_PATH)
    create_genesis_block(DB_PATH)
    print("  Genesis block created (or already exists)")

    conn = sqlite3.connect(DB_PATH)

    # Step 3: Migrate existing transactions
    print("\n[3/5] Migrating existing transactions...")

    # Find transactions without tx_hash (not yet migrated)
    unmigrated = conn.execute(
        "SELECT id, sender, recipient, amount, reason, timestamp "
        "FROM transactions WHERE (tx_hash IS NULL OR tx_hash = '') AND id != 'GENESIS-PREMINE-TX-001'"
    ).fetchall()

    migrated_count = 0
    batch_tx_ids = []
    blocks_created = 0

    for row in unmigrated:
        tx_id, sender, recipient, amount, reason, timestamp = row

        # Convert amount to cents
        try:
            amount_float = float(amount) if amount else 0.0
        except (ValueError, TypeError):
            amount_float = 0.0
        amount_cents = int(amount_float * 100)

        # Compute hash
        tx_dict = {
            "sender": sender or "",
            "recipient": recipient or "",
            "amount_cents": amount_cents,
            "timestamp": timestamp or "",
            "tx_type": TX_TYPE_TRANSFER,
            "reason": reason or "",
        }
        tx_hash = compute_tx_hash(tx_dict)

        # Update the transaction
        conn.execute(
            "UPDATE transactions SET amount_cents = ?, tx_hash = ?, tx_type = ? WHERE id = ?",
            (amount_cents, tx_hash, TX_TYPE_TRANSFER, tx_id)
        )
        migrated_count += 1
        batch_tx_ids.append(tx_id)

        # Create blocks in batches of 100
        if len(batch_tx_ids) >= 100:
            conn.commit()
            create_block(DB_PATH, batch_tx_ids)
            blocks_created += 1
            batch_tx_ids = []

    # Final batch
    if batch_tx_ids:
        conn.commit()
        create_block(DB_PATH, batch_tx_ids)
        blocks_created += 1

    conn.commit()
    print(f"  Migrated {migrated_count} transactions into {blocks_created} new blocks")

    # Step 4: Create user grants for existing wallet owners
    print("\n[4/5] Processing user grants for existing wallets...")

    wallets = conn.execute(
        "SELECT id, owner FROM wallets WHERE id != ? AND owner != '' AND owner IS NOT NULL",
        (TREASURY_WALLET_ID,)
    ).fetchall()

    grants_created = 0
    grants_skipped = 0

    for wallet_id, owner in wallets:
        # Check if this owner already has a grant
        existing_grant = conn.execute(
            "SELECT username FROM user_grants WHERE username = ?", (owner,)
        ).fetchone()

        if existing_grant:
            grants_skipped += 1
            continue

        # Close the conn so process_user_grant can open its own
        conn.close()
        result = process_user_grant(DB_PATH, owner, wallet_id)
        conn = sqlite3.connect(DB_PATH)

        if result:
            grants_created += 1
        else:
            grants_skipped += 1

    print(f"  Grants created: {grants_created}, Skipped (already granted): {grants_skipped}")

    # Step 5: Recalculate wallet balances
    print("\n[5/5] Recalculating wallet balances from blockchain...")

    all_wallets = conn.execute(
        "SELECT id FROM wallets"
    ).fetchall()

    for (wallet_id,) in all_wallets:
        balance_cents = get_balance_cents(DB_PATH, wallet_id)
        conn.execute(
            "UPDATE wallets SET gfc_balance_cents = ?, gfc_balance = ? WHERE id = ?",
            (balance_cents, balance_cents / 100.0, wallet_id)
        )

    conn.commit()
    conn.close()

    print(f"  Updated {len(all_wallets)} wallet balances")

    # Validate
    print("\n" + "=" * 60)
    print("VALIDATION")
    print("=" * 60)

    is_valid, msg = validate_chain(DB_PATH)
    print(f"Chain validation: {msg}")

    stats = get_blockchain_stats(DB_PATH)
    print(f"\nBlockchain Statistics:")
    print(f"  Blocks: {stats['block_count']}")
    print(f"  Transactions: {stats['transaction_count']}")
    print(f"  Treasury balance: {stats['treasury_balance']:,.2f} GFC")
    print(f"  GFC in circulation: {stats['gfc_in_circulation']:,.2f} GFC")
    print(f"  Grants issued: {stats['grants_issued']}")
    print(f"  Chain valid: {stats['chain_valid']}")

    print("\n" + "=" * 60)
    print("MIGRATION COMPLETE")
    print("=" * 60)
    return True


if __name__ == "__main__":
    success = migrate()
    sys.exit(0 if success else 1)
