"""
GFC Sync Ingest - which rows are shared with peers, and how received rows are accepted

Shared by the TCP sync engine (sync_engine.py) and the tracker relay
(peer_discovery.py), so both paths apply the same rules:

- Only whitelisted columns are sent or accepted (security.sanitize_incoming_rows).
- `transactions` rows go through blockchain.ingest_synced_transactions: they must
  be signed and funded, and get a new local block. Only signed rows are sent.
- `seeds` rows signed by their reward wallet must verify, or they are dropped.
  Unsigned (legacy) seeds are still shared as content, but with no reward
  wallet, so they earn nothing on this node.
- `originality_receipts` must be signed by a pinned treasury key (reposts.py), or
  they are dropped. New ones re-check local seeds (the earliest receipt wins).
- `wallets` rows are accepted as directory entries only. Balances are never taken
  from a peer; they are always computed from validated transactions.
- `blocks`, `user_grants`, `podt_proofs` and the local repost tables
  (seed_fingerprints, reposts, repost_credits) are not synced. They are derived on
  each node from the transactions it accepted or issued itself.
"""

import logging
import sqlite3
from typing import Dict, List

import blockchain
import reposts
import signing
from config import DB_PATH
from security import PUBLIC_USER_COLUMNS, sanitize_incoming_rows

logger = logging.getLogger("gfc.sync")

SYNCABLE_TABLES = ["users", "seeds", "transactions", "likes", "comments", "bookmarks", "wallets",
                   "originality_receipts"]

# Columns for each table (sent to peers, and the only ones accepted from them)
TABLE_COLUMNS = {
    "users": PUBLIC_USER_COLUMNS,  # never share passwords, email, phone or names
    "seeds": "id, owner, title, description, tags, filename, thumb_filename, content_type, file_size, gfc_earned, likes, comments, views, created_at, reward_wallet, signature",
    "transactions": "id, sender, recipient, amount, reason, timestamp, amount_cents, tx_hash, tx_type, signature, signer",
    "likes": "id, seed_id, owner, created_at",
    "comments": "id, seed_id, owner, text, created_at",
    "bookmarks": "id, seed_id, owner, created_at",
    "wallets": "id, name, owner, created_at",  # no balance columns: balances come from the ledger
    "originality_receipts": "id, fingerprints, seed_id, owner, reward_wallet, first_seen_at, signer, signature",
}

# Timestamp column for each table (used for "since" queries)
TABLE_TIMESTAMP_COL = {
    "users": "created_at",
    "seeds": "created_at",
    "transactions": "timestamp",
    "likes": "created_at",
    "comments": "created_at",
    "bookmarks": "created_at",
    "wallets": "created_at",
    "originality_receipts": "first_seen_at",
}

# Extra WHERE clause for rows we send. Unsigned transactions (legacy rows, and
# mints from nodes without the treasury key) are local-only.
TABLE_SEND_FILTER = {
    "transactions": "signature != '' AND tx_type != 'PREMINE'",
}


def select_rows_since(conn: sqlite3.Connection, table: str, since: str, limit: int) -> list:
    """Rows of a syncable table newer than `since` (all rows if empty), oldest first."""
    columns = TABLE_COLUMNS[table]
    ts_col = TABLE_TIMESTAMP_COL.get(table, "created_at")
    clauses, params = [], []
    if since:
        clauses.append(f"{ts_col} > ?")
        params.append(since)
    if table in TABLE_SEND_FILTER:
        clauses.append(TABLE_SEND_FILTER[table])
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    return conn.execute(
        f"SELECT {columns} FROM {table} {where} ORDER BY {ts_col} ASC LIMIT {int(limit)}",
        params
    ).fetchall()


def ingest_rows(table: str, columns: List[str], rows: list, db_path: str = DB_PATH) -> Dict:
    """
    Accept rows received from a peer or the tracker. Returns counts plus
    `new_ids` (ids of newly inserted rows, for tables with an id column).
    """
    result = {"received": len(rows), "inserted": 0, "duplicates": 0, "pending": 0,
              "rejected": 0, "errors": 0, "new_ids": []}
    if table not in SYNCABLE_TABLES or not columns or not rows:
        return result

    columns, rows = sanitize_incoming_rows(table, columns, rows, TABLE_COLUMNS)
    if not columns:
        return result

    if table == "transactions":
        counts = blockchain.ingest_synced_transactions(db_path, columns, rows)
        result.update(inserted=counts[blockchain.ACCEPTED], duplicates=counts[blockchain.DUPLICATE],
                      pending=counts[blockchain.PENDING], rejected=counts[blockchain.REJECTED])
        return result

    if table == "originality_receipts":
        counts = reposts.ingest_receipts(db_path, columns, rows)
        result.update(inserted=counts["inserted"], duplicates=counts["duplicates"],
                      rejected=counts["rejected"], new_ids=counts["new_ids"])
        return result

    if table == "seeds":
        kept = []
        for row in rows:
            seed = dict(zip(columns, row))
            if seed.get("signature"):
                if signing.verify_seed(seed):
                    kept.append(row)
            elif "reward_wallet" in columns:
                row = list(row)
                row[columns.index("reward_wallet")] = ""
                kept.append(row)
            else:
                kept.append(row)
        result["rejected"] += len(rows) - len(kept)
        rows = kept

    if table == "wallets":
        id_idx = columns.index("id") if "id" in columns else None
        if id_idx is not None:
            kept = [r for r in rows if r[id_idx] != blockchain.TREASURY_WALLET_ID]
            result["rejected"] += len(rows) - len(kept)
            rows = kept
        # Balance cache columns are always zero for peer wallets
        columns = columns + ["gfc_balance", "gfc_balance_cents", "is_treasury"]
        rows = [list(r) + [0, 0, 0] for r in rows]

    col_names = ", ".join(columns)
    placeholders = ", ".join(["?"] * len(columns))
    id_idx = columns.index("id") if "id" in columns else None
    conn = sqlite3.connect(db_path)
    try:
        for row in rows:
            try:
                cursor = conn.execute(
                    f"INSERT OR IGNORE INTO {table} ({col_names}) VALUES ({placeholders})", row
                )
            except sqlite3.Error as e:
                result["errors"] += 1
                if result["errors"] <= 3:
                    logger.info(f"Sync insert error for {table} row: {e}")
                continue
            if cursor.rowcount > 0:
                result["inserted"] += 1
                if id_idx is not None:
                    result["new_ids"].append(row[id_idx])
            else:
                result["duplicates"] += 1
        conn.commit()
    finally:
        conn.close()
    return result
