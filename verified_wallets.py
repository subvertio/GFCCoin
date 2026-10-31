"""
GFC Verified Wallets - network-wide proof that a post's account verified its phone

On the real network only phone-verified accounts can post (config.REQUIRE_PHONE_TO_POST).
The node you post to checks that locally, but phone verification records are private
and never synced, so a peer couldn't tell whether a synced post's account verified.

The treasury node (it holds the treasury key and runs phone verification) therefore
signs a `verified_wallets` record for each wallet of a verified account: username +
wallet + verified_at, under its own signature domain. These records sync to every node.

On the real network a node only takes a synced post when it's signed by its reward
wallet AND that wallet has a valid record for the post's owner name. Other synced
posts wait in `seed_quarantine` (out of the feed, never re-sent) and go live on their
own if the record arrives later, e.g. once the account verifies.

Records are issued when an account verifies, when a verified account creates a wallet
or posts, and at startup for verified accounts that don't have one yet.
"""

import datetime
import hashlib
import json
import logging
import sqlite3
from typing import Dict, List, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

import config
import phone_verify
import signing

logger = logging.getLogger("gfc.verified")

SIGNATURE_DOMAIN = b"GFC-VERIFIED-WALLET-v1:"
SIGNED_FIELDS = ("username", "wallet", "verified_at")

# Same columns as the seeds sync whitelist (sync_ingest.TABLE_COLUMNS["seeds"])
QUARANTINE_COLUMNS = ("id", "owner", "title", "description", "tags", "filename", "thumb_filename",
                      "content_type", "file_size", "gfc_earned", "likes", "comments", "views",
                      "created_at", "reward_wallet", "signature", "exclusive", "teaser_seconds")


def init_tables(conn: sqlite3.Connection):
    conn.execute('''CREATE TABLE IF NOT EXISTS verified_wallets (
        id TEXT PRIMARY KEY,
        username TEXT NOT NULL,
        wallet TEXT NOT NULL,
        verified_at TEXT NOT NULL,
        signer TEXT NOT NULL,
        signature TEXT NOT NULL
    )''')
    conn.execute("CREATE INDEX IF NOT EXISTS idx_verified_wallets_wallet ON verified_wallets (wallet)")
    conn.execute(f'''CREATE TABLE IF NOT EXISTS seed_quarantine (
        id TEXT PRIMARY KEY,
        owner TEXT NOT NULL,
        title TEXT DEFAULT '',
        description TEXT DEFAULT '',
        tags TEXT DEFAULT '',
        filename TEXT NOT NULL,
        thumb_filename TEXT DEFAULT '',
        content_type TEXT DEFAULT '',
        file_size INTEGER DEFAULT 0,
        gfc_earned REAL DEFAULT 0.0,
        likes INTEGER DEFAULT 0,
        comments INTEGER DEFAULT 0,
        views INTEGER DEFAULT 0,
        created_at TEXT NOT NULL,
        reward_wallet TEXT DEFAULT '',
        signature TEXT DEFAULT '',
        exclusive INTEGER DEFAULT 0,
        teaser_seconds INTEGER DEFAULT 5,
        received_at TEXT NOT NULL
    )''')
    conn.execute("CREATE INDEX IF NOT EXISTS idx_seed_quarantine_wallet ON seed_quarantine (reward_wallet)")


# ---------- signatures ----------

def _message(record: dict) -> bytes:
    canonical = {f: record.get(f, "") for f in SIGNED_FIELDS}
    return SIGNATURE_DOMAIN + json.dumps(canonical, sort_keys=True, separators=(',', ':')).encode()


def record_id(record: dict) -> str:
    return hashlib.sha256(_message(record)).hexdigest()[:24]


def verify_record(record: dict) -> bool:
    """True if signed by a pinned treasury key, well formed, for a real wallet key."""
    signer = record.get("signer") or ""
    signer = signer.lower() if isinstance(signer, str) else ""
    signature = record.get("signature") or ""
    if signer not in signing.treasury_pubkeys() or not isinstance(signature, str) or not signature:
        return False
    if not all(isinstance(record.get(f), str) and record.get(f) for f in SIGNED_FIELDS):
        return False
    if not signing.is_public_key(record["wallet"]) or record.get("id") != record_id(record):
        return False
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(signer)).verify(bytes.fromhex(signature), _message(record))
        return True
    except (ValueError, TypeError, InvalidSignature):
        return False


def is_verified_wallet(conn: sqlite3.Connection, owner: str, wallet: str) -> bool:
    """True if `wallet` has a valid treasury record for account `owner`."""
    init_tables(conn)
    for row in conn.execute(
        "SELECT id, username, wallet, verified_at, signer, signature FROM verified_wallets "
        "WHERE wallet = ? AND LOWER(username) = LOWER(?)", (wallet, owner or "")
    ).fetchall():
        if verify_record(dict(zip(("id",) + SIGNED_FIELDS + ("signer", "signature"), row))):
            return True
    return False


def seed_is_verified(conn: sqlite3.Connection, seed: dict) -> bool:
    """A seed from a verified account: signed by its reward wallet, which is verified for its owner."""
    return signing.verify_seed(seed) and is_verified_wallet(conn, seed.get("owner", ""), seed["reward_wallet"])


# ---------- issuing (treasury node only) ----------

def attest_account(conn: sqlite3.Connection, username: str, treasury_key: Optional[str] = None) -> int:
    """
    Sign records for every wallet of a verified account whose key is on this node and
    that doesn't have one yet. No-op unless this node holds the treasury key. Returns
    how many records were issued. The caller commits.
    """
    treasury_key = treasury_key or signing.load_treasury_private_key()
    if not treasury_key or not phone_verify.is_verified(conn, username):
        return 0
    init_tables(conn)
    signing.init_wallet_keys_table(conn)
    signer = signing.public_key_of(treasury_key)
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(treasury_key))
    issued = 0
    wallets = conn.execute(
        "SELECT wallets.id FROM wallets JOIN wallet_keys ON wallet_keys.wallet_id = wallets.id "
        "WHERE LOWER(wallets.owner) = LOWER(?)", (username,)
    ).fetchall()
    for (wallet,) in wallets:
        if is_verified_wallet(conn, username, wallet):
            continue
        record = {"username": username, "wallet": wallet,
                  "verified_at": datetime.datetime.utcnow().isoformat(), "signer": signer}
        record["signature"] = key.sign(_message(record)).hex()
        record["id"] = record_id(record)
        conn.execute(
            "INSERT OR IGNORE INTO verified_wallets (id, username, wallet, verified_at, signer, signature) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (record["id"], username, wallet, record["verified_at"], signer, record["signature"]))
        issued += 1
    return issued


def attest(db_path: str, username: str) -> int:
    """attest_account in its own connection (for endpoints). Never raises."""
    try:
        conn = sqlite3.connect(db_path)
        try:
            issued = attest_account(conn, username)
            conn.commit()
            return issued
        finally:
            conn.close()
    except Exception as ex:
        logger.warning(f"Verified wallet record for {username} failed: {ex}")
        return 0


def backfill(db_path: str) -> int:
    """Records for verified accounts that don't have them yet (treasury node only)."""
    treasury_key = signing.load_treasury_private_key()
    if not treasury_key:
        return 0
    conn = sqlite3.connect(db_path)
    try:
        phone_verify.init_phone_tables(conn)
        issued = sum(attest_account(conn, u, treasury_key)
                     for (u,) in conn.execute("SELECT username FROM phone_verifications").fetchall())
        conn.commit()
        return issued
    finally:
        conn.close()


# ---------- sync ----------

def ingest_records(db_path: str, columns: List[str], rows: list) -> Dict:
    """Accept treasury-signed records from a peer, then release any posts they verify."""
    counts = {"inserted": 0, "duplicates": 0, "rejected": 0, "new_ids": [], "released": []}
    conn = sqlite3.connect(db_path)
    try:
        init_tables(conn)
        wallets = set()
        for row in rows:
            record = dict(zip(columns, row))
            if not verify_record(record):
                counts["rejected"] += 1
                continue
            cursor = conn.execute(
                "INSERT OR IGNORE INTO verified_wallets (id, username, wallet, verified_at, signer, signature) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (record["id"], record["username"], record["wallet"], record["verified_at"],
                 record["signer"].lower(), record["signature"]))
            if cursor.rowcount > 0:
                counts["inserted"] += 1
                counts["new_ids"].append(record["id"])
                wallets.add(record["wallet"])
            else:
                counts["duplicates"] += 1
        counts["released"] = release_quarantined(conn, wallets)
        conn.commit()
    finally:
        conn.close()
    return counts


def quarantine_rows(conn: sqlite3.Connection, columns: List[str], rows: list) -> int:
    """Hold synced seeds from accounts with no verification record yet. Returns how many are new."""
    init_tables(conn)
    held = 0
    now = datetime.datetime.utcnow().isoformat()
    for row in rows:
        seed = dict(zip(columns, row))
        if not seed.get("id") or conn.execute("SELECT 1 FROM seeds WHERE id = ?", (seed["id"],)).fetchone():
            continue
        values = [seed.get(c, ("" if c not in ("file_size", "gfc_earned", "likes", "comments", "views", "exclusive", "teaser_seconds")
                   else (5 if c == "teaser_seconds" else 0)))
                  for c in QUARANTINE_COLUMNS]
        try:
            cursor = conn.execute(
                f"INSERT OR IGNORE INTO seed_quarantine ({', '.join(QUARANTINE_COLUMNS)}, received_at) "
                f"VALUES ({', '.join('?' * len(QUARANTINE_COLUMNS))}, ?)", values + [now])
            held += cursor.rowcount
        except sqlite3.Error as ex:
            logger.info(f"Quarantine insert failed: {ex}")
    return held


def release_quarantined(conn: sqlite3.Connection, wallets) -> List[str]:
    """Move held seeds signed by these wallets into seeds once their account is verified."""
    released = []
    for wallet in wallets:
        rows = conn.execute(
            f"SELECT {', '.join(QUARANTINE_COLUMNS)} FROM seed_quarantine WHERE reward_wallet = ?", (wallet,)
        ).fetchall()
        for row in rows:
            seed = dict(zip(QUARANTINE_COLUMNS, row))
            if not seed_is_verified(conn, seed):
                continue
            conn.execute(
                f"INSERT OR IGNORE INTO seeds ({', '.join(QUARANTINE_COLUMNS)}) "
                f"VALUES ({', '.join('?' * len(QUARANTINE_COLUMNS))})", row)
            conn.execute("DELETE FROM seed_quarantine WHERE id = ?", (seed["id"],))
            released.append(seed["id"])
    if released:
        import seed_edits
        seed_edits.init_seed_edit_tables(conn)
        for seed_id in released:
            seed_edits.apply_latest(conn, seed_id)
        logger.info(f"Released {len(released)} posts from newly verified accounts")
    return released
