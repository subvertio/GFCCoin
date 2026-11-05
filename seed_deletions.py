"""
GFC Seed Deletions - letting posters delete their own posts, on every node

A poster can delete their post at any time (DELETE /seeds/{id}). The deletion is a
record of its own, in `seed_deletions`, that syncs like edits do (seed_edits.py):

- It's signed by the seed's reward wallet (Ed25519, its own domain), so only the
  poster can delete a post, and any node can check it. A node applies a deletion only
  if its signer is the reward wallet of a correctly signed seed; anything else (a
  forged deletion) never matches a seed and does nothing.
- Applying it removes the seed row and everything hanging off it on this node: likes,
  comments, bookmarks, edits, reports, the download scan, a quarantined copy. The
  record stays as a tombstone, so the seed is never inserted again when a peer that
  hasn't heard yet sends it (or it's released from quarantine).
- A deletion that arrives before its seed is kept; the seed is dropped when it comes.
- The post's files go too: originals, thumbs, streams and teasers on this node's disk,
  and (official nodes with R2 write keys) the objects in the bucket. Community nodes
  delete their local copies; the bucket is cleaned by the official node. A purge that
  fails (R2 down) is retried at startup and by the hourly media sweep. Files made
  after the deletion (a transcode or a synced file that was still in flight) are
  deleted as they land, and media URLs of deleted posts answer 410.
- Ledger transactions are never removed or reversed: GFC the post already earned (or
  that was paid to it) stays where it is. Originality receipts stay as well (they're
  the treasury's signed record of who posted the content first).
- Unsigned (legacy) seeds can only be deleted on their home node: other nodes can't
  verify who made the deletion, so it isn't synced.
"""

import datetime
import hashlib
import json
import sqlite3
from typing import Dict, List, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

import signing
from config import DB_PATH

DELETE_SIGNATURE_DOMAIN = b"GFC-SEED-DELETE-v1:"
DELETE_SIGNED_FIELDS = ("seed_id", "signer", "deleted_at")
# Deletions dated further ahead than this (by the deleting node's clock) are rejected,
# so a peer's sync cursor can't be pushed into the future.
MAX_CLOCK_SKEW = datetime.timedelta(minutes=10)

LEDGER_NOTE = ("Your post and its files are deleted. GFC it already earned or was paid stays in the "
               "ledger: transactions are never removed or reversed.")
GONE_DETAIL = "This post was deleted by its creator."

# Tables whose rows hang off a seed and go with it
DEPENDENT_TABLES = ("likes", "comments", "bookmarks", "seed_edits", "seed_reports", "seed_moderation",
                    "file_scans", "seed_quarantine")


def init_tables(conn: sqlite3.Connection):
    conn.execute('''CREATE TABLE IF NOT EXISTS seed_deletions (
        id TEXT PRIMARY KEY,
        seed_id TEXT NOT NULL,
        deleted_at TEXT NOT NULL,
        signer TEXT DEFAULT '',
        signature TEXT DEFAULT '',
        applied_at TEXT DEFAULT '',
        owner TEXT DEFAULT '',
        filename TEXT DEFAULT '',
        thumb_filename TEXT DEFAULT '',
        content_type TEXT DEFAULT '',
        purged INTEGER DEFAULT 0
    )''')
    conn.execute("CREATE INDEX IF NOT EXISTS idx_seed_deletions_seed ON seed_deletions (seed_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_seed_deletions_file ON seed_deletions (filename)")


def _now() -> str:
    return datetime.datetime.utcnow().isoformat()


# ---------- signatures ----------

def _message(record: dict) -> bytes:
    canonical = {f: record.get(f, "") for f in DELETE_SIGNED_FIELDS}
    return DELETE_SIGNATURE_DOMAIN + json.dumps(canonical, sort_keys=True, separators=(',', ':')).encode()


def deletion_id_for(record: dict) -> str:
    return hashlib.sha256(_message(record)).hexdigest()[:24]


def sign_deletion(private_key_hex: str, record: dict) -> str:
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_key_hex))
    return key.sign(_message(record)).hex()


def verify_deletion(record: dict) -> bool:
    """True if the record is well formed and signed by its signer (not yet checked against the seed)."""
    signer = record.get("signer") or ""
    signature = record.get("signature") or ""
    if not signing.is_public_key(signer) or not isinstance(signature, str) or not signature:
        return False
    if not all(isinstance(record.get(f), str) and record.get(f) for f in DELETE_SIGNED_FIELDS):
        return False
    if record.get("id") != deletion_id_for(record):
        return False
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(signer)).verify(
            bytes.fromhex(signature), _message(record))
        return True
    except (ValueError, TypeError, InvalidSignature):
        return False


def _too_far_ahead(deleted_at: str) -> bool:
    return deleted_at > (datetime.datetime.utcnow() + MAX_CLOCK_SKEW).isoformat()


# ---------- which seeds are deleted ----------

def _signed_wallet(seed: dict) -> Optional[str]:
    """The reward wallet of a correctly signed seed, else None."""
    if not seed.get("signature"):
        return None
    return seed.get("reward_wallet") if signing.verify_seed(seed) else None


def blocks(conn: sqlite3.Connection, seed: dict) -> bool:
    """
    True if this seed (a dict with the signed fields and signature) was deleted by its
    poster: a signed deletion by its reward wallet, or (unsigned seeds) a local deletion.
    """
    wallet = _signed_wallet(seed)
    if wallet:
        return conn.execute("SELECT 1 FROM seed_deletions WHERE seed_id = ? AND signer = ? AND signature != ''",
                            (seed.get("id"), wallet)).fetchone() is not None
    if seed.get("signature"):
        return False  # a bad signature: not a seed we'd keep anyway
    return conn.execute("SELECT 1 FROM seed_deletions WHERE seed_id = ? AND signature = ''",
                        (seed.get("id"),)).fetchone() is not None


def is_deleted(conn: sqlite3.Connection, seed_id: str) -> bool:
    """Deleted here (the tombstone was applied to this node's copy). Cheap: no schema changes."""
    try:
        return conn.execute("SELECT 1 FROM seed_deletions WHERE seed_id = ? AND applied_at != ''",
                            (seed_id,)).fetchone() is not None
    except sqlite3.OperationalError:
        return False  # no table yet: nothing was deleted


def deleted_record(conn: sqlite3.Connection, seed_id: str) -> Optional[Dict]:
    init_tables(conn)
    row = conn.execute("SELECT id, deleted_at, owner, signature, purged FROM seed_deletions "
                       "WHERE seed_id = ? AND applied_at != '' ORDER BY applied_at LIMIT 1", (seed_id,)).fetchone()
    if not row:
        return None
    return {"id": row[0], "deleted_at": row[1], "owner": row[2], "synced": bool(row[3]), "purged": bool(row[4])}


def is_deleted_media(kind: str, name: str, db_path: str = DB_PATH) -> bool:
    """A media file (by its URL kind and name) that belongs to a deleted post."""
    conn = sqlite3.connect(db_path)
    try:
        if kind == "originals":
            q, arg = "filename = ?", name
        elif kind == "thumbs":
            q, arg = "thumb_filename = ?", name
        elif kind in ("streams", "teasers"):
            q, arg = "seed_id = ?", name.rsplit(".", 1)[0]
        else:
            return False
        return conn.execute(f"SELECT 1 FROM seed_deletions WHERE applied_at != '' AND {q} LIMIT 1",
                            (arg,)).fetchone() is not None
    except sqlite3.Error:
        return False
    finally:
        conn.close()


# ---------- applying ----------

def _seed(conn: sqlite3.Connection, seed_id: str) -> Optional[dict]:
    cols = signing.SEED_SIGNED_FIELDS + ("signature", "thumb_filename", "content_type")
    row = conn.execute(f"SELECT {', '.join(cols)} FROM seeds WHERE id = ?", (seed_id,)).fetchone()
    return dict(zip(cols, row)) if row else None


def _remove_rows(conn: sqlite3.Connection, record_id: str, seed: dict):
    """Drop the seed and what hangs off it; remember its files on the tombstone."""
    seed_id = seed["id"]
    conn.execute("UPDATE seed_deletions SET applied_at = ?, owner = ?, filename = ?, thumb_filename = ?, "
                 "content_type = ? WHERE id = ?",
                 (_now(), seed.get("owner") or "", seed.get("filename") or "", seed.get("thumb_filename") or "",
                  seed.get("content_type") or "", record_id))
    conn.execute("DELETE FROM seeds WHERE id = ?", (seed_id,))
    for table in DEPENDENT_TABLES:
        col = "id" if table == "seed_quarantine" else "seed_id"
        try:
            conn.execute(f"DELETE FROM {table} WHERE {col} = ?", (seed_id,))
        except sqlite3.OperationalError:
            pass  # that feature's table isn't on this node


def apply(conn: sqlite3.Connection, seed_id: str) -> Optional[str]:
    """
    Apply a deletion to this node's copy of the seed (or its quarantined copy), if a
    matching one is on record. Returns the applied record's id, else None.
    Files are purged separately (purge), outside the database transaction.
    """
    init_tables(conn)
    seed = _seed(conn, seed_id)
    if seed is None:
        try:
            cols = signing.SEED_SIGNED_FIELDS + ("signature", "thumb_filename", "content_type")
            row = conn.execute(f"SELECT {', '.join(cols)} FROM seed_quarantine WHERE id = ?", (seed_id,)).fetchone()
            seed = dict(zip(cols, row)) if row else None
        except sqlite3.OperationalError:
            seed = None
    if seed is None:
        return None
    wallet = _signed_wallet(seed)
    if wallet:
        row = conn.execute("SELECT id FROM seed_deletions WHERE seed_id = ? AND signer = ? AND signature != '' "
                           "ORDER BY deleted_at LIMIT 1", (seed_id, wallet)).fetchone()
    elif not seed.get("signature"):
        row = conn.execute("SELECT id FROM seed_deletions WHERE seed_id = ? AND signature = '' "
                           "ORDER BY deleted_at LIMIT 1", (seed_id,)).fetchone()
    else:
        row = None
    if not row:
        return None
    _remove_rows(conn, row[0], seed)
    return row[0]


def create_deletion(conn: sqlite3.Connection, seed_id: str, private_key: Optional[str]) -> Dict:
    """
    Record the poster's deletion and apply it (rows only; call purge() after commit).
    `private_key` is the reward wallet's key for signed seeds, or None for unsigned
    ones (a local-only deletion).
    """
    init_tables(conn)
    seed = _seed(conn, seed_id)
    if not seed:
        raise LookupError("seed not found")
    record = {"seed_id": seed_id, "deleted_at": _now()}
    if seed.get("signature"):
        if not private_key:
            raise PermissionError("this post's wallet key isn't unlocked on this node")
        record["signer"] = seed["reward_wallet"]
        record["signature"] = sign_deletion(private_key, record)
    else:
        record["signer"], record["signature"] = "", ""
    record["id"] = deletion_id_for(record)
    conn.execute("INSERT OR IGNORE INTO seed_deletions (id, seed_id, deleted_at, signer, signature) "
                 "VALUES (?, ?, ?, ?, ?)",
                 (record["id"], seed_id, record["deleted_at"], record["signer"], record["signature"]))
    if not apply(conn, seed_id):
        raise ValueError("this post's signature doesn't check out, so it can't be deleted")
    record["synced"] = bool(record["signature"])
    return record


# ---------- files ----------

def _media_of(seed_id: str, filename: str, thumb_filename: str, content_type: str) -> List[tuple]:
    import audio_stream
    import exclusive
    files = []
    if filename:
        files.append(("originals", filename))
    if thumb_filename:
        files.append(("thumbs", thumb_filename))
    for ctype in ("audio", "video"):  # either kind's stream name, in case the type was changed
        try:
            files.append(("streams", audio_stream.stream_path(seed_id, ctype).name))
        except ValueError:
            pass
    try:
        files.append(("teasers", exclusive.teaser_path(seed_id).name))
    except ValueError:
        pass
    return files


def _remove_file(kind: str, name: str, db_path: str) -> bool:
    """Gone from this node's disk and (when this node can write to R2) from the bucket."""
    import media_store
    try:
        path = media_store.local_path(kind, name)
    except ValueError:
        return True
    try:
        path.unlink(missing_ok=True)
    except OSError as ex:
        print(f"[Delete] {kind}/{name}: {type(ex).__name__}")
        return False
    s = media_store.store()
    if not s.writable:
        return True
    key = media_store.key_for(kind, name)
    try:
        s.delete(key)
    except media_store.MediaStoreError as ex:
        print(f"[Delete] {ex}")
        return False
    conn = sqlite3.connect(db_path)
    try:
        media_store.init_tables(conn)
        conn.execute("DELETE FROM media_objects WHERE key = ?", (key,))
        conn.commit()
    finally:
        conn.close()
    return True


def purge(seed_id: str, db_path: str = DB_PATH) -> bool:
    """Delete a deleted post's files everywhere this node can. True when all are gone."""
    conn = sqlite3.connect(db_path)
    try:
        init_tables(conn)
        row = conn.execute("SELECT filename, thumb_filename, content_type FROM seed_deletions "
                           "WHERE seed_id = ? AND applied_at != '' ORDER BY applied_at LIMIT 1",
                           (seed_id,)).fetchone()
    finally:
        conn.close()
    if not row:
        return False
    import wix_publish
    wix_publish.remove_later(seed_id, db_path)  # off the Wix front page too, if it was there
    ok = all([_remove_file(kind, name, db_path) for kind, name in _media_of(seed_id, *row)])
    if ok:
        conn = sqlite3.connect(db_path)
        try:
            conn.execute("UPDATE seed_deletions SET purged = 1 WHERE seed_id = ? AND applied_at != ''", (seed_id,))
            conn.commit()
        finally:
            conn.close()
    return ok


def purge_if_deleted(seed_id: str, db_path: str = DB_PATH) -> bool:
    """For workers that just made a file for this seed (a transcode, a teaser): True if it was deleted."""
    conn = sqlite3.connect(db_path)
    try:
        deleted = is_deleted(conn, seed_id)
    except sqlite3.Error:
        return False
    finally:
        conn.close()
    if deleted:
        purge(seed_id, db_path)
    return deleted


def retry_purges(db_path: str = DB_PATH) -> int:
    """Files of deleted posts that couldn't be removed earlier (R2 was down). Returns how many posts are now clean."""
    conn = sqlite3.connect(db_path)
    try:
        init_tables(conn)
        ids = [r[0] for r in conn.execute(
            "SELECT DISTINCT seed_id FROM seed_deletions WHERE applied_at != '' AND purged = 0")]
    finally:
        conn.close()
    return sum(1 for seed_id in ids if purge(seed_id, db_path))


# ---------- sync ----------

def ingest_deletions(db_path: str, columns: List[str], rows: list) -> Dict:
    """Accept seed_deletions rows from a peer: signed, well formed, not future-dated; apply the ones that match."""
    counts = {"inserted": 0, "duplicates": 0, "rejected": 0, "new_ids": []}
    applied = []
    conn = sqlite3.connect(db_path)
    try:
        init_tables(conn)
        for row in rows:
            record = dict(zip(columns, row))
            if not verify_deletion(record) or _too_far_ahead(record["deleted_at"]):
                counts["rejected"] += 1
                continue
            cursor = conn.execute(
                "INSERT OR IGNORE INTO seed_deletions (id, seed_id, deleted_at, signer, signature) "
                "VALUES (?, ?, ?, ?, ?)",
                (record["id"], record["seed_id"], record["deleted_at"], record["signer"], record["signature"]))
            if cursor.rowcount > 0:
                counts["inserted"] += 1
                counts["new_ids"].append(record["id"])
                if apply(conn, record["seed_id"]):
                    applied.append(record["seed_id"])
            else:
                counts["duplicates"] += 1
        conn.commit()
    finally:
        conn.close()
    for seed_id in applied:
        purge(seed_id, db_path)
    counts["applied"] = len(applied)
    return counts


def drop_deleted(db_path: str, columns: List[str], rows: list) -> list:
    """Incoming seed rows minus the ones their poster deleted (so they're never inserted again)."""
    if not rows:
        return rows
    conn = sqlite3.connect(db_path)
    try:
        init_tables(conn)
        if not conn.execute("SELECT 1 FROM seed_deletions LIMIT 1").fetchone():
            return rows
        return [row for row in rows if not blocks(conn, dict(zip(columns, row)))]
    finally:
        conn.close()
