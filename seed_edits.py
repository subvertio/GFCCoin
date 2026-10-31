"""
GFC Seed Edits - letting posters fix typos and update their post's text

A seed's title, description and tags can be edited; its media can't (the file is
bound to the seed's ID, signature, originality receipt and rewards).

Seed rows sync with INSERT OR IGNORE, so an edited row would never reach nodes that
already have the seed. Edits therefore travel as their own append-only rows in
`seed_edits`:

- Each edit is signed by the seed's reward wallet (Ed25519, its own domain), so
  only the poster can edit, and any node can check it from the row alone.
- Every node applies the newest valid edit (by edited_at, then id), so all nodes
  converge on the same text whatever order edits arrive in. Edits that arrive
  before their seed are kept and applied when the seed does.
- The edit history stays public (GET /seeds/{id}/edits) and seeds carry
  `edited_at`, so a popular post can't be quietly swapped for something else.
- Unsigned (legacy) seeds can only be edited on their home node: other nodes
  can't verify who made the edit, so those edits aren't synced.
"""

import datetime
import hashlib
import json
import sqlite3
from typing import Dict, List, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

import signing

EDIT_SIGNATURE_DOMAIN = b"GFC-SEED-EDIT-v1:"
EDIT_SIGNED_FIELDS = ("seed_id", "title", "description", "tags", "edited_at")

MAX_TITLE = 300
MAX_DESCRIPTION = 20_000
MAX_TAGS = 1_000
MAX_EDITS_PER_SEED = 50
# Edits dated further ahead than this (by the editing node's clock) are rejected,
# so a post can't be pinned to text that later edits never beat.
MAX_CLOCK_SKEW = datetime.timedelta(minutes=10)


def init_seed_edit_tables(conn: sqlite3.Connection):
    conn.execute('''CREATE TABLE IF NOT EXISTS seed_edits (
        id TEXT PRIMARY KEY,
        seed_id TEXT NOT NULL,
        title TEXT DEFAULT '',
        description TEXT DEFAULT '',
        tags TEXT DEFAULT '',
        edited_at TEXT NOT NULL,
        signer TEXT DEFAULT '',
        signature TEXT DEFAULT ''
    )''')
    conn.execute("CREATE INDEX IF NOT EXISTS idx_seed_edits_seed ON seed_edits (seed_id, edited_at)")
    try:
        conn.execute("ALTER TABLE seeds ADD COLUMN edited_at TEXT DEFAULT ''")
    except sqlite3.OperationalError:
        pass  # column already exists


# ---------- signatures ----------

def _edit_message(edit: dict) -> bytes:
    canonical = {f: edit.get(f, "") for f in EDIT_SIGNED_FIELDS}
    return EDIT_SIGNATURE_DOMAIN + json.dumps(canonical, sort_keys=True, separators=(',', ':')).encode()


def edit_id_for(edit: dict) -> str:
    return hashlib.sha256(_edit_message(edit)).hexdigest()[:24]


def sign_edit(private_key_hex: str, edit: dict) -> str:
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_key_hex))
    return key.sign(_edit_message(edit)).hex()


def verify_edit(edit: dict) -> bool:
    """True if the edit is well formed and signed by its signer (not yet checked against the seed)."""
    signer = edit.get("signer") or ""
    signature = edit.get("signature") or ""
    if not signing.is_public_key(signer) or not isinstance(signature, str) or not signature:
        return False
    if not all(isinstance(edit.get(f), str) for f in EDIT_SIGNED_FIELDS):
        return False
    if edit.get("id") != edit_id_for(edit) or not _within_limits(edit):
        return False
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(signer)).verify(
            bytes.fromhex(signature), _edit_message(edit))
        return True
    except (ValueError, TypeError, InvalidSignature):
        return False


def _within_limits(edit: dict) -> bool:
    return (len(edit.get("title", "")) <= MAX_TITLE
            and len(edit.get("description", "")) <= MAX_DESCRIPTION
            and len(edit.get("tags", "")) <= MAX_TAGS)


def _too_far_ahead(edited_at: str) -> bool:
    now = datetime.datetime.utcnow()
    return edited_at > (now + MAX_CLOCK_SKEW).isoformat()


# ---------- applying edits ----------

def apply_latest(conn: sqlite3.Connection, seed_id: str) -> bool:
    """
    Set the seed's text to its newest valid edit. Signed seeds only take edits
    signed by their own reward wallet; unsigned seeds only take local edits.
    Returns True if the seed's text changed.
    """
    row = conn.execute(
        f"SELECT {', '.join(signing.SEED_SIGNED_FIELDS)}, signature, created_at, edited_at, "
        "title, description, tags FROM seeds WHERE id = ?", (seed_id,)
    ).fetchone()
    if not row:
        return False
    n = len(signing.SEED_SIGNED_FIELDS)
    seed = dict(zip(signing.SEED_SIGNED_FIELDS + ("signature",), row[:n + 1]))
    created_at, current_edited_at, cur_title, cur_desc, cur_tags = row[n + 1:]

    if seed.get("signature"):
        wallet = seed["reward_wallet"] if signing.verify_seed(seed) else None
        if not wallet:
            return False
        latest = conn.execute(
            "SELECT title, description, tags, edited_at FROM seed_edits "
            "WHERE seed_id = ? AND signer = ? AND signature != '' AND edited_at > ? "
            "ORDER BY edited_at DESC, id DESC LIMIT 1",
            (seed_id, wallet, created_at)
        ).fetchone()
    else:
        latest = conn.execute(
            "SELECT title, description, tags, edited_at FROM seed_edits "
            "WHERE seed_id = ? AND signature = '' "
            "ORDER BY edited_at DESC, id DESC LIMIT 1", (seed_id,)
        ).fetchone()
    if not latest or (latest[3] == current_edited_at and tuple(latest[:3]) == (cur_title, cur_desc, cur_tags)):
        return False
    conn.execute(
        "UPDATE seeds SET title = ?, description = ?, tags = ?, edited_at = ? WHERE id = ?",
        (latest[0], latest[1], latest[2], latest[3], seed_id)
    )
    return True


def create_edit(conn: sqlite3.Connection, seed_id: str, private_key: Optional[str],
                title: Optional[str], description: Optional[str], tags: Optional[str]) -> Dict:
    """
    Record an edit by the seed's poster and apply it. Fields left as None keep their
    current value. `private_key` is the reward wallet's key for signed seeds, or
    None for unsigned ones (a local-only edit). Raises ValueError on bad input.
    """
    row = conn.execute(
        "SELECT title, description, tags, created_at, signature, reward_wallet FROM seeds WHERE id = ?",
        (seed_id,)
    ).fetchone()
    if not row:
        raise LookupError("seed not found")
    cur_title, cur_desc, cur_tags, created_at, seed_signature, reward_wallet = row

    count = conn.execute("SELECT COUNT(*) FROM seed_edits WHERE seed_id = ?", (seed_id,)).fetchone()[0]
    if count >= MAX_EDITS_PER_SEED:
        raise ValueError(f"a post can be edited at most {MAX_EDITS_PER_SEED} times")

    edit = {
        "seed_id": seed_id,
        "title": (title if title is not None else cur_title or "").strip(),
        "description": description if description is not None else cur_desc or "",
        "tags": ",".join(t.strip() for t in (tags if tags is not None else cur_tags or "").split(",") if t.strip()),
    }
    if not _within_limits(edit):
        raise ValueError(f"too long (title {MAX_TITLE}, description {MAX_DESCRIPTION}, tags {MAX_TAGS} characters)")
    if (edit["title"], edit["description"], edit["tags"]) == (cur_title or "", cur_desc or "", cur_tags or ""):
        raise ValueError("nothing changed")

    # Strictly newer than the current text, even if this node's clock is behind
    edited_at = datetime.datetime.utcnow().isoformat()
    newest = conn.execute("SELECT MAX(edited_at) FROM seed_edits WHERE seed_id = ?", (seed_id,)).fetchone()[0]
    floor = max(created_at or "", newest or "")
    if edited_at <= floor:
        edited_at = (datetime.datetime.fromisoformat(floor) + datetime.timedelta(microseconds=1)).isoformat()
    edit["edited_at"] = edited_at

    if seed_signature:
        if not private_key:
            raise PermissionError("this post's wallet key isn't unlocked on this node")
        edit["signer"] = reward_wallet
        edit["signature"] = sign_edit(private_key, edit)
    else:
        edit["signer"], edit["signature"] = "", ""
    edit["id"] = edit_id_for(edit)

    conn.execute(
        "INSERT INTO seed_edits (id, seed_id, title, description, tags, edited_at, signer, signature) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (edit["id"], seed_id, edit["title"], edit["description"], edit["tags"], edited_at,
         edit["signer"], edit["signature"])
    )
    apply_latest(conn, seed_id)
    edit["synced"] = bool(edit["signature"])
    return edit


def history(conn: sqlite3.Connection, seed_id: str) -> List[Dict]:
    """The seed's applied-eligible edits, newest first."""
    rows = conn.execute(
        "SELECT seed_edits.id, seed_edits.title, seed_edits.description, seed_edits.tags, seed_edits.edited_at "
        "FROM seed_edits JOIN seeds ON seeds.id = seed_edits.seed_id "
        "WHERE seed_edits.seed_id = ? AND ("
        "  (seeds.signature != '' AND seed_edits.signer = seeds.reward_wallet AND seed_edits.signature != '') "
        "  OR (seeds.signature = '' AND seed_edits.signature = '')) "
        "ORDER BY seed_edits.edited_at DESC, seed_edits.id DESC", (seed_id,)
    ).fetchall()
    return [{"id": r[0], "title": r[1], "description": r[2],
             "tags": [t for t in r[3].split(",") if t] if r[3] else [], "edited_at": r[4]} for r in rows]


# ---------- sync ----------

def ingest_edits(db_path: str, columns: List[str], rows: list) -> Dict:
    """Accept seed_edits rows from a peer: signed, well formed, not future-dated."""
    counts = {"inserted": 0, "duplicates": 0, "rejected": 0, "new_ids": []}
    conn = sqlite3.connect(db_path)
    try:
        init_seed_edit_tables(conn)
        touched = set()
        for row in rows:
            edit = dict(zip(columns, row))
            if not verify_edit(edit) or _too_far_ahead(edit["edited_at"]):
                counts["rejected"] += 1
                continue
            cursor = conn.execute(
                "INSERT OR IGNORE INTO seed_edits (id, seed_id, title, description, tags, edited_at, signer, signature) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (edit["id"], edit["seed_id"], edit["title"], edit["description"], edit["tags"],
                 edit["edited_at"], edit["signer"], edit["signature"])
            )
            if cursor.rowcount > 0:
                counts["inserted"] += 1
                counts["new_ids"].append(edit["id"])
                touched.add(edit["seed_id"])
            else:
                counts["duplicates"] += 1
        for seed_id in touched:
            apply_latest(conn, seed_id)
        conn.commit()
    finally:
        conn.close()
    return counts


def apply_pending_for_seeds(db_path: str, seed_ids: List[str]):
    """After new seeds arrive, apply any edits that got here first."""
    if not seed_ids:
        return
    conn = sqlite3.connect(db_path)
    try:
        init_seed_edit_tables(conn)
        for seed_id in seed_ids:
            apply_latest(conn, seed_id)
        conn.commit()
    finally:
        conn.close()
