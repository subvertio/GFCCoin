"""
GFC Anti-Repost - reposting is allowed, but the original creator gets the credit and the GFC

- Every seed file is fingerprinted (fingerprint.py): exact SHA-256 for every type,
  plus near-duplicate fingerprints for images and glTF 3D models.
- Who was first is decided by a notary, not by the seed's self-declared created_at:
  the node holding the treasury key (the gateway) signs an originality receipt the
  first time it sees content, over (fingerprints, seed_id, owner, the seed's signed
  reward_wallet, first_seen_at). Receipts sync to every node, which keeps only
  treasury-signed ones. When receipts conflict, the earliest first_seen_at wins.
- A seed whose fingerprints match an earlier receipt (for another seed) is a
  repost: it's labelled "Repost of @original" and all its earnings go to the
  original's reward wallet (from the receipt): view rewards, PoDT credit for
  transfers of its files, and a 15 GFC treasury REPOST credit per phone-verified
  reposter (once per reposter and original; never for reposting your own work).
- Nodes without the treasury key match against the receipts they hold but issue none.

Local tables (never synced; each node derives them from its own files and receipts):
- seed_fingerprints: what this node computed for each seed file
- reposts:           seed -> the original it reposts
- repost_credits:    (reposter, original) pairs already credited
Synced table: originality_receipts (see sync_ingest.py).
"""

import datetime
import hashlib
import json
import logging
import sqlite3
import threading
from pathlib import Path
from typing import Dict, List, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

import blockchain
import fingerprint
import phone_verify
import signing
from config import SEEDS_ORIG_DIR

logger = logging.getLogger("gfc.reposts")

RECEIPT_DOMAIN = b"GFC-ORIGINALITY-v1:"
RECEIPT_FIELDS = ("fingerprints", "seed_id", "owner", "reward_wallet", "first_seen_at")
MAX_RECEIPT_PRINTS = 8
MAX_PRINT_LEN = 2048
MAX_CLOCK_SKEW = datetime.timedelta(hours=1)

_lock = threading.Lock()  # one seed evaluated/notarised at a time on this node


def init_repost_tables(conn: sqlite3.Connection):
    conn.execute('''CREATE TABLE IF NOT EXISTS originality_receipts (
        id TEXT PRIMARY KEY,
        fingerprints TEXT NOT NULL,
        seed_id TEXT NOT NULL,
        owner TEXT NOT NULL DEFAULT '',
        reward_wallet TEXT NOT NULL,
        first_seen_at TEXT NOT NULL,
        signer TEXT NOT NULL,
        signature TEXT NOT NULL
    )''')
    conn.execute("CREATE INDEX IF NOT EXISTS idx_receipts_seed ON originality_receipts(seed_id)")
    conn.execute('''CREATE TABLE IF NOT EXISTS seed_fingerprints (
        seed_id TEXT PRIMARY KEY,
        fingerprints TEXT NOT NULL,
        computed_at TEXT NOT NULL
    )''')
    conn.execute('''CREATE TABLE IF NOT EXISTS reposts (
        seed_id TEXT PRIMARY KEY,
        original_seed_id TEXT NOT NULL,
        original_owner TEXT NOT NULL,
        original_wallet TEXT NOT NULL,
        receipt_id TEXT NOT NULL,
        matched_by TEXT NOT NULL,
        detected_at TEXT NOT NULL
    )''')
    conn.execute('''CREATE TABLE IF NOT EXISTS repost_credits (
        reposter TEXT NOT NULL,
        original_seed_id TEXT NOT NULL,
        repost_seed_id TEXT NOT NULL,
        created_at TEXT NOT NULL,
        tx_id TEXT,
        note TEXT DEFAULT '',
        PRIMARY KEY (reposter, original_seed_id)
    )''')


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _parse_ts(value) -> Optional[datetime.datetime]:
    if not isinstance(value, str) or not value:
        return None
    try:
        ts = datetime.datetime.fromisoformat(value)
    except ValueError:
        return None
    return ts if ts.tzinfo else ts.replace(tzinfo=datetime.timezone.utc)


# ============================================================================
# RECEIPTS (treasury-signed "this content was first seen as this seed")
# ============================================================================

def _canonical(receipt: dict) -> dict:
    out = {f: receipt.get(f, "") for f in RECEIPT_FIELDS}
    prints = out["fingerprints"]
    if isinstance(prints, str):
        prints = json.loads(prints)
    out["fingerprints"] = sorted(prints)
    return out


def _receipt_message(receipt: dict) -> bytes:
    return RECEIPT_DOMAIN + json.dumps(_canonical(receipt), sort_keys=True, separators=(",", ":")).encode()


def sign_receipt(treasury_key_hex: str, fingerprints: List[str], seed_id: str, owner: str,
                 reward_wallet: str, first_seen_at: str) -> dict:
    receipt = {"fingerprints": sorted(fingerprints), "seed_id": seed_id, "owner": owner,
               "reward_wallet": reward_wallet, "first_seen_at": first_seen_at}
    message = _receipt_message(receipt)
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(treasury_key_hex))
    receipt.update(id=hashlib.sha256(message).hexdigest(), signer=signing.public_key_of(treasury_key_hex),
                   signature=key.sign(message).hex())
    receipt["fingerprints"] = json.dumps(receipt["fingerprints"], separators=(",", ":"))
    return receipt


def verify_receipt(receipt: dict) -> bool:
    """True if the receipt is well formed and signed by a pinned treasury key."""
    try:
        prints = json.loads(receipt.get("fingerprints") or "")
        if not isinstance(prints, list) or not 0 < len(prints) <= MAX_RECEIPT_PRINTS or \
                not all(isinstance(p, str) and 0 < len(p) <= MAX_PRINT_LEN for p in prints):
            return False
        for f in ("seed_id", "owner", "reward_wallet", "first_seen_at", "signer", "signature", "id"):
            if not isinstance(receipt.get(f), str):
                return False
        if not receipt["seed_id"] or len(receipt["seed_id"]) > 100 or len(receipt["owner"]) > 100:
            return False
        if not signing.is_public_key(receipt["reward_wallet"]):
            return False
        ts = _parse_ts(receipt["first_seen_at"])
        if ts is None or ts > datetime.datetime.now(datetime.timezone.utc) + MAX_CLOCK_SKEW:
            return False
        signer = receipt["signer"].lower()
        if signer not in signing.treasury_pubkeys():
            return False
        message = _receipt_message(receipt)
        if receipt["id"] != hashlib.sha256(message).hexdigest():
            return False
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(signer)).verify(bytes.fromhex(receipt["signature"]), message)
        return True
    except (ValueError, TypeError, InvalidSignature):
        return False


def _insert_receipt(conn: sqlite3.Connection, receipt: dict) -> bool:
    cur = conn.execute(
        "INSERT OR IGNORE INTO originality_receipts (id, fingerprints, seed_id, owner, reward_wallet, "
        "first_seen_at, signer, signature) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        tuple(receipt[f] for f in ("id", "fingerprints", "seed_id", "owner", "reward_wallet",
                                   "first_seen_at", "signer", "signature")))
    return cur.rowcount == 1


def ingest_receipts(db_path: str, columns: List[str], rows: list) -> Dict:
    """Accept synced receipts (treasury-signed only), then re-check local seeds they affect."""
    result = {"inserted": 0, "duplicates": 0, "rejected": 0, "new_ids": []}
    conn = sqlite3.connect(db_path)
    try:
        init_repost_tables(conn)
        for row in rows:
            receipt = dict(zip(columns, row))
            if not verify_receipt(receipt):
                result["rejected"] += 1
                continue
            if _insert_receipt(conn, receipt):
                result["inserted"] += 1
                result["new_ids"].append(receipt["id"])
            else:
                result["duplicates"] += 1
        conn.commit()
    finally:
        conn.close()
    if result["new_ids"]:
        try:
            recheck_for_receipts(db_path, result["new_ids"])
        except Exception as ex:
            logger.warning(f"Repost re-check after receipt sync failed: {ex}")
    return result


def _receipts(conn: sqlite3.Connection) -> List[dict]:
    rows = conn.execute("SELECT id, fingerprints, seed_id, owner, reward_wallet, first_seen_at "
                        "FROM originality_receipts").fetchall()
    out = []
    for r in rows:
        try:
            prints = json.loads(r[1])
        except ValueError:
            continue
        out.append({"id": r[0], "fingerprints": prints, "seed_id": r[2], "owner": r[3],
                    "reward_wallet": r[4], "first_seen_at": r[5], "ts": _parse_ts(r[5])})
    return [r for r in out if r["ts"] is not None]


def _match_kind(prints: List[str], receipt_prints: List[str]) -> Optional[str]:
    """The kind of the strongest fingerprint pair that matches (exact first), or None."""
    found = [fingerprint.kind_of(a) for a in prints for b in receipt_prints if fingerprint.matches(a, b)]
    if not found:
        return None
    return "sha256" if "sha256" in found else sorted(found)[0]


# ============================================================================
# FINGERPRINTING AND MATCHING
# ============================================================================

def _seed_file(conn: sqlite3.Connection, seed_id: str) -> Optional[Path]:
    row = conn.execute("SELECT filename FROM seeds WHERE id = ?", (seed_id,)).fetchone()
    if not row or not row[0] or Path(row[0]).name != row[0]:
        return None
    path = SEEDS_ORIG_DIR / row[0]
    return path if path.is_file() else None


def _fingerprints(conn: sqlite3.Connection, seed_id: str) -> Optional[List[str]]:
    """Stored fingerprints of a seed, computing them if its file is on this node."""
    row = conn.execute("SELECT fingerprints FROM seed_fingerprints WHERE seed_id = ?", (seed_id,)).fetchone()
    if row:
        return json.loads(row[0])
    path = _seed_file(conn, seed_id)
    if path is None:
        return None
    prints = fingerprint.fingerprints_for_file(path)
    conn.execute("INSERT OR REPLACE INTO seed_fingerprints (seed_id, fingerprints, computed_at) VALUES (?, ?, ?)",
                 (seed_id, json.dumps(prints), _now()))
    conn.commit()
    return prints


def _evaluate(conn: sqlite3.Connection, seed_id: str, prints: List[str]) -> Optional[dict]:
    """
    Decide whether seed_id is a repost given the receipts on this node: the earliest
    receipt for another seed that matches, unless this seed's own receipt is earlier.
    Updates the reposts table and returns the repost row (or None).
    """
    receipts = _receipts(conn)
    own = [r["ts"] for r in receipts if r["seed_id"] == seed_id]
    own_first = min(own) if own else None
    best, best_kind = None, None
    for r in receipts:
        if r["seed_id"] == seed_id or (own_first is not None and r["ts"] >= own_first):
            continue
        if best is not None and (r["ts"], r["id"]) >= (best["ts"], best["id"]):
            continue
        kind = _match_kind(prints, r["fingerprints"])
        if kind:
            best, best_kind = r, kind
    if best is None:
        conn.execute("DELETE FROM reposts WHERE seed_id = ?", (seed_id,))
        conn.commit()
        return None
    row = {"seed_id": seed_id, "original_seed_id": best["seed_id"], "original_owner": best["owner"],
           "original_wallet": best["reward_wallet"], "receipt_id": best["id"], "matched_by": best_kind}
    existing = conn.execute("SELECT receipt_id, detected_at FROM reposts WHERE seed_id = ?", (seed_id,)).fetchone()
    row["detected_at"] = existing[1] if existing and existing[0] == best["id"] else _now()
    conn.execute("INSERT OR REPLACE INTO reposts (seed_id, original_seed_id, original_owner, original_wallet, "
                 "receipt_id, matched_by, detected_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                 tuple(row[k] for k in ("seed_id", "original_seed_id", "original_owner", "original_wallet",
                                        "receipt_id", "matched_by", "detected_at")))
    conn.commit()
    return row


def process_seed(db_path: str, seed_id: str) -> Optional[dict]:
    """
    Fingerprint a seed whose file is on this node, decide whether it's a repost, and, on
    a treasury node, notarise it as an original if it isn't one. Returns the repost row
    or None. Call after an upload and when a synced seed's file arrives.
    """
    with _lock:
        conn = sqlite3.connect(db_path)
        try:
            init_repost_tables(conn)
            prints = _fingerprints(conn, seed_id)
            if not prints:
                return None
            repost = _evaluate(conn, seed_id, prints)
            if repost is not None:
                return repost
            treasury_key = signing.load_treasury_private_key()
            if not treasury_key:
                return None
            if conn.execute("SELECT 1 FROM originality_receipts WHERE seed_id = ?", (seed_id,)).fetchone():
                return None
            wallet = signing.seed_reward_wallet(conn, seed_id)
            if not wallet:
                return None  # unsigned seeds can't be paid, so they can't be originals
            owner = conn.execute("SELECT owner FROM seeds WHERE id = ?", (seed_id,)).fetchone()[0] or ""
            receipt = sign_receipt(treasury_key, prints[:MAX_RECEIPT_PRINTS], seed_id, owner[:100], wallet, _now())
            _insert_receipt(conn, receipt)
            conn.commit()
            logger.info(f"Originality receipt issued for seed {seed_id}")
            return None
        finally:
            conn.close()


def recheck_for_receipts(db_path: str, receipt_ids: List[str]):
    """Re-evaluate local seeds that new receipts could affect (earliest receipt wins)."""
    with _lock:
        conn = sqlite3.connect(db_path)
        try:
            wanted = set(receipt_ids)
            receipts = [r for r in _receipts(conn) if r["id"] in wanted]
            local = conn.execute("SELECT seed_id, fingerprints FROM seed_fingerprints").fetchall()
            for seed_id, prints_json in local:
                prints = json.loads(prints_json)
                if any(r["seed_id"] == seed_id or _match_kind(prints, r["fingerprints"]) for r in receipts):
                    _evaluate(conn, seed_id, prints)
        finally:
            conn.close()


def backfill(db_path: str) -> int:
    """Process seeds with a file on this node but no fingerprints yet, oldest first. Returns how many."""
    conn = sqlite3.connect(db_path)
    try:
        init_repost_tables(conn)
        ids = [r[0] for r in conn.execute(
            "SELECT id FROM seeds WHERE id NOT IN (SELECT seed_id FROM seed_fingerprints) "
            "ORDER BY created_at ASC").fetchall()]
    finally:
        conn.close()
    done = 0
    for seed_id in ids:
        try:
            process_seed(db_path, seed_id)
            done += 1
        except Exception as ex:
            logger.warning(f"Fingerprinting seed {seed_id} failed: {ex}")
    return done


# ============================================================================
# WHO GETS PAID, AND THE REPOST CREDIT
# ============================================================================

def repost_of(conn: sqlite3.Connection, seed_id: str) -> Optional[dict]:
    init_repost_tables(conn)
    row = conn.execute("SELECT original_seed_id, original_owner, original_wallet, matched_by "
                       "FROM reposts WHERE seed_id = ?", (seed_id,)).fetchone()
    if not row:
        return None
    return {"original_seed_id": row[0], "original_owner": row[1], "original_wallet": row[2], "matched_by": row[3]}


def reward_wallet_for(conn: sqlite3.Connection, seed_id: str) -> Optional[str]:
    """
    The wallet to pay for plays/transfers of a seed: the original's (treasury-attested)
    reward wallet for a repost, else the seed's own signed reward wallet.
    """
    original = repost_of(conn, seed_id)
    if original and signing.is_public_key(original["original_wallet"]):
        return original["original_wallet"]
    return signing.seed_reward_wallet(conn, seed_id)


def public_info(original: Optional[dict]) -> Optional[dict]:
    """The API shape of "repost of": the original's seed ID, owner and share page."""
    if not original:
        return None
    from app_share import share_url  # app layer; imported late to keep this module standalone
    seed_id, owner = original["original_seed_id"], original["original_owner"]
    return {"seed_id": seed_id, "owner": owner, "label": f"Repost of @{owner}",
            "url": share_url(seed_id), "matched_by": original["matched_by"]}


def repost_map(conn: sqlite3.Connection) -> Dict[str, dict]:
    """{repost seed_id: public_info} for every known repost on this node."""
    init_repost_tables(conn)
    rows = conn.execute("SELECT seed_id, original_seed_id, original_owner, original_wallet, matched_by "
                        "FROM reposts").fetchall()
    return {r[0]: public_info({"original_seed_id": r[1], "original_owner": r[2], "original_wallet": r[3],
                               "matched_by": r[4]}) for r in rows}


def maybe_credit(db_path: str, reposter: str, repost_seed_id: str, original: dict) -> Optional[dict]:
    """
    Pay the original creator REPOST_CREDIT_CENTS for a repost, if the reposter is
    phone-verified, isn't the original creator, and hasn't already been counted for
    this original. Returns the mint, or None.
    """
    if not reposter or reposter == "anonymous" or not original:
        return None
    wallet = original["original_wallet"]
    conn = sqlite3.connect(db_path)
    try:
        init_repost_tables(conn)
        if reposter.lower() == (original["original_owner"] or "").lower():
            return None
        if signing.local_wallet_for(conn, reposter, wallet):
            return None  # the reposter owns the original's wallet
        repost_wallet = conn.execute("SELECT reward_wallet FROM seeds WHERE id = ?", (repost_seed_id,)).fetchone()
        if repost_wallet and repost_wallet[0] == wallet:
            return None
        if not phone_verify.is_verified(conn, reposter):
            return None
        cur = conn.execute("INSERT OR IGNORE INTO repost_credits (reposter, original_seed_id, repost_seed_id, "
                           "created_at) VALUES (?, ?, ?, ?)",
                           (reposter, original["original_seed_id"], repost_seed_id, _now()))
        conn.commit()
        if cur.rowcount != 1:
            return None  # this reposter already counted for this original
    finally:
        conn.close()

    tx = blockchain.process_repost_mint(db_path, wallet, f"Repost credit: {reposter} reposted "
                                                         f"{original['original_seed_id']}")
    conn = sqlite3.connect(db_path)
    conn.execute("UPDATE repost_credits SET tx_id = ?, note = ? WHERE reposter = ? AND original_seed_id = ?",
                 ((tx or {}).get("id"), "" if tx else "treasury could not pay",
                  reposter, original["original_seed_id"]))
    conn.commit()
    conn.close()
    return tx
