"""
Signed ledger checkpoints (audit F08; docs/ledger-checkpoints.md).

The canonical node keeps an append-only log of every transaction it has accepted, in the
order it accepted them (block, then tx_hash), with a running hash over it:
    acc[0] = sha256("gfc-checkpoint:v1:<network>")
    acc[n] = sha256(acc[n-1] || tx_hash[n])
Every few minutes it signs a checkpoint: how many rows the log holds, the running hash at
that point, the escrow balances, and the time. The key is a dedicated checkpoint key held by
the node (GFC_CHECKPOINT_KEY_FILE), never the treasury key, and its public key is pinned
(config.CHECKPOINT_PUBKEYS).

Bridge attesters mirror the log (bridge/checkpoints.py): they sign a deposit only once a
checkpoint at least the finality window old covers it, and they stop signing if a new
checkpoint doesn't extend the log they already hold, which is what a ledger restored from an
older backup, or any rewritten history, looks like.

What this still trusts: the canonical node decides which of two conflicting transfers
counts. Checkpoints make that decision public, append-only and checkable; they don't remove
the operator.

Node endpoints (app_checkpoints.py):
    GET /ledger/checkpoint                    the latest signed checkpoint
    GET /ledger/checkpoint/log?start=N&limit=L  log rows N.. (1-based), up to that checkpoint

CLI:
    python ledger_checkpoints.py new-key FILE   a new encrypted checkpoint key; prints only its public key
    python ledger_checkpoints.py sign           extend the log and sign one checkpoint now
"""

import hashlib
import json
import os
import sqlite3
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

import blockchain
import config
import signing

VERSION = 1
SIGNED_PREFIX = "checkpoint:"  # never a 64-hex tx_hash, so no transaction signature can pass as one
DEFAULT_INTERVAL_SECONDS = 300

SCHEMA = """
CREATE TABLE IF NOT EXISTS checkpoint_log (
    position INTEGER PRIMARY KEY,
    tx_hash TEXT NOT NULL,
    block_index INTEGER NOT NULL,
    acc TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_checkpoint_log_hash ON checkpoint_log (tx_hash);
CREATE TABLE IF NOT EXISTS checkpoints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    count INTEGER NOT NULL,
    body TEXT NOT NULL,
    signature TEXT NOT NULL
);
"""


def genesis_acc(network: str) -> str:
    return hashlib.sha256(f"gfc-checkpoint:v{VERSION}:{network}".encode()).hexdigest()


def next_acc(acc: str, tx_hash: str) -> str:
    return hashlib.sha256(bytes.fromhex(acc) + bytes.fromhex(tx_hash)).hexdigest()


def canonical_json(body: dict) -> str:
    return json.dumps(body, sort_keys=True, separators=(",", ":"))


def digest(body: dict) -> str:
    return hashlib.sha256(canonical_json(body).encode()).hexdigest()


def sign_body(private_key: str, body: dict) -> str:
    return signing.sign_tx_hash(private_key, SIGNED_PREFIX + digest(body))


def verify(checkpoint: dict, pubkeys) -> bool:
    """A checkpoint {body, signature} signed by one of the pinned checkpoint keys."""
    if not isinstance(checkpoint, dict):
        return False
    body, sig = checkpoint.get("body"), checkpoint.get("signature")
    if not isinstance(body, dict) or not isinstance(sig, str):
        return False
    return body.get("signer") in pubkeys and \
        signing.verify_tx_signature(body["signer"], SIGNED_PREFIX + digest(body), sig)


def init(conn: sqlite3.Connection):
    conn.executescript(SCHEMA)


def extend_log(conn: sqlite3.Connection, network: str) -> tuple:
    """Append every newly blocked row to the log. Returns (count, acc, last block)."""
    last = conn.execute("SELECT position, acc, block_index FROM checkpoint_log ORDER BY position DESC LIMIT 1"
                        ).fetchone()
    position, acc, last_block = last if last else (0, genesis_acc(network), -1)
    rows = conn.execute("SELECT tx_hash, block_index FROM transactions WHERE block_index > ? AND tx_hash IS NOT NULL "
                        "AND tx_hash != '' ORDER BY block_index, tx_hash", (last_block,)).fetchall()
    for tx_hash, block in rows:
        position += 1
        acc = next_acc(acc, tx_hash)
        conn.execute("INSERT INTO checkpoint_log (position, tx_hash, block_index, acc) VALUES (?, ?, ?, ?)",
                     (position, tx_hash, block, acc))
    if rows:
        last_block = rows[-1][1]
    return position, acc, last_block


def make_checkpoint(db_path: str, private_key: str, network: Optional[str] = None,
                    now: Optional[datetime] = None) -> dict:
    """Extend the log and sign a checkpoint over it, in one write transaction."""
    network = network or config.NETWORK
    signer = signing.public_key_of(private_key)
    conn = sqlite3.connect(db_path)
    try:
        init(conn)  # executescript commits on its own: never inside the write transaction
    finally:
        conn.close()
    with blockchain._write(db_path) as conn:
        count, acc, last_block = extend_log(conn, network)
        prev = conn.execute("SELECT count, body FROM checkpoints ORDER BY id DESC LIMIT 1").fetchone()
        if prev:
            prev_body = json.loads(prev[1])
            logged = conn.execute("SELECT acc FROM checkpoint_log WHERE position = ?", (prev[0],)).fetchone()
            prev_acc = logged[0] if logged else (genesis_acc(network) if prev[0] == 0 else None)
            if prev[0] > count or prev_acc != prev_body["acc"]:
                raise RuntimeError("the checkpoint log no longer matches the last signed checkpoint: "
                                   "this ledger's history changed. Not signing")
        body = {
            "v": VERSION, "network": network, "signer": signer,
            "count": count, "acc": acc, "block_index": last_block,
            "escrows": {str(chain): blockchain._balance_cents(conn, wallet)
                        for chain, wallet in sorted(config.BRIDGE_ESCROWS.items())},
            "time": (now or datetime.now(timezone.utc)).isoformat(),
            "prev": digest(json.loads(prev[1])) if prev else "",
        }
        signature = sign_body(private_key, body)
        conn.execute("INSERT INTO checkpoints (count, body, signature) VALUES (?, ?, ?)",
                     (count, canonical_json(body), signature))
    return {"body": body, "signature": signature}


def latest(db_path: str) -> Optional[dict]:
    conn = sqlite3.connect(db_path)
    try:
        init(conn)
        row = conn.execute("SELECT body, signature FROM checkpoints ORDER BY id DESC LIMIT 1").fetchone()
    finally:
        conn.close()
    return {"body": json.loads(row[0]), "signature": row[1]} if row else None


def log_rows(db_path: str, start: int, limit: int, upto: int) -> List[dict]:
    conn = sqlite3.connect(db_path)
    try:
        init(conn)
        rows = conn.execute("SELECT position, tx_hash FROM checkpoint_log WHERE position >= ? AND position <= ? "
                            "ORDER BY position LIMIT ?", (start, upto, limit)).fetchall()
    finally:
        conn.close()
    return [{"position": p, "tx_hash": h} for p, h in rows]


# ----------------------------------------------------------------------- key and loop

def key_path() -> Path:
    return Path(os.environ.get("GFC_CHECKPOINT_KEY_FILE", str(config.DATA_DIR / "checkpoint_key.hex")))


def load_key() -> Optional[str]:
    """This node's checkpoint key, if it has one and its public key is pinned."""
    path = key_path()
    if not path.exists():
        return None
    priv = signing._read_treasury_key_file(path, os.environ.get("GFC_CHECKPOINT_PASSPHRASE"))
    if signing.public_key_of(priv) not in config.CHECKPOINT_PUBKEYS:
        print("[Checkpoints] the checkpoint key isn't pinned in config.CHECKPOINT_PUBKEYS: not signing")
        return None
    return priv


def start_signer(db_path: str) -> bool:
    """On the canonical node: sign a checkpoint every GFC_CHECKPOINT_INTERVAL seconds."""
    priv = load_key()
    if not priv:
        return False
    interval = float(os.environ.get("GFC_CHECKPOINT_INTERVAL", DEFAULT_INTERVAL_SECONDS))

    def loop():
        while True:
            try:
                make_checkpoint(db_path, priv)
            except Exception as e:  # logged loudly; attesters stop signing once checkpoints go stale
                print(f"[Checkpoints] CRITICAL: no checkpoint signed: {type(e).__name__}: {e}")
            time.sleep(interval)

    threading.Thread(target=loop, daemon=True, name="checkpoint-signer").start()
    print(f"[Checkpoints] signing a checkpoint every {interval:g} s as {signing.public_key_of(priv)}")
    return True


def _cli(argv: list) -> int:
    if len(argv) == 2 and argv[0] == "new-key":
        path = Path(argv[1])
        if path.exists():
            print(f"{path} already exists; not overwriting it", file=sys.stderr)
            return 1
        import keystore
        priv, pub = signing.generate_keypair()  # never written to disk in plaintext
        passphrase = os.environ.get("GFC_CHECKPOINT_PASSPHRASE") or             signing._passphrase("Passphrase for the checkpoint key file (12+ chars): ", True)
        sealed = keystore.seal_backup(passphrase, {"private_key": priv, "public_key": pub}, "treasury")
        signing._write_secret(path, json.dumps(sealed, indent=2))
        print(f"Encrypted checkpoint key written to {path}. The node needs GFC_CHECKPOINT_PASSPHRASE to use it.")
        print(f"Pin this public key in config.PINNED_CHECKPOINT_PUBKEYS (or GFC_CHECKPOINT_PUBKEYS on a testnet):\n"
              f"  {pub}")
        return 0
    if argv == ["sign"]:
        priv = load_key()
        if not priv:
            print("no pinned checkpoint key (GFC_CHECKPOINT_KEY_FILE)", file=sys.stderr)
            return 1
        cp = make_checkpoint(config.DB_PATH, priv)
        print(f"checkpoint: count {cp['body']['count']}, block {cp['body']['block_index']}")
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(_cli(sys.argv[1:]))
