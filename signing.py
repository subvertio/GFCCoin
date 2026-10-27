"""
GFC Ledger Signing - Ed25519 keys for wallets and the treasury

- A wallet's ID is the hex of its Ed25519 public key (64 hex chars), so any
  node can check a transfer's signature from the sender field alone.
- Private keys live in the local `wallet_keys` table. That table is never in
  SYNCABLE_TABLES, so keys never leave the node the wallet was created on.
- Mints (GRANT / REWARD) are signed by the treasury key. Every node pins the
  treasury public key(s) in config.TREASURY_PUBKEYS and only accepts synced
  mints signed by one of them. The private key is only present on the node(s)
  the network operator runs (GFC_TREASURY_KEY_FILE).
"""

import datetime
import os
import sqlite3
from pathlib import Path
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from config import DATA_DIR, DB_PATH, TREASURY_PUBKEYS

SIGNATURE_DOMAIN = b"GFC-TX-SIG-v1:"


# ============================================================================
# KEY HELPERS
# ============================================================================

def generate_keypair() -> tuple:
    """Return (private_key_hex, public_key_hex) for a new Ed25519 key."""
    key = Ed25519PrivateKey.generate()
    priv = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex()
    pub = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    return priv, pub


def public_key_of(private_key_hex: str) -> str:
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_key_hex))
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


def is_public_key(value: str) -> bool:
    """True if value is a 64-hex-char Ed25519 public key."""
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(value))
        return True
    except ValueError:
        return False


def sign_tx_hash(private_key_hex: str, tx_hash: str) -> str:
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_key_hex))
    return key.sign(SIGNATURE_DOMAIN + tx_hash.encode()).hex()


def verify_tx_signature(public_key_hex: str, tx_hash: str, signature_hex: str) -> bool:
    try:
        key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
        key.verify(bytes.fromhex(signature_hex), SIGNATURE_DOMAIN + tx_hash.encode())
        return True
    except (ValueError, TypeError, InvalidSignature):
        return False


# ============================================================================
# WALLET KEYS (local only, never synced)
# ============================================================================

def init_wallet_keys_table(conn: sqlite3.Connection):
    conn.execute('''CREATE TABLE IF NOT EXISTS wallet_keys (
        wallet_id TEXT PRIMARY KEY,
        private_key TEXT NOT NULL,
        created_at TEXT NOT NULL
    )''')


def create_wallet_key(conn: sqlite3.Connection) -> str:
    """Generate and store a wallet keypair. Returns the wallet ID (public key hex)."""
    init_wallet_keys_table(conn)
    priv, pub = generate_keypair()
    conn.execute(
        "INSERT INTO wallet_keys (wallet_id, private_key, created_at) VALUES (?, ?, ?)",
        (pub, priv, datetime.datetime.utcnow().isoformat())
    )
    return pub


def get_wallet_private_key(db_path: str, wallet_id: str) -> Optional[str]:
    conn = sqlite3.connect(db_path)
    try:
        init_wallet_keys_table(conn)
        row = conn.execute(
            "SELECT private_key FROM wallet_keys WHERE wallet_id = ?", (wallet_id,)
        ).fetchone()
    finally:
        conn.close()
    return row[0] if row else None


# ============================================================================
# TREASURY KEY
# ============================================================================

def treasury_pubkeys() -> set:
    """Treasury public keys this node accepts mint signatures from."""
    return {k.lower() for k in TREASURY_PUBKEYS if k}


def load_treasury_private_key() -> Optional[str]:
    """
    Treasury private key hex if this node is a treasury node, else None.
    Read from GFC_TREASURY_KEY_FILE (default: DATA_DIR/treasury_key.hex). The
    key is only used if its public key is pinned in TREASURY_PUBKEYS.
    """
    path = Path(os.environ.get("GFC_TREASURY_KEY_FILE", str(DATA_DIR / "treasury_key.hex")))
    if not path.exists():
        return None
    try:
        priv = path.read_text().strip()
        if public_key_of(priv) in treasury_pubkeys():
            return priv
    except (ValueError, OSError):
        pass
    return None


if __name__ == "__main__":
    # Operator helper: generate a treasury keypair to pin in config.py.
    priv, pub = generate_keypair()
    out = Path(os.environ.get("GFC_TREASURY_KEY_FILE", str(DATA_DIR / "treasury_key.hex")))
    if out.exists():
        raise SystemExit(f"{out} already exists; refusing to overwrite")
    out.write_text(priv)
    print(f"Treasury private key written to {out} (keep it secret, back it up).")
    print(f"Pin this public key in config.TREASURY_PUBKEYS:\n  {pub}")
