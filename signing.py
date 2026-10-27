"""
GFC Ledger Signing - Ed25519 keys for wallets and the treasury

- A wallet's ID is the hex of its Ed25519 public key (64 hex chars), so any
  node can check a transfer's signature from the sender field alone.
- Private keys live in the local `wallet_keys` table, encrypted with the
  owner's data key (keystore.py). That table is never in SYNCABLE_TABLES, so
  keys never leave the node except in a passphrase-encrypted export.
- Mints (GRANT / REWARD) are signed by the treasury key. Every node pins the
  treasury public key(s) in config.TREASURY_PUBKEYS and only accepts synced
  mints signed by one of them. The private key is only present on the node(s)
  the network operator runs (GFC_TREASURY_KEY_FILE).
- Seeds are signed by their reward wallet, and rewards are only paid to that
  signer (see SEED SIGNATURES below).
"""

import datetime
import hashlib
import json
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
# SEED SIGNATURES (who gets paid for a seed)
# ============================================================================
#
# A seed's reward_wallet signs the seed's identity fields. Rewards are only paid
# to a reward_wallet that signed its seed, so a peer can't redirect someone's
# rewards by sending a forged seed or a wallet row with a borrowed owner name.
# The seed ID is derived from (reward_wallet, filename), so re-signing someone
# else's seed with another wallet gives a different seed, not a hijacked one.

SEED_SIGNATURE_DOMAIN = b"GFC-SEED-SIG-v1:"
SEED_SIGNED_FIELDS = ("id", "owner", "filename", "file_size", "created_at", "reward_wallet")


def seed_id_for(reward_wallet: str, filename: str) -> str:
    return hashlib.sha256(f"{reward_wallet}:{filename}".encode()).hexdigest()[:24]


def _seed_message(seed: dict) -> bytes:
    canonical = {f: seed.get(f, "") for f in SEED_SIGNED_FIELDS}
    return SEED_SIGNATURE_DOMAIN + json.dumps(canonical, sort_keys=True, separators=(',', ':')).encode()


def sign_seed(private_key_hex: str, seed: dict) -> str:
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_key_hex))
    return key.sign(_seed_message(seed)).hex()


def verify_seed(seed: dict) -> bool:
    """True if the seed is signed by its reward_wallet and its ID is bound to that wallet."""
    wallet = seed.get("reward_wallet") or ""
    signature = seed.get("signature") or ""
    if not is_public_key(wallet) or not isinstance(signature, str) or not signature:
        return False
    if not isinstance(seed.get("filename"), str) or seed.get("id") != seed_id_for(wallet, seed["filename"]):
        return False
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(wallet)).verify(
            bytes.fromhex(signature), _seed_message(seed))
        return True
    except (ValueError, TypeError, InvalidSignature):
        return False


def seed_reward_wallet(conn: sqlite3.Connection, seed_id: str) -> Optional[str]:
    """The wallet to pay for plays/transfers of a seed, or None if the seed isn't signed."""
    row = conn.execute(
        f"SELECT {', '.join(SEED_SIGNED_FIELDS)}, signature FROM seeds WHERE id = ?", (seed_id,)
    ).fetchone()
    if not row:
        return None
    seed = dict(zip(SEED_SIGNED_FIELDS + ("signature",), row))
    return seed["reward_wallet"] if verify_seed(seed) else None


# ============================================================================
# WALLET KEYS (local only, never synced)
# ============================================================================

def init_wallet_keys_table(conn: sqlite3.Connection):
    conn.execute('''CREATE TABLE IF NOT EXISTS wallet_keys (
        wallet_id TEXT PRIMARY KEY,
        private_key TEXT NOT NULL,
        created_at TEXT NOT NULL
    )''')


def create_wallet_key(conn: sqlite3.Connection, data_key: Optional[bytes] = None) -> str:
    """
    Generate and store a wallet keypair. Returns the wallet ID (public key hex).
    With a user data key (see keystore.py) the private key is stored encrypted.
    """
    import keystore
    init_wallet_keys_table(conn)
    priv, pub = generate_keypair()
    stored = keystore.encrypt_wallet_key(data_key, pub, priv) if data_key else priv
    conn.execute(
        "INSERT INTO wallet_keys (wallet_id, private_key, created_at) VALUES (?, ?, ?)",
        (pub, stored, datetime.datetime.utcnow().isoformat())
    )
    return pub


def local_wallet_for(conn: sqlite3.Connection, owner: str, wallet_id: str = "") -> Optional[str]:
    """
    A wallet of `owner` whose key is on this node: `wallet_id` if it qualifies,
    else (when wallet_id is empty) the owner's oldest such wallet.
    """
    init_wallet_keys_table(conn)
    query = ("SELECT wallets.id FROM wallets JOIN wallet_keys ON wallet_keys.wallet_id = wallets.id "
             "WHERE LOWER(wallets.owner) = LOWER(?)")
    params = [owner]
    if wallet_id:
        query += " AND wallets.id = ?"
        params.append(wallet_id)
    row = conn.execute(query + " ORDER BY wallet_keys.created_at LIMIT 1", params).fetchone()
    return row[0] if row else None


def has_wallet_key(db_path: str, wallet_id: str) -> bool:
    conn = sqlite3.connect(db_path)
    try:
        init_wallet_keys_table(conn)
        return conn.execute("SELECT 1 FROM wallet_keys WHERE wallet_id = ?", (wallet_id,)).fetchone() is not None
    finally:
        conn.close()


def get_wallet_private_key(db_path: str, wallet_id: str, data_key: Optional[bytes] = None) -> Optional[str]:
    """
    The wallet's private key hex, or None if this node doesn't have it, or it
    is encrypted and data_key is missing or wrong.
    """
    import keystore
    conn = sqlite3.connect(db_path)
    try:
        init_wallet_keys_table(conn)
        row = conn.execute(
            "SELECT private_key FROM wallet_keys WHERE wallet_id = ?", (wallet_id,)
        ).fetchone()
    finally:
        conn.close()
    if not row:
        return None
    if not keystore.is_encrypted(row[0]):
        return row[0]
    if not data_key:
        return None
    try:
        return keystore.decrypt_wallet_key(data_key, wallet_id, row[0])
    except keystore.KeystoreError:
        return None


# ============================================================================
# TREASURY KEY
# ============================================================================

def treasury_pubkeys() -> set:
    """Treasury public keys this node accepts mint signatures from."""
    return {k.lower() for k in TREASURY_PUBKEYS if k}


def load_treasury_private_key() -> Optional[str]:
    """
    Treasury private key hex if this node is a treasury node, else None.
    Read from GFC_TREASURY_KEY_FILE (default: DATA_DIR/treasury_key.hex), which
    may be encrypted (`python signing.py encrypt`, unlocked by
    GFC_TREASURY_PASSPHRASE). The key is only used if its public key is pinned.
    """
    path = _treasury_key_path()
    if not path.exists():
        return None
    try:
        priv = _read_treasury_key_file(path, os.environ.get("GFC_TREASURY_PASSPHRASE"))
        if public_key_of(priv) in treasury_pubkeys():
            return priv
    except (ValueError, OSError, KeyError):
        pass  # Missing/wrong passphrase or unreadable file: this node doesn't sign mints
    return None


def _write_secret(path: Path, text: str):
    """Write a key or backup file readable by its owner only (0600), whatever the umask."""
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)
    os.chmod(path, 0o600)  # in case the file already existed with wider permissions


def _treasury_key_path() -> Path:
    return Path(os.environ.get("GFC_TREASURY_KEY_FILE", str(DATA_DIR / "treasury_key.hex")))


def _read_treasury_key_file(path: Path, passphrase: Optional[str]) -> str:
    """Key hex from a plain key file, or from one encrypted by `python signing.py encrypt`."""
    import keystore
    text = path.read_text().strip()
    if text.startswith("{"):
        payload = keystore.open_backup(passphrase or "", json.loads(text), "treasury")
        return payload["private_key"]
    return text


def _passphrase(prompt: str, confirm: bool) -> str:
    """Passphrase from GFC_BACKUP_PASSPHRASE (for scripts) or an interactive prompt."""
    if os.environ.get("GFC_BACKUP_PASSPHRASE"):
        return os.environ["GFC_BACKUP_PASSPHRASE"]
    import getpass
    first = getpass.getpass(prompt)
    if confirm and getpass.getpass("Repeat passphrase: ") != first:
        raise SystemExit("Passphrases don't match")
    return first


def _cli(argv: list) -> int:
    import keystore
    usage = ("usage: python signing.py [generate | backup OUT_FILE | restore BACKUP_FILE | encrypt]\n"
             "  generate  create the treasury key (default)\n"
             "  backup    write a passphrase-encrypted copy of the treasury key\n"
             "  restore   recreate the treasury key file from a backup\n"
             "  encrypt   encrypt the treasury key file in place; the node then needs\n"
             "            GFC_TREASURY_PASSPHRASE set to sign mints\n"
             "  generate-encrypted OUT_FILE\n"
             "            create a new treasury key directly as an encrypted file (for\n"
             "            rotation); prints its public key\n"
             "  pubkey FILE\n"
             "            print the public key of a key file (plain or encrypted; uses\n"
             "            GFC_TREASURY_PASSPHRASE for encrypted ones)")
    cmd = argv[0] if argv else "generate"
    key_path = _treasury_key_path()

    if cmd == "generate":
        if key_path.exists():
            raise SystemExit(f"{key_path} already exists; refusing to overwrite")
        priv, pub = generate_keypair()
        _write_secret(key_path, priv)
        print(f"Treasury private key written to {key_path}. Back it up now: python signing.py backup FILE")
        print(f"Pin this public key in config.PINNED_TREASURY_PUBKEYS:\n  {pub}")
    elif cmd == "backup" and len(argv) == 2:
        out = Path(argv[1])
        if out.exists():
            raise SystemExit(f"{out} already exists; refusing to overwrite")
        priv = _read_treasury_key_file(key_path, os.environ.get("GFC_TREASURY_PASSPHRASE"))
        backup = keystore.seal_backup(_passphrase("Backup passphrase (12+ chars): ", True),
                                      {"private_key": priv, "public_key": public_key_of(priv)}, "treasury")
        _write_secret(out, json.dumps(backup, indent=2))
        print(f"Encrypted backup of treasury key {public_key_of(priv)} written to {out}.")
        print("Store it off this machine (USB drive, password manager). Without the passphrase it can't be opened.")
    elif cmd == "restore" and len(argv) == 2:
        if key_path.exists():
            raise SystemExit(f"{key_path} already exists; refusing to overwrite")
        payload = keystore.open_backup(_passphrase("Backup passphrase: ", False),
                                       json.loads(Path(argv[1]).read_text()), "treasury")
        priv = payload["private_key"]
        _write_secret(key_path, priv)
        pub = public_key_of(priv)
        pinned = "pinned" if pub in treasury_pubkeys() else "NOT pinned in config - mints won't be accepted"
        print(f"Treasury key {pub} restored to {key_path} ({pinned}).")
    elif cmd == "encrypt" and len(argv) == 1:
        priv = _read_treasury_key_file(key_path, None)
        sealed = keystore.seal_backup(_passphrase("New passphrase for the key file (12+ chars): ", True),
                                      {"private_key": priv, "public_key": public_key_of(priv)}, "treasury")
        _write_secret(key_path, json.dumps(sealed, indent=2))
        print(f"{key_path} is now encrypted. Set GFC_TREASURY_PASSPHRASE when starting the treasury node.")
    elif cmd == "generate-encrypted" and len(argv) == 2:
        out = Path(argv[1])
        if out.exists():
            raise SystemExit(f"{out} already exists; refusing to overwrite")
        priv, pub = generate_keypair()  # never written to disk in plaintext
        sealed = keystore.seal_backup(_passphrase("Passphrase for the new key file (12+ chars): ", True),
                                      {"private_key": priv, "public_key": pub}, "treasury")
        _write_secret(out, json.dumps(sealed, indent=2))
        print(pub)
    elif cmd == "pubkey" and len(argv) == 2:
        priv = _read_treasury_key_file(Path(argv[1]), os.environ.get("GFC_TREASURY_PASSPHRASE"))
        print(public_key_of(priv))
    else:
        print(usage)
        return 2
    return 0


if __name__ == "__main__":
    import sys
    raise SystemExit(_cli(sys.argv[1:]))
