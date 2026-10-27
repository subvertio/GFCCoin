"""
GFC Keystore - wallet private keys encrypted at rest, plus encrypted backups

How a wallet key is protected:
- Each user has a random 32-byte data key. Wallet private keys are stored in
  `wallet_keys` encrypted with it (AES-256-GCM, bound to the wallet ID).
- The data key is never stored in the clear. It is kept wrapped twice:
    users.key_wrap    - under a key derived from the user's password (scrypt)
    sessions.dk_wrap  - under a key derived from the session's API token (HKDF)
  Login unwraps it with the password and re-wraps it for the new session, so
  API calls that carry a valid api_token can sign without the password. Only
  the token's hash is stored, so the database alone can't unwrap anything.
- Forgetting the password means losing the keys, unless they were exported.
  export_wallets / import_wallets write and read passphrase-encrypted backups.
"""

import datetime
import hashlib
import json
import os
import secrets
import sqlite3
from typing import List, Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from config import DB_PATH

ENCRYPTED_PREFIX = "enc1:"
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2 ** 15, 8, 1
MIN_BACKUP_PASSPHRASE = 12
BACKUP_FORMAT = "gfc-key-backup"


class KeystoreError(ValueError):
    pass


# ============================================================================
# PRIMITIVES
# ============================================================================

def _scrypt(passphrase: str, salt: bytes, n: int = SCRYPT_N, r: int = SCRYPT_R, p: int = SCRYPT_P) -> bytes:
    return Scrypt(salt=salt, length=32, n=n, r=r, p=p).derive(passphrase.encode())


def _seal(key: bytes, plaintext: bytes, aad: bytes) -> str:
    nonce = os.urandom(12)
    return nonce.hex() + ":" + AESGCM(key).encrypt(nonce, plaintext, aad).hex()


def _open(key: bytes, sealed: str, aad: bytes) -> bytes:
    try:
        nonce_hex, ct_hex = sealed.split(":")
        return AESGCM(key).decrypt(bytes.fromhex(nonce_hex), bytes.fromhex(ct_hex), aad)
    except (ValueError, InvalidTag) as e:
        raise KeystoreError("wrong key or corrupted data") from e


def _session_key(token: str) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=b"gfc-session-data-key-v1").derive(token.encode())


# ============================================================================
# SCHEMA
# ============================================================================

def init_keystore(conn: sqlite3.Connection):
    """Add keystore columns (idempotent). Call after users and sessions exist."""
    for table, col in (("users", "key_wrap"), ("sessions", "dk_wrap")):
        try:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} TEXT DEFAULT ''")
        except sqlite3.OperationalError:
            pass  # Column already exists


# ============================================================================
# USER DATA KEYS
# ============================================================================

def unlock_user_keys(username: str, password: str, db_path: str = DB_PATH) -> bytes:
    """
    Return the user's data key, unwrapping it with their password (creating it
    on first use). Also encrypts any of the user's wallet keys still stored in
    plaintext. Call only after the password has been verified.
    """
    conn = sqlite3.connect(db_path)
    try:
        init_keystore(conn)
        row = conn.execute("SELECT key_wrap FROM users WHERE username = ?", (username,)).fetchone()
        wrap = row[0] if row else ""
        aad = f"user:{username}".encode()
        if wrap:
            salt_hex, sealed = wrap.split("$", 1)
            data_key = _open(_scrypt(password, bytes.fromhex(salt_hex)), sealed, aad)
        else:
            data_key = secrets.token_bytes(32)
            salt = secrets.token_bytes(16)
            conn.execute("UPDATE users SET key_wrap = ? WHERE username = ?",
                         (f"{salt.hex()}${_seal(_scrypt(password, salt), data_key, aad)}", username))
        _encrypt_plaintext_keys(conn, username, data_key)
        conn.commit()
        return data_key
    finally:
        conn.close()


def rewrap_user_key(username: str, data_key: bytes, new_password: str, db_path: str = DB_PATH):
    """Re-wrap the data key under a new password (for a future password change)."""
    salt = secrets.token_bytes(16)
    sealed = _seal(_scrypt(new_password, salt), data_key, f"user:{username}".encode())
    conn = sqlite3.connect(db_path)
    conn.execute("UPDATE users SET key_wrap = ? WHERE username = ?", (f"{salt.hex()}${sealed}", username))
    conn.commit()
    conn.close()


def attach_to_session(token: str, data_key: bytes, db_path: str = DB_PATH):
    """Store the data key wrapped under this session's token."""
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    conn = sqlite3.connect(db_path)
    init_keystore(conn)
    conn.execute("UPDATE sessions SET dk_wrap = ? WHERE token_hash = ?",
                 (_seal(_session_key(token), data_key, token_hash.encode()), token_hash))
    conn.commit()
    conn.close()


def data_key_for_token(token: str, db_path: str = DB_PATH) -> Optional[bytes]:
    """The data key for a valid, unexpired session token, else None."""
    if not token:
        return None
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    conn = sqlite3.connect(db_path)
    try:
        init_keystore(conn)
        row = conn.execute(
            "SELECT dk_wrap FROM sessions WHERE token_hash = ? AND expires_at > ?",
            (token_hash, datetime.datetime.utcnow().isoformat())
        ).fetchone()
    finally:
        conn.close()
    if not row or not row[0]:
        return None
    try:
        return _open(_session_key(token), row[0], token_hash.encode())
    except KeystoreError:
        return None


# ============================================================================
# WALLET KEYS
# ============================================================================

def is_encrypted(stored: str) -> bool:
    return bool(stored) and stored.startswith(ENCRYPTED_PREFIX)


def encrypt_wallet_key(data_key: bytes, wallet_id: str, private_key_hex: str) -> str:
    return ENCRYPTED_PREFIX + _seal(data_key, bytes.fromhex(private_key_hex), f"wallet:{wallet_id}".encode())


def decrypt_wallet_key(data_key: bytes, wallet_id: str, stored: str) -> str:
    return _open(data_key, stored[len(ENCRYPTED_PREFIX):], f"wallet:{wallet_id}".encode()).hex()


def _encrypt_plaintext_keys(conn: sqlite3.Connection, username: str, data_key: bytes):
    rows = conn.execute(
        "SELECT wallet_keys.wallet_id, wallet_keys.private_key FROM wallet_keys "
        "JOIN wallets ON wallets.id = wallet_keys.wallet_id WHERE LOWER(wallets.owner) = LOWER(?)",
        (username,)
    ).fetchall()
    for wallet_id, stored in rows:
        if not is_encrypted(stored):
            conn.execute("UPDATE wallet_keys SET private_key = ? WHERE wallet_id = ?",
                         (encrypt_wallet_key(data_key, wallet_id, stored), wallet_id))


# ============================================================================
# PASSPHRASE BACKUPS (wallet export/import, treasury key)
# ============================================================================

def seal_backup(passphrase: str, payload: dict, kind: str) -> dict:
    if len(passphrase or "") < MIN_BACKUP_PASSPHRASE:
        raise KeystoreError(f"backup passphrase must be at least {MIN_BACKUP_PASSPHRASE} characters")
    salt = secrets.token_bytes(16)
    sealed = _seal(_scrypt(passphrase, salt), json.dumps(payload).encode(), kind.encode())
    return {"format": BACKUP_FORMAT, "version": 1, "kind": kind, "kdf": "scrypt",
            "n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P, "salt": salt.hex(), "sealed": sealed}


def open_backup(passphrase: str, backup: dict, kind: str) -> dict:
    if not isinstance(backup, dict) or backup.get("format") != BACKUP_FORMAT or backup.get("kind") != kind:
        raise KeystoreError(f"not a GFC {kind} backup")
    try:
        n, r, p = int(backup["n"]), int(backup["r"]), int(backup["p"])
        if not (2 ** 14 <= n <= 2 ** 17 and r == 8 and p == 1):  # bound memory/CPU for untrusted files
            raise KeystoreError("unsupported backup parameters")
        key = _scrypt(passphrase or "", bytes.fromhex(backup["salt"]), n, r, p)
        return json.loads(_open(key, backup["sealed"], kind.encode()))
    except (KeyError, TypeError, ValueError) as e:
        raise KeystoreError("wrong passphrase or corrupted backup") from e


def export_wallets(username: str, data_key: bytes, passphrase: str, db_path: str = DB_PATH) -> dict:
    """Passphrase-encrypted backup of every wallet key this user has on this node."""
    import signing
    conn = sqlite3.connect(db_path)
    rows = conn.execute(
        "SELECT wallets.id, wallets.name, wallet_keys.private_key FROM wallets "
        "JOIN wallet_keys ON wallet_keys.wallet_id = wallets.id "
        "WHERE LOWER(wallets.owner) = LOWER(?) ORDER BY wallet_keys.created_at", (username,)
    ).fetchall()
    conn.close()
    wallets = []
    for wallet_id, name, stored in rows:
        priv = decrypt_wallet_key(data_key, wallet_id, stored) if is_encrypted(stored) else stored
        if signing.public_key_of(priv) != wallet_id:
            raise KeystoreError(f"stored key does not match wallet {wallet_id}")
        wallets.append({"wallet_id": wallet_id, "name": name or "", "private_key": priv})
    if not wallets:
        raise KeystoreError("no wallet keys on this node to export")
    return seal_backup(passphrase, {"username": username, "wallets": wallets,
                                    "exported_at": datetime.datetime.utcnow().isoformat()}, "wallets")


def import_wallets(username: str, data_key: bytes, passphrase: str, backup: dict,
                   db_path: str = DB_PATH) -> List[str]:
    """
    Restore wallet keys from a backup onto this node for `username`. Each key is
    checked against its wallet ID, encrypted with the user's data key, and the
    local wallet row is (re)assigned to the user, since holding the key proves
    ownership. Returns the imported wallet IDs.
    """
    import signing
    payload = open_backup(passphrase, backup, "wallets")
    entries = payload.get("wallets") or []
    conn = sqlite3.connect(db_path)
    try:
        signing.init_wallet_keys_table(conn)
        now = datetime.datetime.utcnow().isoformat()
        imported = []
        for entry in entries:
            wallet_id, priv = entry.get("wallet_id", ""), entry.get("private_key", "")
            try:
                if signing.public_key_of(priv) != wallet_id:
                    raise ValueError
            except (ValueError, TypeError) as e:
                raise KeystoreError(f"backup key does not match wallet {wallet_id}") from e
            conn.execute("INSERT OR REPLACE INTO wallet_keys (wallet_id, private_key, created_at) VALUES (?, ?, ?)",
                         (wallet_id, encrypt_wallet_key(data_key, wallet_id, priv), now))
            if conn.execute("SELECT 1 FROM wallets WHERE id = ?", (wallet_id,)).fetchone():
                conn.execute("UPDATE wallets SET owner = ? WHERE id = ?", (username, wallet_id))
            else:
                conn.execute("INSERT INTO wallets (id, name, owner, gfc_balance, created_at, gfc_balance_cents) "
                             "VALUES (?, ?, ?, 0, ?, 0)", (wallet_id, entry.get("name") or "Imported", username, now))
            imported.append(wallet_id)
        conn.commit()
        return imported
    finally:
        conn.close()
