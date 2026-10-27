"""
GFC Backend - Authentication & Sync Privacy Helpers

- Passwords are stored as salted PBKDF2-SHA256 hashes, never plaintext.
- API tokens are random session tokens; only their SHA-256 is stored.
- Sync helpers whitelist which columns may be shared with / accepted from peers,
  so private user data (password hashes, email, phone, real names) never leaves
  the node it was registered on.
"""

import datetime
import hashlib
import hmac
import secrets
import sqlite3
from typing import List, Optional, Tuple

from fastapi import HTTPException

from config import DB_PATH

# ============================================================================
# PASSWORDS
# ============================================================================

PBKDF2_ITERATIONS = 600_000
HASH_PREFIX = "pbkdf2_sha256$"

# Stored for users that arrived via P2P sync: they can only log in on their home node.
REMOTE_USER_PASSWORD = "!"


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS)
    return f"{HASH_PREFIX}{PBKDF2_ITERATIONS}${salt.hex()}${digest.hex()}"


def is_password_hash(stored: str) -> bool:
    return bool(stored) and stored.startswith(HASH_PREFIX)


def verify_password(password: str, stored: str) -> bool:
    if not password or not is_password_hash(stored):
        return False
    try:
        _, iterations, salt_hex, digest_hex = stored.split("$")
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), int(iterations))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(digest.hex(), digest_hex)


def migrate_plaintext_passwords(conn: sqlite3.Connection):
    """Hash any legacy plaintext passwords in place (idempotent)."""
    rows = conn.execute("SELECT id, password FROM users").fetchall()
    for user_id, stored in rows:
        if stored and stored != REMOTE_USER_PASSWORD and not is_password_hash(stored):
            conn.execute("UPDATE users SET password = ? WHERE id = ?", (hash_password(stored), user_id))


# ============================================================================
# SESSIONS / API TOKENS
# ============================================================================

SESSION_TTL = datetime.timedelta(days=30)


def init_sessions_table(conn: sqlite3.Connection):
    conn.execute('''CREATE TABLE IF NOT EXISTS sessions (
        token_hash TEXT PRIMARY KEY,
        username TEXT NOT NULL,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL
    )''')


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create_session(username: str, db_path: str = DB_PATH) -> str:
    """Issue a new random API token for username. Only its hash is stored."""
    token = secrets.token_urlsafe(32)
    now = datetime.datetime.utcnow()
    conn = sqlite3.connect(db_path)
    conn.execute(
        "INSERT INTO sessions (token_hash, username, created_at, expires_at) VALUES (?, ?, ?, ?)",
        (_token_hash(token), username, now.isoformat(), (now + SESSION_TTL).isoformat())
    )
    conn.execute("DELETE FROM sessions WHERE expires_at < ?", (now.isoformat(),))
    conn.commit()
    conn.close()
    return token


def user_from_token(token: str, db_path: str = DB_PATH) -> Optional[str]:
    """Return the username for a valid, unexpired token, else None."""
    if not token:
        return None
    conn = sqlite3.connect(db_path)
    row = conn.execute(
        "SELECT username FROM sessions WHERE token_hash = ? AND expires_at > ?",
        (_token_hash(token), datetime.datetime.utcnow().isoformat())
    ).fetchone()
    conn.close()
    return row[0] if row else None


def owner_from_token(token: str) -> str:
    """Username for a valid token, or 'anonymous'."""
    return user_from_token(token) or "anonymous"


def require_user(token: str) -> str:
    """Username for a valid token, else HTTP 401."""
    username = user_from_token(token)
    if not username:
        raise HTTPException(status_code=401, detail="invalid or expired api_token")
    return username


# ============================================================================
# SYNC PRIVACY
# ============================================================================

# Only these user columns are ever shared with peers or the tracker.
PUBLIC_USER_COLUMNS = "id, username, created_at, bio, avatar_filename"


def sanitize_incoming_rows(table: str, columns: List[str], rows: list,
                           table_columns: dict) -> Tuple[List[str], list]:
    """
    Restrict rows received from a peer/tracker to the columns we allow for that
    table. Peer-supplied column names are interpolated into SQL, so anything not
    on the whitelist is dropped. Incoming users get an unusable password.
    """
    allowed = {c.strip() for c in table_columns.get(table, "").split(",") if c.strip()}
    keep = [i for i, c in enumerate(columns) if c in allowed]
    safe_columns = [columns[i] for i in keep]
    safe_rows = [[row[i] for i in keep] for row in rows if len(row) == len(columns)]
    if table == "users" and safe_columns:
        safe_columns.append("password")
        safe_rows = [r + [REMOTE_USER_PASSWORD] for r in safe_rows]
    return safe_columns, safe_rows
