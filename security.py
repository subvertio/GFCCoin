"""
GFC Backend - Authentication & Sync Privacy Helpers

- Passwords are stored as salted PBKDF2-SHA256 hashes, never plaintext.
- API tokens are random session tokens; only their SHA-256 is stored. Tokens
  are scoped (read / post / spend) and are sent as a Bearer header.
- Sync helpers whitelist which columns may be shared with / accepted from peers,
  so private user data (password hashes, email, phone, real names) never leaves
  the node it was registered on.
"""

import datetime
import hashlib
import hmac
import os
import re
import secrets
import sqlite3
from dataclasses import dataclass
from typing import List, Optional, Tuple

from fastapi import Depends, Form, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

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


def find_username(conn: sqlite3.Connection, typed: str) -> str:
    """
    The account a typed username means, or "". Case doesn't matter, and leading "@"s are ignored
    when no account has that exact name: the apps show names as "@Name", so people type them so.
    """
    typed = (typed or "").strip()
    for name in (typed, typed.lstrip("@").strip()) if typed.startswith("@") else (typed,):
        row = conn.execute("SELECT username FROM users WHERE LOWER(username) = LOWER(?)", (name,)).fetchone()             if name else None
        if row:
            return row[0]
    return ""


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
#
# Every token carries scopes:
#   read  - personal reads (profile, bookmarks, my seeds, personalised feed)
#   post  - seeds, likes, comments, bookmarks, profile, wallet creation, phone verification
#   spend - transfers and wallet key export/import
# Login issues full-scope tokens. POST /auth/tokens mints limited ones, optionally
# with a daily spend limit, for third-party front ends.
#
# Clients send the token as `Authorization: Bearer <token>`. The legacy
# `api_token` form/query/body field still works; the header wins when both are sent.

SESSION_TTL = datetime.timedelta(days=30)
SCOPES = ("read", "post", "spend")
FULL_SCOPES = frozenset(SCOPES)
TOKEN_ID_LEN = 16  # Public token ID: a prefix of the token's hash


def init_sessions_table(conn: sqlite3.Connection):
    conn.execute('''CREATE TABLE IF NOT EXISTS sessions (
        token_hash TEXT PRIMARY KEY,
        username TEXT NOT NULL,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL
    )''')
    for col, coldef in (("scopes", "TEXT DEFAULT 'read post spend'"),
                        ("spend_limit_cents", "INTEGER DEFAULT NULL"),
                        ("label", "TEXT DEFAULT ''")):
        try:
            conn.execute(f"ALTER TABLE sessions ADD COLUMN {col} {coldef}")
        except sqlite3.OperationalError:
            pass  # Column already exists
    conn.execute('''CREATE TABLE IF NOT EXISTS token_spend (
        token_hash TEXT NOT NULL,
        day TEXT NOT NULL,
        cents INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (token_hash, day)
    )''')


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def parse_scopes(text: str) -> frozenset:
    """Parse 'read post' / 'read,post' into a scope set, else HTTP 400."""
    scopes = frozenset(s for s in re.split(r"[\s,]+", text or "") if s)
    unknown = scopes - FULL_SCOPES
    if not scopes or unknown:
        raise HTTPException(status_code=400,
                            detail=f"scopes must be one or more of: {', '.join(SCOPES)}")
    return scopes


def create_session(username: str, db_path: str = DB_PATH, scopes=FULL_SCOPES,
                   ttl: datetime.timedelta = SESSION_TTL, spend_limit_cents: Optional[int] = None,
                   label: str = "") -> str:
    """Issue a new random API token for username. Only its hash is stored."""
    token = secrets.token_urlsafe(32)
    now = datetime.datetime.utcnow()
    conn = sqlite3.connect(db_path)
    init_sessions_table(conn)
    conn.execute(
        "INSERT INTO sessions (token_hash, username, created_at, expires_at, scopes, spend_limit_cents, label) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (_token_hash(token), username, now.isoformat(), (now + ttl).isoformat(),
         " ".join(s for s in SCOPES if s in scopes), spend_limit_cents, label)
    )
    conn.execute("DELETE FROM token_spend WHERE token_hash IN "
                 "(SELECT token_hash FROM sessions WHERE expires_at < ?)", (now.isoformat(),))
    conn.execute("DELETE FROM sessions WHERE expires_at < ?", (now.isoformat(),))
    conn.commit()
    conn.close()
    return token


@dataclass(frozen=True)
class Caller:
    """Who is calling: resolved from a token, or anonymous when there is no valid token."""
    token: str = ""
    username: Optional[str] = None
    scopes: frozenset = frozenset()
    spend_limit_cents: Optional[int] = None

    @property
    def token_id(self) -> str:
        return _token_hash(self.token)[:TOKEN_ID_LEN] if self.token else ""

    @property
    def is_full(self) -> bool:
        return bool(self.username) and self.scopes >= FULL_SCOPES

    def _check_scope(self, scope: str):
        if scope not in self.scopes:
            raise HTTPException(status_code=403, detail=f"this token lacks the '{scope}' scope")

    def require(self, scope: str) -> str:
        """Username for a valid token with `scope`; 401 without a valid token, 403 without the scope."""
        if not self.username:
            raise HTTPException(status_code=401, detail="invalid or expired api_token")
        self._check_scope(scope)
        return self.username

    def owner(self, scope: str) -> str:
        """
        Like require(), but callers with no valid token are 'anonymous' (for
        endpoints that also serve logged-out users). A valid token without
        `scope` still gets 403.
        """
        if not self.username:
            return "anonymous"
        self._check_scope(scope)
        return self.username

    def require_full(self) -> str:
        username = self.require("read")
        if not self.is_full:
            raise HTTPException(status_code=403, detail="this needs a full-scope token (from /auth/login)")
        return username

    def data_key(self) -> Optional[bytes]:
        import keystore
        return keystore.data_key_for_token(self.token)


def caller_for_token(token: str, db_path: str = DB_PATH) -> Caller:
    """The Caller for a valid, unexpired token, else an anonymous Caller."""
    if not token:
        return Caller()
    conn = sqlite3.connect(db_path)
    row = conn.execute(
        "SELECT username, scopes, spend_limit_cents FROM sessions WHERE token_hash = ? AND expires_at > ?",
        (_token_hash(token), datetime.datetime.utcnow().isoformat())
    ).fetchone()
    conn.close()
    if not row:
        return Caller()
    scopes = FULL_SCOPES if row[1] is None else frozenset(row[1].split())
    return Caller(token=token, username=row[0], scopes=scopes, spend_limit_cents=row[2])


def user_from_token(token: str, db_path: str = DB_PATH) -> Optional[str]:
    """Return the username for a valid, unexpired token, else None."""
    return caller_for_token(token, db_path).username


# ---------- FastAPI dependencies ----------

bearer_scheme = HTTPBearer(auto_error=False, description="A token from /auth/login or /auth/tokens")


def bearer_token(creds: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme)) -> str:
    return creds.credentials if creds else ""


def resolve_caller(header_token: str, legacy_token: str = "") -> Caller:
    """The header token wins; the legacy api_token field is only used without one."""
    return caller_for_token(header_token or legacy_token or "")


LEGACY_TOKEN_DOC = "Legacy: prefer the `Authorization: Bearer <token>` header"


def caller_from_form(bearer: str = Depends(bearer_token),
                     api_token: str = Form("", description=LEGACY_TOKEN_DOC)) -> Caller:
    """Dependency for form/multipart endpoints."""
    return resolve_caller(bearer, api_token)


def caller_from_query(bearer: str = Depends(bearer_token),
                      api_token: str = Query("", description=LEGACY_TOKEN_DOC)) -> Caller:
    """Dependency for GET endpoints."""
    return resolve_caller(bearer, api_token)


# ---------- token management ----------

def list_sessions(username: str, db_path: str = DB_PATH) -> List[dict]:
    """The user's unexpired tokens (never the tokens themselves), with today's spend."""
    now = datetime.datetime.utcnow()
    conn = sqlite3.connect(db_path)
    rows = conn.execute(
        "SELECT sessions.token_hash, label, scopes, spend_limit_cents, created_at, expires_at, "
        "COALESCE(token_spend.cents, 0) FROM sessions "
        "LEFT JOIN token_spend ON token_spend.token_hash = sessions.token_hash AND token_spend.day = ? "
        "WHERE username = ? AND expires_at > ? ORDER BY created_at",
        (now.date().isoformat(), username, now.isoformat())
    ).fetchall()
    conn.close()
    return [{"id": r[0][:TOKEN_ID_LEN], "label": r[1] or "",
             "scopes": (r[2] or " ".join(SCOPES)).split(), "spend_limit_cents": r[3],
             "created_at": r[4], "expires_at": r[5], "spent_today_cents": r[6]} for r in rows]


def revoke_session(username: str, token_id: str, db_path: str = DB_PATH) -> bool:
    if len(token_id) != TOKEN_ID_LEN:
        return False
    conn = sqlite3.connect(db_path)
    rows = conn.execute("SELECT token_hash FROM sessions WHERE username = ? AND substr(token_hash, 1, ?) = ?",
                        (username, TOKEN_ID_LEN, token_id)).fetchall()
    for (token_hash,) in rows:
        conn.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))
        conn.execute("DELETE FROM token_spend WHERE token_hash = ?", (token_hash,))
    conn.commit()
    conn.close()
    return bool(rows)


def reserve_spend(caller: Caller, amount_cents: int, db_path: str = DB_PATH):
    """
    Count amount_cents against the token's daily spend limit (UTC day), or raise
    HTTP 403 if it would go over. No-op for tokens without a limit. Call
    release_spend if the transfer then fails.
    """
    if caller.spend_limit_cents is None:
        return
    token_hash, day = _token_hash(caller.token), datetime.datetime.utcnow().date().isoformat()
    conn = sqlite3.connect(db_path, isolation_level=None)
    try:
        conn.execute("BEGIN IMMEDIATE")  # Serialise concurrent transfers on this token
        row = conn.execute("SELECT cents FROM token_spend WHERE token_hash = ? AND day = ?",
                           (token_hash, day)).fetchone()
        spent = row[0] if row else 0
        if spent + amount_cents > caller.spend_limit_cents:
            conn.execute("ROLLBACK")
            raise HTTPException(status_code=403, detail=(
                f"daily spend limit reached for this token "
                f"({spent} of {caller.spend_limit_cents} cents spent today)"))
        conn.execute("INSERT INTO token_spend (token_hash, day, cents) VALUES (?, ?, ?) "
                     "ON CONFLICT(token_hash, day) DO UPDATE SET cents = cents + excluded.cents",
                     (token_hash, day, amount_cents))
        conn.execute("COMMIT")
    finally:
        conn.close()


def release_spend(caller: Caller, amount_cents: int, db_path: str = DB_PATH):
    if caller.spend_limit_cents is None:
        return
    conn = sqlite3.connect(db_path)
    conn.execute("UPDATE token_spend SET cents = MAX(cents - ?, 0) WHERE token_hash = ? AND day = ?",
                 (amount_cents, _token_hash(caller.token), datetime.datetime.utcnow().date().isoformat()))
    conn.commit()
    conn.close()


# ============================================================================
# CORS
# ============================================================================

def cors_origins() -> List[str]:
    """Origins allowed by GFC_CORS_ORIGINS (comma-separated). Empty means same-origin only."""
    return [o.strip().rstrip("/") for o in os.environ.get("GFC_CORS_ORIGINS", "").split(",") if o.strip()]


class NodeCORSMiddleware(CORSMiddleware):
    """
    CORS for the origins in GFC_CORS_ORIGINS, read when the app's middleware
    stack is built. Auth is by bearer header, never cookies, so credentials are off.
    """

    def __init__(self, app):
        super().__init__(app, allow_origins=cors_origins(), allow_credentials=False,
                         allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
                         allow_headers=["Authorization", "Content-Type"], max_age=600)


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
    # Peer JSON can hold anything: only string column names, each once, and rows that are lists
    # of the right length (one malformed row must not take the rest of the batch down with it)
    if not isinstance(columns, (list, tuple)) or not isinstance(rows, (list, tuple)):
        return [], []
    keep, seen = [], set()
    for i, c in enumerate(columns):
        if isinstance(c, str) and c in allowed and c not in seen:
            keep.append(i)
            seen.add(c)
    safe_columns = [columns[i] for i in keep]
    safe_rows = [[row[i] for i in keep] for row in rows
                 if isinstance(row, (list, tuple)) and len(row) == len(columns)]
    if table == "users" and safe_columns:
        safe_columns.append("password")
        safe_rows = [r + [REMOTE_USER_PASSWORD] for r in safe_rows]
    return safe_columns, safe_rows
