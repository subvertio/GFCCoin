"""
GFC Phone Verification - makes each rewarded account cost a phone number.

- Firebase phone sign-in (GFC_FIREBASE_CONFIG) texts and checks the code in the browser,
  and the node checks the Google-signed ID token it returns (see FIREBASE). The node never
  sends an SMS itself.
- Only an HMAC-SHA256 of the normalized E.164 number is stored, keyed with a
  secret in the data dir (phone_hmac_key.hex). The raw number is never written
  to the database, and none of these tables are synced to peers.
- One verified account per phone hash; start requests are rate-limited per user
  and per phone hash.
"""

import base64
import datetime
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import sqlite3
import time
from pathlib import Path
from typing import Optional

import httpx
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from config import DATA_DIR

logger = logging.getLogger("gfc.phone")

# ============================================================================
# LIMITS
# ============================================================================

START_WINDOW = datetime.timedelta(days=1)
MAX_STARTS_PER_USER = 5      # starts per user per START_WINDOW
MAX_STARTS_PER_PHONE = 5     # starts per phone hash per START_WINDOW
CODE_TTL = datetime.timedelta(minutes=10)

E164_RE = re.compile(r"^\+[1-9]\d{7,14}$")


class VerifyError(Exception):
    """A phone number that can't be used (not a valid number)."""


def normalize_phone(phone: str) -> str:
    """
    Normalize to E.164 (+ and 8-15 digits). Spaces, dashes, dots and brackets are dropped.
    Without a + (or 00), the number is taken as US/Canada: 10 digits, or 11 starting with 1.
    """
    cleaned = re.sub(r"[\s\-.()]", "", phone or "")
    if cleaned.startswith("00"):
        cleaned = "+" + cleaned[2:]
    elif cleaned.isdigit() and len(cleaned) == 10:
        cleaned = "+1" + cleaned
    elif cleaned.isdigit() and len(cleaned) == 11 and cleaned.startswith("1"):
        cleaned = "+" + cleaned
    if not E164_RE.match(cleaned):
        raise VerifyError("enter a 10-digit US number, e.g. 415 555 0123 (or + and a country code)")
    return cleaned


# ============================================================================
# PHONE HASH
# ============================================================================

def _hmac_key() -> bytes:
    """Per-node secret for phone hashes (GFC_PHONE_HMAC_KEY_FILE, default DATA_DIR/phone_hmac_key.hex)."""
    path = Path(os.environ.get("GFC_PHONE_HMAC_KEY_FILE", str(DATA_DIR / "phone_hmac_key.hex")))
    if not path.exists():
        try:
            with open(path, "x") as f:  # "x": never overwrite a key another process just wrote
                f.write(secrets.token_bytes(32).hex())
        except FileExistsError:
            pass
    return bytes.fromhex(path.read_text().strip())


def phone_hash(phone: str) -> str:
    """HMAC-SHA256 of the normalized number. Raises VerifyError if it isn't E.164."""
    return hmac.new(_hmac_key(), normalize_phone(phone).encode(), hashlib.sha256).hexdigest()


# ============================================================================
# STORAGE (local only, never synced)
# ============================================================================

def init_phone_tables(conn: sqlite3.Connection):
    conn.execute('''CREATE TABLE IF NOT EXISTS phone_verifications (
        username TEXT PRIMARY KEY,
        phone_hash TEXT UNIQUE NOT NULL,
        verified_at TEXT NOT NULL
    )''')
    # Open verification per user: which number it is for, and how many wrong codes so far
    conn.execute('''CREATE TABLE IF NOT EXISTS phone_verify_pending (
        username TEXT PRIMARY KEY,
        phone_hash TEXT NOT NULL,
        started_at TEXT NOT NULL,
        failed_checks INTEGER NOT NULL DEFAULT 0
    )''')
    # One row per start request, for rate limits
    conn.execute('''CREATE TABLE IF NOT EXISTS phone_verify_starts (
        username TEXT NOT NULL,
        phone_hash TEXT NOT NULL,
        created_at TEXT NOT NULL
    )''')


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def is_verified(conn: sqlite3.Connection, username: str) -> bool:
    init_phone_tables(conn)
    return conn.execute("SELECT 1 FROM phone_verifications WHERE username = ?", (username,)).fetchone() is not None


def record_verified(conn: sqlite3.Connection, username: str, hashed: str) -> bool:
    """Mark username verified with this phone hash. False if the phone is already used by another account."""
    init_phone_tables(conn)
    existing = conn.execute("SELECT username FROM phone_verifications WHERE phone_hash = ?", (hashed,)).fetchone()
    if existing:
        return existing[0] == username
    try:
        conn.execute("INSERT INTO phone_verifications (username, phone_hash, verified_at) VALUES (?, ?, ?)",
                     (username, hashed, _now().isoformat()))
    except sqlite3.IntegrityError:
        return False  # username already verified with another number, or a concurrent insert
    return True


def _phone_taken(conn: sqlite3.Connection, username: str, hashed: str) -> bool:
    row = conn.execute("SELECT username FROM phone_verifications WHERE phone_hash = ?", (hashed,)).fetchone()
    return bool(row) and row[0] != username


# ============================================================================
# FLOW (called by the browser verification page, app_webverify.py)
# ============================================================================

class FlowError(Exception):
    """A refused step, with the HTTP status the endpoint should return."""
    def __init__(self, status: int, detail: str):
        super().__init__(detail)
        self.status = status
        self.detail = detail


def start_verification(db_path: str, username: str, phone: str) -> dict:
    """
    Checks and counts a start before the browser has Firebase text the code: one account
    per phone, and the rate limits. complete_firebase_verification requires the pending row.
    """
    try:
        number = normalize_phone(phone)
    except VerifyError as ex:
        raise FlowError(400, str(ex))
    hashed = phone_hash(number)
    conn = sqlite3.connect(db_path)
    try:
        init_phone_tables(conn)
        if is_verified(conn, username):
            raise FlowError(409, "account already verified")
        if _phone_taken(conn, username, hashed):
            raise FlowError(409, "this phone number is already verified on another account")
        since = (_now() - START_WINDOW).isoformat()
        conn.execute("DELETE FROM phone_verify_starts WHERE created_at < ?", (since,))
        by_user = conn.execute("SELECT COUNT(*) FROM phone_verify_starts WHERE username = ?",
                               (username,)).fetchone()[0]
        by_phone = conn.execute("SELECT COUNT(*) FROM phone_verify_starts WHERE phone_hash = ?",
                                (hashed,)).fetchone()[0]
        if by_user >= MAX_STARTS_PER_USER or by_phone >= MAX_STARTS_PER_PHONE:
            raise FlowError(429, "too many verification requests, try again tomorrow")
        # Count every start, so ones that never finish are rate-limited too
        now = _now().isoformat()
        conn.execute("INSERT INTO phone_verify_starts (username, phone_hash, created_at) VALUES (?, ?, ?)",
                     (username, hashed, now))
        conn.execute("INSERT OR REPLACE INTO phone_verify_pending (username, phone_hash, started_at, failed_checks) "
                     "VALUES (?, ?, ?, 0)", (username, hashed, now))
        conn.commit()
    finally:
        conn.close()
    return {"ok": True, "phone": number}


def complete_firebase_verification(db_path: str, username: str, id_token: str) -> dict:
    """
    Firebase sent and checked the code in the browser; id_token is the Firebase ID token it
    returned. The number comes from the token (Google-signed), and must be the one this user
    started with start_verification within CODE_TTL.
    """
    number = verify_firebase_token(id_token)
    hashed = phone_hash(number)
    conn = sqlite3.connect(db_path)
    try:
        init_phone_tables(conn)
        if is_verified(conn, username):
            return {"ok": True, "verified": True}
        pending = conn.execute("SELECT phone_hash, started_at FROM phone_verify_pending WHERE username = ?",
                               (username,)).fetchone()
        if not pending or pending[0] != hashed:
            raise FlowError(400, "no verification started for this number")
        if _now() - datetime.datetime.fromisoformat(pending[1]) > CODE_TTL:
            conn.execute("DELETE FROM phone_verify_pending WHERE username = ?", (username,))
            conn.commit()
            raise FlowError(400, "code expired, request a new code")
        if not record_verified(conn, username, hashed):
            conn.rollback()
            raise FlowError(409, "this phone number is already verified on another account")
        conn.execute("DELETE FROM phone_verify_pending WHERE username = ?", (username,))
        conn.commit()
    finally:
        conn.close()
    return {"ok": True, "verified": True}


# ============================================================================
# FIREBASE (the browser sends and checks the SMS code; the node checks the result)
# ============================================================================
#
# GFC_FIREBASE_CONFIG is the web app's public config from the Firebase console, as JSON:
#   {"apiKey": "...", "authDomain": "<project>.firebaseapp.com", "projectId": "<project>", "appId": "..."}
# When it's set, the browser verification page sends codes with Firebase phone sign-in, and
# the node accepts the Firebase ID token Firebase hands back; without it, phone verification
# is off. The token is checked here against Google's published keys: no service account is needed.

FIREBASE_CERTS_URL = "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com"
FIREBASE_MAX_AUTH_AGE = datetime.timedelta(minutes=10)  # the sign-in must be this fresh
FIREBASE_LEEWAY = 60  # seconds of clock skew allowed on iat/exp
_firebase_client = httpx.Client(timeout=5.0)
_firebase_certs = {"keys": {}, "expires": 0.0}


def firebase_config() -> Optional[dict]:
    """The web config from GFC_FIREBASE_CONFIG, or None when Firebase isn't set up (or the JSON is bad)."""
    raw = os.environ.get("GFC_FIREBASE_CONFIG", "").strip()
    if not raw:
        return None
    try:
        cfg = json.loads(raw)
    except ValueError:
        logger.error("GFC_FIREBASE_CONFIG isn't valid JSON: Firebase phone verification is off")
        return None
    if not isinstance(cfg, dict) or not all(isinstance(cfg.get(k), str) and cfg[k]
                                            for k in ("apiKey", "authDomain", "projectId")):
        logger.error("GFC_FIREBASE_CONFIG needs apiKey, authDomain and projectId: Firebase phone verification is off")
        return None
    return cfg


def set_firebase_client(client: httpx.Client):
    """Replace the HTTP client that fetches Google's signing certificates (tests). Clears the cache."""
    global _firebase_client
    _firebase_client = client
    _firebase_certs.update(keys={}, expires=0.0)


def _firebase_keys() -> dict:
    """kid -> public key, cached for as long as Google's Cache-Control says."""
    if _firebase_certs["keys"] and time.time() < _firebase_certs["expires"]:
        return _firebase_certs["keys"]
    try:
        r = _firebase_client.get(FIREBASE_CERTS_URL)
        certs = r.json() if r.status_code == 200 else None
    except (httpx.HTTPError, ValueError) as ex:
        logger.warning("Firebase signing keys unreachable: %s", type(ex).__name__)
        certs = None
    if not isinstance(certs, dict) or not certs:
        raise FlowError(503, "verification service unavailable, try again later")
    keys = {}
    for kid, pem in certs.items():
        try:
            keys[kid] = x509.load_pem_x509_certificate(pem.encode()).public_key()
        except (ValueError, TypeError, AttributeError):
            continue
    max_age = re.search(r"max-age=(\d+)", r.headers.get("cache-control", ""))
    _firebase_certs.update(keys=keys, expires=time.time() + min(int(max_age.group(1)) if max_age else 3600, 86400))
    return keys


def _b64url(part: str) -> bytes:
    return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))


def _firebase_claims(id_token: str, providers: tuple, what: str) -> dict:
    """
    The claims of a fresh Firebase ID token for this project, or FlowError(400). Checks the RS256
    signature against Google's keys, the audience and issuer, expiry, that the user signed in
    just now, and that they signed in with one of `providers`.
    """
    cfg = firebase_config()
    if not cfg:
        raise FlowError(503, f"{what} verification isn't set up on this node")
    bad = FlowError(400, f"{what} sign-in didn't verify, " + ("request a new code" if what == "phone" else "try again"))
    parts = (id_token or "").split(".")
    if len(parts) != 3 or len(id_token) > 8192:
        raise bad
    try:
        header = json.loads(_b64url(parts[0]))
        claims = json.loads(_b64url(parts[1]))
        signature = _b64url(parts[2])
    except (ValueError, TypeError):
        raise bad
    if not isinstance(header, dict) or not isinstance(claims, dict) or header.get("alg") != "RS256":
        raise bad
    key = _firebase_keys().get(header.get("kid"))
    if key is None:
        raise bad
    try:
        key.verify(signature, f"{parts[0]}.{parts[1]}".encode(), padding.PKCS1v15(), hashes.SHA256())
    except (InvalidSignature, ValueError, TypeError):
        raise bad

    project = cfg["projectId"]
    now = time.time()
    numbers_ok = all(isinstance(claims.get(k), (int, float)) for k in ("exp", "iat", "auth_time"))
    if (not numbers_ok
            or claims.get("aud") != project
            or claims.get("iss") != f"https://securetoken.google.com/{project}"
            or not isinstance(claims.get("sub"), str) or not claims["sub"]
            or claims["exp"] < now - FIREBASE_LEEWAY
            or claims["iat"] > now + FIREBASE_LEEWAY
            or claims["auth_time"] > now + FIREBASE_LEEWAY
            or now - claims["auth_time"] > FIREBASE_MAX_AUTH_AGE.total_seconds()
            or (claims.get("firebase") or {}).get("sign_in_provider") not in providers):
        raise bad
    return claims


def verify_firebase_token(id_token: str) -> str:
    """The E.164 phone number a fresh Firebase phone sign-in proves, or FlowError(400)."""
    claims = _firebase_claims(id_token, ("phone",), "phone")
    try:
        return normalize_phone(str(claims.get("phone_number") or ""))
    except VerifyError:
        raise FlowError(400, "phone sign-in didn't verify, request a new code")


def verify_firebase_email(id_token: str) -> str:
    """
    The (lowercased) email address a fresh Firebase email-link sign-in proves, or FlowError(400).
    Firebase marks an address verified only once its owner opened a link sent to it.
    """
    claims = _firebase_claims(id_token, ("password", "emailLink"), "email")
    email = str(claims.get("email") or "").strip().lower()
    if claims.get("email_verified") is not True or "@" not in email or len(email) > 254:
        raise FlowError(400, "email sign-in didn't verify, try again")
    return email
