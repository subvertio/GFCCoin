"""
GFC Phone Verification - makes each rewarded account cost a phone number.

- A verifier sends and checks one-time SMS codes: `start(phone)` / `check(phone, code)`.
  TwilioVerifier is used when TWILIO_* credentials (an API key, or the account
  SID and auth token) and the Verify service SID are set, else FakeVerifier.
- Only an HMAC-SHA256 of the normalized E.164 number is stored, keyed with a
  secret in the data dir (phone_hmac_key.hex). The raw number is never written
  to the database, and none of these tables are synced to peers.
- One verified account per phone hash; start requests are rate-limited per user
  and per phone hash.
"""

import datetime
import hashlib
import hmac
import os
import re
import secrets
import sqlite3
from pathlib import Path
from typing import Optional

import httpx

from config import DATA_DIR

# ============================================================================
# LIMITS
# ============================================================================

START_WINDOW = datetime.timedelta(days=1)
MAX_STARTS_PER_USER = 5      # SMS sends per user per START_WINDOW
MAX_STARTS_PER_PHONE = 5     # SMS sends per phone hash per START_WINDOW
MAX_CHECKS_PER_START = 5     # wrong codes allowed before the user must start again
CODE_TTL = datetime.timedelta(minutes=10)

E164_RE = re.compile(r"^\+[1-9]\d{7,14}$")


class VerifyError(Exception):
    """A verification request the provider refused (bad number, VoIP, provider error)."""


def normalize_phone(phone: str) -> str:
    """Normalize to E.164 (+ and 8-15 digits). Spaces, dashes, dots and brackets are dropped."""
    cleaned = re.sub(r"[\s\-.()]", "", phone or "")
    if cleaned.startswith("00"):
        cleaned = "+" + cleaned[2:]
    if not E164_RE.match(cleaned):
        raise VerifyError("phone must be in international format, e.g. +14155550123")
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
# PROVIDERS
# ============================================================================

class FakeVerifier:
    """
    In-memory provider for tests and for nodes without Twilio credentials.
    The code for each number is kept in `sent` (tests read it from there) and
    printed to the console with the number masked. Numbers in `voip_numbers`
    are refused like Twilio Lookup refuses VoIP lines.
    """
    name = "fake"

    def __init__(self):
        self.sent = {}
        self.voip_numbers = set()

    def start(self, phone: str):
        if phone in self.voip_numbers:
            raise VerifyError("VoIP numbers can't be used for verification")
        code = f"{secrets.randbelow(10 ** 6):06d}"
        self.sent[phone] = code
        print(f"[PhoneVerify] (fake provider, no SMS sent) code for ***{phone[-2:]}: {code}")

    def check(self, phone: str, code: str) -> bool:
        expected = self.sent.get(phone)
        if expected and hmac.compare_digest(expected, code or ""):
            del self.sent[phone]
            return True
        return False


class TwilioVerifier:
    """
    Twilio Verify (SMS) for TWILIO_VERIFY_SERVICE_SID. It authenticates with a
    restricted API key (TWILIO_API_KEY_SID + TWILIO_API_KEY_SECRET; preferred,
    since it can be limited to Verify and Lookup) or else the account's
    TWILIO_ACCOUNT_SID + TWILIO_AUTH_TOKEN. With TWILIO_LOOKUP_LINE_TYPE=1, a
    Lookup v2 line-type check runs first and VoIP numbers are refused (it is
    billed per lookup).
    """
    name = "twilio"
    VERIFY_URL = "https://verify.twilio.com/v2/Services/{service}/{path}"
    LOOKUP_URL = "https://lookups.twilio.com/v2/PhoneNumbers/{phone}"
    VOIP_TYPES = {"nonFixedVoip", "fixedVoip"}

    def __init__(self, auth_user: str, auth_secret: str, service_sid: str,
                 lookup_line_type: bool = False, timeout: float = 10.0):
        # auth_user is an API key SID (SK...) or the account SID (AC...); the
        # Verify and Lookup URLs don't contain the account SID, so either works
        self.service_sid = service_sid
        self.lookup_line_type = lookup_line_type
        self.auth_user = auth_user
        self.client = httpx.Client(auth=(auth_user, auth_secret), timeout=timeout)

    def _post(self, path: str, data: dict) -> dict:
        try:
            r = self.client.post(self.VERIFY_URL.format(service=self.service_sid, path=path), data=data)
        except httpx.HTTPError as ex:
            raise VerifyError(f"verification provider unreachable: {type(ex).__name__}")
        if r.status_code == 404 and path == "VerificationCheck":
            return {"status": "expired"}  # Twilio: no pending verification (expired or used up)
        if r.status_code >= 400:
            raise VerifyError(f"verification provider error ({r.status_code})")
        return r.json()

    def _refuse_voip(self, phone: str):
        try:
            r = self.client.get(self.LOOKUP_URL.format(phone=phone),
                                params={"Fields": "line_type_intelligence"})
        except httpx.HTTPError as ex:
            raise VerifyError(f"lookup unreachable: {type(ex).__name__}")
        if r.status_code >= 400:
            raise VerifyError(f"lookup error ({r.status_code})")
        line_type = ((r.json() or {}).get("line_type_intelligence") or {}).get("type")
        if line_type in self.VOIP_TYPES:
            raise VerifyError("VoIP numbers can't be used for verification")

    def start(self, phone: str):
        if self.lookup_line_type:
            self._refuse_voip(phone)
        self._post("Verifications", {"To": phone, "Channel": "sms"})

    def check(self, phone: str, code: str) -> bool:
        return self._post("VerificationCheck", {"To": phone, "Code": code}).get("status") == "approved"


_verifier = None


def twilio_credentials():
    """(user, secret) for Twilio: a restricted API key if set, else the account SID and auth token."""
    key_sid = os.environ.get("TWILIO_API_KEY_SID", "")
    key_secret = os.environ.get("TWILIO_API_KEY_SECRET", "")
    if key_sid and key_secret:
        return key_sid, key_secret
    sid = os.environ.get("TWILIO_ACCOUNT_SID", "")
    token = os.environ.get("TWILIO_AUTH_TOKEN", "")
    if sid and token:
        return sid, token
    return None


def get_verifier():
    """Twilio when its env vars are set, else the fake provider (logged, since it sends nothing)."""
    global _verifier
    if _verifier is None:
        creds = twilio_credentials()
        service = os.environ.get("TWILIO_VERIFY_SERVICE_SID", "")
        if creds and service:
            _verifier = TwilioVerifier(creds[0], creds[1], service,
                                       lookup_line_type=os.environ.get("TWILIO_LOOKUP_LINE_TYPE") == "1")
        else:
            print("[PhoneVerify] No Twilio credentials: using the fake provider (codes go to the console)")
            _verifier = FakeVerifier()
    return _verifier


def set_verifier(verifier):
    """Replace the provider (tests)."""
    global _verifier
    _verifier = verifier


# ============================================================================
# CLOUDFLARE TURNSTILE (bot check before any SMS is sent)
# ============================================================================

TURNSTILE_VERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
_turnstile_client = httpx.Client(timeout=5.0)
_turnstile_warned = False


def set_turnstile_client(client: httpx.Client):
    """Replace the HTTP client used for siteverify (tests)."""
    global _turnstile_client
    _turnstile_client = client


def check_turnstile(token: str, remoteip: str = ""):
    """
    Raise FlowError(403) unless Cloudflare accepts the Turnstile token. Uses the
    secret in GFC_TURNSTILE_SECRET; if unset, the check is skipped (warned once),
    so local nodes work without it. Fails closed if Cloudflare can't be reached.
    """
    global _turnstile_warned
    secret = os.environ.get("GFC_TURNSTILE_SECRET", "")
    if not secret:
        if not _turnstile_warned:
            print("[PhoneVerify] GFC_TURNSTILE_SECRET not set: skipping the Turnstile bot check")
            _turnstile_warned = True
        return
    if not token:
        raise FlowError(403, "bot check required (turnstile_token missing)")
    data = {"secret": secret, "response": token}
    if remoteip:
        data["remoteip"] = remoteip
    try:
        r = _turnstile_client.post(TURNSTILE_VERIFY_URL, data=data)
        success = r.status_code == 200 and (r.json() or {}).get("success") is True
    except (httpx.HTTPError, ValueError):
        raise FlowError(403, "bot check unavailable, try again later")
    if not success:
        raise FlowError(403, "bot check failed")


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
# FLOW (called by the /verify/phone endpoints)
# ============================================================================

class FlowError(Exception):
    """A refused step, with the HTTP status the endpoint should return."""
    def __init__(self, status: int, detail: str):
        super().__init__(detail)
        self.status = status
        self.detail = detail


def start_verification(db_path: str, username: str, phone: str) -> dict:
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
        # Count the attempt before calling the provider, so failures are rate-limited too
        now = _now().isoformat()
        conn.execute("INSERT INTO phone_verify_starts (username, phone_hash, created_at) VALUES (?, ?, ?)",
                     (username, hashed, now))
        conn.commit()
        try:
            get_verifier().start(number)
        except VerifyError as ex:
            raise FlowError(400, str(ex))
        conn.execute("INSERT OR REPLACE INTO phone_verify_pending (username, phone_hash, started_at, failed_checks) "
                     "VALUES (?, ?, ?, 0)", (username, hashed, now))
        conn.commit()
    finally:
        conn.close()
    return {"ok": True, "sent": True}


def check_verification(db_path: str, username: str, phone: str, code: str) -> dict:
    try:
        number = normalize_phone(phone)
    except VerifyError as ex:
        raise FlowError(400, str(ex))
    hashed = phone_hash(number)
    conn = sqlite3.connect(db_path)
    try:
        init_phone_tables(conn)
        if is_verified(conn, username):
            return {"ok": True, "verified": True}
        pending = conn.execute("SELECT phone_hash, started_at, failed_checks FROM phone_verify_pending "
                               "WHERE username = ?", (username,)).fetchone()
        if not pending or pending[0] != hashed:
            raise FlowError(400, "no verification started for this number")
        started = datetime.datetime.fromisoformat(pending[1])
        if pending[2] >= MAX_CHECKS_PER_START or _now() - started > CODE_TTL:
            conn.execute("DELETE FROM phone_verify_pending WHERE username = ?", (username,))
            conn.commit()
            raise FlowError(400, "code expired or too many attempts, request a new code")
        try:
            approved = get_verifier().check(number, (code or "").strip())
        except VerifyError as ex:
            raise FlowError(502, str(ex))
        if not approved:
            conn.execute("UPDATE phone_verify_pending SET failed_checks = failed_checks + 1 WHERE username = ?",
                         (username,))
            conn.commit()
            return {"ok": True, "verified": False, "reason": "wrong code"}
        if not record_verified(conn, username, hashed):
            conn.rollback()
            raise FlowError(409, "this phone number is already verified on another account")
        conn.execute("DELETE FROM phone_verify_pending WHERE username = ?", (username,))
        conn.commit()
    finally:
        conn.close()
    return {"ok": True, "verified": True}
