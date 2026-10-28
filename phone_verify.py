"""
GFC Phone Verification - makes each rewarded account cost a phone number.

- A verifier sends and checks one-time SMS codes: `start(phone)` / `check(phone, code)`.
  TwilioVerifier is used when TWILIO_* credentials (an API key, or the account
  SID and auth token) and the Verify service SID are set, else FakeVerifier.
- Or Firebase phone sign-in (GFC_FIREBASE_CONFIG): the browser texts and checks the code
  with Firebase, and the node checks the Google-signed ID token it returns (see FIREBASE).
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
MAX_STARTS_PER_USER = 5      # SMS sends per user per START_WINDOW
MAX_STARTS_PER_PHONE = 5     # SMS sends per phone hash per START_WINDOW
MAX_CHECKS_PER_START = 5     # wrong codes allowed before the user must start again
CODE_TTL = datetime.timedelta(minutes=10)

E164_RE = re.compile(r"^\+[1-9]\d{7,14}$")


class VerifyError(Exception):
    """
    A verification request the provider refused (bad number, VoIP, provider error).
    provider_code is the provider's own error code when it gave one (Twilio's, e.g. 60410).
    """
    def __init__(self, message: str, provider_code: Optional[int] = None):
        super().__init__(message)
        self.provider_code = provider_code


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
            raise _twilio_error(f"Verify {path}", r)
        return r.json()

    def _refuse_voip(self, phone: str):
        try:
            r = self.client.get(self.LOOKUP_URL.format(phone=phone),
                                params={"Fields": "line_type_intelligence"})
        except httpx.HTTPError as ex:
            raise VerifyError(f"lookup unreachable: {type(ex).__name__}")
        if r.status_code >= 400:
            raise _twilio_error("Lookup", r)
        line_type = ((r.json() or {}).get("line_type_intelligence") or {}).get("type")
        if line_type in self.VOIP_TYPES:
            raise VerifyError("VoIP numbers can't be used for verification")

    def start(self, phone: str):
        if self.lookup_line_type:
            self._refuse_voip(phone)
        self._post("Verifications", {"To": phone, "Channel": "sms"})

    def check(self, phone: str, code: str) -> bool:
        return self._post("VerificationCheck", {"To": phone, "Code": code}).get("status") == "approved"


def _twilio_error(what: str, r: httpx.Response) -> VerifyError:
    """
    Logs a Twilio refusal with Twilio's own error code and message (its JSON body), which say
    why: 60410 Fraud Guard, 60605 country not allowed, 21608 trial account, 20003 bad key...
    logredact masks any phone number in the message.
    """
    try:
        body = r.json()
    except ValueError:
        body = {}
    if not isinstance(body, dict):
        body = {}
    code = body.get("code") if isinstance(body.get("code"), int) else None
    message = str(body.get("message") or "")[:300]
    logger.warning("Twilio %s refused: HTTP %s, Twilio error %s: %s %s", what, r.status_code,
                   code if code is not None else "-", message or "(no message)", body.get("more_info") or "")
    detail = f"verification provider error ({r.status_code}" + (f", Twilio {code}" if code is not None else "") + ")"
    return VerifyError(detail, code)


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

    Every refusal is logged with Cloudflare's error codes, and its FlowError.reason says
    which kind it was (see TURNSTILE_* below), so the pages can say what to do about it.
    """
    global _turnstile_warned
    secret = os.environ.get("GFC_TURNSTILE_SECRET", "")
    if not secret:
        if not _turnstile_warned:
            print("[PhoneVerify] GFC_TURNSTILE_SECRET not set: skipping the Turnstile bot check")
            _turnstile_warned = True
        return
    if not token:
        raise FlowError(403, "bot check required (turnstile_token missing)", TURNSTILE_MISSING)
    data = {"secret": secret, "response": token}
    if remoteip:
        data["remoteip"] = remoteip
    try:
        r = _turnstile_client.post(TURNSTILE_VERIFY_URL, data=data)
        body = r.json() if r.status_code == 200 else {}
        if not isinstance(body, dict):
            body = {}
    except (httpx.HTTPError, ValueError) as ex:
        logger.warning("Turnstile siteverify unreachable: %s", type(ex).__name__)
        raise FlowError(403, "bot check unavailable, try again later", TURNSTILE_UNAVAILABLE)
    if body.get("success") is True:
        return
    codes = [str(c) for c in body.get("error-codes") or []]
    reason = _turnstile_reason(r.status_code, codes)
    if reason == TURNSTILE_MISCONFIGURED:
        logger.error("Turnstile siteverify rejected this node's secret (%s): check GFC_TURNSTILE_SECRET",
                     ", ".join(codes))
    elif reason == TURNSTILE_REJECTED:
        # A site key and secret from different widgets look exactly like this: the widget says
        # "Success!" in the browser, then every token comes back invalid-input-response.
        logger.warning("Turnstile token rejected (%s, hostname %s). If every token fails, "
                       "GFC_TURNSTILE_SITEKEY and GFC_TURNSTILE_SECRET may be from different widgets",
                       ", ".join(codes) or "no error codes", body.get("hostname") or "-")
    else:
        logger.warning("Turnstile token refused (%s, HTTP %s)", ", ".join(codes) or "no error codes", r.status_code)
    raise FlowError(403, f"bot check failed ({', '.join(codes) or 'rejected'})", reason)


# FlowError.reason for each way the Turnstile check can refuse
TURNSTILE_MISSING = "turnstile_missing"            # no token sent
TURNSTILE_EXPIRED = "turnstile_expired"            # token too old or already used: check again
TURNSTILE_REJECTED = "turnstile_rejected"          # Cloudflare didn't accept the token
TURNSTILE_MISCONFIGURED = "turnstile_misconfigured"  # this node's secret is wrong: the operator's problem
TURNSTILE_UNAVAILABLE = "turnstile_unavailable"    # Cloudflare unreachable or erroring: try later


def _turnstile_reason(status: int, codes: list) -> str:
    if status != 200 or "internal-error" in codes:
        return TURNSTILE_UNAVAILABLE
    if "missing-input-secret" in codes or "invalid-input-secret" in codes:
        return TURNSTILE_MISCONFIGURED
    if "timeout-or-duplicate" in codes:
        return TURNSTILE_EXPIRED
    return TURNSTILE_REJECTED


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
    """A refused step, with the HTTP status the endpoint should return (and, for some, why)."""
    def __init__(self, status: int, detail: str, reason: str = ""):
        super().__init__(detail)
        self.status = status
        self.detail = detail
        self.reason = reason


PROVIDER_REASON = "provider"  # FlowError.reason when the SMS provider refused: "provider" or "provider:<code>"


def _provider_reason(ex: VerifyError) -> str:
    return PROVIDER_REASON + (f":{ex.provider_code}" if ex.provider_code is not None else "")


def start_verification(db_path: str, username: str, phone: str, send: bool = True) -> dict:
    """
    Checks and counts a start, then sends the code. send=False is for Firebase, where the
    browser sends the code itself: everything else (limits, the pending row) is the same,
    and complete_firebase_verification requires that pending row.
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
        # Count the attempt before calling the provider, so failures are rate-limited too
        now = _now().isoformat()
        conn.execute("INSERT INTO phone_verify_starts (username, phone_hash, created_at) VALUES (?, ?, ?)",
                     (username, hashed, now))
        conn.commit()
        if send:
            try:
                get_verifier().start(number)
            except VerifyError as ex:
                raise FlowError(400, str(ex), _provider_reason(ex))
        conn.execute("INSERT OR REPLACE INTO phone_verify_pending (username, phone_hash, started_at, failed_checks) "
                     "VALUES (?, ?, ?, 0)", (username, hashed, now))
        conn.commit()
    finally:
        conn.close()
    return {"ok": True, "sent": send, "phone": number}


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
            raise FlowError(502, str(ex), _provider_reason(ex))
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


def complete_firebase_verification(db_path: str, username: str, id_token: str) -> dict:
    """
    Firebase sent and checked the code in the browser; id_token is the Firebase ID token it
    returned. The number comes from the token (Google-signed), and must be the one this user
    started with start_verification(send=False) within CODE_TTL.
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
            raise FlowError(400, "code expired or too many attempts, request a new code")
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
# When it's set, the browser verification page sends codes with Firebase phone sign-in
# instead of Twilio, and the node accepts the Firebase ID token Firebase hands back. The
# token is checked here against Google's published keys: no service account is needed.

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


def verify_firebase_token(id_token: str) -> str:
    """
    The E.164 phone number a Firebase ID token proves, or FlowError(400). Checks the RS256
    signature against Google's keys, the audience and issuer for this project, expiry, that
    the user signed in with phone just now, and that the token carries a phone number.
    """

    cfg = firebase_config()
    if not cfg:
        raise FlowError(503, "phone verification isn't set up on this node")
    bad = FlowError(400, "phone sign-in didn't verify, request a new code")
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
            or (claims.get("firebase") or {}).get("sign_in_provider") != "phone"):
        raise bad
    try:
        return normalize_phone(str(claims.get("phone_number") or ""))
    except VerifyError:
        raise bad
