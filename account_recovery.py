"""
GFC Account Recovery - password reset, verified email, and changing the verified phone.

Proof of ownership comes from Firebase in the browser (app_recovery.py pages): a phone sign-in
(an SMS code) for the account's verified phone, or an email sign-in link for its verified email.
The node checks the Firebase ID token (phone_verify.py) and that it names the account's phone
(by its HMAC hash) or email.

- Reset: prove the phone OR the email, then set a new password. With the recovery code
  (keystore.py) the same wallet keys come back; without it the account gets a new data key and
  old wallets stay locked until a backup is imported. Either way every session is signed out
  and a new recovery code is issued.
- Verify an email (signed in, from the app): proves an address so it can reset the password or
  change the phone later. One account per email.
- Change the phone (lost or new number): prove the verified email, then the new number.
- Operator reset (`python account_recovery.py reset-link USER`, or `gfc reset-link USER` on the
  server): for an account with no verified phone or email, after the operator has confirmed who's
  asking some other way. It makes a reset link that skips the proof; the user still chooses the
  new password themselves, and their recovery code still decides whether the wallets come back.

Flows are random codes (stored as hashes) bound to one account and one purpose, valid for
FLOW_TTL; a proven reset must finish within PROVEN_TTL. At most STARTS_PER_DAY recovery starts
per account. Every mismatch gives the same answer, so the pages don't reveal whose phone or
email is whose.
"""

import datetime
import hashlib
import re
import secrets
import sqlite3
from typing import Optional

import keystore
import phone_verify
from config import DB_PATH
from security import hash_password

FLOW_TTL = datetime.timedelta(minutes=30)     # long enough to fetch an email
PROVEN_TTL = datetime.timedelta(minutes=15)   # from proof to the new password
OPERATOR_TTL = datetime.timedelta(hours=24)   # an operator's reset link, sent to the user privately
STARTS_PER_DAY = 5
MIN_PASSWORD = 8
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]+\.[^@\s]{2,}$")
NO_MATCH = "That doesn't match an account we can recover. Check the username and the phone number or email on it."


class RecoveryError(ValueError):
    def __init__(self, status: int, detail: str):
        super().__init__(detail)
        self.status = status
        self.detail = detail


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _hash(code: str) -> str:
    return hashlib.sha256(code.encode()).hexdigest()


def init_tables(conn: sqlite3.Connection):
    conn.execute('''CREATE TABLE IF NOT EXISTS email_verifications (
        username TEXT PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        verified_at TEXT NOT NULL
    )''')
    conn.execute('''CREATE TABLE IF NOT EXISTS recovery_flows (
        code_hash TEXT PRIMARY KEY,
        username TEXT NOT NULL,
        purpose TEXT NOT NULL,          -- reset | email | phone
        method TEXT NOT NULL DEFAULT '',-- phone | email: what proves the account
        contact TEXT NOT NULL DEFAULT '',-- phone hash or email the proof must match
        new_contact TEXT NOT NULL DEFAULT '',-- phone change: the new number's hash
        stage TEXT NOT NULL DEFAULT 'start',  -- start | proven | done
        created_at TEXT NOT NULL,
        proven_at TEXT NOT NULL DEFAULT ''
    )''')
    conn.execute("CREATE INDEX IF NOT EXISTS idx_recovery_flows_user ON recovery_flows(username, created_at)")


def normalize_email(email: str) -> str:
    email = (email or "").strip().lower()
    if not EMAIL_RE.match(email) or len(email) > 254:
        raise RecoveryError(400, "That email address doesn't look right.")
    return email


def mask_email(email: str) -> str:
    """a***@example.com, for showing which address is on file."""
    if "@" not in (email or ""):
        return ""
    name, domain = email.split("@", 1)
    return f"{name[:1]}***@{domain}"


def verified_email(conn: sqlite3.Connection, username: str) -> str:
    init_tables(conn)
    row = conn.execute("SELECT email FROM email_verifications WHERE username = ?", (username,)).fetchone()
    return row[0] if row else ""


def _canonical_user(conn: sqlite3.Connection, username: str) -> str:
    row = conn.execute("SELECT username FROM users WHERE LOWER(username) = LOWER(?)",
                       ((username or "").strip(),)).fetchone()
    return row[0] if row else ""


def _phone_hash_of(conn: sqlite3.Connection, username: str) -> str:
    phone_verify.init_phone_tables(conn)
    row = conn.execute("SELECT phone_hash FROM phone_verifications WHERE username = ?", (username,)).fetchone()
    return row[0] if row else ""


def _new_flow(conn: sqlite3.Connection, username: str, purpose: str, method: str = "", contact: str = "") -> str:
    code = secrets.token_urlsafe(24)
    conn.execute("INSERT INTO recovery_flows (code_hash, username, purpose, method, contact, created_at) "
                 "VALUES (?, ?, ?, ?, ?, ?)", (_hash(code), username, purpose, method, contact, _now().isoformat()))
    return code


def _rate_limit(conn: sqlite3.Connection, username: str):
    since = (_now() - datetime.timedelta(days=1)).isoformat()
    n = conn.execute("SELECT COUNT(*) FROM recovery_flows WHERE username = ? AND purpose != 'email' "
                     "AND created_at > ?", (username, since)).fetchone()[0]
    if n >= STARTS_PER_DAY:
        raise RecoveryError(429, "Too many attempts for this account today. Please try again tomorrow.")


def _flow(conn: sqlite3.Connection, code: str, purpose: str) -> dict:
    """The live flow for this code and purpose, or RecoveryError(410)."""
    init_tables(conn)
    row = conn.execute("SELECT username, method, contact, new_contact, stage, created_at, proven_at "
                       "FROM recovery_flows WHERE code_hash = ? AND purpose = ?",
                       (_hash(code or ""), purpose)).fetchone()
    expired = RecoveryError(410, "This link has expired. Please start again.")
    if not row or row[4] == "done":
        raise expired
    flow = dict(zip(("username", "method", "contact", "new_contact", "stage", "created_at", "proven_at"), row))
    operator = flow["method"] == "operator"
    if _now() - datetime.datetime.fromisoformat(flow["created_at"]) > (OPERATOR_TTL if operator else FLOW_TTL):
        raise expired
    if flow["stage"] == "proven" and             _now() - datetime.datetime.fromisoformat(flow["proven_at"]) > (OPERATOR_TTL if operator else PROVEN_TTL):
        raise expired
    return flow


def _set(conn: sqlite3.Connection, code: str, **fields):
    cols = ", ".join(f"{k} = ?" for k in fields)
    conn.execute(f"UPDATE recovery_flows SET {cols} WHERE code_hash = ?", (*fields.values(), _hash(code)))


def flow_username(code: str, purpose: str, db_path: str = DB_PATH) -> Optional[str]:
    conn = sqlite3.connect(db_path)
    try:
        return _flow(conn, code, purpose)["username"]
    except RecoveryError:
        return None
    finally:
        conn.close()


def _proof(method: str, id_token: str) -> str:
    """What a Firebase ID token proves: a phone hash, or an email."""
    try:
        if method == "phone":
            return phone_verify.phone_hash(phone_verify.verify_firebase_token(id_token))
        return phone_verify.verify_firebase_email(id_token)
    except phone_verify.FlowError as ex:
        detail = ex.detail[:1].upper() + ex.detail[1:]
        raise RecoveryError(ex.status, detail if detail.endswith(".") else detail + ".")


# ---------- starting: who, and how they'll prove it ----------

def start(username: str, method: str, contact: str, purpose: str = "reset", db_path: str = DB_PATH) -> dict:
    """
    Start a reset (phone or email) or a phone change (email only). Returns {"flow", "phone"} or
    {"flow", "email"} for the page to have Firebase send the code or link, else RecoveryError.
    """
    if purpose not in ("reset", "phone") or method not in ("phone", "email") or (purpose == "phone" and method != "email"):
        raise RecoveryError(400, "Choose how to prove it's your account.")
    conn = sqlite3.connect(db_path)
    try:
        init_tables(conn)
        user = _canonical_user(conn, username)
        if method == "phone":
            try:
                number = phone_verify.normalize_phone(contact)
            except phone_verify.VerifyError:
                raise RecoveryError(400, "That phone number doesn't look right.")
            on_file, given, shown = _phone_hash_of(conn, user) if user else "", phone_verify.phone_hash(number), number
        else:
            given = normalize_email(contact)
            on_file, shown = (verified_email(conn, user) if user else ""), given
        if not user or not on_file or not secrets.compare_digest(on_file, given):
            raise RecoveryError(400, NO_MATCH)
        _rate_limit(conn, user)
        code = _new_flow(conn, user, purpose, method, on_file)
        conn.commit()
        return {"flow": code, method: shown}
    finally:
        conn.close()


def prove(code: str, id_token: str, purpose: str = "reset", db_path: str = DB_PATH) -> str:
    """The browser proved the phone or email Firebase checked; returns the username."""
    conn = sqlite3.connect(db_path)
    try:
        flow = _flow(conn, code, purpose)
        if flow["stage"] != "start":
            raise RecoveryError(410, "This link was already used. Please start again.")
        if not secrets.compare_digest(_proof(flow["method"], id_token), flow["contact"]):
            raise RecoveryError(400, "That isn't the phone number or email on this account.")
        _set(conn, code, stage="proven", proven_at=_now().isoformat())
        conn.commit()
        return flow["username"]
    finally:
        conn.close()


def operator_reset_link(username: str, db_path: str = DB_PATH) -> tuple:
    """
    (username, flow code) for a reset that skips the phone/email proof: the operator has confirmed
    who's asking some other way. Valid for OPERATOR_TTL and once; replaces the account's earlier
    operator links. The code is a secret for that user only.
    """
    conn = sqlite3.connect(db_path)
    try:
        init_tables(conn)
        user = _canonical_user(conn, username)
        if not user:
            raise RecoveryError(404, f"No account named {username!r}.")
        conn.execute("UPDATE recovery_flows SET stage = 'done' WHERE username = ? AND method = 'operator' "
                     "AND stage != 'done'", (user,))
        code = _new_flow(conn, user, "reset", "operator")
        _set(conn, code, stage="proven", proven_at=_now().isoformat())
        conn.commit()
        return user, code
    finally:
        conn.close()


def reset_ready(code: str, db_path: str = DB_PATH) -> Optional[str]:
    """The username if this reset link can set a new password now, else None."""
    conn = sqlite3.connect(db_path)
    try:
        flow = _flow(conn, code, "reset")
        return flow["username"] if flow["stage"] == "proven" else None
    except RecoveryError:
        return None
    finally:
        conn.close()


# ---------- reset ----------

def complete_reset(code: str, new_password: str, recovery_code: str = "", accept_locked: bool = False,
                   db_path: str = DB_PATH) -> dict:
    """
    Set the new password. With the right recovery code the wallets come back; without one,
    accept_locked must be set (old wallets stay locked until a backup is imported).
    Signs out every session and returns {"username", "wallets": "kept"|"locked", "recovery_code"}.
    """
    if len(new_password or "") < MIN_PASSWORD:
        raise RecoveryError(400, f"Use at least {MIN_PASSWORD} characters for the new password.")
    conn = sqlite3.connect(db_path)
    try:
        flow = _flow(conn, code, "reset")
        if flow["stage"] != "proven":
            raise RecoveryError(410, "This link has expired. Please start again.")
        username = flow["username"]
    finally:
        conn.close()
    data_key = None
    if (recovery_code or "").strip():
        data_key = keystore.unlock_with_recovery_code(username, recovery_code, db_path)
        if data_key is None:
            raise RecoveryError(400, "That recovery code isn't right. Check it, or leave it empty to "
                                     "reset without it.")
    elif not accept_locked:
        raise RecoveryError(400, "Without your recovery code, your current wallets stay locked until you "
                                 "import a wallet backup. Tick the box to continue anyway.")
    if data_key is not None:
        keystore.rewrap_user_key(username, data_key, new_password, db_path)
    else:
        data_key = keystore.replace_data_key(username, new_password, db_path)
    conn = sqlite3.connect(db_path)
    try:
        conn.execute("UPDATE users SET password = ? WHERE username = ?", (hash_password(new_password), username))
        conn.execute("DELETE FROM sessions WHERE username = ?", (username,))
        _set(conn, code, stage="done")
        conn.commit()
    finally:
        conn.close()
    return {"username": username, "wallets": "kept" if recovery_code.strip() else "locked",
            "recovery_code": keystore.new_recovery_code(username, data_key, db_path)}


# ---------- verified email (signed in) ----------

def email_link(username: str, db_path: str = DB_PATH) -> str:
    """A flow code for the signed-in user to verify an email address in the browser."""
    conn = sqlite3.connect(db_path)
    try:
        init_tables(conn)
        code = _new_flow(conn, username, "email")
        conn.commit()
        return code
    finally:
        conn.close()


def start_email(code: str, email: str, db_path: str = DB_PATH) -> dict:
    email = normalize_email(email)
    conn = sqlite3.connect(db_path)
    try:
        flow = _flow(conn, code, "email")
        if flow["stage"] != "start":
            raise RecoveryError(410, "This link was already used. Please start again.")
        taken = conn.execute("SELECT username FROM email_verifications WHERE email = ?", (email,)).fetchone()
        if taken and taken[0] != flow["username"]:
            raise RecoveryError(409, "That email is already verified on another account.")
        _set(conn, code, method="email", contact=email)
        conn.commit()
        return {"flow": code, "email": email}
    finally:
        conn.close()


def prove_email(code: str, id_token: str, db_path: str = DB_PATH) -> dict:
    """The new address is proven: it becomes the account's verified email."""
    conn = sqlite3.connect(db_path)
    try:
        flow = _flow(conn, code, "email")
        if not flow["contact"]:
            raise RecoveryError(410, "This link has expired. Please start again.")
        email = _proof("email", id_token)
        if not secrets.compare_digest(email, flow["contact"]):
            raise RecoveryError(400, "That sign-in was for a different email address.")
        try:
            conn.execute("DELETE FROM email_verifications WHERE username = ?", (flow["username"],))
            conn.execute("INSERT INTO email_verifications (username, email, verified_at) VALUES (?, ?, ?)",
                         (flow["username"], email, _now().isoformat()))
        except sqlite3.IntegrityError:
            conn.rollback()
            raise RecoveryError(409, "That email is already verified on another account.")
        conn.execute("UPDATE users SET email = ? WHERE username = ?", (email, flow["username"]))
        _set(conn, code, stage="done")
        conn.commit()
        return {"username": flow["username"], "email": email}
    finally:
        conn.close()


# ---------- changing the verified phone (after proving the email) ----------

def start_new_phone(code: str, phone: str, db_path: str = DB_PATH) -> dict:
    try:
        number = phone_verify.normalize_phone(phone)
    except phone_verify.VerifyError:
        raise RecoveryError(400, "That phone number doesn't look right.")
    hashed = phone_verify.phone_hash(number)
    conn = sqlite3.connect(db_path)
    try:
        flow = _flow(conn, code, "phone")
        if flow["stage"] != "proven":
            raise RecoveryError(410, "This link has expired. Please start again.")
        phone_verify.init_phone_tables(conn)
        taken = conn.execute("SELECT username FROM phone_verifications WHERE phone_hash = ?", (hashed,)).fetchone()
        if taken and taken[0] != flow["username"]:
            raise RecoveryError(409, "That phone number is already verified on another account.")
        _set(conn, code, new_contact=hashed)
        conn.commit()
        return {"flow": code, "phone": number}
    finally:
        conn.close()


def prove_new_phone(code: str, id_token: str, db_path: str = DB_PATH) -> str:
    """The new number is proven: it replaces the account's verified phone. Returns the username."""
    conn = sqlite3.connect(db_path)
    try:
        flow = _flow(conn, code, "phone")
        if flow["stage"] != "proven" or not flow["new_contact"]:
            raise RecoveryError(410, "This link has expired. Please start again.")
        if not secrets.compare_digest(_proof("phone", id_token), flow["new_contact"]):
            raise RecoveryError(400, "That code was for a different number. Try again.")
        try:
            conn.execute("DELETE FROM phone_verifications WHERE username = ?", (flow["username"],))
            conn.execute("INSERT INTO phone_verifications (username, phone_hash, verified_at) VALUES (?, ?, ?)",
                         (flow["username"], flow["new_contact"], _now().isoformat()))
        except sqlite3.IntegrityError:
            conn.rollback()
            raise RecoveryError(409, "That phone number is already verified on another account.")
        _set(conn, code, stage="done")
        conn.commit()
        return flow["username"]
    finally:
        conn.close()


def status(username: str, db_path: str = DB_PATH) -> dict:
    """What this account can recover with, for the app's settings screen."""
    conn = sqlite3.connect(db_path)
    try:
        email = verified_email(conn, username)
        phone = bool(_phone_hash_of(conn, username))
    finally:
        conn.close()
    return {"recovery_code": keystore.has_recovery_code(username, db_path),
            "email": mask_email(email), "email_verified": bool(email), "phone_verified": phone}


def _cli(argv: list) -> int:
    import sys
    if len(argv) != 2 or argv[0] != "reset-link":
        print("usage: python account_recovery.py reset-link USERNAME", file=sys.stderr)
        return 2
    from app_share import public_base_url
    try:
        user, code = operator_reset_link(argv[1])
    except RecoveryError as ex:
        print(ex.detail, file=sys.stderr)
        return 1
    conn = sqlite3.connect(DB_PATH)
    try:
        email, phone = verified_email(conn, user), bool(_phone_hash_of(conn, user))
    finally:
        conn.close()
    if email or phone:
        print(f"Note: @{user} can reset it themselves at /reset with their verified "
              f"{'phone' if phone else 'email'}.")
    hours = int(OPERATOR_TTL.total_seconds() // 3600)
    print(f"Reset link for @{user} (works once, for {hours} hours; earlier operator links no longer work):")
    print(f"{public_base_url()}/reset/set?f={code}")
    print("Send it to them privately, only after confirming it's really them: anyone with the link can set "
          "the password. Their recovery code still decides whether their wallets come back.")
    return 0


if __name__ == "__main__":
    import sys
    raise SystemExit(_cli(sys.argv[1:]))
