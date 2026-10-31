"""
GFC Connect: let a partner site (e.g. creator-world.org) require a confirmed GFC account
(phone verified) at sign-up, without the member ever giving it their GFC password or token.

1. In the GFC app the member opens Connect another site, picks the partner, and the app
   calls POST /connect/code: a one-time code like GFC-7Q4K-2M9X, valid CODE_TTL, for that
   partner only.
2. The member pastes it into the partner's sign-up form.
3. The partner's server calls POST /connect/verify with its partner key: GFC answers with
   the member id (the GFC username) and whether the account is phone verified, and the code
   is used up.

- GET  /connect/partners                the partner sites (for the app's list)
- POST /connect/code (read scope)       form: partner -> {code, partner, name, expiresIn}
- POST /connect/verify (partner key)    {code} -> {confirmed, memberId, verifiedAt | reason}
- GET  /members/{username}              {memberId, confirmed, verifiedAt}: display only, not proof

Partners come from GFC_PARTNERS (in /etc/gfc/gfc.env, never in the repo):
    GFC_PARTNERS=creator-world.org=Creator World:<key>
(id=Display name:key, comma-separated; the name is optional). The key is the partner's
Bearer token; only its hash is compared. Phone numbers and emails never leave the node:
a partner learns the username and when the phone was verified.
"""

import datetime
import hashlib
import hmac
import os
import secrets
import sqlite3
import threading
import time
from collections import deque
from typing import Dict, Optional

from fastapi import APIRouter, Body, Depends, Form, Header, HTTPException
from fastapi.responses import JSONResponse

import phone_verify
from config import DB_PATH
from security import Caller, caller_from_form

router = APIRouter()

CODE_TTL = datetime.timedelta(minutes=15)
CODE_ALPHABET = "23456789ABCDEFGHJKMNPQRSTUVWXYZ"   # no 0/O, 1/I/L
CODES_PER_USER_PER_HOUR = 10
VERIFY_PER_PARTNER_PER_MINUTE = 30

_rate_lock = threading.Lock()
_verify_calls: Dict[str, deque] = {}


def partners() -> Dict[str, dict]:
    """{id: {"name", "key_hash"}} from GFC_PARTNERS."""
    out = {}
    for entry in os.environ.get("GFC_PARTNERS", "").split(","):
        entry = entry.strip()
        if not entry or ":" not in entry:
            continue
        ident, key = entry.rsplit(":", 1)
        ident, _, name = ident.partition("=")
        ident, key = ident.strip().lower(), key.strip()
        if ident and len(key) >= 24:  # a short key is a mistake, not a partner
            out[ident] = {"name": name.strip() or ident, "key_hash": hashlib.sha256(key.encode()).hexdigest()}
    return out


def init_tables(conn: sqlite3.Connection):
    conn.execute("""CREATE TABLE IF NOT EXISTS connect_codes (
        code_hash TEXT PRIMARY KEY,
        username TEXT NOT NULL,
        partner TEXT NOT NULL,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        used_at TEXT
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_connect_codes_user ON connect_codes(username, created_at)")


def _hash(code: str) -> str:
    return hashlib.sha256(code.encode()).hexdigest()


def normalize(code: str) -> str:
    """'gfc 7q4k-2m9x' -> 'GFC-7Q4K-2M9X' (people retype codes)."""
    raw = "".join(ch for ch in (code or "").upper() if ch.isalnum())
    if raw.startswith("GFC"):
        raw = raw[3:]
    return f"GFC-{raw[:4]}-{raw[4:]}" if len(raw) == 8 else ""


def _new_code() -> str:
    body = "".join(secrets.choice(CODE_ALPHABET) for _ in range(8))
    return f"GFC-{body[:4]}-{body[4:]}"


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _iso_z(value: str) -> str:
    """Stored UTC times (naive or with an offset) as ...Z."""
    try:
        t = datetime.datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return value or ""
    if t.tzinfo:
        t = t.astimezone(datetime.timezone.utc).replace(tzinfo=None)
    return t.replace(microsecond=0).isoformat() + "Z"


def member_status(conn: sqlite3.Connection, username: str) -> Optional[dict]:
    """{memberId, confirmed, verifiedAt?} for an account, or None if there's no such account."""
    rows = conn.execute("SELECT username FROM users WHERE username = ?", (username,)).fetchall() or \
        conn.execute("SELECT username FROM users WHERE LOWER(username) = LOWER(?)", (username,)).fetchall()
    if len(rows) != 1:
        return None  # none, or old case variants ("Bob" and "bob"): no guessing
    member = rows[0][0]
    phone_verify.init_phone_tables(conn)
    row = conn.execute("SELECT verified_at FROM phone_verifications WHERE username = ?", (member,)).fetchone()
    out = {"memberId": member, "confirmed": bool(row)}
    if row:
        out["verifiedAt"] = _iso_z(row[0])
    return out


@router.get("/connect/partners")
def list_partners():
    return {"partners": [{"id": k, "name": v["name"]} for k, v in sorted(partners().items())]}


@router.post("/connect/code")
def make_code(partner: str = Form(...), caller: Caller = Depends(caller_from_form)):
    """A one-time code for the logged-in member to paste into a partner site's sign-up."""
    username = caller.require("read")
    partner = (partner or "").strip().lower()
    known = partners()
    if partner not in known:
        raise HTTPException(status_code=404, detail="That site isn't connected to GFC.")
    now = _now()
    conn = sqlite3.connect(DB_PATH, isolation_level=None)
    try:
        init_tables(conn)
        conn.execute("BEGIN IMMEDIATE")
        recent = conn.execute("SELECT COUNT(*) FROM connect_codes WHERE username = ? AND created_at > ?",
                              (username, (now - datetime.timedelta(hours=1)).isoformat())).fetchone()[0]
        if recent >= CODES_PER_USER_PER_HOUR:
            conn.execute("ROLLBACK")
            raise HTTPException(status_code=429, detail="Too many codes this hour. Try again later.")
        # One live code per member and partner: a new one replaces the old
        conn.execute("UPDATE connect_codes SET used_at = ? WHERE username = ? AND partner = ? AND used_at IS NULL",
                     (now.isoformat(), username, partner))
        code = _new_code()
        conn.execute("INSERT INTO connect_codes (code_hash, username, partner, created_at, expires_at) VALUES (?, ?, ?, ?, ?)",
                     (_hash(code), username, partner, now.isoformat(), (now + CODE_TTL).isoformat()))
        conn.execute("COMMIT")
    finally:
        conn.close()
    return {"code": code, "partner": partner, "name": known[partner]["name"], "expiresIn": int(CODE_TTL.total_seconds())}


def _partner_from(authorization: str, partner_header: str) -> str:
    """The partner whose key this is (401 otherwise). The X-GFC-Partner header must name it."""
    key = authorization[7:].strip() if authorization.lower().startswith("bearer ") else ""
    pid = (partner_header or "").strip().lower()
    p = partners().get(pid)
    if not key or not p or not hmac.compare_digest(p["key_hash"], hashlib.sha256(key.encode()).hexdigest()):
        raise HTTPException(status_code=401, detail="Unknown partner or wrong partner key.")
    return pid


def _rate_ok(pid: str) -> bool:
    now = time.monotonic()
    with _rate_lock:
        calls = _verify_calls.setdefault(pid, deque())
        while calls and now - calls[0] > 60:
            calls.popleft()
        if len(calls) >= VERIFY_PER_PARTNER_PER_MINUTE:
            return False
        calls.append(now)
        return True


@router.post("/connect/verify")
def verify_code(code: str = Body(..., embed=True), authorization: str = Header(""),
                x_gfc_partner: str = Header("")):
    """For partner servers: who a code belongs to, and whether that account is phone verified. Single use."""
    pid = _partner_from(authorization, x_gfc_partner)
    if not _rate_ok(pid):
        return JSONResponse({"error": "rate_limited"}, status_code=429)
    normal = normalize(code)
    now = _now()
    conn = sqlite3.connect(DB_PATH, isolation_level=None)
    try:
        init_tables(conn)
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT username, partner, expires_at, used_at FROM connect_codes WHERE code_hash = ?",
                           (_hash(normal),)).fetchone() if normal else None
        if not row or row[1] != pid or row[3] or row[2] <= now.isoformat():
            conn.execute("ROLLBACK")
            return JSONResponse({"error": "invalid_or_expired_code"}, status_code=404)
        conn.execute("UPDATE connect_codes SET used_at = ? WHERE code_hash = ?", (now.isoformat(), _hash(normal)))
        conn.execute("COMMIT")
        status = member_status(conn, row[0])
    finally:
        conn.close()
    if not status:
        return JSONResponse({"error": "invalid_or_expired_code"}, status_code=404)
    if not status["confirmed"]:
        return {"confirmed": False, "memberId": status["memberId"], "reason": "phone_not_verified"}
    return status


@router.get("/members/{username}")
def member(username: str):
    """Public: whether an account is phone verified, for showing a badge. Not proof of who's signing up."""
    conn = sqlite3.connect(DB_PATH)
    try:
        status = member_status(conn, username)
    finally:
        conn.close()
    if not status:
        return JSONResponse({"error": "not_found"}, status_code=404)
    return status
