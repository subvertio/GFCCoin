"""
Discord verification: the GFC Discord server's "Verified GFC" role, for phone-verified GFC
accounts only (the same check GFC Connect gives partner sites: app_connect.member_status).

1. In the GFC app the member opens Link Discord: POST /discord/code (a full-scope session from
   /auth/login) gives a one-time code like GFC-7Q4K-2M9X, valid CODE_TTL. Only accounts with a
   verified phone get one.
2. In the GFC Discord server they run /verify CODE (in #how-to-verify).
3. Discord sends the command to POST /discord/interactions, signed with the application's
   Ed25519 key. The node checks the signature, the server, the code and the account, links that
   Discord user to that GFC account (one to one), and grants the Verified GFC role through
   Discord's REST API with the bot token. The reply is ephemeral: only the member sees it.

No bot process runs: Discord calls the node, and the node calls Discord. The bot only ever
adds or removes the one configured role on the one configured server.

- POST /discord/code (full scope)        -> {code, expiresIn} | 403 not verified | 409 already linked
- GET  /discord/status (read scope)      -> {available, linked, discordName?, linkedAt?, role?}
- POST /discord/unlink (full scope)      -> the link ends and the role is removed
- POST /discord/interactions             Discord's signed requests (PING, /verify)

Unlinking (by the member, or `python -m app_discord unlink USER` by an operator) ends the link
and removes the role. A background pass (RECONCILE_EVERY) retries role changes that failed
(Discord down, rate limited) and removes the role from links whose account is no longer phone
verified. Removing the role in Discord by hand doesn't end the link: the next pass grants it
again, so use unlink.

Settings (in /etc/gfc/gfc.env, never in the repo): GFC_DISCORD_PUBLIC_KEY (the application's
public key, hex), GFC_DISCORD_APP_ID, GFC_DISCORD_BOT_TOKEN, GFC_DISCORD_GUILD_ID,
GFC_DISCORD_ROLE_ID, and optionally GFC_DISCORD_VERIFY_CHANNEL_ID (refuse /verify elsewhere)
and GFC_DISCORD_LOG_CHANNEL_ID (outcomes for moderators; never codes). Setup: docs/discord.md.
"""

import datetime
import hashlib
import json
import logging
import os
import sqlite3
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Dict, List, Optional

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

import app_connect
from config import DB_PATH
from security import Caller, caller_from_form, caller_from_query

router = APIRouter()
logger = logging.getLogger("gfc.discord")

CODE_TTL = datetime.timedelta(minutes=10)
CODES_PER_USER_PER_HOUR = 10
FAILED_TRIES_PER_DISCORD_USER = 5        # wrong or expired codes per FAILED_WINDOW, then wait
FAILED_WINDOW = 15 * 60
COMMANDS_PER_MINUTE = 60                 # all /verify calls together
SIGNATURE_MAX_AGE = 300                  # seconds: older signed requests are replays
RECONCILE_EVERY = 300
API = "https://discord.com/api/v10"
HTTP_TIMEOUT = 2.0                       # Discord wants an answer within 3 s

# Link role states. Active links: pending (grant not done yet), granted, left (not on the server
# any more: granted again by the next pass if they come back). Ended links: removing, removed.
PENDING, GRANTED, LEFT, REMOVING, REMOVED = "pending", "granted", "left", "removing", "removed"

EPHEMERAL = 64

_rate_lock = threading.Lock()
_failed: Dict[str, deque] = {}
_commands: deque = deque()


@dataclass(frozen=True)
class Settings:
    public_key: str
    app_id: str
    bot_token: str
    guild_id: str
    role_id: str
    verify_channel_id: str = ""
    log_channel_id: str = ""


def settings() -> Optional[Settings]:
    """The Discord settings, or None until all the required ones are set."""
    e = os.environ
    s = Settings(public_key=e.get("GFC_DISCORD_PUBLIC_KEY", "").strip(), app_id=e.get("GFC_DISCORD_APP_ID", "").strip(),
                 bot_token=e.get("GFC_DISCORD_BOT_TOKEN", "").strip(), guild_id=e.get("GFC_DISCORD_GUILD_ID", "").strip(),
                 role_id=e.get("GFC_DISCORD_ROLE_ID", "").strip(),
                 verify_channel_id=e.get("GFC_DISCORD_VERIFY_CHANNEL_ID", "").strip(),
                 log_channel_id=e.get("GFC_DISCORD_LOG_CHANNEL_ID", "").strip())
    if not (len(s.public_key) == 64 and s.app_id.isdigit() and s.bot_token and s.guild_id.isdigit()
            and s.role_id.isdigit()):
        return None
    return s


def init_tables(conn: sqlite3.Connection):
    conn.execute("""CREATE TABLE IF NOT EXISTS discord_codes (
        code_hash TEXT PRIMARY KEY,
        username TEXT NOT NULL,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        used_at TEXT
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_discord_codes_user ON discord_codes(username, created_at)")
    conn.execute("""CREATE TABLE IF NOT EXISTS discord_links (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        discord_user_id TEXT NOT NULL,
        discord_name TEXT NOT NULL DEFAULT '',
        guild_id TEXT NOT NULL,
        linked_at TEXT NOT NULL,
        role_state TEXT NOT NULL,
        role_checked_at TEXT,
        ended_at TEXT,
        end_reason TEXT
    )""")
    # One live link per GFC account and per Discord user; ended links stay as history
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_discord_live_user ON discord_links(username) "
                 "WHERE ended_at IS NULL")
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_discord_live_member ON discord_links(discord_user_id) "
                 "WHERE ended_at IS NULL")


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, isolation_level=None, timeout=10)
    init_tables(conn)
    return conn


def _verified(conn: sqlite3.Connection, username: str) -> bool:
    status = app_connect.member_status(conn, username)
    return bool(status and status["confirmed"] and status["memberId"] == username)


def live_link(conn: sqlite3.Connection, *, username: str = "", discord_user_id: str = "") -> Optional[dict]:
    col, val = ("username", username) if username else ("discord_user_id", discord_user_id)
    row = conn.execute(f"SELECT id, username, discord_user_id, discord_name, linked_at, role_state FROM discord_links "
                       f"WHERE {col} = ? AND ended_at IS NULL", (val,)).fetchone()
    if not row:
        return None
    return dict(zip(("id", "username", "discord_user_id", "discord_name", "linked_at", "role_state"), row))


# ---------------------------------------------------------------- Discord REST (one role only)

class DiscordError(Exception):
    pass


class DiscordClient:
    """The bot's only powers: add or remove the configured role, and post to the log channel."""

    def __init__(self, s: Settings):
        self.s = s

    def _call(self, method: str, path: str, **kw) -> httpx.Response:
        headers = {"Authorization": f"Bot {self.s.bot_token}",
                   "User-Agent": "DiscordBot (https://github.com/subvertio/GFCCoin, 1)"}
        headers.update(kw.pop("headers", {}))
        try:
            return httpx.request(method, API + path, headers=headers, timeout=HTTP_TIMEOUT, **kw)
        except httpx.HTTPError as e:
            raise DiscordError(f"Discord unreachable: {type(e).__name__}") from None

    def set_role(self, discord_user_id: str, on: bool, reason: str) -> str:
        """GRANTED/REMOVED, LEFT if they aren't on the server; DiscordError otherwise (retried later)."""
        path = f"/guilds/{self.s.guild_id}/members/{discord_user_id}/roles/{self.s.role_id}"
        r = self._call("PUT" if on else "DELETE", path, headers={"X-Audit-Log-Reason": reason[:400]})
        if r.status_code == 204:
            return GRANTED if on else REMOVED
        if r.status_code == 404 and _discord_code(r) == 10007:  # Unknown Member
            return LEFT
        raise DiscordError(f"role {'grant' if on else 'removal'} failed: HTTP {r.status_code} {_discord_code(r) or ''}".strip())

    def log(self, text: str):
        if not self.s.log_channel_id:
            return
        try:
            self._call("POST", f"/channels/{self.s.log_channel_id}/messages",
                       json={"content": text[:1900], "allowed_mentions": {"parse": []}})
        except DiscordError as e:
            logger.warning(f"Discord log message not sent: {e}")


def _discord_code(r: httpx.Response) -> Optional[int]:
    try:
        return int(r.json().get("code"))
    except Exception:
        return None


def client() -> Optional[DiscordClient]:
    s = settings()
    return DiscordClient(s) if s else None


# ---------------------------------------------------------------- the member's side (GFC app)

@router.post("/discord/code")
def make_code(caller: Caller = Depends(caller_from_form)):
    """A one-time code to type into /verify in the GFC Discord server."""
    username = caller.require_full()  # a limited api token can't tie the account to someone's Discord
    if not settings():
        return JSONResponse({"detail": "Discord verification isn't switched on yet."}, status_code=503)
    now = _now()
    conn = _connect()
    try:
        if not _verified(conn, username):
            return JSONResponse({"detail": "Verify your phone in Wallet first: Discord access is for "
                                           "phone-verified GFC accounts."}, status_code=403)
        conn.execute("BEGIN IMMEDIATE")
        link = live_link(conn, username=username)
        if link:
            conn.execute("ROLLBACK")
            return JSONResponse({"detail": f"This account is already linked to Discord ({link['discord_name'] or 'a member'}). "
                                           "Unlink it first to link another Discord account."}, status_code=409)
        recent = conn.execute("SELECT COUNT(*) FROM discord_codes WHERE username = ? AND created_at > ?",
                              (username, (now - datetime.timedelta(hours=1)).isoformat())).fetchone()[0]
        if recent >= CODES_PER_USER_PER_HOUR:
            conn.execute("ROLLBACK")
            return JSONResponse({"detail": "Too many codes this hour. Try again later."}, status_code=429)
        # One live code per account: a new one replaces the old
        conn.execute("UPDATE discord_codes SET used_at = ? WHERE username = ? AND used_at IS NULL",
                     (now.isoformat(), username))
        code = app_connect._new_code()
        conn.execute("INSERT INTO discord_codes (code_hash, username, created_at, expires_at) VALUES (?, ?, ?, ?)",
                     (app_connect._hash(code), username, now.isoformat(), (now + CODE_TTL).isoformat()))
        conn.execute("COMMIT")
    finally:
        conn.close()
    return {"code": code, "expiresIn": int(CODE_TTL.total_seconds())}


@router.get("/discord/status")
def status(caller: Caller = Depends(caller_from_query)):
    username = caller.require("read")
    conn = _connect()
    try:
        link = live_link(conn, username=username)
        verified = _verified(conn, username)
    finally:
        conn.close()
    out = {"available": settings() is not None, "phoneVerified": verified, "linked": bool(link)}
    if link:
        out.update(discordName=link["discord_name"], linkedAt=app_connect._iso_z(link["linked_at"]),
                   role=link["role_state"])
    return out


@router.post("/discord/unlink")
def unlink_me(caller: Caller = Depends(caller_from_form)):
    username = caller.require_full()
    ended = end_link(username, "unlinked by the member")
    return {"unlinked": ended}


def end_link(username: str, reason: str) -> bool:
    """End the account's live link (if any) and take the role away now, or on the next pass."""
    conn = _connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        link = live_link(conn, username=username)
        if not link:
            conn.execute("ROLLBACK")
            return False
        conn.execute("UPDATE discord_links SET ended_at = ?, end_reason = ?, role_state = ? WHERE id = ?",
                     (_now().isoformat(), reason, REMOVING, link["id"]))
        conn.execute("COMMIT")
    finally:
        conn.close()
    dc = client()
    if dc:
        _apply(dc, link["id"], link["discord_user_id"], on=False, reason=f"GFC: {reason}")
        dc.log(f"Unlinked: <@{link['discord_user_id']}> from GFC account `{username}` ({reason}).")
    return True


# ---------------------------------------------------------------- Discord's side (/verify)

def _signature_ok(s: Settings, signature: str, timestamp: str, body: bytes) -> bool:
    try:
        if abs(time.time() - int(timestamp)) > SIGNATURE_MAX_AGE:
            return False
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(s.public_key)).verify(
            bytes.fromhex(signature), timestamp.encode() + body)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def _reply(text: str) -> dict:
    return {"type": 4, "data": {"content": text, "flags": EPHEMERAL, "allowed_mentions": {"parse": []}}}


def _allow_command() -> bool:
    now = time.monotonic()
    with _rate_lock:
        while _commands and now - _commands[0] > 60:
            _commands.popleft()
        if len(_commands) >= COMMANDS_PER_MINUTE:
            return False
        _commands.append(now)
        return True


def _failures(discord_user_id: str, add: bool = False) -> int:
    now = time.monotonic()
    with _rate_lock:
        q = _failed.setdefault(discord_user_id, deque())
        while q and now - q[0] > FAILED_WINDOW:
            q.popleft()
        if add:
            q.append(now)
        return len(q)


@router.post("/discord/interactions")
async def interactions(request: Request):
    s = settings()
    if not s:
        return JSONResponse({"error": "not_configured"}, status_code=503)
    body = await request.body()
    if not _signature_ok(s, request.headers.get("X-Signature-Ed25519", ""),
                         request.headers.get("X-Signature-Timestamp", ""), body):
        return JSONResponse({"error": "invalid request signature"}, status_code=401)
    try:
        it = json.loads(body)
    except ValueError:
        return JSONResponse({"error": "bad json"}, status_code=400)
    if it.get("type") == 1:  # PING: Discord checking the endpoint
        return {"type": 1}
    if it.get("type") != 2 or (it.get("data") or {}).get("name") != "verify":
        return _reply("Unknown command.")
    return await run_in_threadpool(handle_verify, s, it)  # database and Discord calls block


def handle_verify(s: Settings, it: dict) -> dict:
    member = it.get("member") or {}
    user = member.get("user") or {}
    discord_id = str(user.get("id") or "")
    if it.get("guild_id") != s.guild_id or not discord_id.isdigit():
        return _reply("This command only works in the GFC Discord server.")
    if s.verify_channel_id and it.get("channel_id") != s.verify_channel_id:
        return _reply(f"Use /verify in <#{s.verify_channel_id}>.")
    if not _allow_command():
        return _reply("Lots of people are verifying right now. Please try again in a minute.")
    if _failures(discord_id) >= FAILED_TRIES_PER_DISCORD_USER:
        return _reply("Too many wrong codes. Wait 15 minutes, then get a new code in the GFC app.")
    options = (it.get("data") or {}).get("options") or []
    raw = next((o.get("value") for o in options if o.get("name") == "code"), "")
    name = (user.get("global_name") or user.get("username") or "")[:64]
    outcome, username, link_id = redeem(app_connect.normalize(str(raw or "")), discord_id, name, s.guild_id)
    dc = DiscordClient(s)
    if outcome != "linked":
        if outcome in ("invalid", "not_verified"):
            _failures(discord_id, add=True)
        dc.log(f"/verify by <@{discord_id}>: {outcome.replace('_', ' ')}.")
        return _reply({
            "invalid": "That code isn't valid or has expired. Get a new one in the GFC app: Wallet → Link Discord.",
            "not_verified": "That GFC account doesn't have a verified phone yet. Verify it in the app, then get a new code.",
            "account_taken": "That GFC account is already linked to another Discord account.",
            "member_taken": "Your Discord account is already linked to a GFC account. Unlink it in the GFC app first.",
        }.get(outcome, "Something went wrong. Please try again."))
    state = _apply(dc, link_id, discord_id, on=True, reason=f"GFC: phone-verified account {username}")
    dc.log(f"Verified: <@{discord_id}> is GFC account `{username}`" + ("" if state == GRANTED else f" (role {state})") + ".")
    if state == GRANTED:
        return _reply(f"You're verified as GFC member **{username}**. Welcome! The community channels are open to you now.")
    return _reply(f"Linked to GFC member **{username}**. Discord didn't take the role change right now: "
                  "it'll be added within a few minutes.")


def redeem(code: str, discord_id: str, discord_name: str, guild_id: str):
    """Use a code for this Discord user, all or nothing: (outcome, username, link id)."""
    now = _now()
    conn = _connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT username, expires_at, used_at FROM discord_codes WHERE code_hash = ?",
                           (app_connect._hash(code),)).fetchone() if code else None
        if not row or row[2] or row[1] <= now.isoformat():
            conn.execute("ROLLBACK")
            return "invalid", None, None
        username = row[0]
        if not _verified(conn, username):
            conn.execute("ROLLBACK")
            return "not_verified", None, None
        mine = live_link(conn, discord_user_id=discord_id)
        if mine and mine["username"] != username:
            conn.execute("ROLLBACK")
            return "member_taken", None, None
        theirs = live_link(conn, username=username)
        if theirs and theirs["discord_user_id"] != discord_id:
            conn.execute("ROLLBACK")
            return "account_taken", None, None
        conn.execute("UPDATE discord_codes SET used_at = ? WHERE code_hash = ?", (now.isoformat(), app_connect._hash(code)))
        if theirs:  # the same pair again: already linked, just make sure of the role
            link_id = theirs["id"]
        else:
            link_id = conn.execute(
                "INSERT INTO discord_links (username, discord_user_id, discord_name, guild_id, linked_at, role_state) "
                "VALUES (?, ?, ?, ?, ?, ?)", (username, discord_id, discord_name, guild_id, now.isoformat(), PENDING)).lastrowid
        conn.execute("COMMIT")
        return "linked", username, link_id
    except sqlite3.IntegrityError:  # a concurrent redemption won the race
        conn.execute("ROLLBACK")
        return "invalid", None, None
    finally:
        conn.close()


def _apply(dc: DiscordClient, link_id: int, discord_id: str, on: bool, reason: str) -> str:
    """Try the role change now and record the result; on failure the state stays for the next pass."""
    conn = _connect()
    try:
        if not on and live_link(conn, discord_user_id=discord_id):
            state = REMOVED  # this Discord user has a live link again: keep the role
        else:
            try:
                state = dc.set_role(discord_id, on, reason)
            except DiscordError as e:
                logger.warning(f"Discord link {link_id}: {e}")
                return PENDING if on else REMOVING
            if not on and state == LEFT:
                state = REMOVED
        conn.execute("UPDATE discord_links SET role_state = ?, role_checked_at = ? WHERE id = ?",
                     (state, _now().isoformat(), link_id))
        return state
    finally:
        conn.close()


# ---------------------------------------------------------------- keeping Discord in step

def reconcile(dc: Optional[DiscordClient] = None) -> Dict[str, int]:
    """Retry failed role changes, and end links whose account is no longer phone verified."""
    dc = dc or client()
    counts = {"granted": 0, "removed": 0, "ended": 0, "failed": 0}
    if not dc:
        return counts
    conn = _connect()
    try:
        live = conn.execute("SELECT id, username, discord_user_id, role_state FROM discord_links "
                            "WHERE ended_at IS NULL").fetchall()
        lost = [r for r in live if not _verified(conn, r[1])]
        todo_off = conn.execute("SELECT id, discord_user_id FROM discord_links "
                                "WHERE ended_at IS NOT NULL AND role_state = ?", (REMOVING,)).fetchall()
    finally:
        conn.close()
    for link_id, username, _did, _state in lost:
        if end_link(username, "the account is no longer phone verified"):
            counts["ended"] += 1
    lost_ids = {r[0] for r in lost}
    for link_id, username, did, state in live:
        if link_id in lost_ids or state == GRANTED:
            continue
        new = _apply(dc, link_id, did, on=True, reason=f"GFC: phone-verified account {username}")
        if new == GRANTED:
            counts["granted"] += 1
        elif new == PENDING:
            counts["failed"] += 1
    for link_id, did in todo_off:
        new = _apply(dc, link_id, did, on=False, reason="GFC: link ended")
        counts["removed" if new == REMOVED else "failed"] += 1
    return counts


def start_reconciler(every: float = RECONCILE_EVERY) -> Optional[threading.Thread]:
    if not settings():
        return None

    def loop():
        while True:
            try:
                c = reconcile()
                if any(c.values()):
                    logger.info(f"Discord reconcile: {c}")
            except Exception as e:  # keep going: the next pass retries
                logger.warning(f"Discord reconcile failed: {e}")
            time.sleep(every)

    t = threading.Thread(target=loop, daemon=True, name="discord-reconcile")
    t.start()
    return t


# ---------------------------------------------------------------- operator commands

COMMAND = {
    "name": "verify",
    "type": 1,
    "description": "Link your phone-verified GFC account to get the Verified GFC role",
    "options": [{"type": 3, "name": "code", "description": "The one-time code from the GFC app (Wallet → Link Discord)",
                 "required": True, "min_length": 8, "max_length": 20}],
    "contexts": [0],          # servers only, never DMs
    "integration_types": [0],
}


def _admin_settings() -> Settings:
    s = settings()
    if not s:
        sys.exit("Set GFC_DISCORD_PUBLIC_KEY, GFC_DISCORD_APP_ID, GFC_DISCORD_BOT_TOKEN, GFC_DISCORD_GUILD_ID and "
                 "GFC_DISCORD_ROLE_ID first (GFC_DISCORD_ROLE_ID=0 while discovering ids with 'ids').")
    return s


def main(argv: List[str]) -> int:
    """
    python -m app_discord ids        the server's roles and channels, with their ids (to fill the settings)
    python -m app_discord register   create/update the /verify command on the server
    python -m app_discord links      live links (GFC account, Discord id, role state)
    python -m app_discord unlink USERNAME [reason]
    python -m app_discord reconcile  one pass now
    """
    cmd = argv[0] if argv else ""
    if cmd == "ids":
        e = os.environ
        token, guild = e.get("GFC_DISCORD_BOT_TOKEN", "").strip(), e.get("GFC_DISCORD_GUILD_ID", "").strip()
        if not token or not guild.isdigit():
            sys.exit("Set GFC_DISCORD_BOT_TOKEN and GFC_DISCORD_GUILD_ID first.")
        dc = DiscordClient(Settings("", "", token, guild, ""))
        roles = dc._call("GET", f"/guilds/{guild}/roles")
        chans = dc._call("GET", f"/guilds/{guild}/channels")
        if roles.status_code != 200 or chans.status_code != 200:
            sys.exit(f"Discord refused: roles HTTP {roles.status_code}, channels HTTP {chans.status_code} "
                     "(is the bot on the server?)")
        print("Roles (highest first):")
        for r in sorted(roles.json(), key=lambda r: -r["position"]):
            print(f"  {r['id']}  {r['name']}" + ("  [managed by an integration]" if r.get("managed") else ""))
        print("Channels:")
        for c in sorted(chans.json(), key=lambda c: (c.get("parent_id") or "", c["position"])):
            print(f"  {c['id']}  {'#' if c['type'] == 0 else ''}{c['name']}  (type {c['type']})")
        return 0
    s = _admin_settings()
    if cmd == "register":
        r = DiscordClient(s)._call("PUT", f"/applications/{s.app_id}/guilds/{s.guild_id}/commands", json=[COMMAND])
        print("registered /verify" if r.status_code == 200 else f"failed: HTTP {r.status_code} {r.text[:300]}")
        return 0 if r.status_code == 200 else 1
    if cmd == "links":
        conn = _connect()
        for row in conn.execute("SELECT username, discord_user_id, discord_name, linked_at, role_state "
                                "FROM discord_links WHERE ended_at IS NULL ORDER BY linked_at"):
            print("  ".join(str(x) for x in row))
        conn.close()
        return 0
    if cmd == "unlink" and len(argv) >= 2:
        print("unlinked" if end_link(argv[1], " ".join(argv[2:]) or "unlinked by an operator") else "no live link")
        return 0
    if cmd == "reconcile":
        print(reconcile())
        return 0
    print(main.__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
