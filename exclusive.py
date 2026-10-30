"""
GFC Exclusives - videos and text posts that are only for real GFC accounts

A poster can mark a video or a text post "Exclusive to GFC Network" when uploading
(exclusive=true).

Text posts (a .txt seed whose description holds the text): only the title is public.
Feed/seed JSON, the web feed, share pages, X cards and the edit history leave the body
out; GET /seeds/{id}/play returns it (`text`) to accounts that may watch. The .txt file
itself is locked like a video's full clip.

Videos:

- The node cuts a teaser of the poster's chosen length (TEASER_LENGTHS: 5, 10 or 30 s,
  default 5) with ffmpeg, served publicly at
  /teasers/<seed_id>.mp4: the web feed, share pages and X show it.
- The full clip (/originals/<file> and its /streams/ copy) is locked: those URLs only
  open with a short-lived link signed by this node (?exp=...&sig=..., HMAC-SHA256 with a
  per-node secret), which GET /seeds/{id}/play hands out to accounts that may watch:
  phone-verified accounts on the real network (any logged-in account on a test net),
  and the poster.
- Feed and seed JSON for an exclusive post has "exclusive": true and "teaser", and its
  "full"/"stream" point at the teaser. Apps that don't know about exclusives play the
  teaser instead of failing; apps that do call /play for the full clip.
- The flag syncs with the seed. Peers run the same code, so they lock the clip too
  and make their own teaser when the file arrives.
"""

import datetime
import hashlib
import hmac
import os
import secrets
import sqlite3
import threading
import time
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional
from urllib.parse import quote, unquote

import audio_stream
import config
import phone_verify
from config import DATA_DIR, DB_PATH, SEEDS_ORIG_DIR

TEASER_SECONDS = 5                 # the default
TEASER_LENGTHS = (5, 10, 30)       # what a poster can pick
TEASERS_DIR = DATA_DIR / "seeds" / "teasers"
TEASERS_DIR.mkdir(parents=True, exist_ok=True)
URL_TTL_S = 6 * 3600          # long enough to finish a clip; links are re-fetched after
TEASER_TIMEOUT_S = 5 * 60
KEY_FILE = DATA_DIR / "media_url_key.hex"
GATED_PREFIXES = ("/originals/", "/streams/")
TEXT_EXTENSION = ".txt"
LOCKED_DETAIL = "This clip is exclusive to the GFC Network: log in to the GFC app with a verified account to watch it."

# Tests replace this; the default runs ffmpeg. Called as runner(src, dest).
Runner = Callable[[Path, Path, int], None]  # (source, teaser, seconds)

_key_lock = threading.Lock()
_key: Optional[bytes] = None


def init_tables(conn: sqlite3.Connection):
    for table in ("seeds", "seed_quarantine"):
        for column in ("exclusive INTEGER DEFAULT 0", f"teaser_seconds INTEGER DEFAULT {TEASER_SECONDS}"):
            try:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {column}")
            except sqlite3.OperationalError:
                pass  # column exists, or the table doesn't yet (quarantine is created on demand)


def seconds_of(conn: sqlite3.Connection, seed_id: str) -> int:
    """The teaser length the poster picked (a synced value outside TEASER_LENGTHS falls back to 5)."""
    try:
        row = conn.execute("SELECT teaser_seconds FROM seeds WHERE id = ?", (seed_id,)).fetchone()
    except sqlite3.Error:
        return TEASER_SECONDS
    return row[0] if row and row[0] in TEASER_LENGTHS else TEASER_SECONDS


def is_exclusive(conn: sqlite3.Connection, seed_id: str) -> bool:
    row = conn.execute("SELECT exclusive FROM seeds WHERE id = ?", (seed_id,)).fetchone()
    return bool(row and row[0])


def is_text_file(filename: str) -> bool:
    return (filename or "").lower().endswith(TEXT_EXTENSION)


def can_be_exclusive(filename: str, content_type: str) -> bool:
    """Videos, text posts and downloads (zips: only real accounts can download them)."""
    import filescan
    return content_type == "video" or is_text_file(filename) or filescan.is_download(filename)


# ---------- teasers ----------

def teaser_path(seed_id: str) -> Path:
    safe = "".join(c for c in seed_id if c.isalnum() or c in "-_")
    if not safe or safe != seed_id:
        raise ValueError("bad seed id")
    return TEASERS_DIR / f"{safe}.mp4"


def teaser_url(seed_id: str) -> Optional[str]:
    try:
        path = teaser_path(seed_id)
    except ValueError:
        return None
    return f"/teasers/{path.name}" if path.exists() else None


def run_teaser_ffmpeg(src: Path, dest: Path, seconds: int = TEASER_SECONDS) -> None:
    """The streaming-copy settings (upright, <=720p, H.264/AAC, faststart), first `seconds` only."""
    exe = audio_stream.ffmpeg_path()
    if not exe:
        raise FileNotFoundError("ffmpeg not installed")
    args = audio_stream._ffmpeg_args("video", src, dest, exe)
    out = args.index("-f")  # output options go before the output file
    args[out:out] = ["-t", str(seconds)]
    import subprocess
    subprocess.run(args, check=True, timeout=TEASER_TIMEOUT_S, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)


def make_teaser(seed_id: str, filename: str, runner: Runner = None, seconds: Optional[int] = None,
                db_path: str = DB_PATH) -> bool:
    """Cut the teaser now (synchronously). True if it exists afterwards. Length: the post's choice."""
    if seconds not in TEASER_LENGTHS:
        conn = sqlite3.connect(db_path)
        try:
            seconds = seconds_of(conn, seed_id)
        finally:
            conn.close()
    dest = teaser_path(seed_id)
    if dest.exists():
        return True
    src = SEEDS_ORIG_DIR / filename
    if not src.is_file():
        return False
    tmp = dest.with_name(dest.name + ".part")
    try:
        (runner or run_teaser_ffmpeg)(src, tmp, seconds)
        if not tmp.is_file() or tmp.stat().st_size == 0:
            raise RuntimeError("no output")
        os.replace(tmp, dest)
        return True
    except Exception as ex:
        print(f"[Exclusive] {seed_id}: teaser failed: {type(ex).__name__}")
        return False
    finally:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass


def make_teaser_later(seed_id: str, filename: str):
    """In the background (e.g. when a synced file arrives)."""
    threading.Thread(target=make_teaser, args=(seed_id, filename), name="gfc-teaser", daemon=True).start()


def backfill(db_path: str = DB_PATH) -> int:
    """Teasers for exclusive posts that don't have one (a failed cut, or a synced post). Blocking."""
    conn = sqlite3.connect(db_path)
    try:
        init_tables(conn)
        rows = conn.execute("SELECT id, filename FROM seeds WHERE exclusive = 1").fetchall()
    finally:
        conn.close()
    return sum(1 for sid, fn in rows if teaser_url(sid) is None and fn
               and audio_stream.needs_stream(fn, 0, "video") and not is_text_file(fn)
               and fn.lower().endswith((".mp4", ".mov", ".avi", ".webm", ".mkv", ".wmv", ".flv"))
               and make_teaser(sid, fn))


# ---------- signed links ----------

def _secret() -> bytes:
    global _key
    with _key_lock:
        if _key is None:
            if KEY_FILE.exists():
                _key = bytes.fromhex(KEY_FILE.read_text().strip())
            else:
                _key = secrets.token_bytes(32)
                tmp = KEY_FILE.with_name(KEY_FILE.name + ".part")
                tmp.write_text(_key.hex())
                try:
                    os.chmod(tmp, 0o600)
                except OSError:
                    pass
                os.replace(tmp, KEY_FILE)
        return _key


def _signature(path: str, exp: int) -> str:
    return hmac.new(_secret(), f"{path}\n{exp}".encode(), hashlib.sha256).hexdigest()[:32]


def signed_url(path: str, ttl_s: int = URL_TTL_S) -> str:
    """A link to `path` (unencoded, e.g. /originals/abc_clip.mp4) that works for ttl_s seconds."""
    exp = int(time.time()) + ttl_s
    return f"{quote(path)}?exp={exp}&sig={_signature(path, exp)}"


def link_is_valid(path: str, exp: Optional[str], sig: Optional[str]) -> bool:
    try:
        exp_i = int(exp or "")
    except ValueError:
        return False
    return exp_i >= time.time() and bool(sig) and hmac.compare_digest(_signature(path, exp_i), sig)


def locked(path: str, db_path: str = DB_PATH) -> bool:
    """True if `path` (decoded) is the full clip of an exclusive post."""
    if not path.startswith(GATED_PREFIXES):
        return False
    name = unquote(path.split("/", 2)[2])
    conn = sqlite3.connect(db_path)
    try:
        if path.startswith("/originals/"):
            row = conn.execute("SELECT 1 FROM seeds WHERE filename = ? AND exclusive = 1", (name,)).fetchone()
        else:  # /streams/<seed_id>.<ext>
            row = conn.execute("SELECT 1 FROM seeds WHERE id = ? AND exclusive = 1",
                               (name.rsplit(".", 1)[0],)).fetchone()
        return row is not None
    except sqlite3.Error:
        return False  # no exclusive column yet: nothing is exclusive
    finally:
        conn.close()


# ---------- who may watch ----------

def may_watch(conn: sqlite3.Connection, username: Optional[str], owner: str) -> bool:
    """The poster, and real accounts: phone-verified on the real network, any account on a test net."""
    if not username:
        return False
    if username.lower() == (owner or "").lower():
        return True
    return not config.REQUIRE_PHONE_TO_POST or phone_verify.is_verified(conn, username)


# ---------- JSON items ----------

def apply_to_items(items: Iterable[Dict], db_path: str = DB_PATH) -> List[Dict]:
    """Mark exclusive posts in feed/seed JSON, and point their full/stream at the teaser."""
    items = list(items)
    if not items:
        return items
    conn = sqlite3.connect(db_path)
    try:
        ids = [i.get("id") for i in items if i.get("id")]
        found: Dict[str, int] = {}
        for start in range(0, len(ids), 500):
            chunk = ids[start:start + 500]
            try:
                found.update({r[0]: (r[1] if r[1] in TEASER_LENGTHS else TEASER_SECONDS) for r in conn.execute(
                    f"SELECT id, teaser_seconds FROM seeds WHERE exclusive = 1 AND id IN ({','.join('?' * len(chunk))})",
                    chunk)})
            except sqlite3.Error:
                break
    finally:
        conn.close()
    for item in items:
        if item.get("id") in found:
            item["exclusive"] = True
            item["teaser_seconds"] = found[item["id"]]
            if is_text_file(item.get("full") or ""):
                # Title only: the body (description) and the .txt are for real accounts
                item["teaser"] = None
                item["full"] = None
                item["description"] = ""
            else:
                teaser = teaser_url(item["id"])
                item["teaser"] = teaser
                item["full"] = teaser
            if "stream" in item:
                item["stream"] = None
        else:
            item["exclusive"] = False
            item["teaser"] = None
    return items


def share_text(title: str, text_post: bool = False, seconds: int = TEASER_SECONDS, download: bool = False) -> str:
    if text_post:
        return f"{title or 'New post'}: the full post is exclusive to the GFC Network"
    if download:
        return f"{title or 'New download'}: exclusive to the GFC Network"
    return f"{title or 'New video'}: {seconds}-second preview. The full clip is exclusive to the GFC Network"


def x_post(title: str, url: str, text_post: bool = False, seconds: int = TEASER_SECONDS,
           download: bool = False) -> Dict[str, str]:
    """A ready-made X post: for a video, attach the teaser and post this text and link."""
    text = share_text(title, text_post, seconds, download)
    import app_share
    return {"text": text, "url": url, "intent": app_share.x_intent_url(text, url)}


def share_links(title: str, url: str, text_post: bool = False, seconds: int = TEASER_SECONDS,
                download: bool = False) -> Dict[str, str]:
    """
    Where a poster can share an exclusive: X (web intent with the text and link), LinkedIn
    (its share page takes only the link; it reads the title and image from the share page),
    and Substack (no posting link exists: apps copy `text` and `url`, and open `substack`
    for the poster to paste into a Note).
    """
    from urllib.parse import quote as q
    text = share_text(title, text_post, seconds, download)
    import app_share
    return {"text": text, "url": url,
            "x": app_share.x_intent_url(text, url),
            "linkedin": "https://www.linkedin.com/sharing/share-offsite/?url=" + q(url, safe=""),
            "substack": "https://substack.com/notes"}
