"""
Wix front-page teasers - each new GFC Exclusive video's public teaser goes up on a Wix site
(MisterRobots.com) automatically.

Wix has no API for its Video Library channels, so the site shows teasers from a CMS
collection instead: a front-page section (a repeater or video player bound to a dataset of
this collection, newest first) shows the latest ones. For each exclusive video posted by
one of GFC_WIX_OWNERS, once its teaser exists (exclusive.make_teaser calls maybe_publish_later):

1. The teaser (and the post's thumbnail, as the poster) is imported into the site's Media
   Manager from its public URL (POST /site-media/v1/files/import), under "GFC teasers".
2. Wix processes it; we wait for operationStatus READY (GET /site-media/v1/files/{id}).
3. The CMS item is saved (POST /wix-data/v2/items/save, upsert) with id = the seed id:
   title, description, video, poster, link (the post's share page), postedAt, previewSeconds.

Deleting the post on GFC removes its item (seed_deletions.purge calls remove_later). State
is in the wix_posts table, so a post is published once, and a failure is retried by
`python wix_publish.py publish SEED_ID`.

Settings (environment, e.g. /etc/gfc/gfc.env):
    GFC_WIX_SITE_ID      the site's ID (the GUID in its dashboard URL)
    GFC_WIX_API_KEY_FILE file holding the Wix API key (default DATA_DIR/wix_api_key.txt,
                         mode 600). Key permissions: Wix Data (manage collections, write
                         items) and Media Manager.
    GFC_WIX_COLLECTION   CMS collection ID (default GFCTeasers)
    GFC_WIX_OWNERS       comma-separated GFC usernames whose exclusives go up (default: none)
Off unless the site ID, the key and at least one owner are set.

CLI (on the node, as the gfc user):
    python wix_publish.py check            settings, and whether the key works (never prints it)
    python wix_publish.py setup            create the collection (once)
    python wix_publish.py publish SEED_ID  publish (or re-publish) one post now
    python wix_publish.py status           what's been published
"""

import datetime
import json
import os
import sqlite3
import sys
import threading
import time
from pathlib import Path
from typing import Dict, Optional

import httpx

from config import DATA_DIR, DB_PATH

API = "https://www.wixapis.com"
FOLDER = "/GFC teasers"
READY_TIMEOUT_S = 15 * 60
POLL_S = 5
TIMEOUT = httpx.Timeout(30.0)

FIELDS = [
    ("title", "Title", "TEXT"),
    ("description", "Description", "TEXT"),
    ("video", "Teaser", "VIDEO"),
    ("poster", "Poster", "IMAGE"),
    ("link", "Watch on GFC", "URL"),
    ("postedAt", "Posted", "DATETIME"),
    ("previewSeconds", "Preview seconds", "NUMBER"),
    ("owner", "GFC account", "TEXT"),
]

_lock = threading.Lock()


class WixError(Exception):
    pass


# ---------- settings ----------

def site_id() -> str:
    return os.environ.get("GFC_WIX_SITE_ID", "").strip()


def collection_id() -> str:
    return os.environ.get("GFC_WIX_COLLECTION", "").strip() or "GFCTeasers"


def owners() -> set:
    return {o.strip().lower() for o in os.environ.get("GFC_WIX_OWNERS", "").split(",") if o.strip()}


def key_file() -> Path:
    return Path(os.environ.get("GFC_WIX_API_KEY_FILE", "").strip() or DATA_DIR / "wix_api_key.txt")


def api_key() -> str:
    try:
        return key_file().read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def enabled() -> bool:
    return bool(site_id() and owners() and api_key())


# ---------- HTTP ----------

_client_factory = None  # tests swap in a fake transport


def _client() -> httpx.Client:
    if _client_factory:
        return _client_factory()
    return httpx.Client(timeout=TIMEOUT)


def _call(client: httpx.Client, method: str, path: str, body: Optional[dict] = None, ok=(200,)) -> dict:
    headers = {"Authorization": api_key(), "wix-site-id": site_id(), "Content-Type": "application/json"}
    r = client.request(method, API + path, headers=headers, content=json.dumps(body) if body is not None else None)
    if r.status_code not in ok:
        # Wix errors are JSON with a message; never include our headers (the key)
        try:
            detail = r.json().get("message") or r.text
        except ValueError:
            detail = r.text
        raise WixError(f"{method} {path}: HTTP {r.status_code}: {str(detail)[:300]}")
    try:
        return r.json() if r.content else {}
    except ValueError:
        return {}


# ---------- state ----------

def init_tables(conn: sqlite3.Connection):
    conn.execute('''CREATE TABLE IF NOT EXISTS wix_posts (
        seed_id TEXT PRIMARY KEY,
        status TEXT NOT NULL,           -- pending, published, failed, removed
        video_file_id TEXT DEFAULT '',
        error TEXT DEFAULT '',
        updated_at TEXT NOT NULL)''')


def _set(seed_id: str, status: str, db_path: str, video_file_id: str = "", error: str = ""):
    conn = sqlite3.connect(db_path)
    try:
        init_tables(conn)
        conn.execute("INSERT INTO wix_posts (seed_id, status, video_file_id, error, updated_at) VALUES (?, ?, ?, ?, ?) "
                     "ON CONFLICT(seed_id) DO UPDATE SET status = excluded.status, "
                     "video_file_id = CASE WHEN excluded.video_file_id != '' THEN excluded.video_file_id ELSE video_file_id END, "
                     "error = excluded.error, updated_at = excluded.updated_at",
                     (seed_id, status, video_file_id, error[:500], datetime.datetime.utcnow().isoformat()))
        conn.commit()
    finally:
        conn.close()


def status_of(seed_id: str, db_path: str = DB_PATH) -> Optional[str]:
    conn = sqlite3.connect(db_path)
    try:
        init_tables(conn)
        row = conn.execute("SELECT status FROM wix_posts WHERE seed_id = ?", (seed_id,)).fetchone()
        return row[0] if row else None
    finally:
        conn.close()


# ---------- what goes up ----------

def _seed(seed_id: str, db_path: str) -> Optional[dict]:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute("SELECT id, owner, title, description, content_type, exclusive, teaser_seconds, "
                           "thumb_filename, created_at FROM seeds WHERE id = ?", (seed_id,)).fetchone()
        return dict(row) if row else None
    except sqlite3.Error:
        return None
    finally:
        conn.close()


def eligible(seed: Optional[dict]) -> bool:
    """An exclusive video by one of the site's GFC accounts."""
    return bool(seed and seed.get("exclusive") and seed.get("content_type") == "video"
                and (seed.get("owner") or "").lower() in owners())


def _public_url(kind: str, name: str) -> str:
    """Where Wix can fetch it: the bucket's URL when it's offloaded, else this node's public URL."""
    import media_store
    import config
    direct = media_store.redirect_url(f"/{kind}/{name}")
    if direct:
        return direct
    base = (config.PUBLIC_API_URL or "https://node.galacticfederation.tech").rstrip("/")
    return f"{base}/{kind}/{name}"


def _import(client: httpx.Client, url: str, name: str, media_type: str) -> dict:
    body = {"url": url, "displayName": name, "mediaType": media_type, "filePath": FOLDER, "private": False}
    return _call(client, "POST", "/site-media/v1/files/import", body).get("file") or {}


def _wait_ready(client: httpx.Client, file_id: str, sleep=time.sleep, timeout_s: float = READY_TIMEOUT_S) -> dict:
    from urllib.parse import quote
    deadline = time.monotonic() + timeout_s
    while True:
        f = _call(client, "GET", f"/site-media/v1/files/{quote(file_id, safe='')}").get("file") or {}
        status = f.get("operationStatus")
        if status == "READY":
            return f
        if status == "FAILED":
            raise WixError(f"Wix couldn't process {f.get('displayName') or file_id}")
        if time.monotonic() > deadline:
            raise WixError(f"Wix is still processing {file_id} after {timeout_s // 60:.0f} minutes")
        sleep(POLL_S)


def publish(seed_id: str, db_path: str = DB_PATH, sleep=time.sleep, force: bool = False) -> dict:
    """Put one post's teaser on the site. Returns the saved CMS item's data. Raises WixError."""
    import app_share
    import exclusive
    with _lock:
        if not enabled():
            raise WixError("Wix publishing is off (GFC_WIX_SITE_ID, GFC_WIX_OWNERS and the API key file are needed)")
        seed = _seed(seed_id, db_path)
        if not force and not eligible(seed):
            raise WixError("only exclusive videos by GFC_WIX_OWNERS go to the site")
        if not seed:
            raise WixError("no such post")
        if exclusive.teaser_url(seed_id) is None:
            raise WixError("the teaser isn't made yet")
        _set(seed_id, "pending", db_path)
        title = seed.get("title") or "New on GFC"
        try:
            with _client() as client:
                video = _import(client, _public_url("teasers", exclusive.teaser_path(seed_id).name),
                                f"{title[:200]} (GFC preview).mp4", "VIDEO")
                if not video.get("id"):
                    raise WixError("Wix didn't return a file for the teaser")
                _set(seed_id, "pending", db_path, video_file_id=video["id"])
                poster = None
                if seed.get("thumb_filename"):
                    poster = _import(client, _public_url("thumbs", seed["thumb_filename"]), f"{title[:200]} (GFC).jpg", "IMAGE")
                video = _wait_ready(client, video["id"], sleep)
                if poster and poster.get("id"):
                    try:
                        poster = _wait_ready(client, poster["id"], sleep, timeout_s=300)
                    except WixError:
                        poster = None  # the teaser still goes up, with Wix's own frame
                data = {
                    "title": title,
                    "description": seed.get("description") or "",
                    "video": video.get("url") or "",
                    "link": app_share.share_url(seed_id),
                    "postedAt": {"$date": _iso(seed.get("created_at"))},
                    "previewSeconds": seed.get("teaser_seconds") or exclusive.TEASER_SECONDS,
                    "owner": seed.get("owner") or "",
                }
                if poster and poster.get("url"):
                    data["poster"] = poster["url"]
                _call(client, "POST", "/wix-data/v2/items/save",
                      {"dataCollectionId": collection_id(), "dataItem": {"id": seed_id, "data": data}})
        except (WixError, httpx.HTTPError) as ex:
            _set(seed_id, "failed", db_path, error=str(ex))
            raise WixError(str(ex)) from ex
        _set(seed_id, "published", db_path)
        print(f"[Wix] {seed_id}: teaser is on the site")
        return data


def _iso(created_at: Optional[str]) -> str:
    try:
        t = datetime.datetime.fromisoformat((created_at or "").replace("Z", ""))
    except ValueError:
        t = datetime.datetime.utcnow()
    return t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z"


def maybe_publish_later(seed_id: str, db_path: str = DB_PATH) -> bool:
    """After a teaser is made: publish it in the background if it's for the site and not up yet."""
    if not enabled():
        return False
    if status_of(seed_id, db_path) in ("published", "pending", "removed") or not eligible(_seed(seed_id, db_path)):
        return False

    def run():
        try:
            publish(seed_id, db_path)
        except WixError as ex:
            print(f"[Wix] {seed_id}: not published: {ex}")
    threading.Thread(target=run, name="gfc-wix", daemon=True).start()
    return True


def remove(seed_id: str, db_path: str = DB_PATH) -> bool:
    """Take a deleted post's teaser off the site (the CMS item; the Media Manager copy stays)."""
    from urllib.parse import quote, urlencode
    if not enabled() or status_of(seed_id, db_path) in (None, "removed"):
        return False
    with _client() as client:
        _call(client, "DELETE", f"/wix-data/v2/items/{quote(seed_id, safe='')}?"
              + urlencode({"dataCollectionId": collection_id()}), ok=(200, 404))
    _set(seed_id, "removed", db_path)
    print(f"[Wix] {seed_id}: taken off the site (deleted on GFC)")
    return True


def remove_later(seed_id: str, db_path: str = DB_PATH) -> bool:
    if not enabled() or status_of(seed_id, db_path) in (None, "removed"):
        return False

    def run():
        try:
            remove(seed_id, db_path)
        except (WixError, httpx.HTTPError) as ex:
            print(f"[Wix] {seed_id}: couldn't take it off the site: {ex}")
    threading.Thread(target=run, name="gfc-wix", daemon=True).start()
    return True


def setup() -> dict:
    """Create the collection: anyone can read (the site shows it), only the site admin changes it."""
    body = {"collection": {
        "id": collection_id(), "displayName": "GFC Teasers",
        "fields": [{"key": k, "displayName": n, "type": t} for k, n, t in FIELDS],
        "permissions": {"read": "ANYONE", "insert": "ADMIN", "update": "ADMIN", "remove": "ADMIN"},
    }}
    with _client() as client:
        return _call(client, "POST", "/data/v2/collections", body, ok=(200, 409))


def check() -> str:
    lines = [f"site:       {site_id() or '(GFC_WIX_SITE_ID not set)'}",
             f"collection: {collection_id()}",
             f"owners:     {', '.join(sorted(owners())) or '(GFC_WIX_OWNERS not set)'}",
             f"key file:   {key_file()} ({'present' if api_key() else 'missing'})"]
    if site_id() and api_key():
        try:
            with _client() as client:
                got = _call(client, "GET", "/data/v2/collections/" + collection_id(), ok=(200, 404))
            lines.append("key works: yes; collection " + ("exists" if got.get("collection") else "not created yet (run setup)"))
        except (WixError, httpx.HTTPError) as ex:
            lines.append(f"key works: no ({ex})")
    return "\n".join(lines)


def _cli(argv) -> int:
    if not argv or argv[0] not in ("check", "setup", "publish", "status"):
        print(__doc__.split("CLI", 1)[1])
        return 2
    try:
        if argv[0] == "check":
            print(check())
        elif argv[0] == "setup":
            got = setup()
            print("collection created" if got.get("collection") else "collection already exists")
        elif argv[0] == "publish":
            if len(argv) != 2:
                print("usage: python wix_publish.py publish SEED_ID")
                return 2
            data = publish(argv[1], force=True)
            print(f"published: {data['title']}\nlink: {data['link']}")
        else:
            conn = sqlite3.connect(DB_PATH)
            init_tables(conn)
            for row in conn.execute("SELECT seed_id, status, updated_at, error FROM wix_posts ORDER BY updated_at DESC LIMIT 20"):
                print(*row)
            conn.close()
    except WixError as ex:
        print(f"error: {ex}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(_cli(sys.argv[1:]))
