"""
GFC Media Store - where uploaded media lives: this node's disk, or Cloudflare R2

Media: /originals (posts as uploaded), /streams (streaming copies), /teasers (exclusive
previews), /thumbs and /avatars. Three modes, from the environment:

- local (default, no GFC_R2_* settings): files stay in the data dir, as before.
- r2 (an official node): GFC_R2_ACCOUNT_ID, GFC_R2_BUCKET, GFC_R2_ACCESS_KEY_ID,
  GFC_R2_SECRET_ACCESS_KEY and GFC_R2_PUBLIC_URL all set. Once a file is ready (transcoded,
  thumbnailed) it's uploaded to the bucket under <kind>/<name>, the upload is checked
  (size and MD5 ETag; R2 also checks the SHA-256 we sign), recorded in media_objects,
  and the local copy is deleted. GFC_R2_KEEP_LOCAL=1 uploads but keeps the local copies.
- r2-read-only (a community node): only GFC_R2_PUBLIC_URL set. It never writes to the
  bucket, and refuses new uploads and avatars (READ_ONLY_DETAIL): posting needs an
  official node, which holds the write token.

Serving: a media URL is answered from local disk when the file is here (with Range, as
before); otherwise the node redirects (302) to GFC_R2_PUBLIC_URL/<kind>/<name>.

Gated files never go to the bucket (the whole bucket is public through its public URL,
so a "private prefix" wouldn't be private): the full clip of a GFC Exclusive
(/originals/<file> and its /streams/ copy, exclusive.py) and downloads (.zip,
filescan.py: scanned before anyone gets them, and rescanned daily) stay on this node's
disk, behind the existing signed-link and virus-scan gates. Teasers and thumbnails of
those posts are public and do go to the bucket.

Existing files: `python media_store.py migrate [--keep-local] [--dry-run]` uploads them,
verifies each one, and only then deletes the local copy. `python media_store.py status`
shows the mode and what's stored. See docs/r2.md.
"""

import datetime
import hashlib
import hmac
import mimetypes
import os
import queue
import sqlite3
import sys
import threading
import time
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Tuple
from urllib.parse import quote, unquote, urlsplit

import httpx

import config
from config import DB_PATH

KINDS = ("originals", "streams", "teasers", "thumbs", "avatars")
PREFIXES = tuple(f"/{k}/" for k in KINDS)
READ_ONLY_DETAIL = ("This is a community GFC node: it shows posts but can't store new media. "
                    "Post from the GFC app or an official GFC node.")
CACHE_CONTROL = "public, max-age=31536000, immutable"  # every media name is unique
SETTLE_S = 10 * 60          # the sweep leaves files younger than this (still being processed)
STUCK_S = 24 * 3600         # ...and offloads originals whose streaming copy never came (no ffmpeg)
SWEEP_EVERY_S = 3600
HEAD_TTL_S = (3600, 300)    # read-only nodes: how long a HEAD's yes / no is remembered
REGION = "auto"             # R2's SigV4 region


class MediaStoreError(Exception):
    pass


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


# ---------- local files ----------

def local_dir(kind: str) -> Path:
    if kind == "originals":
        return config.SEEDS_ORIG_DIR
    if kind == "thumbs":
        return config.SEEDS_THUMB_DIR
    if kind == "avatars":
        return config.AVATAR_DIR
    if kind == "streams":
        import audio_stream
        return audio_stream.STREAMS_DIR
    if kind == "teasers":
        import exclusive
        return exclusive.TEASERS_DIR
    raise ValueError("unknown media kind")


def check_name(name: str) -> str:
    """A bare file name in a media directory (no paths, no hidden/.part files)."""
    if not name or "/" in name or "\\" in name or name.startswith("."):
        raise ValueError("bad media name")
    return name


def local_path(kind: str, name: str) -> Path:
    return local_dir(kind) / check_name(name)


def key_for(kind: str, name: str) -> str:
    if kind not in KINDS:
        raise ValueError("unknown media kind")
    return f"{kind}/{check_name(name)}"


def split_path(path: str) -> Optional[Tuple[str, str]]:
    """'/originals/abc%20x.mp4' -> ('originals', 'abc x.mp4'), or None if it isn't a media URL."""
    if not path.startswith(PREFIXES):
        return None
    kind, _, name = path[1:].partition("/")
    try:
        return kind, check_name(unquote(name))
    except ValueError:
        return None


def _hashes(path: Path) -> Tuple[int, str, str]:
    """(size, sha256 hex, md5 hex), in one read."""
    sha, md5, size = hashlib.sha256(), hashlib.md5(), 0
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            sha.update(chunk)
            md5.update(chunk)
            size += len(chunk)
    return size, sha.hexdigest(), md5.hexdigest()


def content_type_of(name: str) -> str:
    ext = Path(name).suffix.lower()
    known = {".m4a": "audio/mp4", ".mp4": "video/mp4", ".webp": "image/webp", ".glb": "model/gltf-binary",
             ".gltf": "model/gltf+json", ".flac": "audio/flac", ".webm": "video/webm", ".mkv": "video/x-matroska"}
    return known.get(ext) or mimetypes.guess_type(name)[0] or "application/octet-stream"


# ---------- AWS Signature Version 4 (R2 speaks the S3 API) ----------

def _uri_encode(s: str) -> str:
    return quote(s, safe="-_.~")


def _hmac(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode(), hashlib.sha256).digest()


def sign_v4(method: str, host: str, path: str, query: Iterable[Tuple[str, str]], headers: Dict[str, str],
            payload_sha256: str, access_key: str, secret_key: str, now: datetime.datetime,
            region: str = REGION, service: str = "s3") -> Dict[str, str]:
    """
    The headers to send (the given ones plus host, x-amz-date, x-amz-content-sha256 and
    Authorization), all signed. `path` is the already URI-encoded path.
    """
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    day = now.strftime("%Y%m%d")
    signed = {k.lower(): " ".join(str(v).strip().split()) for k, v in headers.items()}
    signed.update({"host": host, "x-amz-date": amz_date, "x-amz-content-sha256": payload_sha256})
    names = sorted(signed)
    canonical = "\n".join([
        method, path,
        "&".join(f"{_uri_encode(k)}={_uri_encode(v)}" for k, v in sorted(query)),
        "".join(f"{k}:{signed[k]}\n" for k in names),
        ";".join(names),
        payload_sha256,
    ])
    scope = f"{day}/{region}/{service}/aws4_request"
    to_sign = "\n".join(["AWS4-HMAC-SHA256", amz_date, scope, hashlib.sha256(canonical.encode()).hexdigest()])
    key = _hmac(_hmac(_hmac(_hmac(("AWS4" + secret_key).encode(), day), region), service), "aws4_request")
    signature = hmac.new(key, to_sign.encode(), hashlib.sha256).hexdigest()
    out = dict(signed)
    out["authorization"] = (f"AWS4-HMAC-SHA256 Credential={access_key}/{scope}, "
                            f"SignedHeaders={';'.join(names)}, Signature={signature}")
    return out


EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


# ---------- backends ----------

class Settings:
    def __init__(self, account_id: str = "", bucket: str = "", access_key_id: str = "",
                 secret_access_key: str = "", public_url: str = "", keep_local: bool = False):
        self.account_id = account_id.strip()
        self.bucket = bucket.strip()
        self.access_key_id = access_key_id.strip()
        self.secret_access_key = secret_access_key.strip()
        self.public_url = public_url.strip().rstrip("/")
        self.keep_local = keep_local

    @classmethod
    def from_env(cls, env=os.environ) -> "Settings":
        return cls(env.get("GFC_R2_ACCOUNT_ID", ""), env.get("GFC_R2_BUCKET", ""),
                   env.get("GFC_R2_ACCESS_KEY_ID", ""), env.get("GFC_R2_SECRET_ACCESS_KEY", ""),
                   env.get("GFC_R2_PUBLIC_URL", ""),
                   env.get("GFC_R2_KEEP_LOCAL", "").strip().lower() in ("1", "true", "yes", "on"))

    def write_fields(self) -> List[str]:
        return [self.account_id, self.bucket, self.access_key_id, self.secret_access_key]

    def mode(self) -> str:
        """local, r2 or r2-read-only. A partial write setup is a mistake: say so and stay safe."""
        if not self.public_url:
            if any(self.write_fields()):
                print("[MediaStore] GFC_R2_PUBLIC_URL isn't set: R2 is off and media stays on this node")
            return "local"
        if all(self.write_fields()):
            return "r2"
        if any(self.write_fields()):
            print("[MediaStore] Some GFC_R2_* write settings are missing: this node is read-only for R2 media")
        return "r2-read-only"


class LocalStore:
    """Today's behaviour: everything on this node's disk."""
    mode = "local"
    writable = False
    keep_local = True

    def public_url(self, key: str) -> Optional[str]:
        return None


class R2Store:
    """Cloudflare R2 through its S3-compatible API, signed with SigV4 over httpx."""

    def __init__(self, settings: Settings, client: Optional[httpx.Client] = None,
                 clock: Callable[[], datetime.datetime] = None):
        self.settings = settings
        self.mode = settings.mode()
        self.writable = self.mode == "r2"
        self.keep_local = settings.keep_local
        self.host = f"{settings.account_id}.r2.cloudflarestorage.com"
        self.client = client or httpx.Client(timeout=httpx.Timeout(30.0, read=600.0, write=600.0))
        self.clock = clock or (lambda: datetime.datetime.now(datetime.timezone.utc))
        self._heads: Dict[str, Tuple[bool, float]] = {}
        self._heads_lock = threading.Lock()

    def public_url(self, key: str) -> str:
        return f"{self.settings.public_url}/{'/'.join(_uri_encode(p) for p in key.split('/'))}"

    def _path(self, key: str) -> str:
        return "/" + "/".join(_uri_encode(p) for p in [self.settings.bucket] + key.split("/"))

    def _request(self, method: str, key: str, headers: Optional[Dict[str, str]] = None,
                 payload_sha256: str = EMPTY_SHA256, content=None) -> httpx.Response:
        if not self.writable:
            raise MediaStoreError("this node has no R2 write credentials")
        path = self._path(key)
        signed = sign_v4(method, self.host, path, [], headers or {}, payload_sha256,
                         self.settings.access_key_id, self.settings.secret_access_key, self.clock())
        try:
            return self.client.request(method, f"https://{self.host}{path}", headers=signed, content=content)
        except httpx.HTTPError as ex:
            raise MediaStoreError(f"R2 {method} failed ({type(ex).__name__})") from None

    def put_file(self, key: str, path: Path, size: int, sha256: str, md5: str) -> None:
        def body():
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(1024 * 1024), b""):
                    yield chunk
        headers = {"content-type": content_type_of(path.name), "content-length": str(size),
                   "cache-control": CACHE_CONTROL, "x-amz-meta-sha256": sha256}
        r = self._request("PUT", key, headers, sha256, body())
        if r.status_code != 200:
            raise MediaStoreError(f"R2 PUT {key}: HTTP {r.status_code}")
        etag = (r.headers.get("etag") or "").strip('"')
        if etag and etag != md5:
            raise MediaStoreError(f"R2 PUT {key}: the stored copy's MD5 doesn't match")

    def head(self, key: str) -> Optional[Dict]:
        # identity: R2 gzips text types otherwise, and then sends no content-length (and a weak ETag)
        r = self._request("HEAD", key, {"accept-encoding": "identity"})
        if r.status_code == 404:
            return None
        if r.status_code != 200:
            raise MediaStoreError(f"R2 HEAD {key}: HTTP {r.status_code}")
        return {"size": int(r.headers.get("content-length") or -1),
                "etag": (r.headers.get("etag") or "").strip('"'),
                "sha256": r.headers.get("x-amz-meta-sha256") or ""}

    def delete(self, key: str) -> None:
        r = self._request("DELETE", key)
        if r.status_code not in (200, 204, 404):
            raise MediaStoreError(f"R2 DELETE {key}: HTTP {r.status_code}")

    def public_exists(self, key: str) -> bool:
        """Read-only nodes: is it at the public URL? (HEAD, remembered for a while)"""
        now = time.time()
        with self._heads_lock:
            hit = self._heads.get(key)
            if hit and hit[1] > now:
                return hit[0]
        try:
            found = self.client.head(self.public_url(key), timeout=3.0).status_code == 200
        except httpx.HTTPError:
            return False  # not remembered: try again next time
        with self._heads_lock:
            if len(self._heads) > 50_000:
                self._heads.clear()
            self._heads[key] = (found, now + HEAD_TTL_S[0 if found else 1])
        return found


def _from_env():
    settings = Settings.from_env()
    return LocalStore() if settings.mode() == "local" else R2Store(settings)


_store = None
_store_lock = threading.Lock()


def store():
    global _store
    with _store_lock:
        if _store is None:
            _store = _from_env()
        return _store


def configure(new_store) -> None:
    """Swap the backend (tests; None = read the environment again)."""
    global _store
    with _store_lock:
        _store = new_store


def mode() -> str:
    return store().mode


def read_only() -> bool:
    """A community node: media comes from R2's public URL, and it can't take new uploads."""
    return store().mode == "r2-read-only"


# ---------- what's in the bucket (official nodes) ----------

def init_tables(conn: sqlite3.Connection):
    conn.execute('''CREATE TABLE IF NOT EXISTS media_objects (
        key TEXT PRIMARY KEY,
        size INTEGER NOT NULL,
        sha256 TEXT NOT NULL,
        stored_at TEXT NOT NULL
    )''')


def _stored(key: str, db_path: str) -> Optional[Tuple[int, str, str]]:
    conn = sqlite3.connect(db_path)
    try:
        init_tables(conn)
        return conn.execute("SELECT size, sha256, stored_at FROM media_objects WHERE key = ?", (key,)).fetchone()
    finally:
        conn.close()


def exists(kind: str, name: str, db_path: str = DB_PATH) -> bool:
    """Here on disk, or in the bucket."""
    try:
        if local_path(kind, name).is_file():
            return True
    except ValueError:
        return False
    s = store()
    if s.mode == "r2":
        return _stored(key_for(kind, name), db_path) is not None
    if s.mode == "r2-read-only":
        return s.public_exists(key_for(kind, name))
    return False


def redirect_url(path: str) -> Optional[str]:
    """For a media URL whose file isn't on this node: where it is in the bucket (or None)."""
    s = store()
    if s.mode == "local":
        return None
    parts = split_path(path)
    if not parts or local_path(*parts).is_file():
        return None
    if gated(*parts):
        return None  # never in the bucket
    return s.public_url(key_for(*parts))


# ---------- what stays on this node ----------

def gated(kind: str, name: str, db_path: str = DB_PATH) -> bool:
    """Exclusive full clips (original and stream) and downloads: never in the public bucket."""
    if kind not in ("originals", "streams"):
        return False
    import filescan
    if kind == "originals" and filescan.is_download(name):
        return True
    conn = sqlite3.connect(db_path)
    try:
        if kind == "originals":
            row = conn.execute("SELECT 1 FROM seeds WHERE filename = ? AND exclusive = 1", (name,)).fetchone()
        else:
            row = conn.execute("SELECT 1 FROM seeds WHERE id = ? AND exclusive = 1",
                               (name.rsplit(".", 1)[0],)).fetchone()
        return row is not None
    except sqlite3.Error:
        return False  # no seeds/exclusive column yet: nothing is exclusive
    finally:
        conn.close()


def _waiting_for_stream(name: str, age_s: float, db_path: str) -> bool:
    """An original whose streaming copy (made from it) hasn't been made yet."""
    if age_s >= STUCK_S:
        return False
    import audio_stream
    conn = sqlite3.connect(db_path)
    try:
        row = conn.execute("SELECT id, content_type, file_size FROM seeds WHERE filename = ?", (name,)).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        conn.close()
    if not row or not audio_stream.enabled() or row[1] not in audio_stream.STREAM_KINDS \
            or not audio_stream.needs_stream(name, row[2] or 0, row[1]):
        return False
    try:
        return not exists("streams", audio_stream.stream_path(row[0], row[1]).name, db_path)
    except ValueError:
        return False


# ---------- moving files to the bucket ----------

STORED, KEPT, MISSING, SKIPPED, FAILED = "stored", "kept", "missing", "skipped", "failed"


def offload(kind: str, name: str, db_path: str = DB_PATH, keep_local: Optional[bool] = None,
            dry_run: bool = False) -> str:
    """
    Upload one file to the bucket, check it, record it, then delete the local copy.
    stored, kept (gated: stays here), missing (no local file), skipped (local mode or a
    dry run) or failed (the local copy is kept; logged).
    """
    s = store()
    path = local_path(kind, name)
    if not path.is_file():
        return MISSING
    if gated(kind, name, db_path):
        return KEPT
    import seed_deletions
    if seed_deletions.is_deleted_media(kind, name, db_path):  # e.g. a transcode that finished after the delete
        if not dry_run:
            path.unlink(missing_ok=True)
        return MISSING
    if not s.writable or dry_run:
        return SKIPPED
    keep = s.keep_local if keep_local is None else keep_local
    key = key_for(kind, name)
    try:
        st = path.stat()
        known = _stored(key, db_path)
        already = known and known[0] == st.st_size and known[2] >= datetime.datetime.fromtimestamp(
            st.st_mtime, datetime.timezone.utc).isoformat(timespec="seconds")
        if not already:
            size, sha, md5 = _hashes(path)
            s.put_file(key, path, size, sha, md5)
            got = s.head(key)
            if not got or got["size"] != size or (got["sha256"] and got["sha256"] != sha) \
                    or (got["etag"] and got["etag"] != md5):
                raise MediaStoreError(f"{key}: the bucket's copy doesn't match the local file")
            conn = sqlite3.connect(db_path)
            try:
                init_tables(conn)
                conn.execute("INSERT INTO media_objects (key, size, sha256, stored_at) VALUES (?, ?, ?, ?) "
                             "ON CONFLICT(key) DO UPDATE SET size = excluded.size, sha256 = excluded.sha256, "
                             "stored_at = excluded.stored_at", (key, size, sha, _now()))
                conn.commit()
            finally:
                conn.close()
        if not keep:
            path.unlink(missing_ok=True)
        return STORED
    except (MediaStoreError, OSError) as ex:
        print(f"[MediaStore] {key}: {ex}; keeping the local copy")
        return FAILED


def remove(kind: str, name: str, db_path: str = DB_PATH) -> None:
    """Delete a file everywhere (e.g. a replaced avatar)."""
    try:
        local_path(kind, name).unlink(missing_ok=True)
    except (ValueError, OSError):
        return
    s = store()
    if not s.writable:
        return
    key = key_for(kind, name)
    try:
        s.delete(key)
    except MediaStoreError as ex:
        print(f"[MediaStore] {ex}")
        return
    conn = sqlite3.connect(db_path)
    try:
        init_tables(conn)
        conn.execute("DELETE FROM media_objects WHERE key = ?", (key,))
        conn.commit()
    finally:
        conn.close()


def offload_seed(seed_id: str, db_path: str = DB_PATH) -> Dict[str, str]:
    """A post's files, once it's been processed (streaming copy, thumbnail, teaser)."""
    if not store().writable:
        return {}
    conn = sqlite3.connect(db_path)
    try:
        row = conn.execute("SELECT filename, COALESCE(thumb_filename, ''), content_type FROM seeds WHERE id = ?",
                           (seed_id,)).fetchone()
    finally:
        conn.close()
    if not row:
        return {}
    import audio_stream
    import exclusive
    filename, thumb, content_type = row
    done = {}
    if content_type in audio_stream.STREAM_KINDS:
        try:
            done["stream"] = offload("streams", audio_stream.stream_path(seed_id, content_type).name, db_path)
        except ValueError:
            pass
    try:
        done["teaser"] = offload("teasers", exclusive.teaser_path(seed_id).name, db_path)
    except ValueError:
        pass
    if thumb:
        done["thumb"] = offload("thumbs", thumb, db_path)
    if filename:
        done["original"] = offload("originals", filename, db_path)
    return done


_queue: "queue.Queue[tuple]" = queue.Queue()
_worker: Optional[threading.Thread] = None
_worker_lock = threading.Lock()


def _work():
    while True:
        fn, args = _queue.get()
        try:
            fn(*args)
        except Exception as ex:
            print(f"[MediaStore] background upload failed: {type(ex).__name__}")
        finally:
            _queue.task_done()


def _later(fn, *args) -> bool:
    global _worker
    if not store().writable:
        return False
    with _worker_lock:
        if _worker is None or not _worker.is_alive():
            _worker = threading.Thread(target=_work, name="gfc-media-store", daemon=True)
            _worker.start()
    _queue.put((fn, args))
    return True


def offload_seed_later(seed_id: str) -> bool:
    """In the background, one upload at a time."""
    return _later(offload_seed, seed_id)


def offload_later(kind: str, name: str) -> bool:
    return _later(offload, kind, name)


def remove_later(kind: str, name: str) -> bool:
    return _later(remove, kind, name)


def offload_all(db_path: str = DB_PATH, min_age_s: float = SETTLE_S, keep_local: Optional[bool] = None,
                dry_run: bool = False, report: Callable[[str, str, int], None] = None) -> Dict[str, int]:
    """Every local media file that's ready. The hourly sweep and `migrate` both use this."""
    counts: Dict[str, int] = {}
    now = time.time()
    for kind in KINDS:
        folder = local_dir(kind)
        if not folder.is_dir():
            continue
        for path in sorted(folder.iterdir()):
            try:
                name = check_name(path.name)
                if not path.is_file():
                    continue
                st = path.stat()
            except (ValueError, OSError):
                continue
            age = now - st.st_mtime
            if age < min_age_s:
                status = SKIPPED
            elif kind == "originals" and _waiting_for_stream(name, age, db_path):
                status = SKIPPED
            else:
                status = offload(kind, name, db_path, keep_local=keep_local, dry_run=dry_run)
            counts[status] = counts.get(status, 0) + 1
            if report:
                report(status, key_for(kind, name), st.st_size)
    return counts


def _sweeper(db_path: str):
    while True:
        try:
            import seed_deletions
            seed_deletions.retry_purges(db_path)  # deleted posts whose files R2 didn't take back earlier
        except Exception as ex:
            print(f"[MediaStore] Deleted posts' files: {type(ex).__name__}")
        try:
            counts = offload_all(db_path)
            if counts.get(STORED) or counts.get(FAILED):
                print(f"[MediaStore] Sweep: {counts.get(STORED, 0)} stored, {counts.get(FAILED, 0)} failed")
        except Exception as ex:
            print(f"[MediaStore] Sweep failed: {type(ex).__name__}")
        time.sleep(SWEEP_EVERY_S)


def start_sweeper(db_path: str = DB_PATH) -> bool:
    """Official nodes: offload anything left behind (synced files, a restart mid-upload), hourly."""
    s = store()
    print(f"[MediaStore] Media storage: {s.mode}" + (" (keeping local copies)" if s.writable and s.keep_local else ""))
    if not s.writable:
        return False
    threading.Thread(target=_sweeper, args=(db_path,), name="gfc-media-sweep", daemon=True).start()
    return True


# ---------- command line ----------

def _status(db_path: str) -> int:
    s = store()
    print(f"Mode: {s.mode}")
    if s.mode != "local":
        host = urlsplit(s.settings.public_url).netloc or s.settings.public_url
        print(f"Public URL host: {host}")
    if s.mode == "r2":
        print(f"Bucket: {s.settings.bucket}" + (" (keeping local copies)" if s.keep_local else ""))
        conn = sqlite3.connect(db_path)
        try:
            init_tables(conn)
            n, total = conn.execute("SELECT COUNT(*), COALESCE(SUM(size), 0) FROM media_objects").fetchone()
        finally:
            conn.close()
        print(f"In the bucket: {n} files, {total / 1024 ** 3:.2f} GB")
    for kind in KINDS:
        folder = local_dir(kind)
        files = [p for p in folder.iterdir() if p.is_file()] if folder.is_dir() else []
        print(f"On disk, {kind}: {len(files)} files, {sum(p.stat().st_size for p in files) / 1024 ** 3:.2f} GB")
    return 0


def _migrate(db_path: str, keep_local: bool, dry_run: bool) -> int:
    s = store()
    if not s.writable:
        print("migrate needs an official node's R2 settings (GFC_R2_ACCOUNT_ID, GFC_R2_BUCKET, "
              "GFC_R2_ACCESS_KEY_ID, GFC_R2_SECRET_ACCESS_KEY, GFC_R2_PUBLIC_URL)")
        return 2
    totals: Dict[str, int] = {}

    def report(status: str, key: str, size: int):
        totals[status] = totals.get(status, 0) + size
        if status in (STORED, FAILED, KEPT) or dry_run:
            print(f"  {'would store' if dry_run and status == SKIPPED else status:<11} {size / 1048576:9.1f} MB  {key}")

    print(("Dry run: nothing is uploaded or deleted\n" if dry_run else "") +
          ("Keeping local copies\n" if keep_local else ""))
    counts = offload_all(db_path, min_age_s=0, keep_local=keep_local, dry_run=dry_run, report=report)
    for status in (STORED, KEPT, FAILED, SKIPPED):
        if counts.get(status):
            label = {STORED: "uploaded and verified" + ("" if keep_local else ", local copy deleted"),
                     KEPT: "kept on this node (exclusive clips and downloads)", FAILED: "failed (local copy kept)",
                     SKIPPED: "would be uploaded" if dry_run else "skipped"}[status]
            print(f"{counts[status]} {label}: {totals.get(status, 0) / 1024 ** 3:.2f} GB")
    return 1 if counts.get(FAILED) else 0


def _cli(argv: List[str], db_path: str = DB_PATH) -> int:
    if argv[:1] == ["status"] and len(argv) == 1:
        return _status(db_path)
    if argv[:1] == ["migrate"] and set(argv[1:]) <= {"--keep-local", "--dry-run"}:
        return _migrate(db_path, "--keep-local" in argv, "--dry-run" in argv)
    print("usage: python media_store.py status | migrate [--keep-local] [--dry-run]")
    return 2


if __name__ == "__main__":
    raise SystemExit(_cli(sys.argv[1:]))
