"""
GFC Downloads - zip posts (games, apps, packs), checked and virus-scanned before anyone gets them

Posts whose file is a .zip are downloads. Before a download is offered:

1. Zip checks (in Python, no extraction): password-protected entries (can't be scanned),
   zip bombs (more than MAX_UNCOMPRESSED_BYTES unpacked, or a compression ratio over
   MAX_RATIO), and more than MAX_ENTRIES files are rejected. The contents are summarised
   (how many files, and how many programs/scripts inside).
2. ClamAV scans the file: clamdscan (the clamav-daemon service, fast) when it's running,
   otherwise clamscan (loads the virus database per scan: slow, but needs no resident RAM).
   GFC_CLAMSCAN overrides the command.

Until a download is "clean" its file can't be fetched (/originals answers 403) and the feed
shows it as being checked. "infected" and "rejected" files are deleted and the post is left
out of the feed. Every download is rescanned daily with fresh definitions (gfc-scan.timer
runs `python filescan.py rescan`), so a file that turns out to be bad later is pulled.

Without ClamAV installed, downloads stay held ("unavailable") on the real network; test
networks let them through so development doesn't need ClamAV.

Synced zips are scanned by each node that receives them.
"""

import datetime
import hashlib
import json
import os
import queue
import re
import shutil
import sqlite3
import subprocess
import sys
import threading
import zipfile
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Tuple

import config
from config import DB_PATH, SEEDS_ORIG_DIR

DOWNLOAD_EXTENSIONS = (".zip",)
MAX_UNCOMPRESSED_BYTES = 4 * 1024 ** 3
MAX_RATIO = 200
MAX_ENTRIES = 50_000
SCAN_TIMEOUT_S = 20 * 60
CLAMD_SOCKET = Path("/run/clamav/clamd.ctl")
PROGRAM_EXTENSIONS = (".exe", ".dll", ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".scr",
                      ".com", ".sh", ".apk", ".app", ".so", ".dylib")

PENDING, CLEAN, INFECTED, REJECTED, ERROR, UNAVAILABLE = "pending", "clean", "infected", "rejected", "error", "unavailable"
REMOVED = (INFECTED, REJECTED)  # the file is deleted and the post left out of the feed
GATED_PREFIX = "/originals/"

# Tests replace this: runner(path) -> (status, detail, engine)
Runner = Callable[[Path], Tuple[str, str, str]]

_queue: "queue.Queue[str]" = queue.Queue()
_worker: Optional[threading.Thread] = None
_worker_lock = threading.Lock()


def init_tables(conn: sqlite3.Connection):
    conn.execute('''CREATE TABLE IF NOT EXISTS file_scans (
        seed_id TEXT PRIMARY KEY,
        status TEXT NOT NULL,
        detail TEXT DEFAULT '',
        engine TEXT DEFAULT '',
        scanned_at TEXT DEFAULT '',
        sha256 TEXT DEFAULT '',
        summary TEXT DEFAULT ''
    )''')


def is_download(filename: str) -> bool:
    return (filename or "").lower().endswith(DOWNLOAD_EXTENSIONS)


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


# ---------- zip checks ----------

def check_zip(path: Path) -> Tuple[bool, str, Dict]:
    """(ok, reason if not ok, summary). Reads only the zip's directory, never extracts."""
    try:
        with zipfile.ZipFile(path) as zf:
            infos = zf.infolist()
    except Exception as ex:  # a crafted zip can trip many errors (NotImplementedError, ValueError, EOFError...)
        return False, f"not a readable zip ({type(ex).__name__})", {}
    if len(infos) > MAX_ENTRIES:
        return False, f"too many files ({len(infos)})", {}
    total = sum(i.file_size for i in infos)
    packed = sum(i.compress_size for i in infos) or 1
    files = [i for i in infos if not i.is_dir()]
    summary = {
        "files": len(files),
        "unpacked_bytes": total,
        "programs": sum(1 for i in files if i.filename.lower().endswith(PROGRAM_EXTENSIONS)),
        "archives": sum(1 for i in files if i.filename.lower().endswith((".zip", ".7z", ".rar", ".tar", ".gz"))),
    }
    if any(i.flag_bits & 0x1 for i in infos):
        return False, "password-protected files can't be scanned", summary
    if total > MAX_UNCOMPRESSED_BYTES:
        return False, "unpacks to more than 4 GB", summary
    if total / packed > MAX_RATIO and total > 100 * 1024 * 1024:
        return False, "suspicious compression ratio (a zip bomb?)", summary
    return True, "", summary


# ---------- ClamAV ----------

# ClamAV skips (and passes) files over its limits, 100 MB by default: raise them past the largest
# post. deploy/clamav.sh sets the same limits for the daemon in clamd.conf.
CLAMSCAN_LIMITS = ["--max-filesize=2000M", "--max-scansize=4000M"]


def scanner_command(path: Path) -> Optional[List[str]]:
    custom = os.environ.get("GFC_CLAMSCAN", "").strip()
    if custom:
        return custom.split() + ["--no-summary", str(path)]
    if CLAMD_SOCKET.exists() and shutil.which("clamdscan"):
        # --fdpass: the daemon reads the open file, so it doesn't need access to the node's data dir
        return ["clamdscan", "--no-summary", "--fdpass", str(path)]
    if shutil.which("clamscan"):
        return ["clamscan", "--no-summary", "--scan-archive=yes", *CLAMSCAN_LIMITS, str(path)]
    return None


def run_clamav(path: Path) -> Tuple[str, str, str]:
    cmd = scanner_command(path)
    if not cmd:
        return UNAVAILABLE, "ClamAV isn't installed on this node", ""
    engine = Path(cmd[0]).name
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=SCAN_TIMEOUT_S)
    except (OSError, subprocess.TimeoutExpired) as ex:
        return ERROR, f"scan failed ({type(ex).__name__})", engine
    out = (r.stdout or "") + (r.stderr or "")
    if r.returncode == 0:
        return CLEAN, "", engine
    if r.returncode == 1:
        found = re.findall(r":\s*(\S+)\s+FOUND", out)
        return INFECTED, ", ".join(sorted(set(found))) or "malware found", engine
    return ERROR, out.strip().splitlines()[-1][:200] if out.strip() else f"exit {r.returncode}", engine


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _record(conn: sqlite3.Connection, seed_id: str, status: str, detail: str = "", engine: str = "",
            sha256: str = "", summary: Optional[Dict] = None):
    conn.execute(
        "INSERT INTO file_scans (seed_id, status, detail, engine, scanned_at, sha256, summary) VALUES (?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT(seed_id) DO UPDATE SET status = excluded.status, detail = excluded.detail, "
        "engine = excluded.engine, scanned_at = excluded.scanned_at, "
        "sha256 = CASE WHEN excluded.sha256 != '' THEN excluded.sha256 ELSE file_scans.sha256 END, "
        "summary = CASE WHEN excluded.summary != '' THEN excluded.summary ELSE file_scans.summary END",
        (seed_id, status, detail, engine, _now() if status != PENDING else "", sha256,
         json.dumps(summary) if summary else ""))


def mark_pending(seed_id: str, db_path: str = DB_PATH):
    conn = sqlite3.connect(db_path)
    try:
        init_tables(conn)
        _record(conn, seed_id, PENDING)
        conn.commit()
    finally:
        conn.close()


def scan_seed(seed_id: str, db_path: str = DB_PATH, runner: Runner = None) -> str:
    """Check and scan one download now (blocking). Returns its status."""
    conn = sqlite3.connect(db_path)
    try:
        init_tables(conn)
        row = conn.execute("SELECT filename FROM seeds WHERE id = ?", (seed_id,)).fetchone()
        if not row or not is_download(row[0]):
            return ""
        path = SEEDS_ORIG_DIR / row[0]
        if not path.is_file():
            prev = conn.execute("SELECT status FROM file_scans WHERE seed_id = ?", (seed_id,)).fetchone()
            if prev and prev[0] in REMOVED:
                return prev[0]  # already deleted on purpose
            _record(conn, seed_id, PENDING)  # a synced post whose file hasn't arrived yet
            conn.commit()
            return PENDING
        ok, reason, summary = check_zip(path)
        sha = _sha256(path)
        if not ok:
            status, detail, engine = REJECTED, reason, "zip check"
        else:
            status, detail, engine = (runner or run_clamav)(path)
        _record(conn, seed_id, status, detail, engine, sha, summary)
        conn.commit()
    finally:
        conn.close()
    if status in REMOVED:
        try:
            path.unlink()
        except OSError:
            pass
        print(f"[FileScan] {seed_id}: {status} ({detail}); file removed")
    return status


def _work():
    while True:
        seed_id = _queue.get()
        try:
            scan_seed(seed_id)  # run_clamav resolved at call time, so tests can swap it
        except Exception as ex:
            print(f"[FileScan] {seed_id}: {type(ex).__name__}")
        finally:
            _queue.task_done()


def enqueue(seed_id: str, db_path: str = DB_PATH):
    """Mark a download pending and scan it in the background, one at a time."""
    global _worker
    mark_pending(seed_id, db_path)
    with _worker_lock:
        if _worker is None or not _worker.is_alive():
            _worker = threading.Thread(target=_work, name="gfc-file-scan", daemon=True)
            _worker.start()
    _queue.put(seed_id)


def rescan_all(db_path: str = DB_PATH, runner: Runner = None) -> Dict[str, int]:
    """Rescan every download whose file is still here (daily, after the definitions update)."""
    conn = sqlite3.connect(db_path)
    try:
        init_tables(conn)
        rows = conn.execute("SELECT id, filename FROM seeds").fetchall()
    finally:
        conn.close()
    counts: Dict[str, int] = {}
    for seed_id, filename in rows:
        if is_download(filename) and (SEEDS_ORIG_DIR / filename).is_file():
            status = scan_seed(seed_id, db_path, runner)
            counts[status] = counts.get(status, 0) + 1
    return counts


# ---------- who gets what ----------

def status_of(conn: sqlite3.Connection, seed_id: str) -> Optional[Dict]:
    init_tables(conn)
    row = conn.execute("SELECT status, detail, engine, scanned_at, sha256, summary FROM file_scans WHERE seed_id = ?",
                       (seed_id,)).fetchone()
    if not row:
        return None
    return {"status": row[0], "detail": row[1], "engine": row[2], "scanned_at": row[3], "sha256": row[4],
            "summary": json.loads(row[5]) if row[5] else {}}


def downloadable(status: Optional[str]) -> bool:
    """Clean, or (test networks only) not scannable here."""
    return status == CLEAN or (status == UNAVAILABLE and config.IS_TESTNET)


def blocked(path: str, db_path: str = DB_PATH) -> Optional[str]:
    """For /originals/<file>: why it can't be downloaded yet, or None."""
    if not path.startswith(GATED_PREFIX) or not is_download(path):
        return None
    from urllib.parse import unquote
    name = unquote(path[len(GATED_PREFIX):])
    conn = sqlite3.connect(db_path)
    try:
        init_tables(conn)
        row = conn.execute("SELECT f.status FROM seeds s LEFT JOIN file_scans f ON f.seed_id = s.id "
                           "WHERE s.filename = ?", (name,)).fetchone()
    finally:
        conn.close()
    if row is None:
        return None  # not a post's file (static files 404 as usual)
    status = row[0] or PENDING
    if downloadable(status):
        return None
    if status in REMOVED:
        return "This file was removed: it failed the virus or safety check."
    return "This download is still being checked for viruses. Try again in a few minutes."


def apply_to_items(items: Iterable[Dict], db_path: str = DB_PATH) -> List[Dict]:
    """
    Add `download` to zip posts in feed/seed JSON ({name, size, status, scanned_at, engine,
    sha256, files, programs}), hide the file link until it's clean, and drop removed ones.
    """
    out = []
    items = list(items)
    if not items:
        return items
    conn = sqlite3.connect(db_path)
    try:
        init_tables(conn)
        for item in items:
            full = item.get("full") or ""
            row = None
            if item.get("id") and (is_download(full) or (item.get("exclusive") and not full)):
                row = conn.execute("SELECT s.filename, s.file_size, f.status, f.scanned_at, f.engine, f.sha256, f.summary "
                                   "FROM seeds s LEFT JOIN file_scans f ON f.seed_id = s.id WHERE s.id = ?",
                                   (item["id"],)).fetchone()
            if not row or not is_download(row[0]):
                out.append(item)
                continue
            filename, size, status, scanned_at, engine, sha, summary = row
            status = status or PENDING
            if status in REMOVED:
                continue  # removed downloads leave the feed
            info = json.loads(summary) if summary else {}
            item["download"] = {
                "name": filename.split("_", 1)[1] if "_" in filename else filename,
                "size": size, "status": status, "scanned_at": scanned_at or "", "engine": engine or "",
                "sha256": sha or "", "files": info.get("files"), "programs": info.get("programs"),
            }
            if not downloadable(status):
                item["full"] = None
            out.append(item)
    finally:
        conn.close()
    return out


def _cli(argv: List[str]) -> int:
    if argv == ["rescan"]:
        counts = rescan_all()
        print("Rescanned downloads: " + (", ".join(f"{k or 'skipped'} {v}" for k, v in sorted(counts.items())) or "none"))
        return 0
    if len(argv) == 2 and argv[0] == "scan":
        print(scan_seed(argv[1]) or "not a download")
        return 0
    print("usage: python filescan.py rescan | scan <seed_id>")
    return 2


if __name__ == "__main__":
    raise SystemExit(_cli(sys.argv[1:]))
