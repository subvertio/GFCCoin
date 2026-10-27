"""
GFC Audio Streams - a compressed streaming copy of big or lossless audio uploads

Phones shouldn't pull a 55 MB WAV every listen. For an audio seed that is lossless
(.wav, .flac, .aiff, .aif) or bigger than STREAM_MIN_BYTES, the node makes an
AAC-LC copy (.m4a, 160 kbps, "faststart" so playback can begin before the file has
fully downloaded) next to the original:

    seeds/streams/<seed_id>.m4a   served at /streams/<seed_id>.m4a

The original is never changed or removed: the feed keeps "full" pointing at it and
adds "stream" when the copy exists, and clients prefer "stream" for playback.

- Transcoding runs with ffmpeg in one background worker, one job at a time, at low
  CPU priority, with a timeout. ffmpeg missing: logged once, nothing else changes.
- Output is written to a temp file and renamed into place, so a half-made copy is
  never served. The command is an argument list (no shell); paths come from the
  node's own storage, keyed by seed ID.
- On startup the node backfills copies for audio seeds that need one.

Config (environment):
- GFC_AUDIO_STREAMS=0         turn the feature off
- GFC_FFMPEG=<path>           ffmpeg binary (default: "ffmpeg" on PATH)
"""

import os
import queue
import shutil
import sqlite3
import subprocess
import threading
from pathlib import Path
from typing import Callable, Optional

from config import DATA_DIR, DB_PATH, SEEDS_ORIG_DIR

STREAMS_DIR = DATA_DIR / "seeds" / "streams"
STREAMS_DIR.mkdir(parents=True, exist_ok=True)

LOSSLESS_EXTENSIONS = (".wav", ".flac", ".aiff", ".aif")
STREAM_MIN_BYTES = 8 * 1024 * 1024   # compressed formats get a copy only above this size
STREAM_BITRATE = "160k"
TRANSCODE_TIMEOUT_S = 15 * 60

_queue: "queue.Queue[tuple]" = queue.Queue()
_worker: Optional[threading.Thread] = None
_worker_lock = threading.Lock()
_warned_missing = False

# Tests replace this; the default runs ffmpeg.
Runner = Callable[[Path, Path], None]


def enabled() -> bool:
    return os.environ.get("GFC_AUDIO_STREAMS", "1").strip().lower() not in ("0", "false", "no", "off")


def ffmpeg_path() -> Optional[str]:
    configured = os.environ.get("GFC_FFMPEG", "").strip()
    if configured:
        return configured if Path(configured).exists() else None
    return shutil.which("ffmpeg")


def stream_path(seed_id: str) -> Path:
    # Seed IDs are hex/uuid-ish; refuse anything that could leave the directory
    safe = "".join(c for c in seed_id if c.isalnum() or c in "-_")
    if not safe or safe != seed_id:
        raise ValueError("bad seed id")
    return STREAMS_DIR / f"{safe}.m4a"


def stream_url(seed_id: str) -> Optional[str]:
    """The /streams URL for a seed's compressed copy, or None if there isn't one (yet)."""
    try:
        return f"/streams/{seed_id}.m4a" if stream_path(seed_id).exists() else None
    except ValueError:
        return None


def needs_stream(filename: str, size_bytes: int) -> bool:
    name = (filename or "").lower()
    return name.endswith(LOSSLESS_EXTENSIONS) or (size_bytes or 0) > STREAM_MIN_BYTES


def run_ffmpeg(src: Path, dest: Path) -> None:
    """Transcode src to AAC-LC .m4a at dest (raises on failure)."""
    exe = ffmpeg_path()
    if not exe:
        raise FileNotFoundError("ffmpeg not installed")
    cmd = [exe, "-nostdin", "-hide_banner", "-loglevel", "error", "-y",
           "-i", str(src), "-vn", "-map_metadata", "-1",
           "-c:a", "aac", "-b:a", STREAM_BITRATE, "-movflags", "+faststart",
           "-f", "mp4", str(dest)]
    kwargs = {}
    if hasattr(os, "nice"):
        kwargs["preexec_fn"] = lambda: os.nice(10)  # don't starve the API
    subprocess.run(cmd, check=True, timeout=TRANSCODE_TIMEOUT_S,
                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, **kwargs)


def make_stream(seed_id: str, filename: str, runner: Runner = None) -> bool:
    """Create the compressed copy now (synchronously). True if it exists afterwards."""
    dest = stream_path(seed_id)
    if dest.exists():
        return True
    src = SEEDS_ORIG_DIR / filename
    if not src.is_file():
        return False
    tmp = dest.with_suffix(".m4a.part")
    try:
        (runner or run_ffmpeg)(src, tmp)
        if not tmp.is_file() or tmp.stat().st_size == 0:
            raise RuntimeError("transcoder produced no output")
        os.replace(tmp, dest)
        print(f"[AudioStream] {seed_id}: {src.stat().st_size / 1048576:.1f} MB -> "
              f"{dest.stat().st_size / 1048576:.1f} MB streaming copy")
        return True
    except FileNotFoundError:
        global _warned_missing
        if not _warned_missing:
            print("[AudioStream] ffmpeg not found: big audio is served as uploaded (install ffmpeg)")
            _warned_missing = True
        return False
    except Exception as ex:
        print(f"[AudioStream] {seed_id}: transcode failed: {type(ex).__name__}")
        return False
    finally:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass


def _work():
    while True:
        seed_id, filename = _queue.get()
        try:
            make_stream(seed_id, filename)
        finally:
            _queue.task_done()


def enqueue(seed_id: str, filename: str, content_type: str, size_bytes: int) -> bool:
    """Queue a streaming copy for an audio seed if it needs one. Returns True if queued."""
    global _worker
    if not enabled() or content_type != "audio" or not needs_stream(filename, size_bytes):
        return False
    try:
        if stream_path(seed_id).exists():
            return False
    except ValueError:
        return False
    with _worker_lock:
        if _worker is None or not _worker.is_alive():
            _worker = threading.Thread(target=_work, name="gfc-audio-stream", daemon=True)
            _worker.start()
    _queue.put((seed_id, filename))
    return True


def backfill(db_path: str = DB_PATH) -> int:
    """Queue copies for existing audio seeds that need one. Returns how many were queued."""
    if not enabled():
        return 0
    conn = sqlite3.connect(db_path)
    try:
        rows = conn.execute("SELECT id, filename, content_type, file_size FROM seeds "
                            "WHERE content_type = 'audio' ORDER BY created_at").fetchall()
    finally:
        conn.close()
    return sum(1 for sid, fn, ct, size in rows if enqueue(sid, fn or "", ct, size or 0))
