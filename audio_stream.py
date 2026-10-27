"""
GFC Media Streams - compressed, phone-ready streaming copies of audio and video uploads

Phones shouldn't pull a 55 MB WAV every listen, or a 20 Mbit/s sideways phone video.
The node makes a streaming copy next to the original and serves it at /streams/:

- audio  that is lossless (.wav, .flac, .aiff, .aif) or bigger than STREAM_MIN_BYTES:
         AAC-LC .m4a, 160 kbps                                -> /streams/<seed_id>.m4a
- video  every upload: H.264 .mp4, shorter side at most 720 px, about 2.5 Mbit/s,
         AAC audio. Phone videos are often stored sideways with a "rotate 90" note
         that some players ignore; the copy has the rotation applied to the pixels
         (ffmpeg's autorotate) and no rotate note left, so every player shows it
         upright                                              -> /streams/<seed_id>.mp4

Both use "faststart" so playback can begin before the file has fully downloaded.
The original is never changed or removed: the feed keeps "full" pointing at it and
adds "stream" when the copy exists, and clients prefer "stream" for playback.

- Transcoding runs with ffmpeg in one background worker, one job at a time, at low
  CPU priority, with a timeout. ffmpeg missing: logged once, nothing else changes.
- Output is written to a temp file and renamed into place, so a half-made copy is
  never served. The command is an argument list (no shell); paths come from the
  node's own storage, keyed by seed ID.
- On startup the node backfills copies for audio and video seeds that need one.

Config (environment):
- GFC_AUDIO_STREAMS=0         turn the feature off (audio and video)
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

STREAM_KINDS = ("audio", "video")
EXTENSIONS = {"audio": ".m4a", "video": ".mp4"}
LOSSLESS_EXTENSIONS = (".wav", ".flac", ".aiff", ".aif")
STREAM_MIN_BYTES = 8 * 1024 * 1024   # compressed audio gets a copy only above this size
AUDIO_BITRATE = "160k"
STREAM_BITRATE = AUDIO_BITRATE      # kept for older imports
VIDEO_MAX_SHORT_SIDE = 720
VIDEO_MAXRATE = "2500k"
TRANSCODE_TIMEOUT_S = 30 * 60

_queue: "queue.Queue[tuple]" = queue.Queue()
_worker: Optional[threading.Thread] = None
_worker_lock = threading.Lock()
_warned_missing = False

# Tests replace this; the default runs ffmpeg. Called as runner(src, dest).
Runner = Callable[[Path, Path], None]


def enabled() -> bool:
    return os.environ.get("GFC_AUDIO_STREAMS", "1").strip().lower() not in ("0", "false", "no", "off")


def ffmpeg_path() -> Optional[str]:
    configured = os.environ.get("GFC_FFMPEG", "").strip()
    if configured:
        return configured if Path(configured).exists() else None
    return shutil.which("ffmpeg")


def stream_path(seed_id: str, content_type: str = "audio") -> Path:
    # Seed IDs are hex/uuid-ish; refuse anything that could leave the directory
    safe = "".join(c for c in seed_id if c.isalnum() or c in "-_")
    if not safe or safe != seed_id:
        raise ValueError("bad seed id")
    if content_type not in EXTENSIONS:
        raise ValueError("no streaming copies for this content type")
    return STREAMS_DIR / f"{safe}{EXTENSIONS[content_type]}"


def stream_url(seed_id: str, content_type: str = "audio") -> Optional[str]:
    """The /streams URL of a seed's streaming copy, or None if there isn't one (yet)."""
    try:
        path = stream_path(seed_id, content_type)
    except ValueError:
        return None
    return f"/streams/{path.name}" if path.exists() else None


def needs_stream(filename: str, size_bytes: int, content_type: str = "audio") -> bool:
    if content_type == "video":
        return True  # always: upright, phone-sized, bitrate-capped
    if content_type != "audio":
        return False
    name = (filename or "").lower()
    return name.endswith(LOSSLESS_EXTENSIONS) or (size_bytes or 0) > STREAM_MIN_BYTES


def _ffmpeg_args(content_type: str, src: Path, dest: Path, exe: str) -> list:
    head = [exe, "-nostdin", "-hide_banner", "-loglevel", "error", "-y", "-i", str(src), "-map_metadata", "-1"]
    if content_type == "video":
        short = VIDEO_MAX_SHORT_SIDE
        # Rotation is applied before the filter (autorotate), so iw/ih are the upright size.
        # Scale the shorter side down to <= 720 px, keep the aspect ratio, even dimensions.
        scale = (f"scale=w='if(gt(iw,ih),-2,min({short},iw))':"
                 f"h='if(gt(iw,ih),min({short},ih),-2)'")
        return head + ["-map", "0:v:0", "-map", "0:a:0?", "-vf", scale,
                       "-c:v", "libx264", "-preset", "veryfast", "-crf", "23",
                       "-maxrate", VIDEO_MAXRATE, "-bufsize", "5000k",
                       "-pix_fmt", "yuv420p", "-profile:v", "high",
                       "-metadata:s:v:0", "rotate=0",
                       "-c:a", "aac", "-b:a", "128k",
                       "-movflags", "+faststart", "-f", "mp4", str(dest)]
    return head + ["-vn", "-c:a", "aac", "-b:a", AUDIO_BITRATE,
                   "-movflags", "+faststart", "-f", "mp4", str(dest)]


def run_ffmpeg(src: Path, dest: Path) -> None:
    """Transcode src into dest (raises on failure). Video if dest is <id>.mp4[.part]."""
    content_type = "video" if ".mp4" in dest.name else "audio"
    exe = ffmpeg_path()
    if not exe:
        raise FileNotFoundError("ffmpeg not installed")
    kwargs = {}
    if hasattr(os, "nice"):
        kwargs["preexec_fn"] = lambda: os.nice(10)  # don't starve the API
    subprocess.run(_ffmpeg_args(content_type, src, dest, exe), check=True, timeout=TRANSCODE_TIMEOUT_S,
                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, **kwargs)


def make_stream(seed_id: str, filename: str, runner: Runner = None, content_type: str = "audio") -> bool:
    """Create the streaming copy now (synchronously). True if it exists afterwards."""
    dest = stream_path(seed_id, content_type)
    if dest.exists():
        return True
    src = SEEDS_ORIG_DIR / filename
    if not src.is_file():
        return False
    tmp = dest.with_name(dest.name + ".part")
    try:
        (runner or run_ffmpeg)(src, tmp)
        if not tmp.is_file() or tmp.stat().st_size == 0:
            raise RuntimeError("transcoder produced no output")
        os.replace(tmp, dest)
        print(f"[MediaStream] {seed_id} ({content_type}): {src.stat().st_size / 1048576:.1f} MB -> "
              f"{dest.stat().st_size / 1048576:.1f} MB streaming copy")
        return True
    except FileNotFoundError:
        global _warned_missing
        if not _warned_missing:
            print("[MediaStream] ffmpeg not found: audio and video are served as uploaded (install ffmpeg)")
            _warned_missing = True
        return False
    except Exception as ex:
        print(f"[MediaStream] {seed_id} ({content_type}): transcode failed: {type(ex).__name__}")
        return False
    finally:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass


def _work():
    while True:
        seed_id, filename, content_type = _queue.get()
        try:
            # Resolved at call time so tests can swap the transcoder
            make_stream(seed_id, filename, runner=run_ffmpeg, content_type=content_type)
        finally:
            _queue.task_done()


def enqueue(seed_id: str, filename: str, content_type: str, size_bytes: int) -> bool:
    """Queue a streaming copy for an audio/video seed if it needs one. Returns True if queued."""
    global _worker
    if not enabled() or content_type not in STREAM_KINDS or not needs_stream(filename, size_bytes, content_type):
        return False
    try:
        if stream_path(seed_id, content_type).exists():
            return False
    except ValueError:
        return False
    with _worker_lock:
        if _worker is None or not _worker.is_alive():
            _worker = threading.Thread(target=_work, name="gfc-media-stream", daemon=True)
            _worker.start()
    _queue.put((seed_id, filename, content_type))
    return True


def backfill(db_path: str = DB_PATH) -> int:
    """Queue copies for existing audio/video seeds that need one. Returns how many were queued."""
    if not enabled():
        return 0
    conn = sqlite3.connect(db_path)
    try:
        rows = conn.execute("SELECT id, filename, content_type, file_size FROM seeds "
                            "WHERE content_type IN ('audio', 'video') ORDER BY created_at").fetchall()
    finally:
        conn.close()
    return sum(1 for sid, fn, ct, size in rows if enqueue(sid, fn or "", ct, size or 0))
