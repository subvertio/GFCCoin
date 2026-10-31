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

import json
import os
import queue
import shutil
import sqlite3
import subprocess
import threading
from pathlib import Path
from typing import Callable, Optional

from config import DATA_DIR, DB_PATH, SEEDS_ORIG_DIR, SEEDS_THUMB_DIR

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


def transcode_timeout(src: Path) -> int:
    """30 minutes, or 6 s per MB for big files (a 1 GB video on a 1-CPU server takes a while)."""
    try:
        size_mb = src.stat().st_size / 1048576
    except OSError:
        size_mb = 0
    return int(max(TRANSCODE_TIMEOUT_S, size_mb * 6))


def make_video_thumbnail(seed_id: str, db_path: str = DB_PATH, runner: Runner = None) -> bool:
    """
    A first-frame thumbnail for a video posted without one (apps can't read a 1 GB clip into
    memory to grab a frame). Taken from the streaming copy when there is one. True if made.
    """
    conn = sqlite3.connect(db_path)
    try:
        row = conn.execute("SELECT filename, COALESCE(thumb_filename, '') FROM seeds WHERE id = ? "
                           "AND content_type = 'video'", (seed_id,)).fetchone()
    finally:
        conn.close()
    if not row or row[1]:
        return False
    stream = stream_path(seed_id, "video")
    src = stream if stream.exists() else SEEDS_ORIG_DIR / row[0]
    if not src.is_file():
        return False
    name = f"{seed_id}_thumb.jpg"
    dest = SEEDS_THUMB_DIR / name
    try:
        SEEDS_THUMB_DIR.mkdir(parents=True, exist_ok=True)
        (runner or run_thumbnail_ffmpeg)(src, dest)
        if not dest.is_file() or dest.stat().st_size == 0:
            return False
    except Exception as ex:
        print(f"[MediaStream] {seed_id}: thumbnail failed: {type(ex).__name__}")
        return False
    conn = sqlite3.connect(db_path)
    try:
        conn.execute("UPDATE seeds SET thumb_filename = ? WHERE id = ? AND COALESCE(thumb_filename, '') = ''",
                     (name, seed_id))
        conn.commit()
    finally:
        conn.close()
    return True


def run_thumbnail_ffmpeg(src: Path, dest: Path) -> None:
    """One frame (1 s in, or the first for very short clips), at most 512 px wide, as JPEG."""
    exe = ffmpeg_path()
    if not exe:
        raise FileNotFoundError("ffmpeg not installed")
    for seek in ("1", "0"):
        subprocess.run([exe, "-nostdin", "-hide_banner", "-loglevel", "error", "-y", "-ss", seek, "-i", str(src),
                        "-frames:v", "1", "-vf", "scale='min(512,iw)':-2", "-q:v", "4", str(dest)],
                       check=True, timeout=120, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        if dest.is_file() and dest.stat().st_size:
            return


# ---------- optimising oversized originals (same resolution, same look) ----------
#
# Phones record far more bits than a picture needs (a 5-minute 1080p clip can be 1 GB, about
# 27 Mbit/s). A video well over the ceiling for its resolution is re-encoded at the same size
# and frame rate with H.264 CRF 20 (visually lossless) under that ceiling, and replaces the
# original only if it's at least 25% smaller. Anything already reasonable is left untouched.
OPTIMIZE_CRF = "20"
OPTIMIZE_MIN_SAVING = 0.25
# (max short side, bitrate ceiling in kbit/s): generous enough that quality isn't the limit
OPTIMIZE_CEILINGS = ((720, 5000), (1080, 10000), (1440, 16000), (2160, 35000), (10 ** 6, 60000))


def MAX_STORED_BYTES() -> int:
    import config
    return config.MAX_UPLOAD_BYTES


def ceiling_kbps(width: int, height: int) -> int:
    short = min(width, height) or 1080
    return next(kbps for side, kbps in OPTIMIZE_CEILINGS if short <= side)


def ffprobe_path() -> Optional[str]:
    exe = ffmpeg_path()
    if exe:
        probe = Path(exe).with_name(Path(exe).name.replace("ffmpeg", "ffprobe"))
        if probe.exists():
            return str(probe)
    return shutil.which("ffprobe")


def probe_video(src: Path) -> Optional[dict]:
    """{width, height, kbps, audio} of a video file, or None if ffprobe can't tell."""
    exe = ffprobe_path()
    if not exe:
        return None
    out = subprocess.run([exe, "-v", "error", "-show_entries", "format=duration,bit_rate:stream=codec_type,codec_name,width,height",
                          "-of", "json", str(src)], capture_output=True, timeout=60)
    if out.returncode:
        return None
    info = json.loads(out.stdout or b"{}")
    streams = info.get("streams") or []
    video = next((s for s in streams if s.get("codec_type") == "video"), None)
    audio = next((s for s in streams if s.get("codec_type") == "audio"), None)
    fmt = info.get("format") or {}
    try:
        kbps = int(fmt.get("bit_rate") or 0) / 1000 or src.stat().st_size * 8 / 1000 / float(fmt["duration"])
    except (KeyError, ValueError, ZeroDivisionError):
        return None
    if not video or not kbps:
        return None
    try:
        duration = float(fmt.get("duration") or 0)
    except ValueError:
        duration = 0.0
    return {"width": int(video.get("width") or 0), "height": int(video.get("height") or 0), "kbps": kbps,
            "duration": duration or src.stat().st_size * 8 / 1000 / kbps, "audio": (audio or {}).get("codec_name")}


OPTIMIZE_AUDIO_KBPS = 192


def estimated_optimized_bytes(info: dict, size: int) -> int:
    """
    About how big a video ends up after optimize_video (an upper bound: CRF 20 is usually under
    the ceiling). Videos that aren't oversized are kept as uploaded. The app does the same maths.
    """
    ceiling = ceiling_kbps(info["width"], info["height"])
    if info["kbps"] <= ceiling * 1.2:
        return size
    return int(info["duration"] * (ceiling + OPTIMIZE_AUDIO_KBPS) * 1000 / 8)


def target_mbps(duration: float, limit: int) -> float:
    """The highest video bitrate (Mbit/s, one decimal, rounded down) that keeps `duration` under `limit`."""
    return max(0.1, int((limit * 8 / 1000 / max(duration, 1) - OPTIMIZE_AUDIO_KBPS) / 100) / 10)


def bitrate_tip(info: dict, limit: int, size: int) -> str:
    """What to tell someone whose video would still be over `limit` after optimising (the app says the same)."""
    target = target_mbps(info["duration"], limit)
    short = min(info["width"], info["height"])
    # Below about 3 Mbit/s, 1080p and up looks soft: 720p at the same bitrate looks better
    res = (f", and at 720p (1280x720): at this bitrate it looks better than {short}p"
           if target < 3 and short > 720 else "")
    est = estimated_optimized_bytes(info, size) / 1024 ** 3
    return (f"Tip: lower the bitrate. This video would still be about {est:.2f} GB after GFC optimises it "
            f"({info['duration'] / 60:.0f} min at {info['width']}x{info['height']}), and posts can be up to "
            f"{limit / 1024 ** 3:.0f} GB. Export it at {target:.1f} Mbit/s or less (the video bitrate in your "
            f"editor's export settings){res}. Or split it into parts, then post them.")


def optimize_args(src: Path, dest: Path, info: dict, exe: str) -> list:
    ceiling = ceiling_kbps(info["width"], info["height"])
    # AAC audio is kept as it is; anything else becomes high-quality AAC
    audio = ["-c:a", "copy"] if info.get("audio") == "aac" else ["-c:a", "aac", "-b:a", "192k"]
    return [exe, "-nostdin", "-hide_banner", "-loglevel", "error", "-y", "-i", str(src),
            "-map", "0:v:0", "-map", "0:a:0?", "-c:v", "libx264", "-preset", "faster", "-crf", OPTIMIZE_CRF,
            "-maxrate", f"{ceiling}k", "-bufsize", f"{ceiling * 2}k", "-pix_fmt", "yuv420p",
            *audio, "-movflags", "+faststart", "-f", "mp4", str(dest)]


def run_optimize_ffmpeg(src: Path, dest: Path, info: dict) -> None:
    exe = ffmpeg_path()
    if not exe:
        raise FileNotFoundError("ffmpeg not installed")
    kwargs = {}
    if hasattr(os, "nice"):
        kwargs["preexec_fn"] = lambda: os.nice(10)  # don't starve the API
    subprocess.run(optimize_args(src, dest, info, exe), check=True, timeout=transcode_timeout(src) * 2,
                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, **kwargs)


def optimize_video(seed_id: str, filename: str, runner=None, prober=None) -> bool:
    """
    Re-encode an oversized original (same resolution and frame rate, visually lossless) and
    replace it if that saves at least OPTIMIZE_MIN_SAVING. True if the original was replaced.
    """
    src = SEEDS_ORIG_DIR / filename
    if not src.is_file():
        return False
    try:
        info = (prober or probe_video)(src)
    except Exception:
        info = None
    over_limit = src.stat().st_size > MAX_STORED_BYTES()
    if not info or (info["kbps"] <= ceiling_kbps(info["width"], info["height"]) * 1.2 and not over_limit):
        return False  # unknown, or not oversized: keep exactly what was uploaded
    tmp = src.with_name(f".{src.name}.optimizing.mp4")
    try:
        (runner or run_optimize_ffmpeg)(src, tmp, info)
        before, after = src.stat().st_size, tmp.stat().st_size if tmp.exists() else 0
        # Over the post limit, any saving counts (it was accepted on the promise of this copy)
        if not after or after > before * (1 if over_limit else 1 - OPTIMIZE_MIN_SAVING):
            return False
        os.replace(tmp, src)
        print(f"[MediaStream] {seed_id}: optimised {before / 1048576:.0f} MB -> {after / 1048576:.0f} MB "
              f"({info['kbps']:.0f} kbit/s at {info['width']}x{info['height']})")
        return True
    except Exception as ex:
        print(f"[MediaStream] {seed_id}: optimising failed: {type(ex).__name__}")
        return False
    finally:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass


def run_ffmpeg(src: Path, dest: Path) -> None:
    """Transcode src into dest (raises on failure). Video if dest is <id>.mp4[.part]."""
    content_type = "video" if ".mp4" in dest.name else "audio"
    exe = ffmpeg_path()
    if not exe:
        raise FileNotFoundError("ffmpeg not installed")
    kwargs = {}
    if hasattr(os, "nice"):
        kwargs["preexec_fn"] = lambda: os.nice(10)  # don't starve the API
    subprocess.run(_ffmpeg_args(content_type, src, dest, exe), check=True, timeout=transcode_timeout(src),
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
            if content_type == "video":
                optimize_video(seed_id, filename, runner=run_optimize_ffmpeg, prober=probe_video)
            make_stream(seed_id, filename, runner=run_ffmpeg, content_type=content_type)
            if content_type == "video":
                make_video_thumbnail(seed_id, runner=run_thumbnail_ffmpeg)
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
