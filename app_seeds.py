import re
import uuid
import sqlite3
import datetime
from pathlib import Path
from typing import Optional, Dict, Any, List

from fastapi import APIRouter, UploadFile, File, Form, HTTPException, Depends

import first_post
import moderation
import reposts
import audio_stream
import config
import phone_verify
import signing
from security import Caller, caller_from_form, caller_from_query
from config import DB_PATH, SEEDS_ORIG_DIR as ORIG_DIR, SEEDS_THUMB_DIR as THUMB_DIR

router = APIRouter()

# ---------- helpers ----------
SAFE_RE = re.compile(r"[^A-Za-z0-9._+-]")

# Content type detection by file extension
CONTENT_TYPE_MAP = {
    "image": {".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".tiff", ".tga"},
    "video": {".mp4", ".mov", ".avi", ".webm", ".mkv", ".wmv", ".flv"},
    "audio": {".mp3", ".wav", ".ogg", ".flac", ".aac", ".wma", ".m4a"},
    "3d":    {".glb", ".gltf", ".fbx", ".obj", ".usdz", ".stl", ".3ds"},
}

def detect_content_type(filename: str) -> str:
    """Detect content type from file extension."""
    ext = Path(filename).suffix.lower()
    for ctype, extensions in CONTENT_TYPE_MAP.items():
        if ext in extensions:
            return ctype
    return "other"


def safe_name(name: str) -> str:
    """
    Return a filename that is safe to store on disk.
    Keeps common characters, strips others. Preserves extension where possible.
    """
    if not name:
        return "file"
    name = name.replace("\\", "/").split("/")[-1]  # strip any path
    if "." in name:
        stem = ".".join(name.split(".")[:-1])
        ext  = name.split(".")[-1]
        stem = SAFE_RE.sub("_", stem).strip("._")
        ext  = SAFE_RE.sub("", ext)
        return (stem or "file") + ("." + ext if ext else "")
    return SAFE_RE.sub("_", name)

def seed_row(sid: str, orig_file: str) -> Dict[str, Any]:
    """
    Build a row for /seeds list from filesystem (fallback for pre-DB seeds).
    """
    title = orig_file
    full  = f"/originals/{orig_file}"
    thumb_name = f"{sid}_thumb.jpg"
    thumb = f"/thumbs/{thumb_name}" if (THUMB_DIR / thumb_name).exists() else None
    return {
        "id":           sid,
        "title":        title,
        "thumb":        thumb,
        "full":         full,
        "owner":        "anonymous",
        "content_type": detect_content_type(orig_file),
        "file_size":    0,
        "gfc_earned":   0.0,
        "comments":     0,
        "likes":        0,
        "views":        0,
        "created_at":   "",
    }

def _repost_map() -> Dict[str, Any]:
    """{seed_id: repost_of} for reposts on this node (empty if the tables aren't there)."""
    try:
        conn = sqlite3.connect(DB_PATH)
        try:
            return reposts.repost_map(conn)
        finally:
            conn.close()
    except Exception:
        return {}


def list_rows() -> List[Dict[str, Any]]:
    """List all seeds - pulls from DB first, falls back to filesystem."""
    # Try DB first
    try:
        conn = sqlite3.connect(DB_PATH)
        rows = conn.execute(
            "SELECT seeds.id, seeds.title, seeds.description, seeds.tags, seeds.filename, seeds.thumb_filename, seeds.content_type, "
            "seeds.file_size, COALESCE((SELECT SUM(reward_cents) FROM podt_proofs WHERE podt_proofs.seed_id = seeds.id), 0) / 100.0 AS live_gfc_earned, "
            "(SELECT COUNT(*) FROM likes WHERE likes.seed_id = seeds.id), "
            "(SELECT COUNT(*) FROM comments WHERE comments.seed_id = seeds.id), "
            "seeds.views, seeds.created_at, seeds.owner, seeds.reward_wallet, "
            "COALESCE(users.avatar_filename, '') AS owner_avatar_filename "
            "FROM seeds LEFT JOIN users ON LOWER(seeds.owner) = LOWER(users.username) "
            "ORDER BY seeds.created_at DESC"
        ).fetchall()
        conn.close()
        if rows:
            items = []
            repost_of = _repost_map()
            for r in rows:
                avatar_filename = r[15] if len(r) > 15 else ""
                owner_avatar = f"/avatars/{avatar_filename}" if avatar_filename else ""
                items.append({
                    "id": r[0], "title": r[1] or r[4], "description": r[2],
                    "tags": [t.strip() for t in r[3].split(",") if t.strip()] if r[3] else [],
                    "full": f"/originals/{r[4]}",
                    "thumb": f"/thumbs/{r[5]}" if r[5] else None,
                    "content_type": r[6], "file_size": r[7],
                    "gfc_earned": r[8], "likes": r[9], "comments": r[10],
                    "views": r[11], "created_at": r[12], "owner": r[13],
                    "reward_wallet": r[14] or "",
                    "owner_avatar": owner_avatar,
                    "repost_of": repost_of.get(r[0]),
                })
            return items
    except Exception:
        pass

    # Fallback: scan filesystem (for pre-DB seeds)
    items: List[Dict[str, Any]] = []
    if not ORIG_DIR.exists():
        return items
    for p in ORIG_DIR.iterdir():
        if not p.is_file():
            continue
        if p.name.startswith("."):
            continue
        sid = p.name.split("_", 1)[0] if "_" in p.name else p.stem
        items.append(seed_row(sid, p.name))
    return items

# ---------- routes ----------

PHONE_REQUIRED_DETAIL = "Verify your phone number to post on the GFC network."


def require_phone_to_post(owner: str):
    """On the real network, only logged-in, phone-verified accounts can post (see config.py)."""
    if not config.REQUIRE_PHONE_TO_POST:
        return
    if owner == "anonymous":
        raise HTTPException(status_code=401, detail="Log in to post.")
    conn = sqlite3.connect(DB_PATH)
    try:
        phone_verify.init_phone_tables(conn)
        verified = phone_verify.is_verified(conn, owner)
    finally:
        conn.close()
    if not verified:
        raise HTTPException(status_code=403, detail=PHONE_REQUIRED_DETAIL)


@router.post("/seeds/upload")
async def seeds_upload(
    file: UploadFile = File(...),
    thumbnail: Optional[UploadFile] = File(None),
    title: str = Form(""),
    description: str = Form(""),
    tags: str = Form(""),
    reward_wallet: str = Form(""),
    caller: Caller = Depends(caller_from_form),
):
    """
    Accepts a multipart upload:
      - file          : required (original asset)
      - thumbnail     : optional (client-made JPG)
      - title         : optional
      - description   : optional
      - tags          : optional (comma separated)
      - Authorization : optional Bearer token with the post scope (or legacy api_token field)
      - reward_wallet : optional (one of your wallets on this node; defaults to
                        your oldest one). The wallet signs the seed, and rewards are
                        only ever paid to it. Without a signing wallet the seed is
                        still shared but earns no rewards.

    If the file matches content that was notarised earlier (see reposts.py), the
    seed is still shared but becomes a repost: `repost_of` names the original, and
    all its earnings go to the original creator.

    On the real network (config.REQUIRE_PHONE_TO_POST) the account must be logged in
    (401 otherwise) and phone-verified (403 otherwise). Test networks allow anyone.

    The account's first original seed earns the first post bonus (see first_post.py):
    the response then has `first_post_bonus` (GFC), plus `first_post_bonus_pending: true`
    when it's waiting for a wallet or a verified phone. Both are absent otherwise.
    """
    if not file:
        raise HTTPException(status_code=400, detail="file missing")

    owner = caller.owner("post")
    require_phone_to_post(owner)

    # Pick the signing wallet: must be the owner's, with its key on this node
    conn = sqlite3.connect(DB_PATH)
    try:
        signer_wallet = signing.local_wallet_for(conn, owner, reward_wallet.strip())             if owner != "anonymous" else None
    finally:
        conn.close()
    if reward_wallet.strip() and not signer_wallet:
        raise HTTPException(status_code=400, detail="reward_wallet must be one of your wallets on this node")
    reward_wallet = signer_wallet or ""
    private_key = None
    if reward_wallet:
        private_key = signing.get_wallet_private_key(DB_PATH, reward_wallet, caller.data_key())
        if not private_key:
            raise HTTPException(status_code=401, detail="log in again to unlock your wallet key")

    # Generate id and safe filename. Signed seeds get an ID bound to their reward wallet.
    nonce = uuid.uuid4().hex[:12]
    orig_safe = f"{nonce}_{safe_name(file.filename or 'seed.bin')}"
    sid = signing.seed_id_for(reward_wallet, orig_safe) if reward_wallet else nonce
    orig_path = ORIG_DIR / orig_safe

    # Persist original
    try:
        raw = await file.read()
        orig_path.write_bytes(raw)
    except Exception as ex:
        raise HTTPException(status_code=500, detail=f"failed to save file: {ex}")

    file_size = len(raw)
    content_type = detect_content_type(file.filename or "")
    final_title = title or safe_name(file.filename or "")

    # Persist thumbnail (if present)
    thumb_url = None
    thumb_filename = ""
    if thumbnail is not None:
        try:
            th_raw = await thumbnail.read()
            thumb_filename = f"{sid}_thumb.jpg"
            (THUMB_DIR / thumb_filename).write_bytes(th_raw)
            thumb_url = f"/thumbs/{thumb_filename}"
        except Exception:
            thumb_url = None
            thumb_filename = ""

    # Store metadata in database
    created_at = datetime.datetime.utcnow().isoformat()
    tags_str = tags.strip() if tags else ""
    signature = ""
    if reward_wallet:
        signature = signing.sign_seed(private_key, {
            "id": sid, "owner": owner, "filename": orig_safe, "file_size": file_size,
            "created_at": created_at, "reward_wallet": reward_wallet})
    stored = False
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute(
            "INSERT INTO seeds (id, owner, title, description, tags, filename, "
            "thumb_filename, content_type, file_size, gfc_earned, created_at, reward_wallet, signature) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (sid, owner, final_title, description, tags_str, orig_safe,
             thumb_filename, content_type, file_size, 0.0, created_at,
             reward_wallet, signature)
        )
        conn.commit()
        conn.close()
        stored = True
    except Exception as ex:
        # Log but don't fail - file is already saved
        print(f"Warning: failed to insert seed metadata: {ex}")

    # Repost check: a match makes this a repost of the original (credit and earnings go
    # there); otherwise a treasury node notarises it as an original. See reposts.py.
    repost_info, repost_credit = None, None
    try:
        original = reposts.process_seed(DB_PATH, sid)
        if original:
            repost_info = reposts.public_info(original)
            repost_credit = reposts.maybe_credit(DB_PATH, owner, sid, original)
    except Exception as ex:
        print(f"Warning: repost check failed for seed {sid}: {ex}")

    # Big or lossless audio, and every video, gets a streaming copy in the background (audio_stream.py)
    stream_pending = False
    if stored:
        try:
            stream_pending = audio_stream.enqueue(sid, orig_safe, content_type, file_size)
        except Exception as ex:
            print(f"Warning: media stream queueing failed for seed {sid}: {ex}")

    bonus = None
    if stored:
        try:
            bonus = first_post.on_upload(DB_PATH, owner, sid, is_repost=repost_info is not None)
        except Exception as ex:
            print(f"Warning: first post bonus failed for seed {sid}: {ex}")

    result = {
        "ok": True,
        "id": sid,
        "title": final_title,
        "desc": description,
        "tags": [t.strip() for t in tags_str.split(",") if t.strip()] if tags_str else [],
        "thumb": thumb_url,
        "full":  f"/originals/{orig_safe}",
        "stream_pending": stream_pending,
        "owner": owner,
        "content_type": content_type,
        "file_size": file_size,
        "gfc_earned": 0.0,
        "created_at": created_at,
        "reward_wallet": reward_wallet,
        "rewards_enabled": bool(signature),
        "repost_of": repost_info,
        "repost_credit_gfc": repost_credit["amount"] if repost_credit else 0.0,
    }
    if bonus:
        result["first_post_bonus"] = bonus["amount"]
        if bonus["pending"]:
            result["first_post_bonus_pending"] = True
    return result

@router.get("/seeds/mine")
def my_seeds(caller: Caller = Depends(caller_from_query)):
    """Return seeds uploaded by the authenticated user."""
    owner = caller.owner("read")
    if owner == "anonymous":
        return {"items": []}

    try:
        conn = sqlite3.connect(DB_PATH)
        rows = conn.execute(
            "SELECT seeds.id, seeds.title, seeds.description, seeds.tags, seeds.filename, seeds.thumb_filename, seeds.content_type, "
            "seeds.file_size, COALESCE((SELECT SUM(reward_cents) FROM podt_proofs WHERE podt_proofs.seed_id = seeds.id), 0) / 100.0 AS live_gfc_earned, "
            "(SELECT COUNT(*) FROM likes WHERE likes.seed_id = seeds.id), "
            "(SELECT COUNT(*) FROM comments WHERE comments.seed_id = seeds.id), "
            "seeds.views, seeds.created_at, seeds.reward_wallet, "
            "COALESCE(users.avatar_filename, '') AS owner_avatar_filename "
            "FROM seeds LEFT JOIN users ON LOWER(seeds.owner) = LOWER(users.username) "
            "WHERE seeds.owner = ? ORDER BY seeds.created_at DESC",
            (owner,)
        ).fetchall()
        conn.close()
    except Exception:
        return {"items": []}

    items = []
    repost_of = _repost_map()
    for r in rows:
        avatar_filename = r[14] if len(r) > 14 else ""
        owner_avatar = f"/avatars/{avatar_filename}" if avatar_filename else ""
        items.append({
            "id": r[0], "title": r[1], "description": r[2],
            "tags": [t.strip() for t in r[3].split(",") if t.strip()] if r[3] else [],
            "full": f"/originals/{r[4]}",
            "thumb": f"/thumbs/{r[5]}" if r[5] else None,
            "content_type": r[6], "file_size": r[7],
            "gfc_earned": r[8], "likes": r[9], "comments": r[10],
            "views": r[11], "owner": owner, "created_at": r[12],
            "reward_wallet": r[13] or "",
            "owner_avatar": owner_avatar,
            "repost_of": repost_of.get(r[0]),
        })
    return {"items": items}

@router.get("/seeds")
def list_seeds():
    """Return all seeds in feed-friendly shape (without posts hidden after reports)."""
    conn = sqlite3.connect(DB_PATH)
    try:
        return {"items": moderation.visible_items(conn, list_rows())}
    finally:
        conn.close()

@router.get("/seeds/{sid}")
def get_seed(sid: str):
    """Return a single seed by id (410 if it was hidden after reports)."""
    conn = sqlite3.connect(DB_PATH)
    try:
        hidden = moderation.is_hidden(conn, sid)
    finally:
        conn.close()
    if hidden:
        raise HTTPException(status_code=410, detail="This post was hidden after reports.")
    # Try DB first
    try:
        conn = sqlite3.connect(DB_PATH)
        row = conn.execute(
            "SELECT seeds.id, seeds.title, seeds.description, seeds.tags, seeds.filename, seeds.thumb_filename, seeds.content_type, "
            "seeds.file_size, COALESCE((SELECT SUM(reward_cents) FROM podt_proofs WHERE podt_proofs.seed_id = seeds.id), 0) / 100.0 AS live_gfc_earned, "
            "(SELECT COUNT(*) FROM likes WHERE likes.seed_id = seeds.id), "
            "(SELECT COUNT(*) FROM comments WHERE comments.seed_id = seeds.id), "
            "seeds.views, seeds.created_at, seeds.owner, seeds.reward_wallet, "
            "COALESCE(users.avatar_filename, '') AS owner_avatar_filename "
            "FROM seeds LEFT JOIN users ON LOWER(seeds.owner) = LOWER(users.username) "
            "WHERE seeds.id = ?", (sid,)
        ).fetchone()
        conn.close()
        if row:
            avatar_filename = row[15] if len(row) > 15 else ""
            owner_avatar = f"/avatars/{avatar_filename}" if avatar_filename else ""
            return {
                "id": row[0], "title": row[1], "description": row[2],
                "tags": [t.strip() for t in row[3].split(",") if t.strip()] if row[3] else [],
                "full": f"/originals/{row[4]}",
                "thumb": f"/thumbs/{row[5]}" if row[5] else None,
                "content_type": row[6], "file_size": row[7],
                "gfc_earned": row[8], "likes": row[9], "comments": row[10],
                "views": row[11], "created_at": row[12], "owner": row[13],
                "reward_wallet": row[14] or "",
                "owner_avatar": owner_avatar,
                "repost_of": _repost_map().get(row[0]),
            }
    except Exception:
        pass

    # Fallback: filesystem scan
    try:
        matches = [p for p in ORIG_DIR.iterdir() if p.is_file() and p.name.startswith(f"{sid}_")]
        if not matches:
            raise HTTPException(status_code=404, detail="seed not found")
        p = matches[0]
        return seed_row(sid, p.name)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="seed not found")
