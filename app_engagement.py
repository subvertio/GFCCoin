"""
GFC Engagement API - Comments, Likes, Bookmarks, Rich Feed, PoDT Playback
"""
import uuid
import hashlib
import sqlite3
import datetime
from typing import Optional, Dict, Any, List

from fastapi import APIRouter, HTTPException, Form, Query

from security import owner_from_token
from config import DB_PATH
from blockchain import process_podt_reward

router = APIRouter()


# ---------- helpers ----------



def seed_row_to_dict(row, owner_for_engagement: str = "") -> Dict[str, Any]:
    """Convert a seeds DB row to a JSON-friendly dict.
    Row columns: id, title, description, tags, filename, thumb_filename,
                 content_type, file_size, gfc_earned, likes, comments, views, created_at, owner,
                 owner_avatar_filename
    """
    avatar_filename = row[14] if len(row) > 14 else ""
    owner_avatar = f"/avatars/{avatar_filename}" if avatar_filename else ""
    d = {
        "id": row[0], "title": row[1] or row[4], "description": row[2],
        "tags": [t.strip() for t in row[3].split(",") if t.strip()] if row[3] else [],
        "full": f"/originals/{row[4]}",
        "thumb": f"/thumbs/{row[5]}" if row[5] else None,
        "content_type": row[6], "file_size": row[7],
        "gfc_earned": row[8], "likes": row[9], "comments": row[10],
        "views": row[11], "created_at": row[12], "owner": row[13],
        "owner_avatar": owner_avatar,
    }
    # Per-user engagement state defaults
    d["liked"] = False
    d["bookmarked"] = False
    return d


SEED_SELECT = (
    "SELECT seeds.id, seeds.title, seeds.description, seeds.tags, seeds.filename, seeds.thumb_filename, seeds.content_type, "
    "seeds.file_size, "
    "COALESCE((SELECT SUM(reward_cents) FROM podt_proofs WHERE podt_proofs.seed_id = seeds.id), 0) / 100.0 AS live_gfc_earned, "
    "(SELECT COUNT(*) FROM likes WHERE likes.seed_id = seeds.id) AS live_likes, "
    "(SELECT COUNT(*) FROM comments WHERE comments.seed_id = seeds.id) AS live_comments, "
    "seeds.views, seeds.created_at, seeds.owner, "
    "COALESCE(users.avatar_filename, '') AS owner_avatar_filename "
    "FROM seeds LEFT JOIN users ON LOWER(seeds.owner) = LOWER(users.username)"
)


# ---------- rich feed ----------

def get_feed_items(api_token: str = "") -> Dict[str, Any]:
    """Return all seeds with per-user liked/bookmarked state."""
    owner = owner_from_token(api_token)

    try:
        conn = sqlite3.connect(DB_PATH)
        rows = conn.execute(f"{SEED_SELECT} ORDER BY seeds.created_at DESC").fetchall()

        items = [seed_row_to_dict(r) for r in rows]

        # If authenticated, fetch user's likes and bookmarks in bulk
        if owner != "anonymous":
            liked_set = set()
            for r in conn.execute("SELECT seed_id FROM likes WHERE owner = ?", (owner,)).fetchall():
                liked_set.add(r[0])

            bookmarked_set = set()
            for r in conn.execute("SELECT seed_id FROM bookmarks WHERE owner = ?", (owner,)).fetchall():
                bookmarked_set.add(r[0])

            for item in items:
                item["liked"] = item["id"] in liked_set
                item["bookmarked"] = item["id"] in bookmarked_set

        conn.close()
    except Exception:
        items = []

    return {"items": items}


# ---------- comments ----------

@router.post("/seeds/{seed_id}/comments")
async def add_comment(
    seed_id: str,
    api_token: str = Form(""),
    text: str = Form("")
):
    """Add a comment to a seed."""
    owner = owner_from_token(api_token)
    if owner == "anonymous":
        raise HTTPException(status_code=401, detail="login required")
    if not text.strip():
        raise HTTPException(status_code=400, detail="comment text required")

    comment_id = uuid.uuid4().hex[:12]
    created_at = datetime.datetime.utcnow().isoformat()

    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute(
            "INSERT INTO comments (id, seed_id, owner, text, created_at) VALUES (?, ?, ?, ?, ?)",
            (comment_id, seed_id, owner, text.strip(), created_at)
        )
        # Increment comment counter on seed
        conn.execute("UPDATE seeds SET comments = comments + 1 WHERE id = ?", (seed_id,))
        conn.commit()

        # Get live count from comments table (not stale seeds.comments counter)
        row = conn.execute("SELECT COUNT(*) FROM comments WHERE seed_id = ?", (seed_id,)).fetchone()
        comment_count = row[0] if row else 0
        conn.close()
    except Exception as ex:
        raise HTTPException(status_code=500, detail=f"failed to add comment: {ex}")

    return {
        "ok": True,
        "comment": {
            "id": comment_id,
            "seed_id": seed_id,
            "owner": owner,
            "text": text.strip(),
            "created_at": created_at,
        },
        "comment_count": comment_count,
    }


@router.get("/seeds/{seed_id}/comments")
def list_comments(seed_id: str, limit: int = 50, offset: int = 0):
    """List comments for a seed, newest first."""
    try:
        conn = sqlite3.connect(DB_PATH)
        rows = conn.execute(
            "SELECT id, seed_id, owner, text, created_at FROM comments "
            "WHERE seed_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (seed_id, limit, offset)
        ).fetchall()
        conn.close()
    except Exception:
        rows = []

    items = []
    for r in rows:
        items.append({
            "id": r[0], "seed_id": r[1], "owner": r[2],
            "text": r[3], "created_at": r[4],
        })
    return {"items": items}


# ---------- likes ----------

@router.post("/seeds/{seed_id}/like")
async def toggle_like(seed_id: str, api_token: str = Form("")):
    """Toggle like on a seed. If already liked, unlikes."""
    owner = owner_from_token(api_token)
    if owner == "anonymous":
        raise HTTPException(status_code=401, detail="login required")

    try:
        conn = sqlite3.connect(DB_PATH)
        existing = conn.execute(
            "SELECT id FROM likes WHERE seed_id = ? AND owner = ?",
            (seed_id, owner)
        ).fetchone()

        if existing:
            # Unlike
            conn.execute("DELETE FROM likes WHERE id = ?", (existing[0],))
            conn.execute("UPDATE seeds SET likes = MAX(likes - 1, 0) WHERE id = ?", (seed_id,))
            liked = False
        else:
            # Like
            like_id = uuid.uuid4().hex[:12]
            created_at = datetime.datetime.utcnow().isoformat()
            conn.execute(
                "INSERT INTO likes (id, seed_id, owner, created_at) VALUES (?, ?, ?, ?)",
                (like_id, seed_id, owner, created_at)
            )
            conn.execute("UPDATE seeds SET likes = likes + 1 WHERE id = ?", (seed_id,))
            liked = True

        conn.commit()

        # Get live count from likes table (not stale seeds.likes counter)
        row = conn.execute("SELECT COUNT(*) FROM likes WHERE seed_id = ?", (seed_id,)).fetchone()
        like_count = row[0] if row else 0
        conn.close()
    except Exception as ex:
        raise HTTPException(status_code=500, detail=f"failed to toggle like: {ex}")

    return {"ok": True, "liked": liked, "like_count": like_count}


# ---------- bookmarks ----------

@router.post("/seeds/{seed_id}/bookmark")
async def toggle_bookmark(seed_id: str, api_token: str = Form("")):
    """Toggle bookmark on a seed."""
    owner = owner_from_token(api_token)
    if owner == "anonymous":
        raise HTTPException(status_code=401, detail="login required")

    try:
        conn = sqlite3.connect(DB_PATH)
        existing = conn.execute(
            "SELECT id FROM bookmarks WHERE seed_id = ? AND owner = ?",
            (seed_id, owner)
        ).fetchone()

        if existing:
            conn.execute("DELETE FROM bookmarks WHERE id = ?", (existing[0],))
            bookmarked = False
        else:
            bm_id = uuid.uuid4().hex[:12]
            created_at = datetime.datetime.utcnow().isoformat()
            conn.execute(
                "INSERT INTO bookmarks (id, seed_id, owner, created_at) VALUES (?, ?, ?, ?)",
                (bm_id, seed_id, owner, created_at)
            )
            bookmarked = True

        conn.commit()
        conn.close()
    except Exception as ex:
        raise HTTPException(status_code=500, detail=f"failed to toggle bookmark: {ex}")

    return {"ok": True, "bookmarked": bookmarked}


@router.get("/bookmarks")
def get_bookmarks(api_token: str = ""):
    """Get user's bookmarked seeds with full seed data."""
    owner = owner_from_token(api_token)
    if owner == "anonymous":
        return {"items": []}

    try:
        conn = sqlite3.connect(DB_PATH)
        rows = conn.execute(
            f"{SEED_SELECT} WHERE seeds.id IN (SELECT seed_id FROM bookmarks WHERE owner = ?) "
            "ORDER BY seeds.created_at DESC",
            (owner,)
        ).fetchall()
        conn.close()
    except Exception:
        return {"items": []}

    items = []
    for r in rows:
        d = seed_row_to_dict(r)
        d["bookmarked"] = True  # They're all bookmarked by definition
        d["liked"] = False  # Could check but not critical for bookmarks view
        items.append(d)

    return {"items": items}


# ---------- playback PoDT credits ----------

@router.post("/seeds/{seed_id}/played")
async def record_played(seed_id: str, api_token: str = Form("")):
    """Award PoDT credits to the seed owner when another user plays the media.
    One payout per (seed, requesting_user) pair — duplicates are rejected by proof_id.
    """
    requester = owner_from_token(api_token)
    if requester == "anonymous":
        return {"ok": False, "credited": False, "reason": "login required"}

    try:
        conn = sqlite3.connect(DB_PATH)

        # Look up seed metadata
        seed_row = conn.execute(
            "SELECT owner, reward_wallet, file_size FROM seeds WHERE id = ?",
            (seed_id,)
        ).fetchone()
        if not seed_row:
            conn.close()
            return {"ok": False, "credited": False, "reason": "seed not found"}

        seed_owner, reward_wallet, file_size = seed_row

        # No self-crediting
        if requester == seed_owner:
            conn.close()
            return {"ok": True, "credited": False, "reason": "self-play"}

        file_size = file_size or 0
        if file_size < 1024:
            conn.close()
            return {"ok": True, "credited": False, "reason": "file too small"}

        # Resolve seeder wallet: reward_wallet first, then owner's first wallet
        seeder_wallet = ""
        if reward_wallet:
            wallet_exists = conn.execute(
                "SELECT id FROM wallets WHERE id = ?", (reward_wallet,)
            ).fetchone()
            if wallet_exists:
                seeder_wallet = reward_wallet

        if not seeder_wallet:
            wallet_row = conn.execute(
                "SELECT id FROM wallets WHERE owner = ? LIMIT 1", (seed_owner,)
            ).fetchone()
            if not wallet_row:
                conn.close()
                return {"ok": True, "credited": False, "reason": "no wallet"}
            seeder_wallet = wallet_row[0]

        conn.close()

        # One payout per (seed, user) pair
        proof_string = f"play:{seed_id}:{requester}"
        proof_id = hashlib.sha256(proof_string.encode()).hexdigest()

        result = process_podt_reward(
            db_path=DB_PATH,
            seeder_wallet=seeder_wallet,
            proof_id=proof_id,
            bytes_transferred=file_size,
            file_hash=hashlib.sha256(f"{seed_id}:play".encode()).hexdigest(),
            receiver_wallet="",
            seed_id=seed_id
        )

        if result:
            return {"ok": True, "credited": True, "amount": result["amount"]}
        else:
            return {"ok": True, "credited": False, "reason": "already credited"}

    except Exception as ex:
        return {"ok": False, "credited": False, "reason": str(ex)}
