"""
GFC Engagement API - Comments, Likes, Bookmarks, Rich Feed, PoDT Playback
"""
import os
import uuid
import hashlib
import sqlite3
import datetime
from typing import Optional, Dict, Any, List

from fastapi import APIRouter, HTTPException, Form, Query, Depends

import audio_stream
import echohunt
import moderation
import referrals
import reposts
import signing
from security import Caller, caller_from_form, caller_from_query
from config import DB_PATH
from blockchain import process_podt_reward, play_reward_block_reason, claim_play_slot, release_play_slot

router = APIRouter()


# ---------- helpers ----------



def seed_row_to_dict(row, owner_for_engagement: str = "") -> Dict[str, Any]:
    """Convert a seeds DB row to a JSON-friendly dict.
    Row columns: id, title, description, tags, filename, thumb_filename,
                 content_type, file_size, gfc_earned, likes, comments, views, created_at, owner,
                 owner_avatar_filename, edited_at
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
        "edited_at": (row[15] if len(row) > 15 else "") or "",
    }
    # Streaming copy (compressed audio, or upright 720p H.264 video) when the node has
    # made one; players should prefer it over "full" (the untouched original)
    d["stream"] = audio_stream.stream_url(row[0], row[6]) if row[6] in audio_stream.STREAM_KINDS else None
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
    "COALESCE(users.avatar_filename, '') AS owner_avatar_filename, "
    "COALESCE(seeds.edited_at, '') "
    "FROM seeds LEFT JOIN users ON LOWER(seeds.owner) = LOWER(users.username)"
)


# ---------- rich feed ----------

def get_feed_items(owner: str = "anonymous", author: str = "") -> Dict[str, Any]:
    """Return all seeds (or only `author`'s) with liked/bookmarked state for `owner`."""

    try:
        conn = sqlite3.connect(DB_PATH)
        if author:
            rows = conn.execute(f"{SEED_SELECT} WHERE LOWER(seeds.owner) = LOWER(?) ORDER BY seeds.created_at DESC",
                                (author,)).fetchall()
        else:
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

        # Hidden after reports, or from an account this viewer blocked
        items = moderation.visible_items(conn, items, owner)
        conn.close()
    except Exception:
        items = []

    return {"items": items}


@router.get("/users/{username}/seeds")
def user_seeds(username: str, caller: Caller = Depends(caller_from_query)):
    """
    A profile's posts, newest first, as feed items (e.g. tapping a top earner). Public;
    with a read token, items also have the caller's liked/bookmarked state. Posts hidden
    after reports, or from an account the caller blocked, are left out.
    """
    return get_feed_items(caller.owner("read"), author=username)


# ---------- comments ----------

@router.post("/seeds/{seed_id}/comments")
async def add_comment(
    seed_id: str,
    text: str = Form(""),
    caller: Caller = Depends(caller_from_form),
):
    """Add a comment to a seed."""
    owner = caller.require("post")
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
async def toggle_like(seed_id: str, caller: Caller = Depends(caller_from_form)):
    """Toggle like on a seed. If already liked, unlikes."""
    owner = caller.require("post")

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
async def toggle_bookmark(seed_id: str, caller: Caller = Depends(caller_from_form)):
    """Toggle bookmark on a seed."""
    owner = caller.require("post")

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
def get_bookmarks(caller: Caller = Depends(caller_from_query)):
    """Get user's bookmarked seeds with full seed data."""
    owner = caller.owner("read")
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
async def record_played(seed_id: str, caller: Caller = Depends(caller_from_form)):
    """Award PoDT credits to the seed owner when another user plays the media
    (to the original creator when the seed is a repost).
    One payout per (seed, requesting_user) pair — duplicates are rejected by proof_id.
    The viewer must be phone-verified with an account at least 24h old, and pays
    a given creator wallet at most once per day. With GFC_REQUIRE_ECHOHUNT=1 the
    viewer also needs an Echo Hunt pass from the last 24h.
    """
    requester = caller.owner("post")
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

        # Pay only the wallet that signed the seed (never a wallet picked by owner name).
        # A repost pays the original's signed wallet instead (see reposts.py).
        seeder_wallet = reposts.reward_wallet_for(conn, seed_id)
        if not seeder_wallet:
            conn.close()
            return {"ok": True, "credited": False, "reason": "seed has no signed reward wallet"}
        original = reposts.repost_of(conn, seed_id)
        if original and requester.lower() == (original["original_owner"] or "").lower():
            conn.close()
            return {"ok": True, "credited": False, "reason": "self-play"}

        # No self-crediting through a wallet the requester owns on this node
        if signing.local_wallet_for(conn, requester, seeder_wallet):
            conn.close()
            return {"ok": True, "credited": False, "reason": "self-play"}

        # Sybil friction: only phone-verified viewers with accounts older than 24h pay out
        blocked = play_reward_block_reason(conn, requester)
        if blocked:
            conn.close()
            return {"ok": True, "credited": False, "reason": blocked}

        # Anti-bot game: once the Android app ships, rewarded plays need a recent Echo Hunt pass
        if os.environ.get("GFC_REQUIRE_ECHOHUNT") == "1" and not echohunt.has_recent_pass(conn, requester):
            conn.close()
            return {"ok": True, "credited": False, "reason": "echo hunt not passed in the last 24h"}

        # An invited viewer's first qualifying play releases their inviter's reward (once)
        try:
            referrals.maybe_reward(DB_PATH, requester)
        except Exception as ex:  # never let invite bookkeeping break a play
            print(f"[Referrals] payout check failed for {requester}: {ex}")

        # One payout per (seed, user) pair
        proof_string = f"play:{seed_id}:{requester}"
        proof_id = hashlib.sha256(proof_string.encode()).hexdigest()
        already = conn.execute("SELECT 1 FROM podt_proofs WHERE proof_id = ?", (proof_id,)).fetchone()
        conn.close()
        if already:
            return {"ok": True, "credited": False, "reason": "already credited"}

        # At most PLAY_REWARDS_PER_CREATOR_PER_DAY payouts per (viewer, creator wallet, day)
        if not claim_play_slot(DB_PATH, requester, seeder_wallet, proof_id):
            return {"ok": True, "credited": False, "reason": "daily limit for this creator reached"}

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
            release_play_slot(DB_PATH, proof_id)
            return {"ok": True, "credited": False, "reason": "already credited"}

    except Exception as ex:
        return {"ok": False, "credited": False, "reason": str(ex)}
