"""
GFC Follows API - follow creators, and a Following feed of their posts.

- POST   /users/{username}/follow   (Bearer, post scope)  follow a creator
- DELETE /users/{username}/follow   (Bearer, post scope)  stop following
- GET    /following                 (Bearer, read)        who you follow
- GET    /feed/following            (Bearer, read)        posts from the creators you follow, newest first

Feed items (the /feed, profile, bookmarks and following feeds) say `following: true` when the
viewer follows the post's creator, and GET /users/{username} has follower/following counts
and `followed_by_me`.

Follows are kept on the node you use and aren't synced to peers: an unfollow can't be synced
(rows are append-only), and counts from other nodes couldn't be checked anyway.
"""

import datetime
import sqlite3
import uuid
from typing import Dict, Iterable, List

from fastapi import APIRouter, Depends, HTTPException

from config import DB_PATH
from security import Caller, caller_from_form, caller_from_query

router = APIRouter()


def init_tables(conn: sqlite3.Connection):
    conn.execute("""CREATE TABLE IF NOT EXISTS follows (
        id TEXT PRIMARY KEY,
        follower TEXT NOT NULL,      -- lower-case usernames
        followee TEXT NOT NULL,
        created_at TEXT NOT NULL,
        UNIQUE(follower, followee)
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_follows_followee ON follows(followee)")


def followed_by(conn: sqlite3.Connection, viewer: str) -> set:
    """Lower-case usernames `viewer` follows (empty when logged out)."""
    if not viewer or viewer == "anonymous":
        return set()
    try:
        return {r[0] for r in conn.execute("SELECT followee FROM follows WHERE follower = ?", (viewer.lower(),))}
    except sqlite3.Error:
        return set()


def counts(conn: sqlite3.Connection, username: str) -> Dict[str, int]:
    u = username.lower()
    try:
        return {"followers": conn.execute("SELECT COUNT(*) FROM follows WHERE followee = ?", (u,)).fetchone()[0],
                "following": conn.execute("SELECT COUNT(*) FROM follows WHERE follower = ?", (u,)).fetchone()[0]}
    except sqlite3.Error:
        return {"followers": 0, "following": 0}


def apply_to_items(conn: sqlite3.Connection, items: Iterable[Dict], viewer: str) -> List[Dict]:
    """Mark each feed item with whether the viewer follows its creator."""
    items = list(items)
    follows = followed_by(conn, viewer)
    for item in items:
        item["following"] = (item.get("owner") or "").lower() in follows
    return items


def _target(conn: sqlite3.Connection, me: str, username: str) -> str:
    row = conn.execute("SELECT username FROM users WHERE LOWER(username) = LOWER(?)", (username,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="user not found")
    if row[0].lower() == me.lower():
        raise HTTPException(status_code=400, detail="you can't follow yourself")
    return row[0]


@router.post("/users/{username}/follow")
def follow(username: str, caller: Caller = Depends(caller_from_form)):
    """Follow a creator (doing it twice is fine)."""
    me = caller.require("post")
    conn = sqlite3.connect(DB_PATH)
    try:
        init_tables(conn)
        name = _target(conn, me, username)
        conn.execute("INSERT OR IGNORE INTO follows (id, follower, followee, created_at) VALUES (?, ?, ?, ?)",
                     (uuid.uuid4().hex[:16], me.lower(), name.lower(), datetime.datetime.utcnow().isoformat()))
        conn.commit()
        return {"ok": True, "username": name, "followed_by_me": True, **counts(conn, name)}
    finally:
        conn.close()


@router.delete("/users/{username}/follow")
def unfollow(username: str, caller: Caller = Depends(caller_from_form)):
    """Stop following a creator (fine if you weren't)."""
    me = caller.require("post")
    conn = sqlite3.connect(DB_PATH)
    try:
        init_tables(conn)
        conn.execute("DELETE FROM follows WHERE follower = ? AND followee = ?", (me.lower(), username.lower()))
        conn.commit()
        return {"ok": True, "username": username, "followed_by_me": False, **counts(conn, username)}
    finally:
        conn.close()


@router.get("/following")
def following(caller: Caller = Depends(caller_from_query)):
    """The creators you follow, most recent first, with their avatars."""
    me = caller.owner("read")
    if me == "anonymous":
        return {"users": []}
    conn = sqlite3.connect(DB_PATH)
    try:
        rows = conn.execute(
            "SELECT COALESCE(users.username, follows.followee), COALESCE(users.avatar_filename, ''), follows.created_at "
            "FROM follows LEFT JOIN users ON LOWER(users.username) = follows.followee "
            "WHERE follows.follower = ? ORDER BY follows.created_at DESC", (me.lower(),)).fetchall()
    finally:
        conn.close()
    return {"users": [{"username": r[0], "avatar": f"/avatars/{r[1]}" if r[1] else None, "since": r[2]}
                      for r in rows]}


@router.get("/feed/following")
def following_feed(caller: Caller = Depends(caller_from_query)):
    """Posts from the creators you follow, newest first (empty when logged out or following nobody)."""
    me = caller.owner("read")
    if me == "anonymous":
        return {"items": []}
    from app_engagement import get_feed_items
    conn = sqlite3.connect(DB_PATH)
    try:
        follows = followed_by(conn, me)
    finally:
        conn.close()
    if not follows:
        return {"items": []}
    items = get_feed_items(me)["items"]
    return {"items": [i for i in items if (i.get("owner") or "").lower() in follows]}


def profile_extras(username: str, viewer: str) -> Dict:
    """Follower/following counts for a profile, and whether the viewer follows it."""
    conn = sqlite3.connect(DB_PATH)
    try:
        return {**counts(conn, username), "followed_by_me": username.lower() in followed_by(conn, viewer)}
    finally:
        conn.close()

