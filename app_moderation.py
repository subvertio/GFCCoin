"""
GFC Moderation API - report posts, block accounts. See moderation.py for the rules.

- POST   /seeds/{seed_id}/report   form: reason (spam, nudity, violence, harassment, hate, scam,
                                   copyright, other), detail (optional, 500 chars). One per account per post.
- POST   /users/{username}/block   hide that account's posts from you
- DELETE /users/{username}/block   undo
- GET    /users/me/blocks          the accounts you blocked
"""
import sqlite3

from fastapi import APIRouter, Depends, Form, HTTPException

import moderation
from config import DB_PATH
from security import Caller, caller_from_form, caller_from_query

router = APIRouter()


def _run(fn, *args):
    conn = sqlite3.connect(DB_PATH)
    try:
        return fn(conn, *args)
    except moderation.ModerationError as ex:
        raise HTTPException(status_code=ex.status, detail=ex.detail)
    finally:
        conn.close()


@router.post("/seeds/{seed_id}/report")
def report_seed(seed_id: str, reason: str = Form(...), detail: str = Form(""),
                caller: Caller = Depends(caller_from_form)):
    """Report a post. Enough reports from different accounts hide it until the node's operator reviews it."""
    return _run(moderation.report_seed, seed_id, caller.require("post"), reason, detail)


@router.post("/users/{username}/block")
def block_user(username: str, caller: Caller = Depends(caller_from_form)):
    """Hide this account's posts from you (feed, search, seed lists)."""
    return _run(moderation.block, caller.require("post"), username)


@router.delete("/users/{username}/block")
def unblock_user(username: str, caller: Caller = Depends(caller_from_query)):
    return _run(moderation.unblock, caller.require("post"), username)


@router.get("/users/me/blocks")
def my_blocks(caller: Caller = Depends(caller_from_query)):
    return {"blocked": _run(moderation.blocked_by, caller.require("read"))}
