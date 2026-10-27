"""
GFC Invites API - your invite link and how many friends it has brought in.
See referrals.py for when invite rewards are paid.
"""
from urllib.parse import quote

from fastapi import APIRouter, Depends

import referrals
from app_share import public_base_url, x_intent_url
from config import DB_PATH
from security import Caller, caller_from_query

router = APIRouter()


@router.get("/referrals/me")
def my_referrals(caller: Caller = Depends(caller_from_query)):
    """Your invite link (also: add ?ref=<you> to any share link) and invite stats."""
    username = caller.require("read")
    invite_url = f"{public_base_url()}/join?ref={quote(username, safe='')}"
    result = referrals.stats(DB_PATH, username)
    result.update({
        "invite_url": invite_url,
        "share_link_suffix": f"?ref={quote(username, safe='')}",
        "x_intent_url": x_intent_url("Join me on GFC: 3D art, music and video from creators you can earn for.",
                                     invite_url),
    })
    return result
