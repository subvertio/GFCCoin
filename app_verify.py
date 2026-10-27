"""
GFC Phone Verification API - verify a phone number to unlock the new-user grant
and play rewards. See phone_verify.py for storage and limits.

Apps that can't run Cloudflare Turnstile themselves (the phone app) verify in a
browser instead: see app_webverify.py.
"""
import sqlite3

from fastapi import APIRouter, HTTPException, Form, Request, Depends

import blockchain
import first_post
import phone_verify
import signing
from config import DB_PATH
from security import Caller, caller_from_form, caller_from_query

router = APIRouter()


def pay_on_verified(username: str) -> dict:
    """After a successful check: the new-user grant and any pending first post bonus, if there's a wallet."""
    paid = {"grant": 0.0}
    conn = sqlite3.connect(DB_PATH)
    wallet_id = signing.local_wallet_for(conn, username)
    conn.close()
    if wallet_id:
        grant = blockchain.process_user_grant(DB_PATH, username, wallet_id)
        if grant:
            paid["grant"] = grant["amount"]
        bonus = first_post.pay_pending(DB_PATH, username)
        if bonus:
            paid["first_post_bonus"] = bonus["amount"]
    return paid


@router.get("/verify/status")
def verify_status(caller: Caller = Depends(caller_from_query)):
    """Whether the caller's account is phone-verified (rewards need it)."""
    username = caller.require("read")
    conn = sqlite3.connect(DB_PATH)
    phone_verify.init_phone_tables(conn)
    verified = phone_verify.is_verified(conn, username)
    conn.close()
    return {"verified": verified}


@router.post("/verify/phone/start")
async def verify_phone_start(request: Request, phone: str = Form(...), turnstile_token: str = Form(""),
                             caller: Caller = Depends(caller_from_form)):
    """Send a one-time code by SMS to `phone` (E.164, e.g. +14155550123).
    Requires a Cloudflare Turnstile token when the node has GFC_TURNSTILE_SECRET set."""
    username = caller.require("post")
    try:
        # Bot check first: a failed challenge never counts against limits or costs an SMS
        phone_verify.check_turnstile(turnstile_token, request.client.host if request.client else "")
        return phone_verify.start_verification(DB_PATH, username, phone)
    except phone_verify.FlowError as ex:
        raise HTTPException(status_code=ex.status, detail=ex.detail)


@router.post("/verify/phone/check")
async def verify_phone_check(phone: str = Form(...), code: str = Form(...),
                             caller: Caller = Depends(caller_from_form)):
    """Check the code. On success the account is verified and its first wallet gets the new-user grant."""
    username = caller.require("post")
    try:
        result = phone_verify.check_verification(DB_PATH, username, phone, code)
    except phone_verify.FlowError as ex:
        raise HTTPException(status_code=ex.status, detail=ex.detail)

    result["grant"] = 0.0
    if result["verified"]:
        result.update(pay_on_verified(username))
    return result
