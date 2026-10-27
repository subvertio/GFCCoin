"""
GFC Phone Verification API - verify a phone number to unlock the new-user grant
and play rewards. See phone_verify.py for storage and limits.
"""
import sqlite3

from fastapi import APIRouter, HTTPException, Form, Request

import blockchain
import phone_verify
import signing
from config import DB_PATH
from security import require_user

router = APIRouter()


@router.post("/verify/phone/start")
async def verify_phone_start(request: Request, api_token: str = Form(...), phone: str = Form(...),
                             turnstile_token: str = Form("")):
    """Send a one-time code by SMS to `phone` (E.164, e.g. +14155550123).
    Requires a Cloudflare Turnstile token when the node has GFC_TURNSTILE_SECRET set."""
    username = require_user(api_token)
    try:
        # Bot check first: a failed challenge never counts against limits or costs an SMS
        phone_verify.check_turnstile(turnstile_token, request.client.host if request.client else "")
        return phone_verify.start_verification(DB_PATH, username, phone)
    except phone_verify.FlowError as ex:
        raise HTTPException(status_code=ex.status, detail=ex.detail)


@router.post("/verify/phone/check")
async def verify_phone_check(api_token: str = Form(...), phone: str = Form(...), code: str = Form(...)):
    """Check the code. On success the account is verified and its first wallet gets the new-user grant."""
    username = require_user(api_token)
    try:
        result = phone_verify.check_verification(DB_PATH, username, phone, code)
    except phone_verify.FlowError as ex:
        raise HTTPException(status_code=ex.status, detail=ex.detail)

    result["grant"] = 0.0
    if result["verified"]:
        conn = sqlite3.connect(DB_PATH)
        wallet_id = signing.local_wallet_for(conn, username)
        conn.close()
        if wallet_id:
            grant = blockchain.process_user_grant(DB_PATH, username, wallet_id)
            if grant:
                result["grant"] = grant["amount"]
    return result
