"""
GFC Token API - mint, list and revoke scoped API tokens for third-party front ends.
See security.py for what each scope allows.
"""
import datetime
import sqlite3
from typing import Optional

from fastapi import APIRouter, Depends, Form, HTTPException

import keystore
from config import DB_PATH
from security import (
    Caller, caller_from_form, caller_from_query, create_session, list_sessions,
    parse_scopes, revoke_session, resolve_caller, verify_password,
)

router = APIRouter()

MAX_TOKEN_DAYS = 365


@router.post("/auth/tokens")
async def mint_token(
    password: str = Form(...),
    scopes: str = Form("read", description="Space- or comma-separated: read, post, spend"),
    label: str = Form("", description="A name to recognise the token by, e.g. the front end's name"),
    expires_in_days: float = Form(30, description=f"Lifetime in days (max {MAX_TOKEN_DAYS})"),
    spend_limit_cents: Optional[int] = Form(None, description="Daily spend cap for a spend token, in cents"),
    caller: Caller = Depends(caller_from_form),
):
    """
    Mint a limited token. Needs a full-scope token (from /auth/login) plus the
    password. The new token is returned once; only its hash is stored.
    """
    username = caller.require_full()
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute("SELECT password FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    if not row or not verify_password(password, row[0]):
        raise HTTPException(status_code=401, detail="invalid credentials")

    scope_set = parse_scopes(scopes)
    if not 0 < expires_in_days <= MAX_TOKEN_DAYS:
        raise HTTPException(status_code=400, detail=f"expires_in_days must be between 0 and {MAX_TOKEN_DAYS}")
    if spend_limit_cents is not None and spend_limit_cents < 0:
        raise HTTPException(status_code=400, detail="spend_limit_cents must not be negative")

    token = create_session(username, scopes=scope_set, ttl=datetime.timedelta(days=expires_in_days),
                           spend_limit_cents=spend_limit_cents, label=label.strip())
    # Tokens that sign (seeds with post, transfers with spend) get their own wrap of
    # the data key; read-only tokens never can unlock wallet keys.
    if scope_set & {"post", "spend"}:
        keystore.attach_to_session(token, keystore.unlock_user_keys(username, password))
    minted = resolve_caller(token)
    info = next(t for t in list_sessions(username) if t["id"] == minted.token_id)
    return {"ok": True, "token": token, **info}


@router.get("/auth/tokens")
def list_tokens(caller: Caller = Depends(caller_from_query)):
    """List your unexpired tokens (IDs and settings, never the tokens). Needs a full-scope token."""
    username = caller.require_full()
    tokens = list_sessions(username)
    for t in tokens:
        t["current"] = t["id"] == caller.token_id
    return {"tokens": tokens}


@router.delete("/auth/tokens/{token_id}")
def revoke_token(token_id: str, caller: Caller = Depends(caller_from_query)):
    """
    Revoke a token by its ID. Any token may revoke itself (log out); revoking
    another token needs a full-scope token.
    """
    if token_id != caller.token_id or not caller.username:
        caller.require_full()
    if not revoke_session(caller.username, token_id):
        raise HTTPException(status_code=404, detail="token not found")
    return {"ok": True, "revoked": token_id}
