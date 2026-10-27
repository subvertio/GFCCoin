"""
GFC Echo Hunt API - the 3D-audio anti-bot game that gates rewarded plays when
GFC_REQUIRE_ECHOHUNT=1. Scoring is in echohunt.py, Play Integrity in
play_integrity.py; the protocol is described in docs/echo-hunt.md.
"""
import json
import sqlite3

from fastapi import APIRouter, Depends, HTTPException, Form

import echohunt
import play_integrity
from config import DB_PATH
from security import Caller, caller_from_form

router = APIRouter()

# A pass unlocks rewarded plays, which also need "post", so a read-only
# third-party token can't collect passes on the user's behalf.
ECHOHUNT_SCOPE = "post"


@router.post("/echohunt/start")
async def echohunt_start(caller: Caller = Depends(caller_from_form)):
    """Issue a single-use challenge (valid for 60s). Rate-limited per user. Needs the 'post' scope."""
    username = caller.require(ECHOHUNT_SCOPE)
    challenge = echohunt.new_challenge()
    conn = sqlite3.connect(DB_PATH)
    try:
        echohunt.init_echohunt_tables(conn)
        if echohunt.attempts_in_window(conn, username) >= echohunt.MAX_ATTEMPTS_PER_WINDOW:
            raise HTTPException(status_code=429, detail="too many Echo Hunt attempts, try again in a few minutes")
        echohunt.store_challenge(conn, username, challenge)
        conn.commit()
    finally:
        conn.close()
    return echohunt.client_view(challenge)


@router.post("/echohunt/submit")
async def echohunt_submit(challenge_id: str = Form(...), rounds: str = Form(...),
                          integrity_token: str = Form(""), caller: Caller = Depends(caller_from_form)):
    """
    Score a challenge. `rounds` is a JSON list, one entry per round:
    {"tap_ms": ..., "facing": {"azimuth": ..., "elevation": ...}, "samples": [[t_ms, az, el], ...]}.
    `integrity_token` is a Play Integrity token whose requestHash is the challenge id
    (required when the node has Play Integrity configured). Needs the 'post' scope.
    """
    username = caller.require(ECHOHUNT_SCOPE)
    conn = sqlite3.connect(DB_PATH)
    try:
        echohunt.init_echohunt_tables(conn)
        challenge = echohunt.consume_challenge(conn, username, challenge_id)
        if not challenge:
            raise HTTPException(status_code=410, detail="challenge unknown, expired or already used")

        issued = challenge["created_at"]
        integrity_reason = play_integrity.verify(integrity_token, challenge_id, int(issued.timestamp() * 1000))
        if integrity_reason:
            raise HTTPException(status_code=403, detail=f"play integrity check failed: {integrity_reason}")

        try:
            submitted = json.loads(rounds)
        except ValueError:
            raise HTTPException(status_code=400, detail="rounds must be JSON")
        elapsed_ms = (echohunt._now() - issued).total_seconds() * 1000
        try:
            result = echohunt.score_challenge(challenge, submitted, elapsed_ms)
        except echohunt.SubmissionError as ex:
            raise HTTPException(status_code=400, detail=str(ex))

        if result["passed"]:
            echohunt.record_pass(conn, username)
            conn.commit()
    finally:
        conn.close()
    # Per-round reasons stay server-side: they would tell a bot what to tune
    return {"ok": True, "passed": result["passed"], "rounds_passed": result["rounds_passed"],
            "rounds_to_pass": echohunt.ROUNDS_TO_PASS}
