"""
GFC Phone Verification API - whether an account is phone-verified, and what verifying pays
(the new-user grant and play rewards need it). Verifying itself happens in a browser with
Firebase phone sign-in: see app_webverify.py, and phone_verify.py for storage and limits.
"""
import sqlite3

from fastapi import APIRouter, Depends

import blockchain
import first_post
import phone_verify
import signing
from config import DB_PATH
from security import Caller, caller_from_query

router = APIRouter()


def pay_on_verified(username: str) -> dict:
    """Once the account is verified: the new-user grant and any pending first post bonus, if there's a wallet."""
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
    """
    Whether the caller's account is phone-verified (rewards need it), what verifying has paid
    (the welcome grant and first post bonus, in GFC), and the account's wallets on this node,
    so an app can celebrate the rewards and show the balance on a new device.
    """
    username = caller.require("read")
    conn = sqlite3.connect(DB_PATH)
    try:
        phone_verify.init_phone_tables(conn)
        verified = phone_verify.is_verified(conn, username)
        wallets = [r[0] for r in conn.execute(
            "SELECT id FROM wallets WHERE LOWER(owner) = LOWER(?) ORDER BY rowid", (username,))]
        paid = {}
        for key, tx_type in (("grant", blockchain.TX_TYPE_GRANT), ("first_post_bonus", blockchain.TX_TYPE_FIRST_POST)):
            cents = conn.execute(
                "SELECT COALESCE(SUM(t.amount_cents), 0) FROM transactions t JOIN wallets w ON w.id = t.recipient "
                "WHERE t.tx_type = ? AND LOWER(w.owner) = LOWER(?)", (tx_type, username)).fetchone()[0]
            paid[key] = cents / 100.0
    finally:
        conn.close()
    return {"verified": verified, "rewards": paid, "wallets": wallets}
