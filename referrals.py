"""
GFC Invites - invite friends, earn GFC when they become real, active users

- A new user can name who invited them at sign-up (`ref`, the inviter's username,
  usually carried by an invite link: /join?ref=<username>). That's recorded once and
  can't be changed later.
- When the invited friend is "real and active" (phone-verified, account older than
  24h, Echo Hunt passed if the node requires it, and their first play that passes
  those checks), the treasury pays REFERRAL_REWARD_CENTS (1,000 GFC) to the inviter
  and a REFERRAL_BONUS_CENTS (100 GFC) welcome bonus to the friend, on top of the
  usual new-user grant. Each invite pays once.
- There is no cap per inviter (a deliberate product choice). The anti-farming
  defence is what a "real" friend costs: a unique, non-VoIP phone number, a day of
  waiting, and a qualifying play, plus Echo Hunt once the app ships.
- Payouts go to the inviter's oldest wallet whose key is on this node. An inviter
  with no wallet here isn't paid (the friend's bonus still is); the reason is recorded.
- Everything here is local to the node that issues the reward; the payments themselves
  are treasury-signed REFERRAL transactions that every node can verify.
"""

import datetime
import logging
import os
import sqlite3
from typing import Dict, Optional

import blockchain
import echohunt
import signing

logger = logging.getLogger("gfc.referrals")


def init_referral_tables(conn: sqlite3.Connection):
    conn.execute('''CREATE TABLE IF NOT EXISTS referrals (
        referee TEXT PRIMARY KEY,
        inviter TEXT NOT NULL,
        created_at TEXT NOT NULL,
        rewarded_at TEXT,
        reward_tx TEXT,
        bonus_tx TEXT,
        note TEXT DEFAULT ''
    )''')
    conn.execute("CREATE INDEX IF NOT EXISTS idx_referrals_inviter ON referrals(inviter)")


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def record_invite(db_path: str, referee: str, ref: str) -> Optional[str]:
    """
    Remember that `ref` invited `referee` (call right after the account is created).
    Returns the inviter's canonical username, or None if `ref` isn't a valid inviter.
    """
    ref = (ref or "").strip()
    if not ref or ref.lower() == referee.lower():
        return None
    conn = sqlite3.connect(db_path)
    try:
        init_referral_tables(conn)
        row = conn.execute("SELECT username FROM users WHERE LOWER(username) = LOWER(?)", (ref,)).fetchone()
        if not row:
            return None
        conn.execute("INSERT OR IGNORE INTO referrals (referee, inviter, created_at) VALUES (?, ?, ?)",
                     (referee, row[0], _now()))
        conn.commit()
        return row[0]
    finally:
        conn.close()


def maybe_reward(db_path: str, referee: str) -> Optional[Dict]:
    """
    Pay the invite reward if `referee` was invited, hasn't been paid for, and now
    qualifies. Safe to call on every play: at most one call ever pays.
    """
    conn = sqlite3.connect(db_path)
    try:
        init_referral_tables(conn)
        row = conn.execute("SELECT inviter FROM referrals WHERE referee = ? AND rewarded_at IS NULL",
                           (referee,)).fetchone()
        if not row:
            return None
        inviter = row[0]
        if blockchain.play_reward_block_reason(conn, referee):
            return None  # not verified or account too new yet
        if os.environ.get("GFC_REQUIRE_ECHOHUNT") == "1" and not echohunt.has_recent_pass(conn, referee):
            return None
        # Claim it atomically so concurrent plays can't pay twice
        cur = conn.execute("UPDATE referrals SET rewarded_at = ? WHERE referee = ? AND rewarded_at IS NULL",
                           (_now(), referee))
        conn.commit()
        if cur.rowcount != 1:
            return None
        inviter_wallet = signing.local_wallet_for(conn, inviter)
        referee_wallet = signing.local_wallet_for(conn, referee)
    finally:
        conn.close()

    result = {"inviter": inviter, "reward": None, "bonus": None}
    notes = []
    if inviter_wallet:
        tx = blockchain.process_referral_mint(db_path, inviter_wallet, blockchain.REFERRAL_REWARD_CENTS,
                                              f"Invite reward: {referee} joined")
        result["reward"] = tx
        if not tx:
            notes.append("treasury could not pay inviter")
    else:
        notes.append("inviter has no wallet on this node")
    if referee_wallet:
        tx = blockchain.process_referral_mint(db_path, referee_wallet, blockchain.REFERRAL_BONUS_CENTS,
                                              f"Welcome bonus: invited by {inviter}")
        result["bonus"] = tx
        if not tx:
            notes.append("treasury could not pay bonus")
    else:
        notes.append("friend has no wallet on this node")

    conn = sqlite3.connect(db_path)
    conn.execute("UPDATE referrals SET reward_tx = ?, bonus_tx = ?, note = ? WHERE referee = ?",
                 ((result["reward"] or {}).get("id"), (result["bonus"] or {}).get("id"), "; ".join(notes), referee))
    conn.commit()
    conn.close()
    logger.info(f"Referral paid: {inviter} invited {referee} ({'; '.join(notes) or 'ok'})")
    return result


def stats(db_path: str, inviter: str) -> Dict:
    """Invite counts and earnings for one user."""
    conn = sqlite3.connect(db_path)
    try:
        init_referral_tables(conn)
        invited = conn.execute("SELECT COUNT(*) FROM referrals WHERE inviter = ?", (inviter,)).fetchone()[0]
        active = conn.execute("SELECT COUNT(*) FROM referrals WHERE inviter = ? AND rewarded_at IS NOT NULL",
                              (inviter,)).fetchone()[0]
        paid = conn.execute("SELECT COUNT(*) FROM referrals WHERE inviter = ? AND reward_tx IS NOT NULL",
                            (inviter,)).fetchone()[0]
        invited_by = conn.execute("SELECT inviter FROM referrals WHERE referee = ?", (inviter,)).fetchone()
    finally:
        conn.close()
    return {
        "invited": invited,
        "active": active,
        "pending": invited - active,
        "earned_gfc": paid * blockchain.REFERRAL_REWARD_CENTS / 100.0,
        "reward_per_friend_gfc": blockchain.REFERRAL_REWARD_CENTS / 100.0,
        "friend_bonus_gfc": blockchain.REFERRAL_BONUS_CENTS / 100.0,
        "invited_by": invited_by[0] if invited_by else None,
    }
