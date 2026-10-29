"""
GFC First Post Bonus - 1,000 GFC (by default) the first time an account posts

- Earned by the account's first original seed posted through POST /seeds/upload.
  A seed found to be a repost (reposts.py) earns nothing and doesn't use up the bonus.
- Paid once per account, ever: the `first_post_bonus` row (username PRIMARY KEY) is
  claimed with INSERT OR IGNORE, and the payout with a conditional UPDATE, so retries,
  concurrent uploads and deleting and re-posting the first seed can't pay twice.
  Rows are never deleted.
- Paid only to a phone-verified account with a wallet on this node (the same bar as
  the new-user grant, see phone_verify.py). If either is missing at upload time the
  bonus is recorded as pending and paid when the account creates its first wallet
  (POST /wallets/create) or verifies its phone (POST /verify/web/fb/check).
- The payment is a treasury-signed FIRST_POST mint, notarised like every mint, and
  shows in wallet history as "First post bonus".

Config (environment, read on every call):
  GFC_FIRST_POST_BONUS_GFC      amount in GFC, default 1000, at most
                                blockchain.FIRST_POST_BONUS_MAX_CENTS / 100
  GFC_FIRST_POST_BONUS_ENABLED  "0" turns the bonus off: nothing is earned or paid
                                (pending bonuses wait until it's back on)
"""

import datetime
import logging
import os
import sqlite3
from typing import Dict, Optional

import blockchain
import phone_verify
import signing

logger = logging.getLogger("gfc.first_post")

DEFAULT_BONUS_GFC = 1000
MEMO = "First post bonus"

PENDING = "pending"   # earned, waiting for a wallet / verified phone (or a funded treasury)
PAYING = "paying"     # claimed by one payout; never claimed again
PAID = "paid"


def init_first_post_tables(conn: sqlite3.Connection):
    conn.execute('''CREATE TABLE IF NOT EXISTS first_post_bonus (
        username TEXT PRIMARY KEY,
        seed_id TEXT NOT NULL,
        amount_cents INTEGER NOT NULL,
        status TEXT NOT NULL,
        created_at TEXT NOT NULL,
        paid_at TEXT,
        wallet_id TEXT,
        tx_id TEXT
    )''')


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def enabled() -> bool:
    return os.environ.get("GFC_FIRST_POST_BONUS_ENABLED", "1").strip().lower() not in ("0", "false", "no", "off")


def amount_cents() -> int:
    """The configured bonus in cents, clamped to what peers accept for a FIRST_POST mint."""
    raw = os.environ.get("GFC_FIRST_POST_BONUS_GFC", "").strip()
    try:
        cents = int(round(float(raw) * 100)) if raw else DEFAULT_BONUS_GFC * 100
    except ValueError:
        logger.warning(f"GFC_FIRST_POST_BONUS_GFC={raw!r} is not a number, using {DEFAULT_BONUS_GFC}")
        cents = DEFAULT_BONUS_GFC * 100
    if cents > blockchain.FIRST_POST_BONUS_MAX_CENTS:
        logger.warning("GFC_FIRST_POST_BONUS_GFC is above the protocol limit, paying the limit")
        cents = blockchain.FIRST_POST_BONUS_MAX_CENTS
    return max(cents, 0)


def on_upload(db_path: str, username: str, seed_id: str, is_repost: bool) -> Optional[Dict]:
    """
    Call after a seed is stored. Records the bonus if this is the account's first
    original post and pays it if the account can be paid now (or pays a bonus still
    pending from an earlier post). Returns {"amount": GFC, "pending": bool} when this
    upload earned or paid the bonus, else None.
    """
    if not enabled() or not username or username == "anonymous":
        return None
    cents = amount_cents()
    conn = sqlite3.connect(db_path)
    try:
        init_first_post_tables(conn)
        earned = False
        if not is_repost and cents > 0:
            cur = conn.execute("INSERT OR IGNORE INTO first_post_bonus (username, seed_id, amount_cents, status, "
                               "created_at) VALUES (?, ?, ?, ?, ?)", (username, seed_id, cents, PENDING, _now()))
            conn.commit()
            earned = cur.rowcount == 1
    finally:
        conn.close()
    tx = pay_pending(db_path, username)
    if tx:
        return {"amount": tx["amount"], "pending": False}
    if earned:
        return {"amount": cents / 100.0, "pending": True}
    return None


def pay_pending(db_path: str, username: str) -> Optional[dict]:
    """Pay `username`'s pending bonus if they're verified and have a wallet here. Returns the mint or None."""
    if not enabled() or not username:
        return None
    conn = sqlite3.connect(db_path)
    try:
        init_first_post_tables(conn)
        row = conn.execute("SELECT amount_cents FROM first_post_bonus WHERE username = ? AND status = ?",
                           (username, PENDING)).fetchone()
        if not row:
            return None
        cents = row[0]
        if not phone_verify.is_verified(conn, username):
            return None
        wallet_id = signing.local_wallet_for(conn, username)
        if not wallet_id:
            return None
        # Claim it atomically so concurrent uploads / wallet creation can't pay twice
        cur = conn.execute("UPDATE first_post_bonus SET status = ?, wallet_id = ? WHERE username = ? AND status = ?",
                           (PAYING, wallet_id, username, PENDING))
        conn.commit()
        if cur.rowcount != 1:
            return None
    finally:
        conn.close()

    try:
        tx = blockchain.process_first_post_mint(db_path, wallet_id, cents, MEMO)
    except Exception:
        # The mint may or may not have been written: stay claimed (never pay twice)
        logger.exception(f"First post bonus mint failed for {username}; left in '{PAYING}' for review")
        return None
    conn = sqlite3.connect(db_path)
    if tx:
        conn.execute("UPDATE first_post_bonus SET status = ?, paid_at = ?, tx_id = ? WHERE username = ?",
                     (PAID, _now(), tx["id"], username))
    else:
        # Treasury short: nothing was minted, so a later call can retry
        conn.execute("UPDATE first_post_bonus SET status = ?, wallet_id = NULL WHERE username = ?",
                     (PENDING, username))
    conn.commit()
    conn.close()
    if tx:
        logger.info(f"First post bonus: {cents / 100:.2f} GFC -> {wallet_id} ({username})")
    return tx
