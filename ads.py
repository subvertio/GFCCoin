"""
GFC Ads: creators promote a post with GFC, and it's shown in other people's For you feeds.

Buying
- An ad is one of your own posts. You set a budget (GFC), a max price (GFC per 1,000 views)
  and how many days it runs. The budget moves to the node's ads wallet with an ordinary
  signed transfer when the ad starts; whatever isn't spent comes back when it ends or is
  cancelled (also an ordinary transfer, signed by the ads wallet's key on this node).

The market rate (a uniform-price auction, recomputed every MARKET_PERIOD_S)
- Supply: the ad slots the feed showed in the last hour (one every AD_EVERY posts).
- Demand: each active ad's max price, and the views it wants this period, its remaining
  budget paced evenly over its remaining time.
- The highest bids win slots until supply runs out; every winner pays the same clearing
  price: the bid of the first ad that missed out, or the floor (FLOOR_CPM_CENTS) when they
  all fit. That price is the public market rate (GET /ads/market).
- Each slot picks one of the winners at random, weighted by the views it won.

Views and pay (instant)
- A view counts when the ad was on screen (the app reports it with the token the node signed
  when it served the ad): a different, logged-in (on the real network, phone-verified)
  person, once per ad per day, never the advertiser.
- Each counted view costs the price the slot was served at. CREATOR_SHARE (70%) is paid at
  once, as its own transfer, to the creator of the post shown just above the ad; the rest
  stays in the ads wallet as the network's share (out of circulation, like money returned
  to the treasury). A view under the advertiser's own post, or a post with no reward wallet,
  pays no creator.

Prices are in cents per 1,000 views (CPM); one view at P cents/1,000 costs P millicents.
"""

import datetime
import hashlib
import hmac
import json
import os
import random
import sqlite3
import threading
import time
import uuid
from typing import Dict, Iterable, List, Optional

import blockchain
import config
import moderation
import signing
from config import DB_PATH

AD_EVERY = 8                       # one ad slot after every 8 posts
CREATOR_SHARE = 0.70
FLOOR_CPM_CENTS = int(float(os.environ.get("GFC_ADS_FLOOR_GFC", "100")) * 100)  # 100 GFC / 1,000 views
MARKET_PERIOD_S = 15 * 60
MIN_SUPPLY_PER_PERIOD = 25         # until there's traffic to measure
MAX_DAYS = 30
MIN_BUDGET_CENTS = 10 * 100        # 10 GFC
TOKEN_TTL_S = 6 * 3600
ADS_WALLET_OWNER = "gfc-ads"

_market_lock = threading.Lock()
_market: Dict = {}                 # the last computed market (computed_at, clearing_cpm, winners, ...)


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def init_tables(conn: sqlite3.Connection):
    conn.execute("""CREATE TABLE IF NOT EXISTS ad_campaigns (
        id TEXT PRIMARY KEY,
        owner TEXT NOT NULL,
        wallet TEXT NOT NULL,          -- pays the budget, gets the refund
        seed_id TEXT NOT NULL,
        budget_cents INTEGER NOT NULL,
        max_cpm_cents INTEGER NOT NULL,
        spent_mc INTEGER NOT NULL DEFAULT 0,       -- millicents
        paid_creators_cents INTEGER NOT NULL DEFAULT 0,
        views INTEGER NOT NULL DEFAULT 0,
        starts_at TEXT NOT NULL,
        ends_at TEXT NOT NULL,
        status TEXT NOT NULL,          -- active | ended | cancelled
        escrow_tx TEXT,
        refund_tx TEXT,
        refund_cents INTEGER,
        created_at TEXT NOT NULL,
        ended_at TEXT
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS ad_views (
        id TEXT PRIMARY KEY,
        campaign_id TEXT NOT NULL,
        viewer TEXT NOT NULL,
        day TEXT NOT NULL,
        above_seed TEXT,
        creator_wallet TEXT,
        price_mc INTEGER NOT NULL,
        creator_cents INTEGER NOT NULL,
        payout_tx TEXT,
        created_at TEXT NOT NULL,
        UNIQUE(campaign_id, viewer, day)
    )""")
    conn.execute("CREATE TABLE IF NOT EXISTS ad_slots (hour TEXT PRIMARY KEY, slots INTEGER NOT NULL)")
    conn.execute("CREATE TABLE IF NOT EXISTS ads_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")


# ---------- the ads wallet ----------

def ads_wallet(db_path: str = DB_PATH) -> str:
    """The node's ads wallet (escrow for budgets, the network's share stays here). Made on first use."""
    conn = sqlite3.connect(db_path)
    try:
        init_tables(conn)
        row = conn.execute("SELECT value FROM ads_meta WHERE key = 'wallet'").fetchone()
        if row:
            return row[0]
        wallet = signing.create_wallet_key(conn)
        conn.execute("INSERT INTO wallets (id, name, owner, created_at, gfc_balance) VALUES (?, 'GFC ads', ?, ?, 0)",
                     (wallet, ADS_WALLET_OWNER, _now().isoformat()))
        conn.execute("INSERT INTO ads_meta (key, value) VALUES ('wallet', ?)", (wallet,))
        conn.commit()
        return wallet
    finally:
        conn.close()


# ---------- campaigns ----------

class AdError(ValueError):
    pass


def create_campaign(owner: str, wallet: str, seed_id: str, budget_cents: int, max_cpm_cents: int,
                    days: int, data_key: Optional[bytes] = None, db_path: str = DB_PATH) -> dict:
    """Start an ad: checks, then the budget moves to the ads wallet (a signed transfer)."""
    if not 1 <= days <= MAX_DAYS:
        raise AdError(f"An ad can run for 1 to {MAX_DAYS} days.")
    if max_cpm_cents < FLOOR_CPM_CENTS:
        raise AdError(f"The lowest price is {FLOOR_CPM_CENTS / 100:g} GFC per 1,000 views.")
    if budget_cents < max(MIN_BUDGET_CENTS, max_cpm_cents // 10):
        raise AdError(f"The budget must be at least {max(MIN_BUDGET_CENTS, max_cpm_cents // 10) / 100:g} GFC "
                      "(enough for 100 views at your price).")
    conn = sqlite3.connect(db_path)
    try:
        init_tables(conn)
        seed = conn.execute("SELECT owner FROM seeds WHERE id = ?", (seed_id,)).fetchone()
        if not seed or seed[0].lower() != owner.lower():
            raise AdError("You can only promote your own posts.")
        if moderation.is_hidden(conn, seed_id):
            raise AdError("This post was hidden after reports, so it can't be promoted.")
        w = conn.execute("SELECT owner FROM wallets WHERE id = ?", (wallet,)).fetchone()
        if not w or (w[0] or "").lower() != owner.lower():
            raise AdError("Pay from one of your own wallets.")
        if config.REQUIRE_PHONE_TO_POST:
            import phone_verify
            if not phone_verify.is_verified(conn, owner):
                raise AdError("Verify your phone number to run ads.")
    finally:
        conn.close()

    escrow = ads_wallet(db_path)
    cid = uuid.uuid4().hex[:16]
    tx = blockchain.process_transfer(db_path, wallet, escrow, budget_cents, reason=f"ads: budget for ad {cid}",
                                     data_key=data_key)  # ValueError if the balance is short
    now = _now()
    row = {"id": cid, "owner": owner, "wallet": wallet, "seed_id": seed_id, "budget_cents": budget_cents,
           "max_cpm_cents": max_cpm_cents, "starts_at": now.isoformat(),
           "ends_at": (now + datetime.timedelta(days=days)).isoformat(), "status": "active",
           "escrow_tx": tx["id"], "created_at": now.isoformat()}
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(f"INSERT INTO ad_campaigns ({', '.join(row)}) VALUES ({', '.join('?' * len(row))})",
                     list(row.values()))
        conn.commit()
    finally:
        conn.close()
    invalidate_market()
    return campaign(cid, db_path)


def campaign(cid: str, db_path: str = DB_PATH) -> Optional[dict]:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        init_tables(conn)
        row = conn.execute("SELECT * FROM ad_campaigns WHERE id = ?", (cid,)).fetchone()
        return _public(dict(row)) if row else None
    finally:
        conn.close()


def campaigns_of(owner: str, db_path: str = DB_PATH) -> List[dict]:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        init_tables(conn)
        rows = conn.execute("SELECT * FROM ad_campaigns WHERE LOWER(owner) = LOWER(?) ORDER BY created_at DESC",
                            (owner,)).fetchall()
        return [_public(dict(r)) for r in rows]
    finally:
        conn.close()


def _public(c: dict) -> dict:
    spent_cents = c["spent_mc"] / 1000
    return {
        "id": c["id"], "seed_id": c["seed_id"], "wallet": c["wallet"], "status": c["status"],
        "budget": c["budget_cents"] / 100, "max_cpm": c["max_cpm_cents"] / 100,
        "spent": round(spent_cents / 100, 2), "remaining": round((c["budget_cents"] - spent_cents) / 100, 2),
        "views": c["views"], "paid_to_creators": c["paid_creators_cents"] / 100,
        "avg_cpm": round(c["spent_mc"] / c["views"] / 100, 2) if c["views"] else None,
        "starts_at": c["starts_at"], "ends_at": c["ends_at"], "ended_at": c.get("ended_at"),
        "refund": c["refund_cents"] / 100 if c.get("refund_cents") is not None else None,
    }


def end_campaign(cid: str, status: str = "ended", db_path: str = DB_PATH) -> Optional[dict]:
    """Stop an ad and refund what's left of its budget (once)."""
    conn = sqlite3.connect(db_path, isolation_level=None)
    try:
        init_tables(conn)
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT wallet, budget_cents, spent_mc, status FROM ad_campaigns WHERE id = ?",
                           (cid,)).fetchone()
        if not row or row[3] != "active":
            conn.execute("ROLLBACK")
            return campaign(cid, db_path)
        refund_cents = max(0, (row[1] * 1000 - row[2]) // 1000)
        conn.execute("UPDATE ad_campaigns SET status = ?, ended_at = ?, refund_cents = ? WHERE id = ?",
                     (status, _now().isoformat(), refund_cents, cid))
        conn.execute("COMMIT")
        wallet = row[0]
    finally:
        conn.close()
    if refund_cents:
        tx = blockchain.process_transfer(db_path, ads_wallet(db_path), wallet, refund_cents,
                                         reason=f"ads: refund for ad {cid}")
        conn = sqlite3.connect(db_path)
        conn.execute("UPDATE ad_campaigns SET refund_tx = ? WHERE id = ?", (tx["id"], cid))
        conn.commit()
        conn.close()
    invalidate_market()
    return campaign(cid, db_path)


def sweep(db_path: str = DB_PATH) -> int:
    """End ads whose time is up or whose budget can't buy another view. Returns how many."""
    conn = sqlite3.connect(db_path)
    try:
        init_tables(conn)
        rows = conn.execute("SELECT id, ends_at, budget_cents * 1000 - spent_mc FROM ad_campaigns "
                            "WHERE status = 'active'").fetchall()
    finally:
        conn.close()
    now, ended = _now().isoformat(), 0
    for cid, ends_at, left_mc in rows:
        if ends_at <= now or left_mc < FLOOR_CPM_CENTS:
            end_campaign(cid, db_path=db_path)
            ended += 1
    return ended


# ---------- the market ----------

def invalidate_market():
    with _market_lock:
        _market.clear()


def _hour(t: datetime.datetime) -> str:
    return t.strftime("%Y-%m-%dT%H")


def supply_per_period(conn: sqlite3.Connection) -> int:
    """Ad slots the feed showed in the last hour, scaled to one market period."""
    now = _now()
    hours = [_hour(now), _hour(now - datetime.timedelta(hours=1))]
    shown = conn.execute(f"SELECT COALESCE(SUM(slots), 0) FROM ad_slots WHERE hour IN ({','.join('?' * len(hours))})",
                         hours).fetchone()[0]
    return max(MIN_SUPPLY_PER_PERIOD, int(shown / 2 * MARKET_PERIOD_S / 3600))


def compute_market(db_path: str = DB_PATH, now: Optional[datetime.datetime] = None) -> dict:
    """The uniform-price auction for the next period (see the module docstring)."""
    now = now or _now()
    conn = sqlite3.connect(db_path)
    try:
        init_tables(conn)
        supply = supply_per_period(conn)
        rows = conn.execute("SELECT id, owner, seed_id, max_cpm_cents, budget_cents * 1000 - spent_mc, ends_at "
                            "FROM ad_campaigns WHERE status = 'active' AND ends_at > ? ORDER BY max_cpm_cents DESC, "
                            "created_at ASC", (now.isoformat(),)).fetchall()
    finally:
        conn.close()
    demand = []
    for cid, owner, seed_id, bid, left_mc, ends_at in rows:
        if left_mc < bid:  # can't afford a view at its own price; the clearing price may be lower
            if left_mc < FLOOR_CPM_CENTS:
                continue
        periods = max(1.0, (datetime.datetime.fromisoformat(ends_at) - now).total_seconds() / MARKET_PERIOD_S)
        wants = max(1, int(left_mc / bid / periods))
        demand.append({"id": cid, "owner": owner, "seed_id": seed_id, "bid": bid, "wants": wants})
    winners, left, price = [], supply, FLOOR_CPM_CENTS
    for d in demand:
        if left <= 0:
            price = max(FLOOR_CPM_CENTS, d["bid"])  # the first ad that missed out sets the price
            break
        take = min(d["wants"], left)
        winners.append({**d, "views": take})
        left -= take
    market = {"computed_at": time.time(), "clearing_cpm_cents": price, "supply": supply,
              "demand": sum(d["wants"] for d in demand), "winners": winners, "active": len(demand)}
    with _market_lock:
        _market.clear()
        _market.update(market)
    return market


def current_market(db_path: str = DB_PATH) -> dict:
    with _market_lock:
        fresh = _market and time.time() - _market["computed_at"] < MARKET_PERIOD_S
        if fresh:
            return dict(_market)
    sweep(db_path)
    return compute_market(db_path)


def public_market(db_path: str = DB_PATH) -> dict:
    m = current_market(db_path)
    return {"price_per_1000_views": m["clearing_cpm_cents"] / 100, "floor_per_1000_views": FLOOR_CPM_CENTS / 100,
            "active_ads": m["active"], "views_per_15_min": m["supply"], "views_wanted_per_15_min": m["demand"],
            "creator_share": CREATOR_SHARE, "ad_every": AD_EVERY, "max_days": MAX_DAYS,
            "min_budget": MIN_BUDGET_CENTS / 100}


# ---------- serving ----------

def _token(cid: str, viewer: str, above: str, price: int, exp: int) -> str:
    import exclusive
    body = f"{cid}|{viewer.lower()}|{above}|{price}|{exp}"
    sig = hmac.new(exclusive._secret(), b"ads\n" + body.encode(), hashlib.sha256).hexdigest()[:32]
    return f"{body}|{sig}"


def _read_token(token: str) -> Optional[dict]:
    import exclusive
    parts = (token or "").split("|")
    if len(parts) != 6:
        return None
    cid, viewer, above, price, exp, sig = parts
    body = "|".join(parts[:5])
    good = hmac.new(exclusive._secret(), b"ads\n" + body.encode(), hashlib.sha256).hexdigest()[:32]
    try:
        if not hmac.compare_digest(good, sig) or int(exp) < time.time():
            return None
        return {"campaign": cid, "viewer": viewer, "above": above, "price": int(price)}
    except ValueError:
        return None


def insert_ads(items: List[dict], viewer: str, ad_items: Dict[str, dict], db_path: str = DB_PATH) -> List[dict]:
    """
    The feed with an ad after every AD_EVERY posts, for a logged-in viewer. `ad_items` maps
    seed ids to feed items (the ads' posts). Each ad carries a signed token for its view.
    """
    if not viewer or viewer == "anonymous" or len(items) < AD_EVERY:
        return items
    m = current_market(db_path)
    conn = sqlite3.connect(db_path)
    try:
        blocked = {b.lower() for b in moderation.blocked_by(conn, viewer)}
        hidden = moderation.hidden_seed_ids(conn)
    finally:
        conn.close()
    pool = [w for w in m.get("winners", []) if w["owner"].lower() != viewer.lower()
            and w["owner"].lower() not in blocked and w["seed_id"] not in hidden and w["seed_id"] in ad_items]
    if not pool:
        return items
    out, slots, exp = [], 0, int(time.time()) + TOKEN_TTL_S
    for i, item in enumerate(items, 1):
        out.append(item)
        if i % AD_EVERY:
            continue
        w = random.choices(pool, weights=[p["views"] for p in pool])[0]
        ad = dict(ad_items[w["seed_id"]])
        ad["ad"] = {"campaign": w["id"], "label": "Sponsored",
                    "token": _token(w["id"], viewer, item.get("id", ""), m["clearing_cpm_cents"], exp)}
        out.append(ad)
        slots += 1
    if slots:
        conn = sqlite3.connect(db_path)
        try:
            conn.execute("INSERT INTO ad_slots (hour, slots) VALUES (?, ?) "
                         "ON CONFLICT(hour) DO UPDATE SET slots = slots + excluded.slots", (_hour(_now()), slots))
            conn.commit()
        finally:
            conn.close()
    return out


def ad_seed_ids(db_path: str = DB_PATH) -> List[str]:
    return [w["seed_id"] for w in current_market(db_path).get("winners", [])]


# ---------- views and instant pay ----------

def record_view(token: str, viewer: str, db_path: str = DB_PATH) -> dict:
    """
    Count one view of an ad (the token the node signed when it served the ad), charge the
    campaign the slot's price, and pay the creator of the post above it at once.
    """
    t = _read_token(token)
    if not t or t["viewer"] != viewer.lower():
        raise AdError("This ad view isn't valid (it expired or wasn't served to you).")
    conn = sqlite3.connect(db_path)
    try:
        init_tables(conn)
        row = conn.execute("SELECT owner, status, budget_cents * 1000 - spent_mc FROM ad_campaigns WHERE id = ?",
                           (t["campaign"],)).fetchone()
        if not row:
            raise AdError("No such ad.")
        owner, status, left_mc = row
        if owner.lower() == viewer.lower():
            return {"counted": False, "why": "your own ad"}
        if status != "active":
            return {"counted": False, "why": "the ad has ended"}
        if config.REQUIRE_PHONE_TO_POST:
            import phone_verify
            if not phone_verify.is_verified(conn, viewer):
                return {"counted": False, "why": "views count from verified accounts"}
        price = min(t["price"], left_mc)
        above = conn.execute("SELECT owner, COALESCE(reward_wallet, ''), COALESCE(signature, '') FROM seeds "
                             "WHERE id = ?", (t["above"],)).fetchone()
        creator_wallet = ""
        if above and above[1] and above[2] and above[0].lower() not in (viewer.lower(), owner.lower()):
            creator_wallet = above[1]
        creator_cents = int(price * CREATOR_SHARE) // 1000 if creator_wallet else 0
        day = _now().date().isoformat()
        vid = uuid.uuid4().hex
        try:
            conn.execute("INSERT INTO ad_views (id, campaign_id, viewer, day, above_seed, creator_wallet, price_mc, "
                         "creator_cents, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                         (vid, t["campaign"], viewer.lower(), day, t["above"], creator_wallet, price, creator_cents,
                          _now().isoformat()))
        except sqlite3.IntegrityError:
            return {"counted": False, "why": "already counted today"}
        conn.execute("UPDATE ad_campaigns SET spent_mc = spent_mc + ?, views = views + 1, "
                     "paid_creators_cents = paid_creators_cents + ? WHERE id = ?",
                     (price, creator_cents, t["campaign"]))
        conn.commit()
    finally:
        conn.close()

    payout = None
    if creator_cents:
        tx = blockchain.process_transfer(db_path, ads_wallet(db_path), creator_wallet, creator_cents,
                                         reason=f"ads: a view of ad {t['campaign']} under your post")
        payout = tx["id"]
        conn = sqlite3.connect(db_path)
        conn.execute("UPDATE ad_views SET payout_tx = ? WHERE id = ?", (payout, vid))
        conn.commit()
        conn.close()
    if left_mc - price < FLOOR_CPM_CENTS:
        end_campaign(t["campaign"], db_path=db_path)
    return {"counted": True, "price_per_1000_views": price / 100, "creator_paid": creator_cents / 100,
            "payout_tx": payout}


def apply_to_feed(items: List[dict], viewer: str, fetch_items, db_path: str = DB_PATH) -> List[dict]:
    """For /feed: ads' posts as feed items (via `fetch_items(seed_ids)`), placed by insert_ads."""
    if not viewer or viewer == "anonymous":
        return items
    try:
        ids = ad_seed_ids(db_path)
        if not ids:
            return items
        ad_items = {i["id"]: i for i in fetch_items(ids)}
        return insert_ads(items, viewer, ad_items, db_path)
    except Exception as ex:  # ads never break the feed
        print(f"[Ads] feed: {type(ex).__name__}: {ex}")
        return items
