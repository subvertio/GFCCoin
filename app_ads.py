"""
GFC Ads API (ads.py has how the market works).

- GET  /ads/market                    the current price per 1,000 views, and how busy the market is
- POST /ads/campaigns (spend scope)   promote one of your posts: seed_id, wallet_id, budget (GFC),
                                      max_cpm (GFC per 1,000 views), days
- GET  /ads/campaigns (read)          your ads, with views, spend and what creators were paid
- POST /ads/campaigns/{id}/cancel     stop an ad now; the unspent budget comes back
- POST /ads/view (read)               the app reports an ad it showed (the token from the feed);
                                      a counted view pays the creator of the post above it at once
"""

import sqlite3
from typing import List

from fastapi import APIRouter, Depends, Form, HTTPException

import ads
from config import DB_PATH
from security import Caller, caller_from_form, caller_from_query, release_spend, reserve_spend

router = APIRouter()


@router.get("/ads/market")
def market():
    return ads.public_market()


@router.post("/ads/campaigns")
def create(seed_id: str = Form(...), wallet_id: str = Form(...), budget: float = Form(...),
           max_cpm: float = Form(...), days: int = Form(7), caller: Caller = Depends(caller_from_form)):
    owner = caller.require("spend")
    budget_cents = int(round(budget * 100))
    reserve_spend(caller, budget_cents)
    try:
        return ads.create_campaign(owner, wallet_id, seed_id, budget_cents, int(round(max_cpm * 100)), days,
                                   data_key=caller.data_key())
    except ValueError as ex:  # AdError, or the wallet can't cover it
        release_spend(caller, budget_cents)
        raise HTTPException(status_code=400, detail=str(ex))


@router.get("/ads/campaigns")
def mine(caller: Caller = Depends(caller_from_query)):
    owner = caller.owner("read")
    if owner == "anonymous":
        raise HTTPException(status_code=401, detail="log in to see your ads")
    return {"campaigns": ads.campaigns_of(owner), "market": ads.public_market()}


@router.post("/ads/campaigns/{cid}/cancel")
def cancel(cid: str, caller: Caller = Depends(caller_from_form)):
    owner = caller.require("spend")
    c = ads.campaign(cid)
    if not c or not any(x["id"] == cid for x in ads.campaigns_of(owner)):
        raise HTTPException(status_code=404, detail="no such ad")
    return ads.end_campaign(cid, status="cancelled")


@router.post("/ads/view")
def view(token: str = Form(...), caller: Caller = Depends(caller_from_form)):
    viewer = caller.require("read")
    try:
        return ads.record_view(token, viewer)
    except ads.AdError as ex:
        raise HTTPException(status_code=400, detail=str(ex))


def feed_items_for(seed_ids: List[str], viewer: str) -> List[dict]:
    """Feed items for the ads' posts, with the viewer's like/bookmark/follow state."""
    from app_engagement import SEED_SELECT, seed_row_to_dict
    import app_follows
    import exclusive
    import filescan
    if not seed_ids:
        return []
    conn = sqlite3.connect(DB_PATH)
    try:
        rows = conn.execute(f"{SEED_SELECT} WHERE seeds.id IN ({','.join('?' * len(seed_ids))})", seed_ids).fetchall()
        items = [seed_row_to_dict(r) for r in rows]
        app_follows.apply_to_items(conn, items, viewer)
    finally:
        conn.close()
    return filescan.apply_to_items(exclusive.apply_to_items(items))
