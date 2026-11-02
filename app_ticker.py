"""
GFC price ticker for galacticfederation.tech: the price of GFC on Base (Uniswap v3 GFC/WETH),
fetched by the node at most once a minute so visitors' browsers never hit a rate-limited API.

- GET /ticker.json   {symbol, priceUsd, change24hPct, volume24hUsd, liquidityUsd, fdvUsd,
                     updatedAt, source, stale, tradeUrl, chartUrl}. CORS open (public data, no
                     cookies), cached CACHE_SECONDS.
- GET /ticker        a small dark widget showing it (price, 24 h change, Trade on Uniswap),
                     refreshing itself every minute; made to be framed by the Wix site.

Sources, in order:
1. GeckoTerminal's free pool API (price, 24 h change, volume, liquidity, FDV).
2. On chain, when GeckoTerminal fails: the pool's own price (slot0) and Chainlink's ETH/USD feed
   on Base. Price only (no change or volume): nothing to trust but Base itself.
3. The last good answer, marked stale, for up to STALE_SECONDS; then 503.

Settings (optional): GFC_TICKER_POOL (default: the mainnet pool), GFC_TICKER_RPC_URL (default
https://mainnet.base.org).
"""

import datetime
import html
import os
import secrets
import threading
import time
from typing import Optional

import httpx
from fastapi import APIRouter
from fastapi.responses import HTMLResponse, JSONResponse

router = APIRouter()

POOL = os.environ.get("GFC_TICKER_POOL", "0xD64D155f4AB27Ef21CE4917FDB0c3Dc91a0F6C5E")
TOKEN = "0xc32695f463947170EC142F7987DaC93aa7243336"
RPC_URL = os.environ.get("GFC_TICKER_RPC_URL", "https://mainnet.base.org")
CHAINLINK_ETH_USD = "0x71041dddad3595F9CEd3DcCFBe3D1F4b0a16Bb70"  # Base mainnet, 8 decimals
GECKO_URL = "https://api.geckoterminal.com/api/v2/networks/base/pools/{pool}"
CACHE_SECONDS = 60
STALE_SECONDS = 3600
TIMEOUT = 8.0

_lock = threading.Lock()
_cache: dict = {"at": 0.0, "data": None}


def trade_url() -> str:
    return f"https://app.uniswap.org/swap?chain=base&outputCurrency={TOKEN}"


def chart_url() -> str:
    return f"https://www.geckoterminal.com/base/pools/{POOL}"


def _num(v) -> Optional[float]:
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def from_gecko() -> dict:
    r = httpx.get(GECKO_URL.format(pool=POOL), timeout=TIMEOUT, headers={"Accept": "application/json"})
    r.raise_for_status()
    a = r.json()["data"]["attributes"]
    price = _num(a.get("base_token_price_usd"))
    if not price or price <= 0:
        raise ValueError("no price in GeckoTerminal's answer")
    return {"priceUsd": price,
            "change24hPct": _num((a.get("price_change_percentage") or {}).get("h24")),
            "volume24hUsd": _num((a.get("volume_usd") or {}).get("h24")),
            "liquidityUsd": _num(a.get("reserve_in_usd")),
            "fdvUsd": _num(a.get("fdv_usd")),
            "source": "geckoterminal"}


def _eth_call(to: str, data: str) -> str:
    r = httpx.post(RPC_URL, timeout=TIMEOUT, json={"jsonrpc": "2.0", "id": 1, "method": "eth_call",
                                                   "params": [{"to": to, "data": data}, "latest"]})
    r.raise_for_status()
    out = r.json().get("result") or ""
    if len(out) < 66:
        raise ValueError(f"empty eth_call answer from {to}")
    return out[2:]


def from_chain() -> dict:
    """GFC in USD from the pool's sqrtPriceX96 (token0 WETH, token1 GFC, both 18 decimals) and Chainlink ETH/USD."""
    sqrt_price = int(_eth_call(POOL, "0x3850c7bd")[:64], 16)                 # slot0()
    words = _eth_call(CHAINLINK_ETH_USD, "0xfeaf968c")                       # latestRoundData()
    answer = int(words[64:128], 16)
    updated = int(words[192:256], 16)
    if sqrt_price == 0 or answer <= 0 or time.time() - updated > 6 * 3600:
        raise ValueError("pool or ETH/USD feed answer unusable")
    gfc_per_eth = (sqrt_price / 2 ** 96) ** 2
    return {"priceUsd": (answer / 1e8) / gfc_per_eth, "change24hPct": None, "volume24hUsd": None,
            "liquidityUsd": None, "fdvUsd": None, "source": "onchain"}


def ticker(now: Optional[float] = None) -> Optional[dict]:
    """The current ticker (cached), the last good one marked stale, or None."""
    now = now or time.time()
    with _lock:
        if _cache["data"] and now - _cache["at"] < CACHE_SECONDS:
            return _cache["data"]
        data = None
        for source in (from_gecko, from_chain):
            try:
                data = source()
                break
            except Exception:
                continue
        if data:
            data.update(symbol="GFC", stale=False, tradeUrl=trade_url(), chartUrl=chart_url(),
                        updatedAt=datetime.datetime.fromtimestamp(now, datetime.timezone.utc)
                        .replace(microsecond=0).isoformat().replace("+00:00", "Z"))
            _cache.update(at=now, data=data)
            return data
        if _cache["data"] and now - _cache["at"] < STALE_SECONDS:
            return {**_cache["data"], "stale": True}
        return None


@router.get("/ticker.json")
def ticker_json():
    data = ticker()
    headers = {"Access-Control-Allow-Origin": "*", "Cache-Control": f"public, max-age={CACHE_SECONDS}"}
    if not data:
        return JSONResponse({"error": "price unavailable"}, status_code=503, headers=headers)
    return JSONResponse(data, headers=headers)


@router.get("/ticker", response_class=HTMLResponse)
def ticker_widget():
    """A small widget for the website (framed by Wix): price, 24 h change, Trade on Uniswap."""
    nonce = secrets.token_urlsafe(16)
    e = lambda s: html.escape(s, quote=True)  # noqa: E731
    page = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>GFC price</title>
<style nonce="{nonce}">
html,body{{margin:0;background:transparent;font-family:system-ui,-apple-system,"Segoe UI",sans-serif}}
.t{{display:flex;align-items:center;justify-content:center;flex-wrap:wrap;gap:10px 16px;padding:10px 14px;
   border:1px solid #7c4dff66;border-radius:14px;background:#0b0618d9;color:#e8e6ff}}
.sym{{font-weight:800;letter-spacing:2px;color:#7df9ff}}
.price{{font-size:1.4rem;font-weight:800}}
.chg{{font-weight:700}}
.up{{color:#3ddc97}} .down{{color:#ff6b8a}} .flat{{color:#a9b0b6}}
.meta{{color:#a9b0b6;font-size:.8rem}}
a{{color:#05010f;background:linear-gradient(90deg,#7c4dff,#00e5ff);padding:8px 14px;border-radius:999px;
   font-weight:700;text-decoration:none;font-size:.9rem}}
</style></head>
<body><div class="t">
<span class="sym">GFC</span><span class="price" id="p">&hellip;</span><span class="chg flat" id="c"></span>
<span class="meta" id="m">on Base &middot; Uniswap</span>
<a href="{e(trade_url())}" target="_blank" rel="noopener">Trade on Uniswap</a>
</div>
<script nonce="{nonce}">
const fmt = (v) => v >= 1 ? v.toFixed(2) : v >= 0.01 ? v.toFixed(4) : v.toPrecision(3);
async function load() {{
  try {{
    const r = await fetch("/ticker.json", {{cache: "no-store"}});
    const t = await r.json();
    if (!r.ok || !t.priceUsd) throw new Error();
    document.getElementById("p").textContent = "$" + fmt(t.priceUsd);
    const c = document.getElementById("c");
    if (typeof t.change24hPct === "number") {{
      const v = t.change24hPct;
      c.textContent = (v > 0 ? "\\u25B2" : v < 0 ? "\\u25BC" : "") + Math.abs(v).toFixed(2) + "% 24h";
      c.className = "chg " + (v > 0 ? "up" : v < 0 ? "down" : "flat");
    }} else {{ c.textContent = ""; }}
    document.getElementById("m").textContent = t.stale ? "price may be delayed" : "on Base \\u00B7 Uniswap";
  }} catch (e) {{
    document.getElementById("m").textContent = "price unavailable right now";
  }}
}}
load();
setInterval(load, 60000);
</script></body></html>"""
    csp = (f"default-src 'none'; script-src 'nonce-{nonce}'; style-src 'nonce-{nonce}'; connect-src 'self'; "
           "base-uri 'none'; form-action 'none'; frame-ancestors *")  # a price widget: anyone may show it
    return HTMLResponse(page, headers={"Content-Security-Policy": csp, "X-Content-Type-Options": "nosniff",
                                       "Cache-Control": "no-cache"})
