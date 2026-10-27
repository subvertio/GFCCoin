"""
GFC Treasury transparency - every operator grant, in public.

- GET /treasury/grants   HTML for browsers; JSON for API clients (Accept: application/json
                         or ?format=json): date, amount, purpose, recipient wallet, memo,
                         plus totals by purpose.

Read straight from the ledger (treasury-signed OPERATOR transactions, which every node
syncs and verifies), so any node shows the same list. The page runs no script; every
field is HTML-escaped (memos are free text).
"""
import html
import secrets

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse

import blockchain
import treasury_grants

router = APIRouter()

PURPOSE_LABELS = {"hackathon": "Hackathon", "node-host": "Node host", "other": "Other"}


def _summary(grants):
    totals = {p: 0.0 for p in blockchain.OPERATOR_PURPOSES}
    for g in grants:
        totals[g["purpose"]] = totals.get(g["purpose"], 0.0) + g["amount"]
    return {"count": len(grants), "total": round(sum(totals.values()), 2),
            "by_purpose": {k: round(v, 2) for k, v in totals.items()},
            "max_per_grant": blockchain.OPERATOR_GRANT_MAX_CENTS / 100.0,
            "node_host_grant": blockchain.NODE_HOST_GRANT_CENTS / 100.0}


@router.get("/treasury/grants")
def treasury_grants_page(request: Request):
    grants = treasury_grants.list_grants()
    summary = _summary(grants)
    wants_json = (request.query_params.get("format") == "json"
                  or "application/json" in request.headers.get("accept", "")
                  and "text/html" not in request.headers.get("accept", ""))
    if wants_json:
        return JSONResponse({"grants": grants, "summary": summary})

    e = lambda s: html.escape(str(s), quote=True)  # noqa: E731
    rows = "\n".join(
        f'<tr><td>{e(g["timestamp"][:10])}</td><td class="num">{g["amount"]:,.2f}</td>'
        f'<td>{e(PURPOSE_LABELS.get(g["purpose"], g["purpose"]))}</td>'
        f'<td class="wallet" title="{e(g["wallet"])}">{e(g["wallet"][:10])}&hellip;</td>'
        f'<td>{e(g["memo"])}</td></tr>' for g in grants
    ) or '<tr><td colspan="5" class="empty">No operator grants yet.</td></tr>'
    by = " &middot; ".join(f'{e(PURPOSE_LABELS[p])}: {summary["by_purpose"][p]:,.2f}'
                           for p in blockchain.OPERATOR_PURPOSES)
    nonce = secrets.token_urlsafe(16)
    page = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Treasury grants | GFC</title>
<meta name="description" content="Every GFC the network operator has granted: hackathon prizes, node hosts and more, with the reason for each.">
<style nonce="{nonce}">
*{{box-sizing:border-box}}
body{{margin:0;font-family:system-ui,-apple-system,"Segoe UI",sans-serif;background:#000;color:#e7e9ea}}
main{{max-width:760px;margin:0 auto;padding:24px 16px}}
h1{{margin:0 0 8px;font-size:1.4rem}}
p{{color:#71767b;line-height:1.5}}
.totals{{padding:12px 16px;border:1px solid #2f3336;border-radius:16px;background:#16181c;color:#e7e9ea}}
.totals b{{font-size:1.2rem}}
table{{width:100%;margin-top:16px;border-collapse:collapse;font-size:.92rem}}
th,td{{padding:10px 8px;border-bottom:1px solid #2f3336;text-align:left;vertical-align:top}}
th{{color:#71767b;font-weight:600}}
.num{{text-align:right;white-space:nowrap}}
.wallet{{font-family:ui-monospace,monospace;white-space:nowrap}}
td:last-child{{overflow-wrap:anywhere}}
.empty{{text-align:center;color:#71767b}}
a{{color:#7f8ce0}}
</style>
</head>
<body>
<main>
<h1>Treasury grants</h1>
<p>Every GFC the network operator has granted on purpose, such as hackathon prizes and thank-yous to people
running GFC nodes, with the reason for each. Every node checks these: at most
{summary["max_per_grant"]:,.0f} GFC per grant, and a node host's grant is exactly
{summary["node_host_grant"]:,.0f} GFC, once per wallet. <a href="/treasury/grants?format=json">JSON</a></p>
<div class="totals"><b>{summary["total"]:,.2f} GFC</b> in {summary["count"]} grant{"" if summary["count"] == 1 else "s"}<br>{by}</div>
<table>
<thead><tr><th>Date</th><th class="num">GFC</th><th>Purpose</th><th>Wallet</th><th>Memo</th></tr></thead>
<tbody>
{rows}
</tbody>
</table>
</main>
</body>
</html>
"""
    csp = (f"default-src 'none'; style-src 'nonce-{nonce}'; base-uri 'none'; "
           "form-action 'none'; frame-ancestors 'none'")
    return HTMLResponse(page, headers={"Content-Security-Policy": csp, "X-Content-Type-Options": "nosniff",
                                       "Vary": "Accept"})
