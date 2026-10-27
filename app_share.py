"""
GFC Share Pages - public, read-only pages for seeds, so apps can post links to X etc.

Home nodes sit behind routers, so X and other sites can't fetch them. A gateway
node on the public domain serves these pages for every seed it has synced.

- GET /p/{seed_id}                 HTML page with Open Graph / Twitter Card tags
- GET /p/{seed_id}/share           share URL, text and X web intent URL (JSON)
- GET /.well-known/assetlinks.json Android App Links verification

Seed rows arrive from peers and are untrusted: every field is HTML-escaped and
every path segment is URL-quoted. The pages run no script.

Environment:
- GFC_PUBLIC_BASE_URL       absolute base for og:url / og:image (default https://galacticfederation.tech)
- GFC_APP_LINK_BASE         deep link prefix for "Open in GFC" (default gfc://seed)
- GFC_ANDROID_PACKAGE       Android package name for assetlinks.json (default: none)
- GFC_ANDROID_CERT_SHA256   comma-separated SHA-256 signing cert fingerprints (default: none)
- GFC_ANDROID_FALLBACK_URL  where Android goes from "Open in GFC" when the app isn't installed
                            (default: stay on the share page; set to the Play Store listing once live)

On Android, "Open in GFC" is an intent:// link (when GFC_ANDROID_PACKAGE is set). X and other
apps often open links in an in-app browser that ignores App Links and custom schemes; Android
intent links still launch the app there, or fall back to GFC_ANDROID_FALLBACK_URL.
"""
import html
import os
import secrets
import sqlite3
from urllib.parse import quote, urlencode, urlsplit

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse

import signing
from config import DB_PATH
from security import PUBLIC_USER_COLUMNS

router = APIRouter()

DEFAULT_PUBLIC_BASE_URL = "https://galacticfederation.tech"
DEFAULT_APP_LINK_BASE = "gfc://seed"
DESCRIPTION_LIMIT = 200


# ---------- config (read per request so a gateway can change it without code edits) ----------

def public_base_url() -> str:
    return (os.environ.get("GFC_PUBLIC_BASE_URL") or DEFAULT_PUBLIC_BASE_URL).rstrip("/")


def app_link_base() -> str:
    return (os.environ.get("GFC_APP_LINK_BASE") or DEFAULT_APP_LINK_BASE).rstrip("/")


def android_open_link(seed_id: str, page_url: str) -> str:
    """
    Android intent:// link that opens the GFC app at this seed, e.g. for gfc://seed/<id>:
    intent://seed/<id>#Intent;scheme=gfc;package=<pkg>;S.browser_fallback_url=<url>;end
    """
    target = urlsplit(app_link_base())
    package = os.environ.get("GFC_ANDROID_PACKAGE", "").strip()
    fallback = os.environ.get("GFC_ANDROID_FALLBACK_URL", "").strip() or page_url
    path = f"{target.netloc}{target.path}/{quote(seed_id, safe='')}"
    return (f"intent://{path}#Intent;scheme={target.scheme};package={package};"
            f"S.browser_fallback_url={quote(fallback, safe='')};end")


def open_in_app_link(seed_id: str, page_url: str, user_agent: str) -> str:
    """intent:// on Android when the app's package is configured, else the plain deep link."""
    if "android" in (user_agent or "").lower() and os.environ.get("GFC_ANDROID_PACKAGE", "").strip():
        return android_open_link(seed_id, page_url)
    return f"{app_link_base()}/{quote(seed_id, safe='')}"


def share_url(seed_id: str) -> str:
    return f"{public_base_url()}/p/{quote(seed_id, safe='')}"


def x_intent_url(text: str, url: str) -> str:
    """X web intent: https://x.com/intent/post?text=<text>&url=<url> (both URL-encoded)."""
    return "https://x.com/intent/post?" + urlencode({"text": text, "url": url})


# ---------- data ----------

def load_seed(seed_id: str) -> dict:
    """The public fields of a seed and its creator, or HTTP 404."""
    conn = sqlite3.connect(DB_PATH)
    try:
        row = conn.execute(
            "SELECT id, owner, title, description, filename, thumb_filename, content_type, created_at "
            "FROM seeds WHERE id = ?", (seed_id,)
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="seed not found")
        seed = dict(zip(("id", "owner", "title", "description", "filename", "thumb_filename",
                         "content_type", "created_at"), row))
        seed = {k: ("" if v is None else str(v)) for k, v in seed.items()}
        # Only public user columns, never email/phone/names/password.
        user = conn.execute(
            f"SELECT {PUBLIC_USER_COLUMNS} FROM users WHERE LOWER(username) = LOWER(?)", (seed["owner"],)
        ).fetchone()
        public_user = dict(zip([c.strip() for c in PUBLIC_USER_COLUMNS.split(",")], user)) if user else {}
        seed["owner_avatar"] = public_user.get("avatar_filename") or ""
        seed["reward_wallet"] = signing.seed_reward_wallet(conn, seed_id) or ""
        return seed
    finally:
        conn.close()


def share_text(seed: dict) -> str:
    title = seed["title"] or "a seed"
    return f"{title} by {seed['owner']} on GFC" if seed["owner"] else f"{title} on GFC"


# ---------- routes ----------

@router.get("/p/{seed_id}/share")
def share_info(seed_id: str):
    """What the app needs to share a seed: the page URL, suggested text and an X intent URL."""
    seed = load_seed(seed_id)
    url, text = share_url(seed["id"]), share_text(seed)
    return {"url": url, "text": text, "x_intent_url": x_intent_url(text, url),
            "app_link": f"{app_link_base()}/{quote(seed['id'], safe='')}"}


@router.get("/p/{seed_id}", response_class=HTMLResponse)
def share_page(seed_id: str, request: Request):
    seed = load_seed(seed_id)
    e = lambda s: html.escape(s, quote=True)  # noqa: E731
    base = public_base_url()
    url = share_url(seed["id"])
    title = seed["title"] or seed["filename"] or "Untitled seed"
    description = seed["description"] or f"A seed by {seed['owner']} on GFC"
    og_description = description if len(description) <= DESCRIPTION_LIMIT else description[:DESCRIPTION_LIMIT - 1] + "…"
    thumb_path = f"/thumbs/{quote(seed['thumb_filename'], safe='')}" if seed["thumb_filename"] else ""
    media_path = f"/originals/{quote(seed['filename'], safe='')}" if seed["filename"] else ""
    app_link = open_in_app_link(seed["id"], url, request.headers.get("user-agent", ""))
    intent = x_intent_url(share_text(seed), url)

    ctype = seed["content_type"]
    poster = f' poster="{e(thumb_path)}"' if thumb_path else ""
    if ctype == "image" and media_path:
        media = f'<img class="media" src="{e(media_path)}" alt="{e(title)}">'
    elif ctype == "video" and media_path:
        media = f'<video class="media" controls preload="metadata"{poster} src="{e(media_path)}"></video>'
    elif ctype == "audio" and media_path:
        cover = f'<img class="media" src="{e(thumb_path)}" alt="{e(title)}">' if thumb_path else ""
        media = f'{cover}<audio controls preload="metadata" src="{e(media_path)}"></audio>'
    elif thumb_path:  # 3D and anything else: poster image only
        media = f'<img class="media" src="{e(thumb_path)}" alt="{e(title)}">'
    else:
        media = '<div class="media placeholder">Open in GFC to view</div>'

    image_tags = ""
    if thumb_path or (ctype == "image" and media_path):
        image = base + (thumb_path or media_path)
        image_tags = (f'<meta property="og:image" content="{e(image)}">\n'
                      f'<meta name="twitter:image" content="{e(image)}">\n')
    badge = ('<p class="badge" title="Signed by its reward wallet">&#10003; Rewards verified</p>'
             if seed["reward_wallet"] else "")
    avatar = (f'<img class="avatar" src="/avatars/{e(quote(seed["owner_avatar"], safe=""))}" alt="">'
              if seed["owner_avatar"] else "")

    nonce = secrets.token_urlsafe(16)
    page = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{e(title)} | GFC</title>
<meta name="description" content="{e(og_description)}">
<link rel="canonical" href="{e(url)}">
<meta property="og:type" content="website">
<meta property="og:site_name" content="GFC">
<meta property="og:title" content="{e(title)}">
<meta property="og:description" content="{e(og_description)}">
<meta property="og:url" content="{e(url)}">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="{e(title)}">
<meta name="twitter:description" content="{e(og_description)}">
{image_tags}<style nonce="{nonce}">
body{{margin:0;font-family:system-ui,sans-serif;background:#0b0d17;color:#e8e9f0}}
main{{max-width:720px;margin:0 auto;padding:16px}}
.media{{display:block;width:100%;max-height:70vh;object-fit:contain;background:#000;border-radius:8px}}
.placeholder{{padding:64px 0;text-align:center;color:#9aa}}
audio{{width:100%;margin-top:8px}}
h1{{font-size:1.4rem;margin:16px 0 4px}}
.creator{{display:flex;align-items:center;gap:8px;color:#b8bccc}}
.avatar{{width:28px;height:28px;border-radius:50%}}
.badge{{display:inline-block;padding:2px 8px;border-radius:12px;background:#1d4d2f;color:#9ff0b8;font-size:.85rem}}
.desc{{white-space:pre-wrap;line-height:1.5}}
.actions a{{display:inline-block;margin:8px 8px 0 0;padding:10px 16px;border-radius:8px;background:#3b4cca;color:#fff;text-decoration:none}}
</style>
</head>
<body>
<main>
{media}
<h1>{e(title)}</h1>
<p class="creator">{avatar}<span>by {e(seed["owner"])}</span></p>
{badge}
<p class="desc">{e(seed["description"])}</p>
<p class="actions"><a href="{e(app_link)}">Open in GFC</a><a href="{e(intent)}" rel="noopener" target="_blank">Post to X</a></p>
</main>
</body>
</html>
"""
    csp = ("default-src 'none'; img-src 'self'; media-src 'self'; "
           f"style-src 'nonce-{nonce}'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
    return HTMLResponse(page, headers={
        "Content-Security-Policy": csp,
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Vary": "User-Agent",  # "Open in GFC" differs on Android
    })


@router.get("/.well-known/assetlinks.json")
def assetlinks():
    """Android App Links: lets the GFC app open /p/... links directly once configured."""
    package = os.environ.get("GFC_ANDROID_PACKAGE", "").strip()
    fingerprints = [f.strip().upper() for f in os.environ.get("GFC_ANDROID_CERT_SHA256", "").split(",") if f.strip()]
    if not package or not fingerprints:
        return []
    return [{
        "relation": ["delegate_permission/common.handle_all_urls"],
        "target": {"namespace": "android_app", "package_name": package,
                   "sha256_cert_fingerprints": fingerprints},
    }]
