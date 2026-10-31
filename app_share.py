"""
GFC Share Pages - public, read-only pages for seeds, so apps can post links to X etc.

Home nodes sit behind routers, so X and other sites can't fetch them. A gateway
node on the public domain serves these pages for every seed it has synced.

- GET /p/{seed_id}                 HTML page with Open Graph / Twitter Card tags
- GET /p/{seed_id}/share           share URL, text and X web intent URL (JSON)
- GET /join?ref=<username>         invite landing page ("<username> invited you"), see referrals.py
- GET /.well-known/assetlinks.json Android App Links verification

Any page accepts ?ref=<username>; it's passed to the app's deep link so the
invite survives install-and-open, and the app sends it at sign-up.

A repost (reposts.py) is labelled "Repost of @original", linking to the original's
page, and its share text credits the original creator.

Seed rows arrive from peers and are untrusted: every field is HTML-escaped and
every path segment is URL-quoted. The pages run no script of their own; a 3D seed's
page (.glb / .gltf) loads Google's <model-viewer> web component, pinned with SRI, to
show the model like the app's viewer does (turntable, orbit, neutral lighting, looping
animation). Other pages load no script at all.

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
import re
import secrets
import sqlite3
from urllib.parse import quote, urlencode, urlsplit

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse

import app_release
import audio_stream
import exclusive
import filescan
import moderation
import reposts
import signing
from config import DB_PATH
from security import PUBLIC_USER_COLUMNS

router = APIRouter()

DEFAULT_PUBLIC_BASE_URL = "https://galacticfederation.tech"
DEFAULT_APP_LINK_BASE = "gfc://seed"
DESCRIPTION_LIMIT = 200

# <model-viewer> for 3D seeds. Pinned version + SRI hash; bump both together.
MODEL_VIEWER_SRC = "https://cdn.jsdelivr.net/npm/@google/model-viewer@4.4.0/dist/model-viewer.min.js"
MODEL_VIEWER_SRI = "sha384-wjsPzEO+lXOf7d9csIDfAQpPt2OKuUU3m0K9qsdKIuzX4N8czSF6hdh23eAbZa3p"
# Hash of the <style> model-viewer puts in its shadow DOM (fixed per version), so the CSP
# can allow it without 'unsafe-inline'. The browser console prints the new one after a bump.
MODEL_VIEWER_STYLE_HASH = "sha256-PXtZZkJMMyc18o/DN1ZEFOJ2qEGq95IQbVaJFMOXOb0="
MODEL_VIEWER_EXTENSIONS = (".glb", ".gltf")


# ---------- config (read per request so a gateway can change it without code edits) ----------

# Shown next to "Open in GFC" once an Android release is published (app_release.py)
GET_APP_LINK = '<a class="secondary" href="/app">Get the app</a>'


def public_base_url() -> str:
    return (os.environ.get("GFC_PUBLIC_BASE_URL") or DEFAULT_PUBLIC_BASE_URL).rstrip("/")


def app_link_base() -> str:
    return (os.environ.get("GFC_APP_LINK_BASE") or DEFAULT_APP_LINK_BASE).rstrip("/")


REF_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


def clean_ref(ref) -> str:
    """An invite ref (inviter username) safe to pass along, or '' if it isn't one."""
    ref = (ref or "").strip()
    return ref if REF_RE.match(ref) else ""


def _with_ref(route: str, ref: str) -> str:
    return f"{route}{'&' if '?' in route else '?'}ref={quote(ref, safe='')}" if ref else route


def _app_link(route: str, page_url: str, user_agent: str) -> str:
    """
    Link that opens the app at `route` (e.g. "seed/<id>", "join?ref=x"): an Android
    intent:// link (works inside X's in-app browser, falls back to page_url or
    GFC_ANDROID_FALLBACK_URL) when the package is configured, else gfc://<route>.
    """
    scheme = urlsplit(app_link_base()).scheme or "gfc"
    if "android" in (user_agent or "").lower() and os.environ.get("GFC_ANDROID_PACKAGE", "").strip():
        return _intent_link(route, page_url)
    return f"{scheme}://{route}"


def _intent_link(route: str, page_url: str) -> str:
    """intent://<route>#Intent;scheme=gfc;package=<pkg>;S.browser_fallback_url=<url>;end"""
    scheme = urlsplit(app_link_base()).scheme or "gfc"
    package = os.environ.get("GFC_ANDROID_PACKAGE", "").strip()
    # No app installed: the download page once a release is published, else the page itself
    fallback = (os.environ.get("GFC_ANDROID_FALLBACK_URL", "").strip()
                or (f"{public_base_url()}/app" if app_release.info() else page_url))
    return (f"intent://{route}#Intent;scheme={scheme};package={package};"
            f"S.browser_fallback_url={quote(fallback, safe='')};end")


def _seed_route(seed_id: str) -> str:
    target = urlsplit(app_link_base())
    return f"{target.netloc}{target.path}/{quote(seed_id, safe='')}"


def android_open_link(seed_id: str, page_url: str, ref: str = "") -> str:
    """Android intent:// link that opens the GFC app at this seed (see _app_link)."""
    return _intent_link(_with_ref(_seed_route(seed_id), ref), page_url)


def open_in_app_link(seed_id: str, page_url: str, user_agent: str, ref: str = "") -> str:
    """intent:// on Android when the app's package is configured, else the plain deep link."""
    if "android" in (user_agent or "").lower() and os.environ.get("GFC_ANDROID_PACKAGE", "").strip():
        return android_open_link(seed_id, page_url, ref)
    return _with_ref(f"{app_link_base()}/{quote(seed_id, safe='')}", ref)


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
        if moderation.is_hidden(conn, seed_id):
            raise HTTPException(status_code=410, detail="This post was hidden after reports.")
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
        seed["repost_of"] = reposts.public_info(reposts.repost_of(conn, seed_id))
        seed["stream"] = (audio_stream.stream_url(seed_id, seed["content_type"])
                          if seed["content_type"] in audio_stream.STREAM_KINDS else None)
        seed["exclusive"] = exclusive.is_exclusive(conn, seed_id)
        if filescan.is_download(seed["filename"]):
            scan = filescan.status_of(conn, seed_id)
            if scan and scan["status"] in filescan.REMOVED:
                raise HTTPException(status_code=410, detail="This file was removed: it failed the virus or safety check.")
        seed["teaser"] = exclusive.teaser_url(seed_id) if seed["exclusive"] else None
        seed["teaser_seconds"] = exclusive.seconds_of(conn, seed_id)
        if seed["exclusive"]:
            seed["stream"] = None
            if exclusive.is_text_file(seed["filename"]):
                seed["description"] = ""  # the body is for real accounts only
        return seed
    finally:
        conn.close()


def share_text(seed: dict) -> str:
    title = seed["title"] or "a seed"
    if seed.get("repost_of"):  # credit the original creator, not the reposter
        return f"{title} by {seed['repost_of']['owner']} on GFC"
    return f"{title} by {seed['owner']} on GFC" if seed["owner"] else f"{title} on GFC"


# ---------- routes ----------

@router.get("/p/{seed_id}/share")
def share_info(seed_id: str):
    """What the app needs to share a seed: the page URL, suggested text and an X intent URL."""
    seed = load_seed(seed_id)
    url, text = share_url(seed["id"]), share_text(seed)
    return {"url": url, "text": text, "x_intent_url": x_intent_url(text, url),
            "app_link": f"{app_link_base()}/{quote(seed['id'], safe='')}",
            "repost_of": seed["repost_of"]}


@router.get("/p/{seed_id}", response_class=HTMLResponse)
def share_page(seed_id: str, request: Request):
    seed = load_seed(seed_id)
    e = lambda s: html.escape(s, quote=True)  # noqa: E731
    base = public_base_url()
    url = share_url(seed["id"])
    title = seed["title"] or seed["filename"] or "Untitled seed"
    description = seed["description"] or f"A seed by {seed['owner']} on GFC"
    if seed["exclusive"]:
        text_post = exclusive.is_text_file(seed["filename"])
        title = seed["title"] or "GFC Exclusive"
        if text_post or not seed["description"]:
            what = "the whole post" if text_post else "the full clip"
            description = f"Exclusive to the GFC Network: log in to the GFC app to see {what}. By {seed['owner']}."
    og_description = description if len(description) <= DESCRIPTION_LIMIT else description[:DESCRIPTION_LIMIT - 1] + "…"
    thumb_path = f"/thumbs/{quote(seed['thumb_filename'], safe='')}" if seed["thumb_filename"] else ""
    media_path = f"/originals/{quote(seed['filename'], safe='')}" if seed["filename"] else ""
    app_link = open_in_app_link(seed["id"], url, request.headers.get("user-agent", ""),
                                clean_ref(request.query_params.get("ref")))
    intent = x_intent_url(share_text(seed), url)

    ctype = seed["content_type"]
    viewer_3d = (ctype == "3d" and bool(media_path)
                 and seed["filename"].lower().endswith(MODEL_VIEWER_EXTENSIONS))
    poster = f' poster="{e(thumb_path)}"' if thumb_path else ""
    if filescan.is_download(seed["filename"]):
        viewer_3d = False
        from app_web import download_box  # app_web imports this module
        item = filescan.apply_to_items([{"id": seed["id"], "full": media_path and f"/originals/{seed['filename']}",
                                          "exclusive": seed["exclusive"]}])
        dl_item = item[0] if item else {"download": {"name": seed["filename"], "status": filescan.PENDING}}
        media = download_box(dl_item, "")
        if seed["exclusive"]:
            media = '<p class="badge exclusive">&#9733; Exclusive to the GFC Network</p>' + media
    elif seed["exclusive"]:
        viewer_3d = False
        if ctype == "video" and seed["teaser"]:
            media = (f'<video class="hero" controls playsinline preload="metadata"{poster} data-exclusive="1" '
                     f'src="{e(seed["teaser"])}"></video>')
        elif thumb_path:
            media = f'<img class="hero" src="{e(thumb_path)}" alt="{e(title)}">'
        else:
            media = ""
        what = "read the whole post" if ctype != "video" else "watch the full clip"
        preview = f" &middot; {seed['teaser_seconds']}-second preview" if ctype == "video" and seed["teaser"] else ""
        media += (f'<p class="badge exclusive">&#9733; Exclusive to the GFC Network{preview}</p>'
                  f'<p class="exclusive-note">Log in to the <a class="getapp-open" href="/app">GFC app</a> '
                  f'with a verified account to {what}.</p>')
    elif ctype == "image" and media_path:
        media = f'<img class="hero" src="{e(media_path)}" alt="{e(title)}">'
    elif ctype == "video" and media_path:
        video_path = seed["stream"] or media_path  # the upright 720p copy plays everywhere
        media = f'<video class="hero" controls playsinline preload="metadata"{poster} src="{e(video_path)}"></video>'
    elif ctype == "audio" and media_path:
        cover = f'<img class="hero" src="{e(thumb_path)}" alt="{e(title)}">' if thumb_path else ""
        play_path = seed["stream"] or media_path  # prefer the compressed streaming copy
        media = f'{cover}<audio controls preload="metadata" src="{e(play_path)}"></audio>'
    elif viewer_3d:
        # Like the app's viewer: slow turntable that resumes after the user lets go,
        # orbit/pinch zoom, neutral lighting, first animation looping. The poster shows
        # at once; the model only downloads when the viewer scrolls into view.
        media = (f'<model-viewer class="hero" src="{e(media_path)}"{poster} alt="{e(title)}" '
                 'loading="lazy" reveal="auto" camera-controls disable-zoom touch-action="pan-y" '
                 'auto-rotate auto-rotate-delay="3000" rotation-per-second="14deg" '
                 'environment-image="neutral" exposure="1" shadow-intensity="0.5" autoplay>'
                 '</model-viewer>')
    elif thumb_path:  # other 3D formats and anything else: poster image only
        media = f'<img class="hero" src="{e(thumb_path)}" alt="{e(title)}">'
    else:
        media = '<div class="placeholder">Open in GFC to view</div>'

    badge = ('<p class="badge" title="Signed by its reward wallet">&#10003; Rewards verified</p>'
             if seed["reward_wallet"] and not seed["repost_of"] else "")
    repost = ""
    if seed["repost_of"]:
        original = seed["repost_of"]
        repost = (f'<p class="repost">Repost of <a href="/p/{e(quote(original["seed_id"], safe=""))}">'
                  f'@{e(original["owner"])}</a>. Earnings go to the original creator.</p>')
    avatar = (f'<img class="avatar" src="/avatars/{e(quote(seed["owner_avatar"], safe=""))}" alt="">'
              if seed["owner_avatar"] else "")

    viewer_head = (f'<script type="module" src="{MODEL_VIEWER_SRC}" integrity="{MODEL_VIEWER_SRI}" '
                   'crossorigin="anonymous"></script>\n' if viewer_3d else "")
    featured_html = (f'{media}\n<h1>{e(title)}</h1>\n'
                     f'<p class="creator">{avatar}<span>by {e(seed["owner"])}</span></p>\n'
                     f'{repost}{badge}\n<p class="desc">{e(seed["description"])}</p>\n'
                     f'<p class="actions"><a href="{e(app_link)}">Open in GFC</a>'
                     f'<a class="secondary" href="{e(intent)}" rel="noopener" target="_blank">Post to X</a>'
                     f'{GET_APP_LINK if app_release.info() else ""}</p>\n'
                     '<a class="next" href="#feed">More on GFC <span aria-hidden="true">&#8595;</span></a>')
    image = base + (thumb_path or media_path) if (thumb_path or (ctype == "image" and media_path)) else ""
    if seed["exclusive"]:
        image = base + thumb_path if thumb_path else ""  # never the locked original

    # The shared post, focused on top, then the whole feed below it (newest first)
    from app_web import feed_html_response  # app_web imports this module
    return feed_html_response(request, 1, featured={
        "id": seed["id"], "html": featured_html, "title": title, "page_title": f"{title} | GFC", "description": og_description,
        "url": url, "image": image, "app_link": app_link, "head": viewer_head,
    })

@router.get("/join", response_class=HTMLResponse)
def join_page(request: Request):
    """Invite landing page: '<inviter> invited you to GFC', with Open in GFC carrying the invite."""
    ref = clean_ref(request.query_params.get("ref"))
    inviter = ""
    if ref:
        conn = sqlite3.connect(DB_PATH)
        row = conn.execute("SELECT username FROM users WHERE LOWER(username) = LOWER(?)", (ref,)).fetchone()
        conn.close()
        inviter = row[0] if row else ""
    e = lambda s: html.escape(s, quote=True)  # noqa: E731
    url = f"{public_base_url()}/join" + (f"?ref={quote(inviter, safe='')}" if inviter else "")
    title = f"{inviter} invited you to GFC" if inviter else "Join GFC"
    description = ("Discover 3D art, music and video from independent creators, and earn GFC for the "
                   "creators you watch. Join with this invite for a 100 GFC welcome bonus.")
    app_link = _app_link(_with_ref("join", inviter), url, request.headers.get("user-agent", ""))
    nonce = secrets.token_urlsafe(16)
    page = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{e(title)}</title>
<meta name="description" content="{e(description)}">
<link rel="canonical" href="{e(url)}">
<meta property="og:type" content="website">
<meta property="og:site_name" content="GFC">
<meta property="og:title" content="{e(title)}">
<meta property="og:description" content="{e(description)}">
<meta property="og:url" content="{e(url)}">
<meta name="twitter:card" content="summary">
<meta name="twitter:title" content="{e(title)}">
<meta name="twitter:description" content="{e(description)}">
<style nonce="{nonce}">
body{{margin:0;font-family:system-ui,sans-serif;background:#0b0d17;color:#e8e9f0}}
main{{max-width:560px;margin:0 auto;padding:48px 16px;text-align:center}}
h1{{font-size:1.6rem}}
p{{line-height:1.5;color:#b8bccc}}
.actions a{{display:inline-block;margin-top:16px;padding:12px 20px;border-radius:8px;background:#3b4cca;color:#fff;text-decoration:none}}
</style>
</head>
<body>
<main>
<h1>{e(title)}</h1>
<p>{e(description)}</p>
<p class="actions"><a href="{e(app_link)}">Open in GFC</a>{GET_APP_LINK if app_release.info() else ""}</p>
</main>
</body>
</html>
"""
    csp = (f"default-src 'none'; style-src 'nonce-{nonce}'; base-uri 'none'; "
           "form-action 'none'; frame-ancestors 'none'")
    return HTMLResponse(page, headers={
        "Content-Security-Policy": csp,
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Vary": "User-Agent",
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
