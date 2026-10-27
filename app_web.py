"""
GFC Web Feed - the whole feed as a public web page, for visitors to the node's domain.

- GET /  (browsers, i.e. Accept: text/html)  the feed page; API clients still get JSON (main.py)
- GET /web, /explore                         the feed page, ?page=N for older posts
- GET /web/cards?page=N                      just the cards of page N (the page's infinite scroll)

Cards look like the app's: letter avatar, name @handle · time, title, text, media,
views / likes / comments, each linking to its /p/{id} share page. Order is the feed's
(newest first) with the app's fairness rule: at most 2 posts in a row from one creator.

Like the share pages, every field is HTML-escaped and every path segment URL-quoted
(seed rows come from peers). The page runs one small inline script (CSP nonce) for
tap-to-play video, infinite scroll and 3D: a 3D card (.glb / .gltf) shows its poster
until it scrolls into view or is tapped, and only then gets a <model-viewer> (same
pinned, SRI-checked build and settings as the share page), so a long feed doesn't
download every model. Models far off screen are dropped again to save memory.
"""
import datetime
import html
import json
import secrets
import sqlite3
from urllib.parse import quote

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

import moderation
import reposts
from app_engagement import SEED_SELECT, seed_row_to_dict
from app_share import (MODEL_VIEWER_EXTENSIONS, MODEL_VIEWER_SRC, MODEL_VIEWER_SRI,
                       MODEL_VIEWER_STYLE_HASH, _app_link, _with_ref, clean_ref, public_base_url)
from config import DB_PATH

router = APIRouter()

PAGE_SIZE = 20
MAX_RUN = 2  # the app's FGFCFeedMixer: no more than 2 posts in a row from one creator
TEXT_LIMIT, DESCRIPTION_LIMIT = 600, 200  # the app's feed body lengths for text / other posts
FEED_TITLE = "GFC: the latest posts"
FEED_DESCRIPTION = ("3D art, music, video and posts from independent creators on GFC, "
                    "where creators earn GFC for what they post.")


def wants_html(request: Request) -> bool:
    """True for browsers (Accept names text/html); curl, requests and the app send */* or JSON."""
    return "text/html" in request.headers.get("accept", "").lower()


# ---------- data ----------

def mix_creators(seeds: list, max_run: int = MAX_RUN) -> list:
    """
    Keep the order, but when one creator would get more than max_run posts in a row,
    pull the next post by someone else forward (a port of the app's FGFCFeedMixer).
    If nobody else is left, the tail stays as it is: better a run than hiding posts.
    """
    seeds = list(seeds)
    max_run = max(1, max_run)
    owner = lambda s: (s["owner"] or "").lower()  # noqa: E731
    for i in range(len(seeds)):
        run = 0
        while run < i and owner(seeds[i - 1 - run]) == owner(seeds[i]):
            run += 1
        if run < max_run:
            continue
        for j in range(i + 1, len(seeds)):
            if owner(seeds[j]) != owner(seeds[i]):
                seeds.insert(i, seeds.pop(j))
                break
    return seeds


def feed_page(page: int, page_size: int = PAGE_SIZE):
    """(seeds on this page, whether there's a next page). Mixes the whole order first, so pages line up."""
    conn = sqlite3.connect(DB_PATH)
    try:
        order = [{"id": r[0], "owner": r[1]} for r in
                 conn.execute("SELECT id, owner FROM seeds ORDER BY created_at DESC").fetchall()]
        order = mix_creators(moderation.visible_items(conn, order))  # no posts hidden after reports
        start = (page - 1) * page_size
        ids = [s["id"] for s in order[start:start + page_size]]
        if not ids:
            return [], False
        rows = conn.execute(f"{SEED_SELECT} WHERE seeds.id IN ({', '.join('?' * len(ids))})", ids).fetchall()
        by_id = {r[0]: seed_row_to_dict(r) for r in rows}
        seeds = [by_id[i] for i in ids if i in by_id]
        for s in seeds:
            s["repost_of"] = reposts.public_info(reposts.repost_of(conn, s["id"]))
        return seeds, start + page_size < len(order)
    finally:
        conn.close()


# ---------- rendering ----------

def relative_time(iso: str, now: datetime.datetime = None) -> str:
    """Like the app: now, 5m, 3h, 2d, then the date. The node writes UTC without a zone."""
    try:
        when = datetime.datetime.fromisoformat((iso or "").replace("Z", "+00:00"))
    except ValueError:
        return ""
    if when.tzinfo is None:
        when = when.replace(tzinfo=datetime.timezone.utc)
    age = (now or datetime.datetime.now(datetime.timezone.utc)) - when
    minutes = age.total_seconds() / 60
    if minutes < 1:
        return "now"
    if minutes < 60:
        return f"{int(minutes)}m"
    if minutes < 24 * 60:
        return f"{int(minutes // 60)}h"
    if age.days < 7:
        return f"{age.days}d"
    return f"{when.strftime('%b')} {when.day}, {when.year}"


def _shorten(text: str, limit: int) -> str:
    text = (text or "").strip()
    return text if len(text) <= limit else text[:limit - 1] + "…"


def _title_from_body(body: str) -> str:
    """The app's UGFCCreateScreen::TitleFromBody: a text post's default title is its first line."""
    line = (body or "").strip().split("\n", 1)[0].rstrip()
    return line if len(line) <= 80 else line[:79].rstrip() + "…"


def is_text_post(seed: dict) -> bool:
    """A text post is a small .txt seed (stored as "other") whose description holds the text."""
    return (seed.get("full") or "").lower().endswith(".txt") or (seed.get("content_type") or "").startswith("text")


def render_card(seed: dict, now: datetime.datetime = None) -> str:
    e = lambda s: html.escape(str(s or ""), quote=True)  # noqa: E731
    sid = seed["id"]
    page = f"/p/{quote(sid, safe='')}"
    owner = seed["owner"] or "unknown"
    filename = (seed.get("full") or "").removeprefix("/originals/")
    media_path = f"/originals/{quote(filename, safe='')}" if filename else ""
    thumb = seed.get("thumb") or ""
    thumb_path = f"/thumbs/{quote(thumb.removeprefix('/thumbs/'), safe='')}" if thumb else ""
    title = seed.get("title") or ""
    text_post = is_text_post(seed)
    ctype = seed.get("content_type") or ""
    when = relative_time(seed.get("created_at") or "", now)
    when_html = f' · <a href="{e(page)}"><time datetime="{e(seed.get("created_at"))}">{e(when)}</time></a>' if when else ""

    media = ""
    if text_post:
        pass  # text only, no media frame
    elif ctype == "image" and (thumb_path or media_path):
        media = (f'<a class="media" href="{e(page)}"><img src="{e(thumb_path or media_path)}" alt="{e(title)}" '
                 'loading="lazy"></a>')
    elif ctype == "video" and media_path:
        poster = f'<img src="{e(thumb_path)}" alt="" loading="lazy">' if thumb_path else ""
        media = (f'<button type="button" class="media video" data-video="{e(media_path)}" '
                 f'data-poster="{e(thumb_path)}" aria-label="Play {e(title or "video")} (muted)">'
                 f'{poster}<span class="play" aria-hidden="true">&#9654;</span></button>')
    elif ctype == "audio" and media_path:
        cover = f'<img src="{e(thumb_path)}" alt="" loading="lazy">' if thumb_path else ""
        media = (f'<div class="media audio">{cover}'
                 f'<audio controls preload="none" src="{e(media_path)}"></audio></div>')
    elif ctype == "3d" and media_path and filename.lower().endswith(MODEL_VIEWER_EXTENSIONS):
        # The model-viewer is created by the page script once this card is near the screen or tapped.
        poster = f'<img src="{e(thumb_path)}" alt="" loading="lazy">' if thumb_path else ""
        media = (f'<div class="media model-slot" role="button" tabindex="0" data-model="{e(media_path)}" '
                 f'data-poster="{e(thumb_path)}" data-alt="{e(title)}" aria-label="Show {e(title or "model")} in 3D">'
                 f'{poster}<span class="tag">3D</span></div>')
    elif thumb_path:
        media = f'<a class="media" href="{e(page)}"><img src="{e(thumb_path)}" alt="{e(title)}" loading="lazy"></a>'
    elif media_path:
        media = f'<a class="media placeholder" href="{e(page)}">Open in GFC to view</a>'

    description = seed.get("description") or ""
    if text_post:
        show_title = bool(title) and title != _title_from_body(description) and title != filename
        body = (f'<a class="text post" href="{e(page)}">{e(_shorten(description, TEXT_LIMIT))}</a>'
                if description.strip() else "")
    else:
        show_title = bool(title)
        body = f'<p class="text">{e(_shorten(description, DESCRIPTION_LIMIT))}</p>' if description.strip() else ""
    heading = f'<h2><a href="{e(page)}">{e(title)}</a></h2>' if show_title else ""
    repost = ""
    if seed.get("repost_of"):
        original = seed["repost_of"]
        repost = (f'<p class="repost">Repost of <a href="/p/{e(quote(original["seed_id"], safe=""))}">'
                  f'@{e(original["owner"])}</a></p>')
    return (f'<article class="card" data-id="{e(sid)}">'
            f'<div class="avatar" aria-hidden="true">{e(owner[:1].upper() or "?")}</div>'
            f'<div class="post"><p class="who"><b>{e(owner)}</b> <span>@{e(owner)}{when_html}</span></p>'
            f'{repost}{heading}{body}{media}'
            f'<p class="stats">{int(seed.get("views") or 0)} views &middot; {int(seed.get("likes") or 0)} likes '
            f'&middot; {int(seed.get("comments") or 0)} comments</p></div></article>')


def render_cards(page: int):
    """The cards of a page followed by the link to the next one (if any)."""
    seeds, more = feed_page(page)
    now = datetime.datetime.now(datetime.timezone.utc)
    cards = "\n".join(render_card(s, now) for s in seeds)
    if more:
        cards += (f'\n<a class="more" href="/web?page={page + 1}" data-next="/web/cards?page={page + 1}">'
                  'Older posts</a>')
    elif page > 1 or seeds:
        cards += '\n<p class="end">You\'re all caught up.</p>'
    return cards, bool(seeds)


SCRIPT = """
(() => {
  const MV_SRC = %(src)s, MV_SRI = %(sri)s;
  let mvLoading = false;
  function loadViewer() {
    if (mvLoading) return;
    mvLoading = true;
    const s = document.createElement('script');
    s.type = 'module'; s.src = MV_SRC; s.integrity = MV_SRI; s.crossOrigin = 'anonymous';
    document.head.appendChild(s);
  }
  // Same settings as the share page and the app's viewer: slow turntable that resumes
  // after the user lets go, orbit/pinch zoom, neutral lighting, first animation looping.
  const MODEL_ATTRS = {loading: 'lazy', reveal: 'auto', 'camera-controls': '', 'touch-action': 'pan-y',
    'auto-rotate': '', 'auto-rotate-delay': '3000', 'rotation-per-second': '14deg',
    'environment-image': 'neutral', exposure: '1', 'shadow-intensity': '0.5', autoplay: ''};
  function showModel(slot) {
    if (slot.querySelector('model-viewer')) return;
    loadViewer();
    const m = document.createElement('model-viewer');
    for (const k in MODEL_ATTRS) m.setAttribute(k, MODEL_ATTRS[k]);
    m.setAttribute('src', slot.dataset.model);
    m.setAttribute('alt', slot.dataset.alt || '3D model');
    if (slot.dataset.poster) m.setAttribute('poster', slot.dataset.poster);
    slot.appendChild(m);
    slot.classList.add('live');
  }
  function dropModel(slot) {
    const m = slot.querySelector('model-viewer');
    if (m) { m.remove(); slot.classList.remove('live'); }
  }
  const io = 'IntersectionObserver' in window;
  const near = io && new IntersectionObserver(es => es.forEach(e => e.isIntersecting && showModel(e.target)),
                                              {rootMargin: '200px 0px'});
  const far = io && new IntersectionObserver(es => es.forEach(e => e.isIntersecting || dropModel(e.target)),
                                             {rootMargin: '2500px 0px'});
  function watch(root) {
    if (!io) return;
    root.querySelectorAll('.model-slot').forEach(s => { near.observe(s); far.observe(s); });
    root.querySelectorAll('.more').forEach(a => more.observe(a));
  }
  function playVideo(btn) {
    const v = document.createElement('video');
    v.className = 'media'; v.controls = true; v.muted = true; v.playsInline = true; v.preload = 'metadata';
    if (btn.dataset.poster) v.poster = btn.dataset.poster;
    v.src = btn.dataset.video;
    btn.replaceWith(v);
    v.play().catch(() => {});
  }
  document.addEventListener('click', ev => {
    const video = ev.target.closest('.video');
    if (video) { ev.preventDefault(); playVideo(video); return; }
    const slot = ev.target.closest('.model-slot');
    if (slot) showModel(slot);
  });
  document.addEventListener('keydown', ev => {
    const slot = ev.target.closest && ev.target.closest('.model-slot');
    if (slot && (ev.key === 'Enter' || ev.key === ' ')) { ev.preventDefault(); showModel(slot); }
  });
  const feed = document.getElementById('feed');
  let fetching = false;
  async function loadMore(link) {
    if (fetching) return;
    fetching = true;
    try {
      const r = await fetch(link.dataset.next, {headers: {Accept: 'text/html'}});
      if (!r.ok) throw new Error(r.status);
      const t = document.createElement('template');
      t.innerHTML = await r.text();
      // Skip cards already shown (new posts can shift the pages while scrolling).
      t.content.querySelectorAll('.card').forEach(c => {
        if (feed.querySelector('.card[data-id="' + CSS.escape(c.dataset.id) + '"]')) c.remove();
      });
      more.unobserve(link);
      link.replaceWith(t.content);
      watch(feed);
    } catch (err) {
      link.textContent = 'Older posts';  // still a plain link to the next page
    } finally {
      fetching = false;
    }
  }
  const more = io && new IntersectionObserver(es => es.forEach(e => e.isIntersecting && loadMore(e.target)),
                                              {rootMargin: '600px 0px'});
  watch(document);
})();
"""


def _security_headers(nonce: str) -> dict:
    # model-viewer fetches models from this node, decodes textures to blob: URLs and loads
    # Draco/KTX2 decoders (wasm in blob: workers) from gstatic when a model needs them.
    csp = ("default-src 'none'; img-src 'self' blob: data:; media-src 'self'; "
           f"script-src 'nonce-{nonce}' {MODEL_VIEWER_SRC} 'wasm-unsafe-eval'; "
           "connect-src 'self' blob: data: https://www.gstatic.com; worker-src blob:; "
           f"style-src 'nonce-{nonce}' '{MODEL_VIEWER_STYLE_HASH}'; "
           "base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
    return {
        "Content-Security-Policy": csp,
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
    }


def feed_html_response(request: Request, page: int = 1) -> HTMLResponse:
    """The full feed page (also served at / to browsers)."""
    page = max(1, page)
    e = lambda s: html.escape(s, quote=True)  # noqa: E731
    base = public_base_url()
    url = f"{base}/" if page == 1 else f"{base}/web?page={page}"
    ref = clean_ref(request.query_params.get("ref"))
    app_link = _app_link(_with_ref("feed", ref), url, request.headers.get("user-agent", ""))
    cards, any_cards = render_cards(page)
    if not any_cards:
        cards = '<p class="end">No posts here yet.</p>'
    nonce = secrets.token_urlsafe(16)
    script = SCRIPT % {"src": json.dumps(MODEL_VIEWER_SRC), "sri": json.dumps(MODEL_VIEWER_SRI)}
    body = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{e(FEED_TITLE)}</title>
<meta name="description" content="{e(FEED_DESCRIPTION)}">
<link rel="canonical" href="{e(url)}">
<meta property="og:type" content="website">
<meta property="og:site_name" content="GFC">
<meta property="og:title" content="{e(FEED_TITLE)}">
<meta property="og:description" content="{e(FEED_DESCRIPTION)}">
<meta property="og:url" content="{e(url)}">
<meta name="twitter:card" content="summary">
<meta name="twitter:title" content="{e(FEED_TITLE)}">
<meta name="twitter:description" content="{e(FEED_DESCRIPTION)}">
<style nonce="{nonce}">
*{{box-sizing:border-box}}
html{{background:#000}}
body{{margin:0;font-family:system-ui,-apple-system,"Segoe UI",sans-serif;background:#000;color:#e7e9ea;overflow-x:hidden}}
a{{color:inherit}}
.top{{position:sticky;top:0;z-index:2;display:flex;align-items:center;justify-content:space-between;gap:12px;
max-width:640px;margin:0 auto;padding:10px 16px;background:rgba(0,0,0,.85);backdrop-filter:blur(8px);border-bottom:1px solid #2f3336}}
.top h1{{margin:0;font-size:1.2rem}}
.open{{flex:none;padding:8px 14px;border-radius:999px;background:#3b4cca;color:#fff;text-decoration:none;font-weight:600}}
main{{max-width:640px;margin:0 auto}}
.card{{display:flex;gap:12px;padding:12px 16px;border-bottom:1px solid #2f3336}}
.avatar{{flex:none;width:40px;height:40px;border-radius:50%;display:flex;align-items:center;justify-content:center;
background:#1d1f23;border:1px solid #2f3336;font-weight:700}}
.post{{flex:1;min-width:0}}
.who{{margin:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
.who span,.stats{{color:#71767b}}
.who a{{text-decoration:none}}
.who a:hover,h2 a:hover{{text-decoration:underline}}
h2{{margin:4px 0;font-size:1.05rem}}
h2 a{{text-decoration:none}}
.text{{display:block;margin:4px 0;white-space:pre-wrap;overflow-wrap:anywhere;line-height:1.45;text-decoration:none}}
.repost{{margin:4px 0;color:#c9b8ff;font-size:.9rem}}
.media{{position:relative;display:block;width:100%;margin:8px 0 0;padding:0;border:1px solid #2f3336;border-radius:16px;
overflow:hidden;background:#000;color:inherit;font:inherit;text-decoration:none}}
.media img,video.media{{display:block;width:100%;max-height:70vh;object-fit:contain}}
.video{{cursor:pointer;min-height:120px}}
.play{{position:absolute;left:50%;top:50%;transform:translate(-50%,-50%);width:56px;height:56px;border-radius:50%;
display:flex;align-items:center;justify-content:center;background:rgba(0,0,0,.65);font-size:24px}}
.audio audio{{display:block;width:100%}}
.model-slot{{aspect-ratio:1/1;max-height:70vh;cursor:pointer}}
.model-slot img{{width:100%;height:100%;max-height:none;object-fit:contain}}
.model-slot model-viewer{{position:absolute;inset:0;width:100%;height:100%;--poster-color:transparent}}
.tag{{position:absolute;left:8px;top:8px;padding:2px 8px;border-radius:8px;background:rgba(0,0,0,.7);font-size:.8rem}}
.placeholder{{padding:48px 0;text-align:center;color:#9aa}}
.stats{{margin:8px 0 0;font-size:.9rem}}
.more,.end{{display:block;padding:20px 16px;text-align:center;color:#71767b}}
</style>
</head>
<body>
<header class="top"><h1>GFC</h1><a class="open" href="{e(app_link)}">Open in GFC</a></header>
<main id="feed">
{cards}
</main>
<script nonce="{nonce}">{script}</script>
</body>
</html>
"""
    headers = _security_headers(nonce)
    headers["Vary"] = "Accept, User-Agent"  # / is JSON for API clients; "Open in GFC" differs on Android
    return HTMLResponse(body, headers=headers)


# ---------- routes ----------

@router.get("/web", response_class=HTMLResponse)
def web_feed(request: Request, page: int = 1):
    return feed_html_response(request, page)


@router.get("/explore", response_class=HTMLResponse)
def explore(request: Request, page: int = 1):
    return feed_html_response(request, page)


@router.get("/web/cards", response_class=HTMLResponse)
def web_cards(page: int = 1):
    """The cards of one page, for the feed page's infinite scroll."""
    cards, _ = render_cards(max(1, page))
    headers = _security_headers(secrets.token_urlsafe(16))
    return HTMLResponse(cards, headers=headers)
