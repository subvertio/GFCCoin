"""
GFC Web Feed - the whole feed as a public web page, for visitors to the node's domain.

- GET /  (browsers, i.e. Accept: text/html)  the feed page; API clients still get JSON (main.py)
- GET /web, /explore                         the feed page, ?page=N for older posts
- GET /web/cards?page=N                      just the cards of page N (the page's infinite scroll)
- GET /p/{id} (app_share.py)                 the shared post, focused on top, then this feed below


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
import os
import re
import secrets
import sqlite3
from urllib.parse import quote

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

import app_release
import exclusive
import filescan
import moderation
import reposts
from app_engagement import SEED_SELECT, seed_row_to_dict
from app_share import (MODEL_VIEWER_EXTENSIONS, MODEL_VIEWER_SRC, MODEL_VIEWER_SRI,
                       MODEL_VIEWER_STYLE_HASH, public_base_url)
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
        seeds = filescan.apply_to_items(exclusive.apply_to_items([by_id[i] for i in ids if i in by_id]))
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


def _fmt_size(n) -> str:
    n = int(n or 0)
    if n >= 1024 ** 3:
        return f"{n / 1024 ** 3:.1f} GB"
    if n >= 1024 ** 2:
        return f"{n / 1024 ** 2:.1f} MB"
    return f"{max(1, n // 1024)} KB"


def download_box(seed: dict, page: str) -> str:
    """A zip post: name, size, what's inside, the virus-scan result and (once clean) the Download button."""
    e = lambda s: html.escape(str(s or ""), quote=True)  # noqa: E731
    d = seed["download"]
    inside = []
    if d.get("files") is not None:
        inside.append(f'{d["files"]} file{"s" if d["files"] != 1 else ""}')
    if d.get("programs"):
        inside.append(f'{d["programs"]} program{"s" if d["programs"] != 1 else ""}')
    meta = " &middot; ".join([e(_fmt_size(d.get("size")))] + [e(x) for x in inside])
    status = d.get("status")
    if seed.get("exclusive"):
        action = ('<p class="exclusive-note">Download it in the <a class="getapp-open" href="/app">GFC app</a> '
                  'with a verified account.</p>')
    elif filescan.downloadable(status) and seed.get("full"):
        action = f'<a class="dl-button" href="{e(seed["full"])}" download>Download</a>'
    else:
        action = '<p class="dl-wait">Checking for viruses&hellip; the download opens when it passes.</p>'
    scanned = ""
    if status == filescan.CLEAN:
        when = (d.get("scanned_at") or "")[:10]
        scanned = (f'<p class="dl-scan">&#10003; Scanned by ClamAV{" on " + e(when) if when else ""}</p>'
                   + (f'<p class="dl-hash">SHA-256 <code>{e(d["sha256"])}</code></p>' if d.get("sha256") else ""))
    return (f'<div class="download"><p class="dl-name">&#128230; {e(d.get("name"))}</p>'
            f'<p class="dl-meta">{meta}</p>{scanned}{action}</div>')


EXCLUSIVE_BADGE = '<p class="exclusive">&#9733; Exclusive to the GFC Network</p>'


def exclusive_note(text_post: bool) -> str:
    what = "read the whole post" if text_post else "watch the full clip"
    return (f'<p class="exclusive-note">Log in to the <a class="getapp-open" href="/app">GFC app</a> '
            f'with a verified account to {what}.</p>')


def render_card(seed: dict, now: datetime.datetime = None) -> str:
    e = lambda s: html.escape(str(s or ""), quote=True)  # noqa: E731
    sid = seed["id"]
    page = f"/p/{quote(sid, safe='')}"
    owner = seed["owner"] or "unknown"
    is_exclusive = bool(seed.get("exclusive"))
    filename = "" if is_exclusive else (seed.get("full") or "").removeprefix("/originals/")
    media_path = f"/originals/{quote(filename, safe='')}" if filename else ""
    thumb = seed.get("thumb") or ""
    thumb_path = f"/thumbs/{quote(thumb.removeprefix('/thumbs/'), safe='')}" if thumb else ""
    title = seed.get("title") or ""
    text_post = is_text_post(seed)
    ctype = seed.get("content_type") or ""
    when = relative_time(seed.get("created_at") or "", now)
    when_html = f' · <a href="{e(page)}"><time datetime="{e(seed.get("created_at"))}">{e(when)}</time></a>' if when else ""

    media = ""
    if seed.get("download"):
        media = download_box(seed, page)
        if is_exclusive:
            media = EXCLUSIVE_BADGE + media
            is_exclusive = False  # handled here: show the description as usual
        text_post = False
    elif is_exclusive:
        teaser = seed.get("teaser") or ""
        seconds = seed.get("teaser_seconds") or exclusive.TEASER_SECONDS
        if ctype == "video" and teaser:
            poster = f'<img src="{e(thumb_path)}" alt="" loading="lazy">' if thumb_path else ""
            media = (f'<button type="button" class="media video" data-video="{e(teaser)}" data-exclusive="1" '
                     f'data-poster="{e(thumb_path)}" aria-label="Play the {seconds}-second preview of {e(title or "video")} (muted)">'
                     f'{poster}<span class="play" aria-hidden="true">&#9654;</span>'
                     f'<span class="tag">{seconds}s preview</span></button>')
        elif thumb_path:
            media = f'<a class="media" href="{e(page)}"><img src="{e(thumb_path)}" alt="{e(title)}" loading="lazy"></a>'
        text_post = ctype != "video"
        media += exclusive_note(text_post)
    elif text_post:
        pass  # text only, no media frame
    elif ctype == "image" and (thumb_path or media_path):
        media = (f'<a class="media" href="{e(page)}"><img src="{e(thumb_path or media_path)}" alt="{e(title)}" '
                 'loading="lazy"></a>')
    elif ctype == "video" and media_path:
        poster = f'<img src="{e(thumb_path)}" alt="" loading="lazy">' if thumb_path else ""
        play_path = seed.get("stream") or media_path  # the upright 720p copy when it's ready
        media = (f'<button type="button" class="media video" data-video="{e(play_path)}" '
                 f'data-poster="{e(thumb_path)}" aria-label="Play {e(title or "video")} (muted)">'
                 f'{poster}<span class="play" aria-hidden="true">&#9654;</span></button>')
    elif ctype == "audio" and media_path:
        cover = f'<img src="{e(thumb_path)}" alt="" loading="lazy">' if thumb_path else ""
        play_path = seed.get("stream") or media_path  # prefer the compressed streaming copy
        media = (f'<div class="media audio">{cover}'
                 f'<audio controls preload="none" src="{e(play_path)}"></audio></div>')
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
    if is_exclusive:
        show_title = True  # the title is all of an exclusive text post that's public
        title = title or "GFC Exclusive"
        body = EXCLUSIVE_BADGE + (f'<p class="text">{e(_shorten(description, DESCRIPTION_LIMIT))}</p>'
                                  if description.strip() else "")
    elif text_post:
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


def render_cards(page: int, exclude: str = ""):
    """The cards of a page followed by the link to the next one (if any)."""
    seeds, more = feed_page(page)
    if exclude:  # the post a share page is focused on is already shown above the feed
        seeds = [s for s in seeds if s["id"] != exclude]
    now = datetime.datetime.now(datetime.timezone.utc)
    cards = "\n".join(render_card(s, now) for s in seeds)
    if more:
        skip = f"&amp;exclude={quote(exclude, safe='')}" if exclude else ""
        cards += (f'\n<a class="more" href="/web?page={page + 1}" data-next="/web/cards?page={page + 1}{skip}">'
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
  const MODEL_ATTRS = {loading: 'lazy', reveal: 'auto', 'camera-controls': '', 'disable-zoom': '', 'touch-action': 'pan-y',
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
  // "Get the GFC app" pop-up: after an exclusive's teaser, on "watch the full clip",
  // and once per visit after a while on the page.
  const getApp = document.getElementById('getapp');
  function showGetApp() {
    if (!getApp || !getApp.hidden) return;
    getApp.hidden = false;
    try { sessionStorage.setItem('gfc-getapp', '1'); } catch (e) {}
    const first = getApp.querySelector('a');
    if (first) first.focus();
  }
  function hideGetApp() { if (getApp) getApp.hidden = true; }
  if (getApp) {
    getApp.addEventListener('click', ev => {
      if (ev.target === getApp || ev.target.closest('.getapp-close')) { ev.preventDefault(); hideGetApp(); }
    });
    document.addEventListener('keydown', ev => { if (ev.key === 'Escape') hideGetApp(); });
    let seen = false;
    try { seen = sessionStorage.getItem('gfc-getapp') === '1'; } catch (e) {}
    if (!seen) setTimeout(showGetApp, 15000);
  }
  document.querySelectorAll('video[data-exclusive]').forEach(v => v.addEventListener('ended', showGetApp));
  function playVideo(btn) {
    const v = document.createElement('video');
    v.className = 'media'; v.controls = true; v.muted = true; v.playsInline = true; v.preload = 'metadata';
    if (btn.dataset.poster) v.poster = btn.dataset.poster;
    v.src = btn.dataset.video;
    if (btn.dataset.exclusive) v.addEventListener('ended', showGetApp);
    btn.replaceWith(v);
    v.play().catch(() => {});
  }
  document.addEventListener('click', ev => {
    if (getApp && ev.target.closest('.getapp-open')) { ev.preventDefault(); showGetApp(); return; }
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


def bonus_text() -> str:
    """What a new account gets, from the node's own settings, so the header never over-promises."""
    import blockchain
    import first_post
    grant = blockchain.NEW_USER_GRANT_CENTS // 100
    bonus = first_post.amount_cents() // 100 if first_post.enabled() else 0
    if bonus:
        return f"{grant + bonus:,} GFC for signing up and your first post!"
    return f"{grant:,} GFC for signing up!"


def visitor_platform(user_agent: str) -> str:
    """"android", "windows" or "other", from the browser's User-Agent (only picks the main download button)."""
    ua = user_agent or ""
    if "Android" in ua:
        return "android"
    if "Windows" in ua:
        return "windows"
    return "other"


def get_app_popup(platform: str) -> str:
    """
    The "Get the GFC app" pop-up (hidden until the page script opens it): the sign-up bonus,
    and the download for this visitor's device first. Unpublished downloads link to /app.
    """
    e = lambda s: html.escape(s, quote=True)  # noqa: E731
    # Android goes to its install page (an APK from outside Google Play takes a few taps to install)
    android = ("/app/android", False)
    windows = ("/app/windows", True) if app_release.windows_info() else ("/app#windows", False)

    def button(target, label, cls):
        href, direct = target
        return f'<a class="{cls}" href="{e(href)}"{" download" if direct else ""}>{label}</a>'
    if platform == "android":
        buttons = button(android, "Get GFC for Android", "primary") + button(windows, "Windows version", "secondary")
    elif platform == "windows":
        buttons = button(windows, "Get GFC for Windows", "primary") + button(android, "Android version", "secondary")
    else:
        buttons = button(android, "Get GFC for Android", "primary") + button(windows, "Get GFC for Windows", "primary")
    return ('<div id="getapp" class="getapp" hidden role="dialog" aria-modal="true" aria-labelledby="getapp-title">'
            '<div class="getapp-box">'
            '<button type="button" class="getapp-close" aria-label="Close">&#10005;</button>'
            '<h2 id="getapp-title">Get the GFC app</h2>'
            f'<p class="getapp-bonus">{e(bonus_text())}</p>'
            '<p>Create your account to watch GFC Exclusives in full, and earn GFC when people view what you post.</p>'
            f'<div class="getapp-buttons">{buttons}</div>'
            '<p class="getapp-more"><a href="/app">How to install</a> &middot; '
            f'<a href="{e(app_release.SITE_URL)}" rel="noopener">Learn more about GFC</a></p>'
            '</div></div>')


def site_header() -> str:
    """
    Always at the top of the web feed and share pages (people arriving from X): the app
    downloads, GalacticFederation.tech, and the sign-up bonus. Android opens /app/android (the
    download and how to install it); an unpublished download links to /app ("coming soon").
    """
    e = lambda s: html.escape(s, quote=True)  # noqa: E731
    android = '<a href="/app/android">'  # the download plus how to install it
    windows = '<a href="/app/windows" download>' if app_release.windows_info() else '<a href="/app#windows">'
    return (f'<header class="top">\n<nav aria-label="Get GFC">'
            f'{android}Get GFC for Android</a>'
            f'{windows}Get GFC for Windows</a>'
            f'<a class="learn" href="{e(app_release.SITE_URL)}" rel="noopener">Learn more about GFC</a>'
            f'</nav>\n<p class="promo">{e(bonus_text())}</p>\n</header>')


# ---------- analytics ----------

CLARITY_ID_RE = re.compile(r"^[a-z0-9]{6,20}$")
# Hosts Microsoft Clarity loads its script from and sends its data to
CLARITY_SCRIPT_SRC = "https://www.clarity.ms https://*.clarity.ms"
CLARITY_CONNECT_SRC = "https://*.clarity.ms https://c.bing.com"


def clarity_project_id() -> str:
    """
    The Microsoft Clarity project for the web feed and share pages (GFC_CLARITY_PROJECT_ID),
    or "" when analytics is off. Only these pages get it: never /verify, /account or /app,
    so phone numbers, codes and recovery forms are never recorded.
    """
    value = os.environ.get("GFC_CLARITY_PROJECT_ID", "").strip()
    return value if CLARITY_ID_RE.match(value) else ""


def clarity_script(project_id: str, page_type: str) -> str:
    """Clarity's standard loader, plus a page_type tag ("feed" or "share") to filter by."""
    return (f'(function(c,l,a,r,i,t,y){{c[a]=c[a]||function(){{(c[a].q=c[a].q||[]).push(arguments)}};'
            f't=l.createElement(r);t.async=1;t.src="https://www.clarity.ms/tag/"+i;'
            f'y=l.getElementsByTagName(r)[0];y.parentNode.insertBefore(t,y);}})'
            f'(window,document,"clarity","script",{json.dumps(project_id)});'
            f'window.clarity("set","page_type",{json.dumps(page_type)});')


def _security_headers(nonce: str, analytics: bool = False) -> dict:
    # model-viewer fetches models from this node, decodes textures to blob: URLs and loads
    # Draco/KTX2 decoders (wasm in blob: workers) from gstatic when a model needs them.
    # With analytics on, Clarity's script and data hosts are allowed too.
    extra_script = f" {CLARITY_SCRIPT_SRC}" if analytics else ""
    extra_connect = f" {CLARITY_CONNECT_SRC}" if analytics else ""
    csp = (f"default-src 'none'; img-src 'self' blob: data:{extra_connect}; media-src 'self'; "
           f"script-src 'nonce-{nonce}' {MODEL_VIEWER_SRC}{extra_script} 'wasm-unsafe-eval'; "
           f"connect-src 'self' blob: data: https://www.gstatic.com{extra_connect}; worker-src blob:; "
           f"style-src 'nonce-{nonce}' '{MODEL_VIEWER_STYLE_HASH}'; "
           "base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
    return {
        "Content-Security-Policy": csp,
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
    }


def feed_html_response(request: Request, page: int = 1, featured: dict = None) -> HTMLResponse:
    """
    The full feed page (also served at / to browsers). With `featured` (from the
    /p/{id} share page) the shared post comes first, focused, and the feed follows
    below without it; the page's title, description, link and X card are the post's.
    featured: {"id", "html", "title", "description", "url", "image", "app_link", "head"}.
    """
    page = max(1, page)
    e = lambda s: html.escape(s, quote=True)  # noqa: E731
    base = public_base_url()
    url = f"{base}/" if page == 1 else f"{base}/web?page={page}"
    cards, any_cards = render_cards(page, exclude=featured["id"] if featured else "")
    if not any_cards:
        cards = '<p class="end">No posts here yet.</p>'
    title = page_title = FEED_TITLE
    description = FEED_DESCRIPTION
    card_type, image_tags, extra_head, top = "summary", "", "", ""
    header = site_header()
    popup = get_app_popup(visitor_platform(request.headers.get("user-agent", "")))
    if featured:
        title, description, url = featured["title"], featured["description"], featured["url"]
        page_title = featured.get("page_title", title)
        extra_head = featured.get("head", "")
        if featured.get("image"):
            card_type = "summary_large_image"
            image_tags = (f'<meta property="og:image" content="{e(featured["image"])}">\n'
                          f'<meta name="twitter:image" content="{e(featured["image"])}">\n')
        top = (f'<section class="featured" aria-label="Shared post">{featured["html"]}</section>\n'
               '<h2 class="more-head">Latest on GFC</h2>\n')
    nonce = secrets.token_urlsafe(16)
    script = SCRIPT % {"src": json.dumps(MODEL_VIEWER_SRC), "sri": json.dumps(MODEL_VIEWER_SRI)}
    clarity_id = clarity_project_id()
    analytics = (f'<script nonce="{nonce}">{clarity_script(clarity_id, "share" if featured else "feed")}</script>\n'
                 if clarity_id else "")
    body = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{e(page_title)}</title>
<meta name="description" content="{e(description)}">
<link rel="canonical" href="{e(url)}">
<meta property="og:type" content="website">
<meta property="og:site_name" content="GFC">
<meta property="og:title" content="{e(title)}">
<meta property="og:description" content="{e(description)}">
<meta property="og:url" content="{e(url)}">
<meta name="twitter:card" content="{card_type}">
<meta name="twitter:title" content="{e(title)}">
<meta name="twitter:description" content="{e(description)}">
{image_tags}{extra_head}<style nonce="{nonce}">
*{{box-sizing:border-box}}
html{{background:#000}}
body{{margin:0;font-family:system-ui,-apple-system,"Segoe UI",sans-serif;background:#000;color:#e7e9ea;overflow-x:hidden}}
a{{color:inherit}}
.top{{position:sticky;top:0;z-index:2;max-width:640px;margin:0 auto;padding:10px 16px 8px;
background:rgba(0,0,0,.9);backdrop-filter:blur(8px);border-bottom:1px solid #2f3336}}
.top nav{{display:flex;flex-wrap:wrap;justify-content:center;gap:8px}}
.top nav a{{flex:1 1 auto;padding:8px 14px;border-radius:999px;background:#3b4cca;color:#fff;text-align:center;
text-decoration:none;font-weight:600;font-size:.95rem;white-space:nowrap}}
.top nav a.learn{{background:transparent;border:1px solid #536471;color:#e7e9ea}}
.top nav a:hover{{filter:brightness(1.15)}}
.top .promo{{margin:8px 0 0;text-align:center;color:#ffd400;font-weight:700}}
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
.exclusive{{display:inline-block;margin:4px 0;padding:2px 10px;border-radius:12px;background:#2a2410;color:#ffd400;font-size:.85rem;font-weight:700}}
.exclusive-note{{margin:8px 0 0;color:#a9b0b6}}
.exclusive-note a{{color:#7f8ce0}}
.download{{margin:8px 0 0;padding:12px 14px;border:1px solid #2f3336;border-radius:16px;background:#0d0f12}}
.download p{{margin:2px 0}}
.dl-name{{font-weight:700;overflow-wrap:anywhere}}
.dl-meta,.dl-hash{{color:#71767b;font-size:.85rem}}
.dl-hash code{{overflow-wrap:anywhere}}
.dl-scan{{color:#00ba7c;font-size:.9rem}}
.dl-wait{{color:#ffd400;font-size:.9rem}}
.dl-button{{display:inline-block;margin-top:8px;padding:8px 18px;border-radius:999px;background:#3b4cca;color:#fff;text-decoration:none;font-weight:700}}
.getapp{{position:fixed;inset:0;z-index:10;display:flex;align-items:center;justify-content:center;padding:16px;background:rgba(0,0,0,.7)}}
.getapp[hidden]{{display:none}}
.getapp-box{{position:relative;width:100%;max-width:420px;padding:24px 20px 16px;border-radius:16px;background:#15181c;border:1px solid #2f3336;text-align:center}}
.getapp-box h2{{margin:0 0 8px;font-size:1.4rem}}
.getapp-bonus{{margin:0 0 8px;color:#ffd400;font-weight:700;font-size:1.1rem}}
.getapp-box p{{color:#a9b0b6}}
.getapp-buttons{{display:flex;flex-direction:column;gap:8px;margin:16px 0 8px}}
.getapp-buttons a{{display:block;padding:12px 16px;border-radius:999px;text-decoration:none;font-weight:700}}
.getapp-buttons a.primary{{background:#3b4cca;color:#fff}}
.getapp-buttons a.secondary{{border:1px solid #536471;color:#e7e9ea}}
.getapp-more{{font-size:.9rem}}
.getapp-more a{{color:#7f8ce0}}
.getapp-close{{position:absolute;top:8px;right:8px;width:36px;height:36px;border:0;border-radius:50%;background:transparent;color:#a9b0b6;font-size:1.1rem;cursor:pointer}}
.more,.end{{display:block;padding:20px 16px;text-align:center;color:#71767b}}
.featured{{padding:12px 16px 16px;border-bottom:1px solid #2f3336}}
.featured .hero{{display:block;width:100%;max-height:min(55vh,480px);object-fit:contain;background:#000;border:1px solid #2f3336;border-radius:16px}}
.featured model-viewer.hero{{height:min(55vh,480px);--poster-color:#000}}
.featured .next{{display:block;margin:16px 0 0;padding:10px;border-radius:999px;text-align:center;color:#71767b;text-decoration:none;border:1px solid #2f3336}}
.featured .next:hover{{color:#e7e9ea}}
.featured audio{{display:block;width:100%;margin-top:8px}}
.featured h1{{margin:12px 0 4px;font-size:1.4rem}}
.featured .creator{{display:flex;align-items:center;gap:8px;margin:0;color:#71767b}}
.featured .creator img{{width:28px;height:28px;border-radius:50%}}
.featured .badge{{display:inline-block;margin:8px 0 0;padding:2px 8px;border-radius:12px;background:#0f3d2e;color:#00ba7c;font-size:.85rem}}
.featured .badge.exclusive{{background:#2a2410;color:#ffd400;font-weight:700}}
.featured .repost{{display:block;margin:8px 0 0;padding:8px 12px;border-radius:8px;background:#1d1f23}}
.featured .desc{{white-space:pre-wrap;line-height:1.5}}
.featured .actions a{{display:inline-block;margin:8px 8px 0 0;padding:10px 16px;border-radius:999px;background:#3b4cca;color:#fff;text-decoration:none;font-weight:600}}
.featured .actions a.secondary{{background:transparent;border:1px solid #536471}}
.featured .placeholder{{padding:64px 0;text-align:center;color:#9aa}}
.more-head{{margin:0;padding:12px 16px;font-size:1rem;color:#71767b;border-bottom:1px solid #2f3336}}
</style>
{analytics}</head>
<body>
{header}
<main>
{top}<div id="feed" tabindex="-1">
{cards}
</div>
</main>
{popup}
<script nonce="{nonce}">{script}</script>
</body>
</html>
"""
    headers = _security_headers(nonce, analytics=bool(clarity_id))
    headers["Vary"] = "Accept, User-Agent"  # / is JSON for API clients; a shared post's "Open in GFC" differs on Android
    return HTMLResponse(body, headers=headers)


# ---------- routes ----------

@router.get("/web", response_class=HTMLResponse)
def web_feed(request: Request, page: int = 1):
    return feed_html_response(request, page)


@router.get("/explore", response_class=HTMLResponse)
def explore(request: Request, page: int = 1):
    return feed_html_response(request, page)


@router.get("/web/cards", response_class=HTMLResponse)
def web_cards(page: int = 1, exclude: str = ""):
    """The cards of one page, for the feed page's infinite scroll."""
    cards, _ = render_cards(max(1, page), exclude=exclude)
    headers = _security_headers(secrets.token_urlsafe(16))
    return HTMLResponse(cards, headers=headers)
