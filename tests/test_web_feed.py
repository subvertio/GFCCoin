"""
Tests for the public web feed (/, /web, /explore, /web/cards).

Run from the repository root:
    python -m unittest discover -s tests -v
"""

import os
import re
import sqlite3
import sys
import tempfile
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from html.parser import HTMLParser
from pathlib import Path

# --- Isolated data dir, set before any GFC module loads config. setdefault: when the
# whole suite runs, another test may already have configured the process. ---
_TMP = tempfile.mkdtemp(prefix="gfc_web_")
os.environ.setdefault("GFC_DATA_DIR", _TMP)
os.environ.setdefault("GFC_TREASURY_KEY_FILE", str(Path(_TMP) / "no_treasury_key.hex"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient  # noqa: E402

import app_engagement  # noqa: E402
import app_share  # noqa: E402
import app_web  # noqa: E402
import main  # noqa: E402

BROWSER = {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}
XSS = '<script>alert(1)</script>"><img src=x onerror=alert(2)>'
ROOT_JSON = {
    "service": "Galactic Federation Coin API",
    "version": "4.0.0",
    "features": ["Wallet Management", "Seed Sharing", "Transaction Ledger", "Feed System", "P2P Sync",
                 "Blockchain (Hybrid SQLite Chain)", "Proof-of-Data-Transfer (PoDT)"],
    "documentation": "/docs",
}


class Cards(HTMLParser):
    """Card ids in order, plus inline scripts and their nonces."""
    def __init__(self):
        super().__init__()
        self.ids, self.scripts, self.tags = [], [], []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        self.tags.append(tag)
        if tag == "article":
            self.ids.append(a["data-id"])
        if tag == "script":
            self.scripts.append(a)


def cards(html: str) -> Cards:
    p = Cards()
    p.feed(html)
    return p


class WebFeedTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.db = str(Path(os.environ["GFC_DATA_DIR"]) / f"web_{uuid.uuid4().hex[:8]}.db")
        saved_main = main.DB_PATH
        main.DB_PATH = cls.db
        try:
            main.init_db()
        finally:
            main.DB_PATH = saved_main
        cls.saved = (app_web.DB_PATH, app_share.DB_PATH, app_engagement.DB_PATH)
        app_web.DB_PATH = app_share.DB_PATH = app_engagement.DB_PATH = cls.db
        cls.client = TestClient(main.app)
        cls.clock = datetime.now(timezone.utc) - timedelta(days=1)

    @classmethod
    def tearDownClass(cls):
        app_web.DB_PATH, app_share.DB_PATH, app_engagement.DB_PATH = cls.saved

    def setUp(self):
        conn = sqlite3.connect(self.db)
        conn.execute("DELETE FROM seeds")
        conn.commit()
        conn.close()

    def add_seed(self, **fields) -> str:
        """Each new seed is a minute newer than the last."""
        WebFeedTests.clock += timedelta(minutes=1)
        seed = dict(id=uuid.uuid4().hex[:24], owner="alice", title="My Ship", description="A starship",
                    tags="", filename=f"{uuid.uuid4().hex[:12]}_pic.png", thumb_filename="",
                    content_type="image", file_size=4096,
                    created_at=WebFeedTests.clock.replace(tzinfo=None).isoformat(), reward_wallet="", signature="")
        seed.update(fields)
        conn = sqlite3.connect(self.db)
        conn.execute(f"INSERT INTO seeds ({', '.join(seed)}) VALUES ({', '.join('?' * len(seed))})",
                     list(seed.values()))
        conn.commit()
        conn.close()
        return seed["id"]

    def card_html(self, html: str, seed_id: str) -> str:
        m = re.search(r'<article class="card" data-id="%s">.*?</article>' % re.escape(seed_id), html, re.S)
        self.assertIsNotNone(m, f"no card for {seed_id}")
        return m.group(0)

    # ----- / content negotiation -----

    def test_browser_gets_html_feed_at_root(self):
        a = self.add_seed(title="First post")
        b = self.add_seed(title="Second post", owner="bob")
        r = self.client.get("/", headers=BROWSER)
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.headers["content-type"].startswith("text/html"))
        self.assertEqual(cards(r.text).ids, [b, a])  # newest first
        self.assertIn(f'href="/p/{a}"', r.text)
        self.assertIn("Open in GFC", r.text)
        self.assertIn('<meta property="og:title"', r.text)
        self.assertIn("Accept", r.headers["vary"])

    def test_api_clients_still_get_json_at_root(self):
        self.add_seed()
        for headers in ({}, {"Accept": "application/json"}, {"Accept": "*/*"}):
            r = self.client.get("/", headers=headers)
            self.assertEqual(r.headers["content-type"], "application/json")
            self.assertEqual(r.json(), ROOT_JSON)

    def test_feed_json_unchanged(self):
        sid = self.add_seed()
        r = self.client.get("/feed", headers=BROWSER)
        self.assertEqual(r.headers["content-type"], "application/json")
        self.assertEqual([i["id"] for i in r.json()["items"]], [sid])

    def test_web_and_explore_serve_the_feed(self):
        sid = self.add_seed()
        for path in ("/web", "/explore"):
            r = self.client.get(path)  # no Accept needed at the stable paths
            self.assertTrue(r.headers["content-type"].startswith("text/html"))
            self.assertEqual(cards(r.text).ids, [sid])

    # ----- cards -----

    def test_card_shows_creator_time_title_text_stats(self):
        sid = self.add_seed(owner="zed", title="Nebula", description="Gas and dust",
                            thumb_filename="neb.jpg", views=12)
        card = self.card_html(self.client.get("/web").text, sid)
        self.assertIn('<div class="avatar" aria-hidden="true">Z</div>', card)
        self.assertIn("<b>zed</b> <span>@zed · ", card)
        self.assertRegex(card, r"<time datetime=\"[^\"]+\">\d+[mh]</time>")
        self.assertIn(">Nebula</a></h2>", card)
        self.assertIn("Gas and dust", card)
        self.assertIn('<img src="/thumbs/neb.jpg"', card)  # images use the thumbnail
        self.assertIn("12 views &middot; 0 likes &middot; 0 comments", card)

    def test_3d_card_defers_model_viewer(self):
        sid = self.add_seed(content_type="3d", filename="walker.glb", thumb_filename="walker.jpg", title="Bug")
        r = self.client.get("/web")
        card = self.card_html(r.text, sid)
        self.assertIn('data-model="/originals/walker.glb"', card)
        self.assertIn('data-poster="/thumbs/walker.jpg"', card)
        self.assertIn('<img src="/thumbs/walker.jpg"', card)
        # No model-viewer element and no viewer script until the card is in view or tapped.
        self.assertNotIn("<model-viewer", r.text)
        self.assertEqual([s.get("src") for s in cards(r.text).scripts], [None])
        # The page script loads the same pinned, SRI-checked build as the share page, with its settings.
        self.assertIn(app_share.MODEL_VIEWER_SRC, r.text)
        self.assertIn(app_share.MODEL_VIEWER_SRI, r.text)
        for attr in ("'auto-rotate'", "'camera-controls'", "autoplay", "loading: 'lazy'"):
            self.assertIn(attr, r.text)

    def test_other_3d_formats_show_poster_only(self):
        sid = self.add_seed(content_type="3d", filename="ship.fbx", thumb_filename="ship.jpg")
        card = self.card_html(self.client.get("/web").text, sid)
        self.assertNotIn("data-model", card)
        self.assertIn('<img src="/thumbs/ship.jpg"', card)

    def test_text_post_renders_as_text(self):
        body = "Hello GFC!\nSecond line"
        sid = self.add_seed(content_type="other", filename="abc_post.txt", title="Hello GFC!", description=body)
        card = self.card_html(self.client.get("/web").text, sid)
        self.assertIn(f'<a class="text post" href="/p/{sid}">Hello GFC!\nSecond line</a>', card)
        self.assertNotIn('class="media', card)  # no media frame
        self.assertNotIn("<h2>", card)  # title is the first line: shown once, not twice
        self.assertNotIn("/originals/", card)

    def test_video_is_tap_to_play(self):
        sid = self.add_seed(content_type="video", filename="clip.mp4", thumb_filename="clip.jpg")
        card = self.card_html(self.client.get("/web").text, sid)
        self.assertIn('data-video="/originals/clip.mp4"', card)
        self.assertIn('<img src="/thumbs/clip.jpg"', card)
        self.assertNotIn("<video", card)
        self.assertNotIn("autoplay", card)

    def test_untrusted_fields_are_escaped(self):
        sid = self.add_seed(owner=XSS, title=XSS, description=XSS, filename='a"b<c>.png')
        r = self.client.get("/", headers=BROWSER)
        card = self.card_html(r.text, sid)
        self.assertNotIn("<script>alert", card)
        self.assertNotIn("<img src=x", card)
        self.assertIn("/originals/a%22b%3Cc%3E.png", card)
        self.assertEqual(cards(r.text).tags.count("script"), 1)  # only the page's own script

    # ----- order and pages -----

    def test_at_most_two_in_a_row_from_one_creator(self):
        ids = [self.add_seed(owner="bob") for _ in range(2)]
        ids += [self.add_seed(owner="alice") for _ in range(4)]  # newest
        shown = cards(self.client.get("/web").text).ids
        owners = ["alice" if i in ids[2:] else "bob" for i in shown]
        self.assertEqual(owners, ["alice", "alice", "bob", "alice", "alice", "bob"])

    def test_mix_keeps_tail_run_when_nobody_else_is_left(self):
        seeds = [{"owner": o} for o in ("a", "b", "b", "b", "b")]
        self.assertEqual([s["owner"] for s in app_web.mix_creators(seeds)], ["a", "b", "b", "b", "b"])

    def test_pages_of_twenty(self):
        ids = [self.add_seed(owner=f"user{i}") for i in range(app_web.PAGE_SIZE + 5)][::-1]
        first = self.client.get("/web").text
        self.assertEqual(cards(first).ids, ids[:app_web.PAGE_SIZE])
        self.assertIn('href="/web?page=2" data-next="/web/cards?page=2"', first)
        more = self.client.get("/web/cards?page=2")
        self.assertEqual(cards(more.text).ids, ids[app_web.PAGE_SIZE:])
        self.assertNotIn("<html", more.text)
        self.assertNotIn('class="more"', more.text)
        self.assertEqual(cards(self.client.get("/web?page=2").text).ids, ids[app_web.PAGE_SIZE:])

    def test_empty_feed(self):
        r = self.client.get("/web")
        self.assertEqual(r.status_code, 200)
        self.assertIn("No posts here yet.", r.text)

    # ----- CSP -----

    def test_csp_allows_only_the_page_script_and_pinned_viewer(self):
        self.add_seed(content_type="3d", filename="walker.glb")
        r = self.client.get("/", headers=BROWSER)
        csp = r.headers["content-security-policy"]
        nonce = re.search(r"script-src 'nonce-([^']+)'", csp).group(1)
        self.assertEqual(cards(r.text).scripts, [{"nonce": nonce}])
        self.assertIn(f'<style nonce="{nonce}">', r.text)
        self.assertIn(f"script-src 'nonce-{nonce}' {app_share.MODEL_VIEWER_SRC} 'wasm-unsafe-eval'", csp)
        self.assertIn("default-src 'none'", csp)
        self.assertIn("frame-ancestors 'none'", csp)
        self.assertNotIn("unsafe-inline", csp)
        self.assertNotIn(" style=", r.text)  # no inline style attributes (the CSP would block them)
        self.assertEqual(r.headers["x-content-type-options"], "nosniff")


if __name__ == "__main__":
    unittest.main()
