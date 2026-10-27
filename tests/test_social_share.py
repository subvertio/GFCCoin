"""
Tests for public share pages (/p/{seed_id}) and Android App Links.

Run from the repository root:
    python -m unittest discover -s tests -v
"""

import os
import sqlite3
import sys
import tempfile
import unittest
import uuid
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import parse_qs, urlparse

# --- Isolated data dir, set before any GFC module loads config. setdefault: when the
# whole suite runs, test_signed_ledger may already have configured the process. ---
_TMP = tempfile.mkdtemp(prefix="gfc_share_")
os.environ.setdefault("GFC_DATA_DIR", _TMP)
os.environ.setdefault("GFC_TREASURY_KEY_FILE", str(Path(_TMP) / "no_treasury_key.hex"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient  # noqa: E402

import app_share  # noqa: E402
import app_web  # noqa: E402
import main  # noqa: E402
import signing  # noqa: E402

BASE = "https://gfc.example"
XSS = '<script>alert(1)</script>"><img src=x onerror=alert(2)>'


class MetaParser(HTMLParser):
    """Collects <meta property/name=... content=...> and <script> tags."""
    def __init__(self):
        super().__init__()
        self.meta, self.scripts = {}, 0

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "meta" and "content" in a:
            self.meta[a.get("property") or a.get("name")] = a["content"]
        if tag == "script":
            self.scripts += 1


def parse(html: str) -> MetaParser:
    p = MetaParser()
    p.feed(html)
    return p


class SharePageTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # A dedicated node database, so the suite's other tests don't interfere.
        cls.db = str(Path(os.environ["GFC_DATA_DIR"]) / f"share_{uuid.uuid4().hex[:8]}.db")
        saved_main, saved_share = main.DB_PATH, app_share.DB_PATH
        main.DB_PATH = cls.db
        try:
            main.init_db()
        finally:
            main.DB_PATH = saved_main
        cls.saved_share_db = saved_share
        app_share.DB_PATH = cls.db
        cls.saved_web_db = app_web.DB_PATH
        app_web.DB_PATH = cls.db  # the feed under a shared post reads the same database
        cls.env = {k: os.environ.get(k) for k in
                   ("GFC_PUBLIC_BASE_URL", "GFC_APP_LINK_BASE", "GFC_ANDROID_PACKAGE", "GFC_ANDROID_CERT_SHA256")}
        os.environ["GFC_PUBLIC_BASE_URL"] = BASE + "/"
        os.environ["GFC_APP_LINK_BASE"] = "gfc://seed"
        cls.client = TestClient(main.app)

        conn = sqlite3.connect(cls.db)
        conn.execute(
            "INSERT INTO users (id, username, password, first_name, last_name, email, phone, created_at) "
            "VALUES (?, 'alice', 'pbkdf2_sha256$secret-hash', 'Alice', 'Private', 'alice@private.test', "
            "'+15550001111', ?)", (str(uuid.uuid4()), datetime.now(timezone.utc).isoformat()))
        conn.commit()
        cls.wallet = signing.create_wallet_key(conn)
        conn.commit()
        cls.priv = signing.get_wallet_private_key(cls.db, cls.wallet)
        conn.close()

    @classmethod
    def tearDownClass(cls):
        app_share.DB_PATH = cls.saved_share_db
        app_web.DB_PATH = cls.saved_web_db
        for k, v in cls.env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def add_seed(self, signed=False, **fields) -> str:
        filename = fields.pop("filename", f"{uuid.uuid4().hex[:12]}_model.glb")
        seed = dict(owner="alice", title="My Ship", description="A starship model", tags="",
                    filename=filename, thumb_filename="", content_type="3d", file_size=4096,
                    created_at=datetime.now(timezone.utc).isoformat(), reward_wallet="", signature="")
        seed.update(fields)
        if signed:
            seed["reward_wallet"] = self.wallet
            seed["id"] = signing.seed_id_for(self.wallet, filename)
            seed["signature"] = signing.sign_seed(self.priv, seed)
        else:
            seed.setdefault("id", uuid.uuid4().hex[:24])
        conn = sqlite3.connect(self.db)
        cols = ", ".join(seed)
        conn.execute(f"INSERT INTO seeds ({cols}) VALUES ({', '.join('?' * len(seed))})", list(seed.values()))
        conn.commit()
        conn.close()
        return seed["id"]

    def featured(self, text):
        """The shared post's section (the feed follows it on the same page)."""
        start = text.index('<section class="featured"')
        return text[start:text.index('</section>', start)]

    def assert_page_scripts_only(self, r, viewer: bool):
        """Only the feed's nonce'd inline script, plus the pinned 3D viewer when the post is glTF."""
        csp = r.headers["content-security-policy"]
        self.assertIn("default-src 'none'", csp)
        self.assertIn("frame-ancestors 'none'", csp)
        self.assertNotIn("unsafe-inline", csp)
        script_src = csp.split("script-src ", 1)[1].split(";", 1)[0].split()
        self.assertTrue(all(x.startswith("'nonce-") or x in (app_share.MODEL_VIEWER_SRC, "'wasm-unsafe-eval'")
                            for x in script_src), script_src)
        head = r.text.split("</head>", 1)[0]
        self.assertEqual(f'src="{app_share.MODEL_VIEWER_SRC}"' in head, viewer)

    def test_shared_post_on_top_then_feed_newest_first(self):
        # Dated ahead of everything other tests add, so both land on the feed's first page
        self.add_seed(owner="olga", title="Older post", created_at="2099-01-01T00:00:00+00:00")
        self.add_seed(owner="nina", title="Newer post", created_at="2099-06-01T00:00:00+00:00")
        shared = self.add_seed(title="The shared one", created_at="2025-01-01T00:00:00+00:00")
        text = self.client.get(f"/p/{shared}").text
        top = self.featured(text)
        self.assertIn("The shared one", top)
        feed = text[text.index('<div id="feed">'):]
        self.assertLess(text.index('<section class="featured"'), text.index('<div id="feed">'))
        self.assertLess(feed.index("Newer post"), feed.index("Older post"))  # newest on top
        self.assertNotIn(f'data-id="{shared}"', feed)  # not repeated below
        self.assertIn(f"exclude={shared}", feed) if 'class="more"' in feed else None

    def test_page_has_open_graph_and_twitter_tags(self):
        sid = self.add_seed(thumb_filename="ship_thumb.jpg")
        r = self.client.get(f"/p/{sid}")
        self.assertEqual(r.status_code, 200, r.text)
        self.assertTrue(r.headers["content-type"].startswith("text/html"))
        meta = parse(r.text).meta
        self.assertEqual(meta["og:title"], "My Ship")
        self.assertEqual(meta["og:description"], "A starship model")
        self.assertEqual(meta["og:type"], "website")
        self.assertEqual(meta["og:url"], f"{BASE}/p/{sid}")
        self.assertEqual(meta["og:image"], f"{BASE}/thumbs/ship_thumb.jpg")
        self.assertEqual(meta["twitter:card"], "summary_large_image")
        self.assertIn(f'href="gfc://seed/{sid}"', r.text)

    def test_3d_seed_gets_model_viewer(self):
        sid = self.add_seed(filename="walker.glb", thumb_filename="walker_thumb.jpg")
        r = self.client.get(f"/p/{sid}")
        self.assertEqual(r.status_code, 200, r.text)
        self.assertIn('<model-viewer class="hero" src="/originals/walker.glb"', self.featured(r.text))
        self.assertIn('poster="/thumbs/walker_thumb.jpg"', r.text)
        for attr in ('loading="lazy"', 'reveal="auto"', "camera-controls", "auto-rotate",
                     'rotation-per-second="14deg"', 'environment-image="neutral"', "autoplay"):
            self.assertIn(attr, r.text)
        self.assertIn(f'<script type="module" src="{app_share.MODEL_VIEWER_SRC}" '
                      f'integrity="{app_share.MODEL_VIEWER_SRI}" crossorigin="anonymous">', r.text)
        self.assert_page_scripts_only(r, viewer=True)
        # Open Graph and "Open in GFC" are unchanged.
        meta = parse(r.text).meta
        self.assertEqual(meta["og:image"], f"{BASE}/thumbs/walker_thumb.jpg")
        self.assertIn(f'href="gfc://seed/{sid}"', r.text)
        csp = r.headers["content-security-policy"]
        self.assertIn(f"{app_share.MODEL_VIEWER_SRC} 'wasm-unsafe-eval'", csp)
        self.assertIn(f"'{app_share.MODEL_VIEWER_STYLE_HASH}'", csp)  # its shadow-DOM <style>
        gltf = self.client.get(f"/p/{self.add_seed(filename='Ship.GLTF')}").text
        self.assertIn('<model-viewer class="hero" src="/originals/Ship.GLTF"', self.featured(gltf))

    def test_non_gltf_pages_load_no_viewer(self):
        # Other 3D formats keep the poster image, and never link the model file.
        fbx = self.client.get(f"/p/{self.add_seed(filename='ship.fbx', thumb_filename='ship.jpg')}")
        self.assertIn('<img class="hero" src="/thumbs/ship.jpg"', self.featured(fbx.text))
        self.assertNotIn("/originals/", self.featured(fbx.text))
        img = self.client.get(f"/p/{self.add_seed(content_type='image', filename='pic.glb.png')}")
        for r in (fbx, img):
            self.assertNotIn("model-viewer", self.featured(r.text))
            self.assert_page_scripts_only(r, viewer=False)

    ANDROID_UA = "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 Chrome/130 Mobile Safari/537.36"
    DESKTOP_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130 Safari/537.36"

    def open_link(self, sid, ua, **env):
        saved = {k: os.environ.get(k) for k in ("GFC_ANDROID_PACKAGE", "GFC_ANDROID_FALLBACK_URL")}
        try:
            for k in saved:
                os.environ.pop(k, None)
            os.environ.update(env)
            r = self.client.get(f"/p/{sid}", headers={"User-Agent": ua})
        finally:
            for k, v in saved.items():
                os.environ.pop(k, None)
                if v is not None:
                    os.environ[k] = v
        self.assertIn("User-Agent", r.headers.get("vary", ""))
        a = [h for h in r.text.split('<a href="')[1:] if h.split('"', 1)[1].startswith(">Open in GFC")]
        return a[0].split('"', 1)[0].replace("&amp;", "&")

    def test_android_gets_intent_link_to_the_app(self):
        sid = self.add_seed()
        link = self.open_link(sid, self.ANDROID_UA, GFC_ANDROID_PACKAGE="tech.galacticfederation.gfc")
        self.assertTrue(link.startswith(f"intent://seed/{sid}#Intent;scheme=gfc;"), link)
        self.assertIn("package=tech.galacticfederation.gfc;", link)
        # Not installed yet: stays on this share page (URL-encoded) until a store URL is set
        self.assertIn("S.browser_fallback_url=" + f"{BASE}/p/{sid}".replace(":", "%3A").replace("/", "%2F"), link)
        self.assertTrue(link.endswith(";end"))
        store = "https://play.google.com/store/apps/details?id=tech.galacticfederation.gfc"
        link = self.open_link(sid, self.ANDROID_UA, GFC_ANDROID_PACKAGE="tech.galacticfederation.gfc",
                              GFC_ANDROID_FALLBACK_URL=store)
        self.assertIn("S.browser_fallback_url=https%3A%2F%2Fplay.google.com%2F", link)

    def test_other_devices_and_unconfigured_package_get_plain_deep_link(self):
        sid = self.add_seed()
        self.assertEqual(self.open_link(sid, self.DESKTOP_UA, GFC_ANDROID_PACKAGE="tech.galacticfederation.gfc"),
                         f"gfc://seed/{sid}")
        self.assertEqual(self.open_link(sid, self.ANDROID_UA), f"gfc://seed/{sid}")

    def test_intent_link_escapes_seed_id(self):
        link = app_share.android_open_link('a"b<c', "https://x.example/p/1")
        self.assertIn("seed/a%22b%3Cc#Intent", link)

    def test_media_preview_by_type(self):
        img = self.client.get(f"/p/{self.add_seed(content_type='image', filename='pic.png')}").text
        self.assertIn('<img class="hero" src="/originals/pic.png"', self.featured(img))
        vid = self.client.get(f"/p/{self.add_seed(content_type='video', filename='clip.mp4')}").text
        self.assertIn('<video', vid)
        self.assertIn('src="/originals/clip.mp4"', vid)

    def test_untrusted_fields_are_escaped(self):
        sid = self.add_seed(title=XSS, description=XSS, owner=XSS,
                            thumb_filename='x"onerror="alert(3).jpg', content_type="image",
                            filename='a" onload="alert(4).png')
        r = self.client.get(f"/p/{sid}")
        self.assertEqual(r.status_code, 200)
        self.assertNotIn("<script>", r.text)
        self.assertNotIn("<img src=x", r.text)
        self.assertNotIn('" onload="', r.text)
        self.assertNotIn('"onerror="', r.text)
        self.assertIn("&lt;script&gt;", r.text)
        parsed = parse(r.text)
        self.assertLessEqual(parsed.scripts, 1)  # only the feed's own nonce'd script
        self.assertEqual(parsed.meta["og:title"], XSS)  # round-trips as text, not markup

    def test_strict_csp(self):
        r = self.client.get(f"/p/{self.add_seed(content_type='image', filename='pic.png')}")
        self.assert_page_scripts_only(r, viewer=False)

    def test_unknown_seed_404(self):
        self.assertEqual(self.client.get("/p/does-not-exist").status_code, 404)
        self.assertEqual(self.client.get("/p/does-not-exist/share").status_code, 404)

    def test_no_private_user_fields(self):
        sid = self.add_seed()
        for path in (f"/p/{sid}", f"/p/{sid}/share"):
            body = self.client.get(path).text
            for secret in ("alice@private.test", "+15550001111", "Private", "secret-hash"):
                self.assertNotIn(secret, body, path)

    def test_rewards_badge_only_for_signed_seeds(self):
        self.assertNotIn("Rewards verified", self.client.get(f"/p/{self.add_seed()}").text)
        self.assertIn("Rewards verified", self.client.get(f"/p/{self.add_seed(signed=True)}").text)
        forged = self.add_seed(reward_wallet=self.wallet, signature="00" * 64)
        self.assertNotIn("Rewards verified", self.client.get(f"/p/{forged}").text)

    def test_share_helper_builds_x_intent(self):
        sid = self.add_seed(title="Ship & Co")
        info = self.client.get(f"/p/{sid}/share").json()
        self.assertEqual(info["url"], f"{BASE}/p/{sid}")
        self.assertEqual(info["app_link"], f"gfc://seed/{sid}")
        intent = urlparse(info["x_intent_url"])
        self.assertEqual((intent.scheme, intent.netloc, intent.path), ("https", "x.com", "/intent/post"))
        q = parse_qs(intent.query)
        self.assertEqual(q["url"], [info["url"]])
        self.assertEqual(q["text"], ["Ship & Co by alice on GFC"])

    def test_assetlinks_shape(self):
        os.environ.pop("GFC_ANDROID_PACKAGE", None)
        os.environ.pop("GFC_ANDROID_CERT_SHA256", None)
        r = self.client.get("/.well-known/assetlinks.json")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json(), [])

        fp = ":".join(["AB"] * 32)
        os.environ["GFC_ANDROID_PACKAGE"] = "tech.galacticfederation.gfc"
        os.environ["GFC_ANDROID_CERT_SHA256"] = f"{fp.lower()}, {fp}"
        try:
            r = self.client.get("/.well-known/assetlinks.json")
        finally:
            os.environ.pop("GFC_ANDROID_PACKAGE")
            os.environ.pop("GFC_ANDROID_CERT_SHA256")
        self.assertTrue(r.headers["content-type"].startswith("application/json"))
        self.assertEqual(r.json(), [{
            "relation": ["delegate_permission/common.handle_all_urls"],
            "target": {"namespace": "android_app", "package_name": "tech.galacticfederation.gfc",
                       "sha256_cert_fingerprints": [fp, fp]},
        }])


if __name__ == "__main__":
    unittest.main()
