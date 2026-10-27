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
        # 3D seeds get a poster image only, never the model file.
        self.assertNotIn("/originals/", r.text)

    def test_media_preview_by_type(self):
        img = self.client.get(f"/p/{self.add_seed(content_type='image', filename='pic.png')}").text
        self.assertIn('<img class="media" src="/originals/pic.png"', img)
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
        self.assertEqual(parsed.scripts, 0)
        self.assertEqual(parsed.meta["og:title"], XSS)  # round-trips as text, not markup

    def test_strict_csp(self):
        r = self.client.get(f"/p/{self.add_seed()}")
        csp = r.headers["content-security-policy"]
        self.assertIn("default-src 'none'", csp)
        self.assertIn("frame-ancestors 'none'", csp)
        self.assertNotIn("script-src", csp)  # default-src 'none' blocks all script
        self.assertNotIn("unsafe-inline", csp)

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
