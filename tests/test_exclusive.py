"""
Tests for GFC Exclusives (exclusive.py): videos and text posts only real accounts can see.

Run from the repository root:
    python -m unittest discover -s tests -v
"""

import os
import sqlite3
import sys
import time
import unittest
import uuid
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_signed_ledger  # noqa: F401  (sets up the isolated data dir and a test treasury first)
from test_signed_ledger import mark_verified

from fastapi.testclient import TestClient  # noqa: E402

import audio_stream  # noqa: E402
import config  # noqa: E402
import exclusive  # noqa: E402
import main  # noqa: E402

BROWSER = {"Accept": "text/html"}


def fake_teaser(src: Path, dest: Path):
    dest.write_bytes(b"TEASER" + src.read_bytes()[:64])


class ExclusiveTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(main.app)
        cls.saved_runner = exclusive.run_teaser_ffmpeg
        exclusive.run_teaser_ffmpeg = fake_teaser

    @classmethod
    def tearDownClass(cls):
        exclusive.run_teaser_ffmpeg = cls.saved_runner

    def setUp(self):
        self.saved_require = config.REQUIRE_PHONE_TO_POST
        config.REQUIRE_PHONE_TO_POST = False  # posting itself isn't what's tested here

    def tearDown(self):
        config.REQUIRE_PHONE_TO_POST = self.saved_require

    # ---------- helpers ----------

    def account(self, verified=False):
        name = "x" + uuid.uuid4().hex[:10]
        token = self.client.post("/auth/register", data={"username": name, "password": "pw-" + name}).json()["token"]
        self.client.post("/wallets/create", data={"name": "main", "api_token": token})
        if verified:
            mark_verified(main.DB_PATH, name)
        return name, token

    def upload(self, token, filename="clip.mp4", exclusive_flag=True, title="My clip", description="Watch this"):
        data = {"api_token": token, "title": title, "description": description}
        if exclusive_flag:
            data["exclusive"] = "true"
        r = self.client.post("/seeds/upload", data=data, files={"file": (filename, os.urandom(4096), "application/octet-stream")})
        return r

    def get(self, url, token=None):
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        return self.client.get(url, headers=headers)

    def feed_item(self, sid):
        return next(i for i in self.client.get("/feed").json()["items"] if i["id"] == sid)

    # ---------- posting ----------

    def test_exclusive_video_gets_a_public_teaser_and_an_x_post(self):
        _, token = self.account()
        r = self.upload(token)
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        self.assertTrue(body["exclusive"])
        self.assertEqual(body["teaser"], f"/teasers/{body['id']}.mp4")
        self.assertTrue(self.client.get(body["teaser"]).content.startswith(b"TEASER"))
        self.assertIn("exclusive to the GFC Network", body["x_post"]["text"])
        self.assertTrue(body["x_post"]["url"].endswith(f"/p/{body['id']}"))
        self.assertTrue(body["x_post"]["intent"].startswith("https://x.com/intent/post?"))

    def test_only_videos_and_text_posts_can_be_exclusive(self):
        _, token = self.account()
        r = self.upload(token, filename="pic.png")
        self.assertEqual(r.status_code, 400)
        self.assertIn("videos, text posts and downloads", r.json()["detail"])
        self.assertEqual(self.upload(token, filename="note.txt").status_code, 200)

    # ---------- the lock ----------

    def test_full_clip_is_locked_without_a_signed_link(self):
        owner, token = self.account()
        sid = self.upload(token).json()["id"]
        conn = sqlite3.connect(main.DB_PATH)
        filename = conn.execute("SELECT filename FROM seeds WHERE id = ?", (sid,)).fetchone()[0]
        conn.close()
        audio_stream.stream_path(sid, "video").write_bytes(b"STREAM")  # as if transcoded

        self.assertEqual(self.client.get(f"/originals/{filename}").status_code, 403)
        self.assertEqual(self.client.get(f"/streams/{sid}.mp4").status_code, 403)

        links = self.get(f"/seeds/{sid}/play", token).json()  # the poster may watch
        self.assertEqual(self.client.get(links["full"]).status_code, 200)
        self.assertEqual(self.client.get(links["stream"]).content, b"STREAM")

        # Tampered, borrowed or expired links don't open it
        path, query = links["full"].split("?")
        self.assertEqual(self.client.get(f"{path}?{query[:-1]}0").status_code, 403)
        other_sig = links["stream"].split("sig=")[1]
        self.assertEqual(self.client.get(f"{path}?exp={query.split('&')[0][4:]}&sig={other_sig}").status_code, 403)
        expired = exclusive.signed_url(f"/originals/{filename}", ttl_s=-10)
        self.assertEqual(self.client.get(expired).status_code, 403)

        # The feed points old apps at the teaser, never the locked file
        item = self.feed_item(sid)
        self.assertTrue(item["exclusive"])
        self.assertEqual(item["full"], item["teaser"])
        self.assertIsNone(item["stream"])

    def test_who_may_watch_on_the_real_network(self):
        _, poster_token = self.account()
        sid = self.upload(poster_token).json()["id"]
        config.REQUIRE_PHONE_TO_POST = True  # the real network
        self.assertEqual(self.client.get(f"/seeds/{sid}/play").status_code, 401)
        _, stranger = self.account(verified=False)
        r = self.get(f"/seeds/{sid}/play", stranger)
        self.assertEqual(r.status_code, 403)
        self.assertIn("Verify your phone", r.json()["detail"])
        _, fan = self.account(verified=True)
        r = self.get(f"/seeds/{sid}/play", fan)
        self.assertEqual(r.status_code, 200, r.text)
        self.assertIn("sig=", r.json()["full"])
        self.assertEqual(r.json()["expires_in"], exclusive.URL_TTL_S)
        self.assertEqual(self.get(f"/seeds/{sid}/play", poster_token).status_code, 200)  # the poster, always

    def test_test_networks_let_any_logged_in_account_watch(self):
        _, poster_token = self.account()
        sid = self.upload(poster_token).json()["id"]
        _, someone = self.account(verified=False)
        self.assertEqual(self.get(f"/seeds/{sid}/play", someone).status_code, 200)

    def test_normal_posts_are_unchanged(self):
        _, token = self.account()
        body = self.upload(token, exclusive_flag=False).json()
        self.assertNotIn("exclusive", body)
        sid = body["id"]
        conn = sqlite3.connect(main.DB_PATH)
        filename = conn.execute("SELECT filename FROM seeds WHERE id = ?", (sid,)).fetchone()[0]
        conn.close()
        self.assertEqual(self.client.get(f"/originals/{filename}").status_code, 200)
        links = self.get(f"/seeds/{sid}/play", token).json()
        self.assertEqual(links["full"], f"/originals/{filename}")
        self.assertFalse(self.feed_item(sid)["exclusive"])

    # ---------- text posts ----------

    def test_exclusive_text_post_shows_only_its_title(self):
        _, poster = self.account()
        secret = "The secret part of this post"
        r = self.upload(poster, filename="post.txt", title="Big news", description=secret)
        self.assertEqual(r.status_code, 200, r.text)
        sid = r.json()["id"]
        self.assertIsNone(r.json()["teaser"])
        self.assertIn("full post is exclusive", r.json()["x_post"]["text"])

        item = self.feed_item(sid)
        self.assertEqual((item["title"], item["description"], item["full"]), ("Big news", "", None))
        self.assertNotIn(secret, self.client.get(f"/seeds/{sid}").text)
        web = self.client.get("/web").text
        self.assertIn("Big news", web)
        self.assertNotIn(secret, web)
        self.assertIn("read the whole post", web)
        share = self.client.get(f"/p/{sid}", headers=BROWSER).text
        self.assertNotIn(secret, share)
        self.assertIn("Exclusive to the GFC Network", share)

        # Edit history doesn't leak it either
        self.client.post(f"/seeds/{sid}/edit", data={"api_token": poster, "description": secret + " (edited)"})
        config.REQUIRE_PHONE_TO_POST = True
        _, stranger = self.account(verified=False)
        hist = self.get(f"/seeds/{sid}/edits", stranger).json()["edits"]
        self.assertTrue(hist and all(h["description"] == "" for h in hist))

        _, fan = self.account(verified=True)
        play = self.get(f"/seeds/{sid}/play", fan).json()
        self.assertEqual(play["text"], secret + " (edited)")
        self.assertEqual(self.get(f"/seeds/{sid}/edits", fan).json()["edits"][0]["description"], secret + " (edited)")

    # ---------- web pages ----------

    def test_web_feed_and_share_page_play_only_the_teaser(self):
        _, token = self.account()
        body = self.upload(token, title="Exclusive drop").json()
        sid = body["id"]
        conn = sqlite3.connect(main.DB_PATH)
        filename = conn.execute("SELECT filename FROM seeds WHERE id = ?", (sid,)).fetchone()[0]
        conn.close()
        for page in (self.client.get("/web").text, self.client.get(f"/p/{sid}", headers=BROWSER).text):
            self.assertIn(body["teaser"], page)
            self.assertIn("Exclusive to the GFC Network", page)
            self.assertIn("watch the full clip", page)
            self.assertNotIn(filename, page)
        self.assertIn("5-second preview", self.client.get(f"/p/{sid}", headers=BROWSER).text)

    def test_get_the_app_popup_fits_the_device(self):
        android_ua = "Mozilla/5.0 (Linux; Android 15; moto g) AppleWebKit/537.36 Chrome/130 Mobile Safari/537.36"
        windows_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130 Safari/537.36"
        iphone_ua = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148"
        pages = {name: self.client.get("/web", headers={"User-Agent": ua}).text
                 for name, ua in (("android", android_ua), ("windows", windows_ua), ("iphone", iphone_ua))}
        for page in pages.values():
            self.assertIn('id="getapp" class="getapp" hidden role="dialog"', page)
            self.assertIn("1,100 GFC for signing up and your first post!", page)
            self.assertIn("setTimeout(showGetApp, 15000)", page)
        self.assertRegex(pages["android"], r'class="primary" href="/app[^"]*">Get GFC for Android')
        self.assertRegex(pages["android"], r'class="secondary" href="/app[^"]*">Windows version')
        self.assertRegex(pages["windows"], r'class="primary" href="/app[^"]*">Get GFC for Windows')
        self.assertRegex(pages["iphone"], r'class="primary" href="/app[^"]*">Get GFC for Android')
        self.assertRegex(pages["iphone"], r'class="primary" href="/app[^"]*">Get GFC for Windows')

    def test_exclusives_open_the_popup(self):
        _, token = self.account()
        sid = self.upload(token).json()["id"]
        web = self.client.get("/web").text
        self.assertIn('data-exclusive="1"', web)                  # the teaser card: pop-up when it ends
        self.assertIn('class="getapp-open" href="/app"', web)     # "watch the full clip"
        share = self.client.get(f"/p/{sid}", headers=BROWSER).text
        self.assertIn('data-exclusive="1"', share)
        self.assertIn('class="getapp-open" href="/app"', share)

    def test_signed_links_survive_url_encoding(self):
        path = "/originals/abc_my clip (1).mp4"
        url = exclusive.signed_url(path)
        parts = urlsplit(url)
        q = dict(kv.split("=") for kv in parts.query.split("&"))
        from urllib.parse import unquote
        self.assertTrue(exclusive.link_is_valid(unquote(parts.path), q["exp"], q["sig"]))
        self.assertFalse(exclusive.link_is_valid(unquote(parts.path), str(int(time.time()) - 1), q["sig"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
