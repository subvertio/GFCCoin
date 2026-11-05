"""
Tests for wix_publish.py: exclusive videos by the site's GFC accounts go to a Wix CMS
collection (MisterRobots.com's front page), against a fake Wix API.

Run from the repository root:
    python -m unittest tests.test_wix_publish -v
"""

import json
import os
import sqlite3
import sys
import tempfile
import threading
import unittest
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_signed_ledger  # noqa: F401  (isolated data dir and test treasury first)

import httpx  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

import config  # noqa: E402
import exclusive  # noqa: E402
import main  # noqa: E402
import wix_publish  # noqa: E402

KEY = "IST.secret-wix-key-do-not-print"
SITE = "b1930f61-9667-472d-a66a-2093d1847865"
JPEG = b"\xff\xd8\xff\xe0" + b"0" * 64


def fake_teaser(src, dest, seconds=exclusive.TEASER_SECONDS):
    dest.write_bytes(b"TEASER" + src.read_bytes()[:32])


class FakeWix:
    """Media import (PENDING, then READY on the second GET), and CMS items."""

    def __init__(self):
        self.calls, self.items, self.files, self.fail_import = [], {}, {}, False

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.calls.append((request.method, request.url.path, request.headers.get("authorization"),
                           request.headers.get("wix-site-id")))
        body = json.loads(request.content) if request.content else {}
        path = request.url.path
        if path == "/site-media/v1/files/import":
            if self.fail_import:
                return httpx.Response(400, json={"message": "URL isn't reachable"})
            fid = uuid.uuid4().hex
            self.files[fid] = {"id": fid, "displayName": body["displayName"], "sourceUrl": body["url"],
                               "mediaType": body["mediaType"], "operationStatus": "PENDING", "polls": 0}
            return httpx.Response(200, json={"file": {k: v for k, v in self.files[fid].items() if k != "polls"}})
        if path.startswith("/site-media/v1/files/"):
            f = self.files[path.rsplit("/", 1)[1]]
            f["polls"] += 1
            if f["polls"] >= 2:
                f["operationStatus"] = "READY"
                f["url"] = f"https://video.wixstatic.com/video/{f['id']}/file" if f["mediaType"] == "VIDEO" \
                    else f"https://static.wixstatic.com/media/{f['id']}.jpg"
            return httpx.Response(200, json={"file": {k: v for k, v in f.items() if k != "polls"}})
        if path == "/wix-data/v2/items/save":
            item = body["dataItem"]
            self.items[item["id"]] = dict(item["data"], _collection=body["dataCollectionId"])
            return httpx.Response(200, json={"dataItem": item})
        if request.method == "DELETE" and path.startswith("/wix-data/v2/items/"):
            self.items.pop(path.rsplit("/", 1)[1], None)
            return httpx.Response(200, json={})
        if path == "/data/v2/collections":
            return httpx.Response(200, json={"collection": body["collection"]})
        if path.startswith("/data/v2/collections/"):
            return httpx.Response(200, json={"collection": {"id": path.rsplit("/", 1)[1]}})
        return httpx.Response(404, json={"message": "no such endpoint"})


class WixPublishTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(main.app)
        cls.tmp = tempfile.TemporaryDirectory()
        cls.key_path = Path(cls.tmp.name) / "wix_api_key.txt"
        cls.key_path.write_text(KEY + "\n")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def setUp(self):
        self.fake = FakeWix()
        self.owner = "w" + uuid.uuid4().hex[:10]
        self.saved_env = {k: os.environ.get(k) for k in ("GFC_WIX_SITE_ID", "GFC_WIX_OWNERS", "GFC_WIX_API_KEY_FILE")}
        os.environ.update({"GFC_WIX_SITE_ID": SITE, "GFC_WIX_OWNERS": f"Someone, {self.owner.upper()}",
                           "GFC_WIX_API_KEY_FILE": str(self.key_path)})
        wix_publish._client_factory = lambda: httpx.Client(transport=httpx.MockTransport(self.fake.handler))
        self.saved_sleep, self.saved_poll = wix_publish.time.sleep, wix_publish.POLL_S
        wix_publish.POLL_S = 0
        self.saved = (config.REQUIRE_PHONE_TO_POST, exclusive.run_teaser_ffmpeg)
        config.REQUIRE_PHONE_TO_POST = False
        exclusive.run_teaser_ffmpeg = fake_teaser

    def tearDown(self):
        self.join()
        wix_publish._client_factory = None
        wix_publish.POLL_S = self.saved_poll
        config.REQUIRE_PHONE_TO_POST, exclusive.run_teaser_ffmpeg = self.saved
        for k, v in self.saved_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    @staticmethod
    def join():
        for t in threading.enumerate():
            if t.name == "gfc-wix":
                t.join(10)

    def account(self, name=None):
        name = name or "x" + uuid.uuid4().hex[:10]
        token = self.client.post("/auth/register", data={"username": name, "password": "pw-" + name}).json()["token"]
        self.client.post("/wallets/create", data={"name": "main", "api_token": token})
        return {"Authorization": f"Bearer {token}"}

    def upload(self, auth, filename="show.mp4", exclusive_flag=True, title="Episode 12"):
        data = {"title": title, "description": "Robots, rebooted", "teaser_seconds": "30"}
        if exclusive_flag:
            data["exclusive"] = "true"
        r = self.client.post("/seeds/upload", headers=auth, data=data,
                             files={"file": (filename, os.urandom(4096), "application/octet-stream"),
                                    "thumbnail": ("t.jpg", JPEG, "image/jpeg")})
        self.assertEqual(r.status_code, 200, r.text)
        self.join()
        return r.json()["id"]

    def test_an_owners_exclusive_video_goes_to_the_site(self):
        sid = self.upload(self.account(self.owner))
        item = self.fake.items[sid]
        self.assertEqual(item["_collection"], "GFCTeasers")
        self.assertEqual((item["title"], item["description"], item["previewSeconds"]), ("Episode 12", "Robots, rebooted", 30))
        self.assertTrue(item["video"].startswith("https://video.wixstatic.com/video/"))
        self.assertTrue(item["poster"].startswith("https://static.wixstatic.com/media/"))
        self.assertTrue(item["link"].endswith(f"/p/{sid}"))
        self.assertRegex(item["postedAt"]["$date"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$")
        imported = [f["sourceUrl"] for f in self.fake.files.values()]
        self.assertTrue(any(u.endswith(f"/teasers/{sid}.mp4") for u in imported), imported)
        self.assertEqual(wix_publish.status_of(sid), "published")
        # Every call carries the key and the site; a second teaser cut doesn't publish again
        self.assertTrue(all(c[2] == KEY and c[3] == SITE for c in self.fake.calls))
        calls = len(self.fake.calls)
        self.assertTrue(exclusive.make_teaser(sid, self.filename(sid)))
        self.join()
        self.assertEqual(len(self.fake.calls), calls)

    def test_other_posts_stay_off_the_site(self):
        owner = self.account(self.owner)
        self.upload(self.account())                         # someone else's exclusive
        self.upload(owner, exclusive_flag=False)            # the owner's public video
        self.upload(owner, filename="song.mp3")             # the owner's exclusive track
        self.assertEqual((self.fake.items, self.fake.calls), ({}, []))

    def test_off_without_settings(self):
        os.environ["GFC_WIX_OWNERS"] = ""
        self.upload(self.account(self.owner))
        self.assertEqual(self.fake.calls, [])

    def test_deleting_the_post_takes_it_off_the_site(self):
        auth = self.account(self.owner)
        sid = self.upload(auth)
        self.assertIn(sid, self.fake.items)
        self.assertEqual(self.client.delete(f"/seeds/{sid}", headers=auth).status_code, 200)
        self.join()
        self.assertNotIn(sid, self.fake.items)
        self.assertEqual(wix_publish.status_of(sid), "removed")

    def test_a_failure_is_recorded_without_the_key_and_can_be_retried(self):
        self.fake.fail_import = True
        sid = self.upload(self.account(self.owner))
        self.assertEqual(wix_publish.status_of(sid), "failed")
        conn = sqlite3.connect(main.DB_PATH)
        error = conn.execute("SELECT error FROM wix_posts WHERE seed_id = ?", (sid,)).fetchone()[0]
        conn.close()
        self.assertIn("URL isn't reachable", error)
        self.assertNotIn(KEY, error)
        self.fake.fail_import = False
        self.assertEqual(wix_publish.publish(sid)["title"], "Episode 12")
        self.assertEqual(wix_publish.status_of(sid), "published")

    def test_setup_and_check(self):
        made = wix_publish.setup()
        self.assertEqual(made["collection"]["permissions"]["read"], "ANYONE")
        self.assertEqual({f["key"] for f in made["collection"]["fields"]} >= {"video", "poster", "link", "postedAt"}, True)
        report = wix_publish.check()
        self.assertIn("key works: yes", report)
        self.assertNotIn(KEY, report)

    def filename(self, sid):
        conn = sqlite3.connect(main.DB_PATH)
        try:
            return conn.execute("SELECT filename FROM seeds WHERE id = ?", (sid,)).fetchone()[0]
        finally:
            conn.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
