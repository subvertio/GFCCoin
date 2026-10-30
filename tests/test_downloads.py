"""
Tests for downloads (zip posts) and their virus scanning (filescan.py). ClamAV isn't needed:
the scanner is replaced by a stand-in.

Run from the repository root:
    python -m unittest discover -s tests -v
"""

import hashlib
import io
import os
import sqlite3
import sys
import unittest
import uuid
import zipfile
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_signed_ledger  # noqa: F401  (sets up the isolated data dir and a test treasury first)
from test_signed_ledger import mark_verified

from fastapi.testclient import TestClient  # noqa: E402

import config  # noqa: E402
import filescan  # noqa: E402
import main  # noqa: E402
from config import SEEDS_ORIG_DIR  # noqa: E402

BROWSER = {"Accept": "text/html"}


def game_zip(files=None) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in (files or {"AlteredEarth/AlteredEarth.exe": b"MZ" + os.urandom(3000),
                                     "AlteredEarth/readme.txt": b"Have fun",
                                     "AlteredEarth/data/level1.pak": os.urandom(5000)}).items():
            zf.writestr(name, data)
    return buf.getvalue()


def scanner(status, detail=""):
    return lambda path: (status, detail, "clamscan")


class DownloadTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(main.app)
        # Uploads only mark the scan pending here; each test runs the scan itself
        cls.patch = mock.patch.object(filescan, "enqueue", side_effect=lambda sid, db_path=None: filescan.mark_pending(sid))
        cls.patch.start()

    @classmethod
    def tearDownClass(cls):
        cls.patch.stop()

    def setUp(self):
        self.saved = (config.REQUIRE_PHONE_TO_POST, config.IS_TESTNET)
        config.REQUIRE_PHONE_TO_POST = False

    def tearDown(self):
        config.REQUIRE_PHONE_TO_POST, config.IS_TESTNET = self.saved

    def account(self, verified=False):
        name = "d" + uuid.uuid4().hex[:10]
        token = self.client.post("/auth/register", data={"username": name, "password": "pw-" + name}).json()["token"]
        self.client.post("/wallets/create", data={"name": "main", "api_token": token})
        if verified:
            mark_verified(main.DB_PATH, name)
        return name, token

    def upload(self, token, data=None, name="AlteredEarth.zip", exclusive=False):
        form = {"api_token": token, "title": "Altered Earth", "description": "My game"}
        if exclusive:
            form["exclusive"] = "true"
        r = self.client.post("/seeds/upload", data=form, files={"file": (name, data or game_zip(), "application/zip")})
        self.assertEqual(r.status_code, 200, r.text)
        return r.json()

    def filename(self, sid):
        conn = sqlite3.connect(main.DB_PATH)
        try:
            return conn.execute("SELECT filename FROM seeds WHERE id = ?", (sid,)).fetchone()[0]
        finally:
            conn.close()

    def feed_item(self, sid):
        return next((i for i in self.client.get("/feed").json()["items"] if i["id"] == sid), None)

    # ---------- held until scanned ----------

    def test_new_download_is_held_until_scanned(self):
        _, token = self.account()
        body = self.upload(token)
        self.assertEqual(body["download"]["status"], "pending")
        self.assertIsNone(body["full"])
        sid = body["id"]
        r = self.client.get(f"/originals/{self.filename(sid)}")
        self.assertEqual(r.status_code, 403)
        self.assertIn("being checked for viruses", r.json()["detail"])
        item = self.feed_item(sid)
        self.assertEqual(item["download"]["status"], "pending")
        self.assertIsNone(item["full"])
        self.assertIn("Checking for viruses", self.client.get("/web").text)

    def test_clean_download_is_offered_with_its_checksum(self):
        _, token = self.account()
        data = game_zip()
        sid = self.upload(token, data)["id"]
        self.assertEqual(filescan.scan_seed(sid, runner=scanner(filescan.CLEAN)), "clean")
        item = self.feed_item(sid)
        d = item["download"]
        self.assertEqual((d["status"], d["files"], d["programs"]), ("clean", 3, 1))
        self.assertEqual(d["sha256"], hashlib.sha256(data).hexdigest())
        self.assertEqual(d["name"], "AlteredEarth.zip")
        self.assertEqual(self.client.get(item["full"]).content, data)
        web = self.client.get("/web").text
        self.assertIn("Scanned by ClamAV", web)
        self.assertIn(f'href="{item["full"]}" download>Download</a>', web)
        share = self.client.get(f"/p/{sid}", headers=BROWSER).text
        self.assertIn(d["sha256"], share)

    def test_infected_download_is_deleted_and_removed(self):
        _, token = self.account()
        sid = self.upload(token)["id"]
        fn = self.filename(sid)
        self.assertEqual(filescan.scan_seed(sid, runner=scanner(filescan.INFECTED, "Win.Trojan.Test")), "infected")
        self.assertFalse((SEEDS_ORIG_DIR / fn).exists())
        self.assertIsNone(self.feed_item(sid))
        self.assertEqual(self.client.get(f"/p/{sid}", headers=BROWSER).status_code, 410)
        self.assertIn("removed", self.client.get(f"/originals/{fn}").json()["detail"])

    # ---------- zip checks ----------

    def test_password_protected_zips_are_rejected(self):
        data = bytearray(game_zip({"secret.exe": b"MZ" + os.urandom(500)}))
        # Set the "encrypted" flag in the local and central headers
        for sig in (b"PK\x03\x04", b"PK\x01\x02"):
            i = data.find(sig)
            flag_at = i + (6 if sig == b"PK\x03\x04" else 8)
            data[flag_at] |= 0x1
        _, token = self.account()
        sid = self.upload(token, bytes(data))["id"]
        self.assertEqual(filescan.scan_seed(sid, runner=scanner(filescan.CLEAN)), "rejected")
        conn = sqlite3.connect(main.DB_PATH)
        self.assertIn("password", filescan.status_of(conn, sid)["detail"])
        conn.close()

    def test_zip_bombs_and_broken_zips_are_rejected(self):
        bomb = io.BytesIO()
        with zipfile.ZipFile(bomb, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("zeros.bin", b"\0" * (150 * 1024 * 1024))
        ok, reason, _ = filescan.check_zip(self._write(bomb.getvalue()))
        self.assertFalse(ok)
        self.assertIn("zip bomb", reason)
        ok, reason, _ = filescan.check_zip(self._write(b"not a zip at all" * 100))
        self.assertFalse(ok)
        self.assertIn("not a readable zip", reason)

    def _write(self, data: bytes) -> Path:
        p = SEEDS_ORIG_DIR / f"check_{uuid.uuid4().hex[:8]}.zip"
        p.write_bytes(data)
        self.addCleanup(lambda: p.unlink(missing_ok=True))
        return p

    # ---------- no scanner ----------

    def test_without_clamav_the_real_network_holds_downloads(self):
        _, token = self.account()
        sid = self.upload(token)["id"]
        self.assertEqual(filescan.scan_seed(sid, runner=scanner(filescan.UNAVAILABLE, "not installed")), "unavailable")
        config.IS_TESTNET = False
        self.assertIsNone(self.feed_item(sid)["full"])
        self.assertEqual(self.client.get(f"/originals/{self.filename(sid)}").status_code, 403)
        config.IS_TESTNET = True  # test networks let them through
        self.assertIsNotNone(self.feed_item(sid)["full"])

    # ---------- exclusive downloads ----------

    def test_exclusive_download_only_for_real_accounts_once_clean(self):
        _, poster = self.account()
        sid = self.upload(poster, exclusive=True)["id"]
        config.REQUIRE_PHONE_TO_POST = True
        _, fan = self.account(verified=True)
        headers = {"Authorization": f"Bearer {fan}"}
        self.assertEqual(self.client.get(f"/seeds/{sid}/play", headers=headers).status_code, 409)  # not scanned yet
        filescan.scan_seed(sid, runner=scanner(filescan.CLEAN))
        links = self.client.get(f"/seeds/{sid}/play", headers=headers).json()
        self.assertIn("sig=", links["full"])
        self.assertEqual(self.client.get(links["full"]).status_code, 200)
        self.assertEqual(self.client.get(f"/originals/{self.filename(sid)}").status_code, 403)  # no signed link
        _, stranger = self.account(verified=False)
        self.assertEqual(self.client.get(f"/seeds/{sid}/play", headers={"Authorization": f"Bearer {stranger}"}).status_code, 403)
        item = self.feed_item(sid)
        self.assertTrue(item["exclusive"])
        self.assertIsNone(item["full"])
        self.assertIn("Download it in the", self.client.get("/web").text)

    # ---------- daily rescan ----------

    def test_daily_rescan_pulls_a_newly_detected_file(self):
        _, token = self.account()
        sid = self.upload(token)["id"]
        filescan.scan_seed(sid, runner=scanner(filescan.CLEAN))
        self.assertIsNotNone(self.feed_item(sid))
        counts = filescan.rescan_all(runner=lambda p: (filescan.INFECTED, "Win.Trojan.NewDefs", "clamscan")
                                     if p.name == self.filename(sid) else (filescan.CLEAN, "", "clamscan"))
        self.assertGreaterEqual(counts.get("infected", 0), 1)
        self.assertIsNone(self.feed_item(sid))

    def test_scanner_command_prefers_the_daemon(self):
        p = Path("x.zip")
        with mock.patch.dict(os.environ, {"GFC_CLAMSCAN": ""}):
            with mock.patch.object(filescan.CLAMD_SOCKET.__class__, "exists", return_value=True), \
                 mock.patch.object(filescan.shutil, "which", side_effect=lambda n: f"/usr/bin/{n}"):
                self.assertEqual(filescan.scanner_command(p)[:3], ["clamdscan", "--no-summary", "--fdpass"])
            with mock.patch.object(filescan.CLAMD_SOCKET.__class__, "exists", return_value=False), \
                 mock.patch.object(filescan.shutil, "which", side_effect=lambda n: f"/usr/bin/{n}" if n == "clamscan" else None):
                self.assertEqual(filescan.scanner_command(p)[0], "clamscan")
            with mock.patch.object(filescan.CLAMD_SOCKET.__class__, "exists", return_value=False), \
                 mock.patch.object(filescan.shutil, "which", return_value=None):
                self.assertIsNone(filescan.scanner_command(p))
        with mock.patch.dict(os.environ, {"GFC_CLAMSCAN": "/opt/clam/clamscan"}):
            self.assertEqual(filescan.scanner_command(p)[0], "/opt/clam/clamscan")

    def test_other_posts_are_untouched(self):
        _, token = self.account()
        r = self.client.post("/seeds/upload", data={"api_token": token, "title": "pic"},
                             files={"file": ("pic.png", os.urandom(2048), "image/png")})
        sid = r.json()["id"]
        self.assertNotIn("download", r.json())
        self.assertNotIn("download", self.feed_item(sid))
        self.assertEqual(self.client.get(f"/originals/{self.filename(sid)}").status_code, 200)


if __name__ == "__main__":
    unittest.main(verbosity=2)
