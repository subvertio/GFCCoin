"""
Tests for profile photos (POST /users/me/avatar): only real images, up to 5 MB, served from
the node's own origin, so never HTML or SVG.

Run from the repository root:
    python -m unittest discover -s tests -v
"""

import sys
import unittest
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_signed_ledger  # noqa: F401  (sets up the isolated data dir and a test treasury first)

from fastapi.testclient import TestClient  # noqa: E402

import app_profile  # noqa: E402
import main  # noqa: E402
from config import AVATAR_DIR  # noqa: E402

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64
JPEG = b"\xff\xd8\xff\xe0" + b"\x00" * 64
WEBP = b"RIFF\x24\x00\x00\x00WEBPVP8 " + b"\x00" * 64


class AvatarTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(main.app)

    def account(self, name=None):
        name = name or "a" + uuid.uuid4().hex[:10]
        token = self.client.post("/auth/register", data={"username": name, "password": "pw-" + name}).json()["token"]
        return name, {"Authorization": f"Bearer {token}"}

    def upload(self, headers, data, filename="me.png"):
        return self.client.post("/users/me/avatar", headers=headers, files={"avatar": (filename, data, "image/png")})

    def test_real_images_are_saved_and_replace_the_old_one(self):
        name, h = self.account()
        first = self.upload(h, PNG)
        self.assertEqual(first.status_code, 200, first.text)
        self.assertTrue(first.json()["avatar"].endswith(".png"))
        self.assertEqual(self.client.get(first.json()["avatar"]).content, PNG)
        # A new photo gets a new address (no stale cache), the old file is gone, the profile points at it
        second = self.upload(h, JPEG, filename="whatever.html")  # the name's extension is ignored
        self.assertTrue(second.json()["avatar"].endswith(".jpg"))
        self.assertNotEqual(second.json()["avatar"], first.json()["avatar"])
        self.assertFalse((AVATAR_DIR / first.json()["avatar"].rsplit("/", 1)[1]).exists())
        self.assertEqual(self.client.get(f"/users/{name}").json()["avatar"], second.json()["avatar"])
        self.assertTrue(self.upload(h, WEBP).json()["avatar"].endswith(".webp"))

    def test_html_svg_and_other_files_are_refused(self):
        _, h = self.account()
        for data, fn in ((b"<html><script>alert(1)</script></html>", "x.html"),
                         (b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>', "x.svg"),
                         (b"MZ\x90\x00", "x.png")):
            r = self.upload(h, data, fn)
            self.assertEqual(r.status_code, 400, fn)
            self.assertIn("JPEG, PNG, GIF or WebP", r.json()["detail"])

    def test_too_big_and_empty_are_refused(self):
        _, h = self.account()
        self.assertEqual(self.upload(h, PNG + b"\x00" * app_profile.MAX_AVATAR_BYTES).status_code, 413)
        self.assertEqual(self.upload(h, b"").status_code, 400)
        self.assertEqual(self.client.post("/users/me/avatar", files={"avatar": ("a.png", PNG, "image/png")}).status_code, 401)

    def test_a_similar_name_keeps_its_own_photo(self):
        base = "s" + uuid.uuid4().hex[:6]
        other_name, other_h = self.account(base + "_avatar_x")
        mine_name, mine_h = self.account(base)
        theirs = self.upload(other_h, PNG).json()["avatar"]
        self.upload(mine_h, PNG)
        self.upload(mine_h, JPEG)  # replacing mine must not delete theirs
        self.assertEqual(self.client.get(theirs).status_code, 200)


if __name__ == "__main__":
    unittest.main(verbosity=2)
