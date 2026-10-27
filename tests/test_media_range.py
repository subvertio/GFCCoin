"""
Media files support HTTP Range requests (206 Partial Content), so audio and video
players can seek and stream instead of downloading everything first.

Run from the repository root:
    python -m unittest discover -s tests -v
"""

import os
import unittest
import uuid

# Sets up the isolated data dir and test treasury key before any GFC module loads config
import test_signed_ledger  # noqa: F401

from fastapi.testclient import TestClient  # noqa: E402

import audio_stream  # noqa: E402
import main  # noqa: E402
from config import SEEDS_ORIG_DIR, SEEDS_THUMB_DIR  # noqa: E402

DATA = bytes(range(256)) * 400  # 102,400 bytes, every offset distinguishable


class MediaRangeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(main.app)
        cls.name = uuid.uuid4().hex[:12]
        cls.files = {
            "/originals": SEEDS_ORIG_DIR / f"{cls.name}_clip.mp4",
            "/streams": audio_stream.STREAMS_DIR / f"{cls.name}.m4a",
            "/thumbs": SEEDS_THUMB_DIR / f"{cls.name}_thumb.jpg",
        }
        for path in cls.files.values():
            path.write_bytes(DATA)

    @classmethod
    def tearDownClass(cls):
        for path in cls.files.values():
            path.unlink(missing_ok=True)

    def url(self, mount):
        return f"{mount}/{self.files[mount].name}"

    def test_seek_returns_exact_bytes(self):
        for mount in ("/originals", "/streams"):
            r = self.client.get(self.url(mount), headers={"Range": "bytes=1000-1999"})
            self.assertEqual(r.status_code, 206, mount)
            self.assertEqual(r.headers["content-range"], f"bytes 1000-1999/{len(DATA)}")
            self.assertEqual(r.content, DATA[1000:2000])

    def test_open_ended_and_suffix_ranges(self):
        r = self.client.get(self.url("/streams"), headers={"Range": "bytes=100000-"})
        self.assertEqual((r.status_code, r.content), (206, DATA[100000:]))
        r = self.client.get(self.url("/streams"), headers={"Range": "bytes=-500"})
        self.assertEqual((r.status_code, r.content), (206, DATA[-500:]))

    def test_full_download_advertises_ranges(self):
        r = self.client.get(self.url("/originals"))
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.content, DATA)
        self.assertEqual(r.headers.get("accept-ranges"), "bytes")

    def test_unsatisfiable_range(self):
        r = self.client.get(self.url("/originals"), headers={"Range": f"bytes={len(DATA) + 10}-"})
        self.assertEqual(r.status_code, 416)

    def test_media_types(self):
        self.assertEqual(self.client.get(self.url("/streams")).headers["content-type"], "audio/mp4")
        self.assertEqual(self.client.get(self.url("/originals")).headers["content-type"], "video/mp4")

    def test_path_traversal_still_refused(self):
        for bad in ("/streams/../gfc_ledger.db", "/originals/..%2fgfc_ledger.db", "/streams/%2e%2e/gfc_ledger.db"):
            self.assertIn(self.client.get(bad).status_code, (400, 404), bad)


if __name__ == "__main__":
    unittest.main(verbosity=2)
