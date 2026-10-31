"""
Tests for big posts (up to config.MAX_UPLOAD_BYTES, 1 GB by default): uploads and files from
peers go to disk in pieces, never whole into memory; over the limit is refused; videos posted
without a thumbnail get one from the node; ClamAV scans files that big.

Run from the repository root:
    python -m unittest discover -s tests -v
"""

import base64
import os
import sqlite3
import sys
import types
import unittest
import uuid
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_signed_ledger  # noqa: F401  (sets up the isolated data dir and a test treasury first)

from fastapi.testclient import TestClient  # noqa: E402

import audio_stream  # noqa: E402
import config  # noqa: E402
import filescan  # noqa: E402
import main  # noqa: E402
import sync_engine  # noqa: E402
from config import SEEDS_ORIG_DIR, SEEDS_THUMB_DIR  # noqa: E402


class BigUploadTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(main.app)

    def setUp(self):
        self.saved = (config.REQUIRE_PHONE_TO_POST, config.MAX_UPLOAD_BYTES, config.MAX_VIDEO_UPLOAD_BYTES)
        config.REQUIRE_PHONE_TO_POST = False

    def tearDown(self):
        config.REQUIRE_PHONE_TO_POST, config.MAX_UPLOAD_BYTES, config.MAX_VIDEO_UPLOAD_BYTES = self.saved

    def account(self):
        name = "b" + uuid.uuid4().hex[:10]
        token = self.client.post("/auth/register", data={"username": name, "password": "pw-" + name}).json()["token"]
        self.client.post("/wallets/create", data={"name": "main", "api_token": token})
        return {"Authorization": f"Bearer {token}"}

    def upload(self, headers, data, name="clip.mp4"):
        return self.client.post("/seeds/upload", data={"title": "Big"}, headers=headers,
                                files={"file": (name, data, "video/mp4")})

    def test_default_limit_is_a_gigabyte(self):
        self.assertEqual(self.saved[1], 1024 * 1024 * 1024)

    def test_uploads_up_to_the_limit_are_saved_whole_and_bigger_ones_refused(self):
        h = self.account()
        config.MAX_UPLOAD_BYTES = config.MAX_VIDEO_UPLOAD_BYTES = 3 * 1024 * 1024 + 5  # several 1 MB pieces
        data = os.urandom(config.MAX_UPLOAD_BYTES)
        with mock.patch.object(audio_stream, "enqueue", return_value=False):
            r = self.upload(h, data)
        self.assertEqual(r.status_code, 200, r.text)
        conn = sqlite3.connect(main.DB_PATH)
        filename, size = conn.execute("SELECT filename, file_size FROM seeds WHERE id = ?", (r.json()["id"],)).fetchone()
        conn.close()
        self.assertEqual(size, len(data))
        self.assertEqual((SEEDS_ORIG_DIR / filename).read_bytes(), data)

        before = set(SEEDS_ORIG_DIR.iterdir())
        r = self.upload(h, data + b"x")
        self.assertEqual(r.status_code, 413)
        self.assertIn("up to 3 MB", r.json()["detail"])
        self.assertEqual(set(SEEDS_ORIG_DIR.iterdir()), before)  # nothing half-saved left behind

    def test_peer_files_are_written_piece_by_piece_and_capped(self):
        engine = sync_engine.SyncEngine.__new__(sync_engine.SyncEngine)
        engine._pending_file_chunks = {}
        peer = types.SimpleNamespace(peer_address="peer")
        size = sync_engine.FILE_CHUNK_SIZE * 2 + 123
        data = os.urandom(size)
        name = f"{uuid.uuid4().hex[:8]}_peer.bin"
        engine._on_seed_file_response(peer, {"seed_id": "s1", "file_type": "original", "found": True,
                                             "filename": name, "file_size": size})
        pending = engine._pending_file_chunks["s1:original"]
        self.assertNotIn("chunks", pending)  # nothing kept in memory
        pieces = [data[i:i + sync_engine.FILE_CHUNK_SIZE] for i in range(0, size, sync_engine.FILE_CHUNK_SIZE)]
        for i in (2, 0, 1):  # out of order is fine
            engine._on_seed_file_chunk(peer, {"seed_id": "s1", "file_type": "original", "chunk_idx": i,
                                              "data": base64.b64encode(pieces[i]).decode(), "is_last": False})
        with mock.patch.object(engine, "_award_podt_credits"):
            engine._on_seed_file_chunk(peer, {"seed_id": "s1", "file_type": "original", "chunk_idx": 3,
                                              "data": "", "is_last": True})
        self.assertEqual((SEEDS_ORIG_DIR / name).read_bytes(), data)
        self.assertFalse(list(SEEDS_ORIG_DIR.glob(".*.part")))

        # Over the limit: not even started
        config.MAX_UPLOAD_BYTES = config.MAX_VIDEO_UPLOAD_BYTES = 1000
        engine._on_seed_file_response(peer, {"seed_id": "s2", "file_type": "original", "found": True,
                                             "filename": "big.bin", "file_size": 5000})
        self.assertNotIn("s2:original", engine._pending_file_chunks)
        # A chunk past the announced size: dropped, and the half file deleted
        config.MAX_UPLOAD_BYTES, config.MAX_VIDEO_UPLOAD_BYTES = self.saved[1], self.saved[2]
        engine._on_seed_file_response(peer, {"seed_id": "s3", "file_type": "original", "found": True,
                                             "filename": "liar.bin", "file_size": 10})
        engine._on_seed_file_chunk(peer, {"seed_id": "s3", "file_type": "original", "chunk_idx": 5,
                                          "data": base64.b64encode(b"x" * 100).decode(), "is_last": False})
        self.assertNotIn("s3:original", engine._pending_file_chunks)
        self.assertFalse(list(SEEDS_ORIG_DIR.glob(".*.part")))

    def test_videos_without_a_thumbnail_get_one_from_the_node(self):
        h = self.account()
        with mock.patch.object(audio_stream, "enqueue", return_value=False):
            sid = self.upload(h, os.urandom(2048)).json()["id"]
        made = []

        def fake(src, dest):
            made.append(src)
            dest.write_bytes(b"\xff\xd8\xff thumb")
        self.assertTrue(audio_stream.make_video_thumbnail(sid, runner=fake))
        conn = sqlite3.connect(main.DB_PATH)
        thumb = conn.execute("SELECT thumb_filename FROM seeds WHERE id = ?", (sid,)).fetchone()[0]
        conn.close()
        self.assertEqual(thumb, f"{sid}_thumb.jpg")
        self.assertTrue((SEEDS_THUMB_DIR / thumb).exists())
        self.assertIn(f"/thumbs/{thumb}", [i.get("thumb") for i in self.client.get("/feed").json()["items"]])
        # One the app sent (or one already made) is never replaced
        self.assertFalse(audio_stream.make_video_thumbnail(sid, runner=fake))
        self.assertEqual(len(made), 1)

    def test_big_files_get_a_longer_transcode_and_a_full_virus_scan(self):
        with mock.patch.object(Path, "stat", return_value=types.SimpleNamespace(st_size=10 * 1048576)):
            self.assertEqual(audio_stream.transcode_timeout(Path("small.mp4")), audio_stream.TRANSCODE_TIMEOUT_S)
        with mock.patch.object(Path, "stat", return_value=types.SimpleNamespace(st_size=1024 * 1048576)):
            self.assertGreater(audio_stream.transcode_timeout(Path("big.mp4")), 90 * 60)
        with mock.patch.dict(os.environ, {"GFC_CLAMSCAN": ""}), \
             mock.patch.object(filescan.CLAMD_SOCKET.__class__, "exists", return_value=False), \
             mock.patch.object(filescan.shutil, "which", side_effect=lambda n: f"/usr/bin/{n}" if n == "clamscan" else None):
            cmd = filescan.scanner_command(Path("x.zip"))
        self.assertIn("--max-filesize=4000M", cmd)

    # ---------- optimising oversized videos ----------

    def _original(self, data=b"V" * 4000):
        name = f"{uuid.uuid4().hex[:8]}_clip.mp4"
        (SEEDS_ORIG_DIR / name).write_bytes(data)
        return name

    def test_an_oversized_video_is_reencoded_at_its_own_resolution(self):
        name = self._original()
        calls = []

        def encoder(src, dest, info):
            calls.append(audio_stream.optimize_args(src, dest, info, "ffmpeg"))
            dest.write_bytes(b"v" * 1000)  # 75% smaller
        info = {"width": 1920, "height": 1080, "kbps": 27000, "audio": "aac"}
        self.assertTrue(audio_stream.optimize_video("s", name, runner=encoder, prober=lambda p: info))
        self.assertEqual((SEEDS_ORIG_DIR / name).read_bytes(), b"v" * 1000)
        args = calls[0]
        self.assertNotIn("-vf", args)  # no scaling: same resolution
        self.assertEqual(args[args.index("-crf") + 1], "20")
        self.assertEqual(args[args.index("-maxrate") + 1], "10000k")  # the 1080p ceiling
        self.assertEqual(args[args.index("-c:a") + 1], "copy")  # AAC audio kept as is
        self.assertFalse(list(SEEDS_ORIG_DIR.glob(".*optimizing*")))

    def test_reasonable_videos_and_small_savings_are_left_alone(self):
        name = self._original()
        never = mock.Mock(side_effect=AssertionError("should not re-encode"))
        # Already fine for 1080p (8 Mbit/s): untouched, not even re-encoded
        self.assertFalse(audio_stream.optimize_video("s", name, runner=never,
                                                     prober=lambda p: {"width": 1920, "height": 1080, "kbps": 8000}))
        # 4K at 30 Mbit/s is under the 4K ceiling
        self.assertFalse(audio_stream.optimize_video("s", name, runner=never,
                                                     prober=lambda p: {"width": 3840, "height": 2160, "kbps": 30000}))
        # Unknown (ffprobe failed): keep what was uploaded
        self.assertFalse(audio_stream.optimize_video("s", name, runner=never, prober=lambda p: None))
        # Oversized, but the re-encode only saves 10%: keep the original
        self.assertFalse(audio_stream.optimize_video(
            "s", name, runner=lambda s, d, i: d.write_bytes(b"v" * 3600),
            prober=lambda p: {"width": 1280, "height": 720, "kbps": 20000, "audio": "opus"}))
        self.assertEqual((SEEDS_ORIG_DIR / name).read_bytes(), b"V" * 4000)
        self.assertFalse(list(SEEDS_ORIG_DIR.glob(".*optimizing*")))
        # A failed encode keeps the original too
        def broken(src, dest, info):
            dest.write_bytes(b"half")
            raise RuntimeError("ffmpeg died")
        self.assertFalse(audio_stream.optimize_video("s", name, runner=broken,
                                                     prober=lambda p: {"width": 1920, "height": 1080, "kbps": 50000}))
        self.assertEqual((SEEDS_ORIG_DIR / name).read_bytes(), b"V" * 4000)
        self.assertFalse(list(SEEDS_ORIG_DIR.glob(".*optimizing*")))

    def test_ceilings_follow_the_resolution(self):
        self.assertEqual(audio_stream.ceiling_kbps(1280, 720), 5000)
        self.assertEqual(audio_stream.ceiling_kbps(1080, 1920), 10000)  # portrait 1080p
        self.assertEqual(audio_stream.ceiling_kbps(3840, 2160), 35000)

    # ---------- videos over the post limit: kept if their optimised copy fits ----------

    def test_a_big_video_is_taken_when_its_optimised_copy_fits_and_refused_with_a_tip_when_not(self):
        h = self.account()
        config.MAX_UPLOAD_BYTES = 1024 * 1024           # 1 MB posts (stands in for 1 GB)
        config.MAX_VIDEO_UPLOAD_BYTES = 4 * 1024 * 1024  # 4 MB raw videos (for 4 GB)
        data = os.urandom(2 * 1024 * 1024)
        before = set(SEEDS_ORIG_DIR.iterdir())

        # 1080p at 27 Mbit/s for 0.3 s: optimised to (10,000 + 192) kbit/s -> ~380 KB, fits
        fits = {"width": 1920, "height": 1080, "kbps": 27000, "duration": 0.3, "audio": "aac"}
        with mock.patch.object(audio_stream, "probe_video", return_value=fits),              mock.patch.object(audio_stream, "enqueue", return_value=False):
            self.assertEqual(self.upload(h, data).status_code, 200)

        # 4K at 100 Mbit/s for 1 s: optimised is still ~4.4 MB at the 4K ceiling: refused, with the tip
        huge = {"width": 3840, "height": 2160, "kbps": 100000, "duration": 1.0, "audio": "aac"}
        with mock.patch.object(audio_stream, "probe_video", return_value=huge):
            r = self.upload(h, data)
        self.assertEqual(r.status_code, 413)
        self.assertIn("Mbit/s or less", r.json()["detail"])
        self.assertIn("3840x2160", r.json()["detail"])

        # Can't read it: refused (nothing to base the promise on)
        with mock.patch.object(audio_stream, "probe_video", return_value=None):
            self.assertIn("can't read its length", self.upload(h, data).json()["detail"])
        # Not a video: the post limit as before
        r = self.client.post("/seeds/upload", data={"title": "zip"}, headers=h,
                             files={"file": ("big.zip", data, "application/zip")})
        self.assertEqual(r.status_code, 413)
        # Over the raw video limit: refused while receiving
        self.assertEqual(self.upload(h, os.urandom(5 * 1024 * 1024)).status_code, 413)
        self.assertEqual(len(set(SEEDS_ORIG_DIR.iterdir()) - before), 1)  # only the one that fit

    def test_the_estimate(self):
        five_min_1080 = {"width": 1920, "height": 1080, "kbps": 27000, "duration": 300}
        est = audio_stream.estimated_optimized_bytes(five_min_1080, 1_000_000_000)
        self.assertAlmostEqual(est / 1e6, 382, delta=2)  # 1 GB phone clip -> ~380 MB
        modest = {"width": 1920, "height": 1080, "kbps": 9000, "duration": 300}
        self.assertEqual(audio_stream.estimated_optimized_bytes(modest, 337_000_000), 337_000_000)  # kept as is
        hour_4k = {"width": 3840, "height": 2160, "kbps": 80000, "duration": 3600}
        tip = audio_stream.bitrate_tip(hour_4k, 1024 ** 3, int(3.5 * 1024 ** 3))
        self.assertIn("60 min at 3840x2160", tip)
        self.assertIn("Export it at 2.1 Mbit/s or less", tip)  # 1 GB over an hour, less the audio
        self.assertIn("at 720p", tip)
        self.assertEqual(audio_stream.target_mbps(86 * 60, 1024 ** 3), 1.4)  # an 86-minute show
        # Not oversized (2.3 Mbit/s 1080p) but over 1 GB as it is: the tip gives its real size
        show = {"width": 1920, "height": 1080, "kbps": 2300, "duration": 86 * 60}
        self.assertIn("about 1.48 GB", audio_stream.bitrate_tip(show, 1024 ** 3, int(1.48 * 1024 ** 3)))

    def test_a_video_over_the_limit_is_replaced_by_any_smaller_copy(self):
        config.MAX_UPLOAD_BYTES = 3000
        name = self._original()  # 4000 bytes, over the (test) limit
        info = {"width": 1920, "height": 1080, "kbps": 9000, "audio": "aac"}  # not "oversized" by bitrate
        self.assertTrue(audio_stream.optimize_video("s", name, runner=lambda s, d, i: d.write_bytes(b"v" * 3900),
                                                    prober=lambda p: info))
        self.assertEqual((SEEDS_ORIG_DIR / name).stat().st_size, 3900)  # a 2.5% saving still counts here


if __name__ == "__main__":
    unittest.main(verbosity=2)
