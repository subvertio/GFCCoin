"""
Tests for compressed audio streaming copies (audio_stream.py), with a stand-in
transcoder so they run without ffmpeg.

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

WAV_HEADER = b"RIFF\x24\x00\x00\x00WAVEfmt "


def fake_runner(src, dest):
    """Stand-in for ffmpeg: a small 'compressed' file."""
    dest.write_bytes(b"\x00\x00\x00\x20ftypM4A " + b"x" * 1000)


def failing_runner(src, dest):
    dest.write_bytes(b"partial")
    raise RuntimeError("boom")


class AudioStreamTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(main.app)
        cls.real_runner = audio_stream.run_ffmpeg
        audio_stream.run_ffmpeg = fake_runner  # the worker and make_stream use it by default

    @classmethod
    def tearDownClass(cls):
        audio_stream.run_ffmpeg = cls.real_runner

    def register(self):
        name = "a" + uuid.uuid4().hex[:10]
        r = self.client.post("/auth/register", data={"username": name, "password": "pw-" + name})
        token = r.json()["token"]
        self.client.post("/wallets/create", data={"name": "main", "api_token": token})
        return token

    def upload(self, filename, data, content_type="audio/wav"):
        token = self.register()
        r = self.client.post("/seeds/upload", data={"api_token": token, "title": "Track"},
                             files={"file": (filename, data, content_type)})
        self.assertEqual(r.status_code, 200, r.text)
        return r.json()

    def wait_for_queue(self):
        audio_stream._queue.join()

    def test_which_uploads_get_a_copy(self):
        self.assertTrue(audio_stream.needs_stream("x.wav", 1000))
        self.assertTrue(audio_stream.needs_stream("x.FLAC", 1000))
        self.assertTrue(audio_stream.needs_stream("x.aiff", 1000))
        self.assertFalse(audio_stream.needs_stream("x.mp3", 3 * 1024 * 1024))
        self.assertTrue(audio_stream.needs_stream("x.mp3", 20 * 1024 * 1024))

    def test_bad_seed_ids_never_leave_the_streams_dir(self):
        for bad in ("../x", "a/b", "a\\b", "", "x.m4a"):
            with self.assertRaises(ValueError):
                audio_stream.stream_path(bad)
            self.assertIsNone(audio_stream.stream_url(bad))

    def test_wav_upload_gets_a_streaming_copy_in_the_feed(self):
        seed = self.upload("song.wav", WAV_HEADER + os.urandom(20_000))
        self.assertTrue(seed["stream_pending"])
        self.assertTrue(seed["full"].endswith(".wav"))  # the original stays the original
        self.wait_for_queue()
        url = f"/streams/{seed['id']}.m4a"
        self.assertEqual(audio_stream.stream_url(seed["id"]), url)
        self.assertEqual(self.client.get(url).status_code, 200)
        items = {s["id"]: s for s in self.client.get("/feed", headers={"Accept": "application/json"}).json()["items"]}
        self.assertEqual(items[seed["id"]]["stream"], url)
        self.assertTrue(items[seed["id"]]["full"].endswith(".wav"))

    def test_web_feed_and_share_page_play_the_copy(self):
        seed = self.upload("live.wav", WAV_HEADER + os.urandom(20_000))
        self.wait_for_queue()
        url = f"/streams/{seed['id']}.m4a"
        share = self.client.get(f"/p/{seed['id']}").text
        top = share[share.index('<section class="featured"'):share.index("</section>")]
        self.assertIn(f'<audio controls preload="metadata" src="{url}"', top)
        web = self.client.get("/web", headers={"Accept": "text/html"}).text
        self.assertIn(f'src="{url}"', web)

    def test_small_compressed_audio_and_other_types_are_left_alone(self):
        mp3 = self.upload("short.mp3", b"ID3" + os.urandom(5000), "audio/mpeg")
        self.assertFalse(mp3["stream_pending"])
        img = self.upload("pic.png", os.urandom(5000), "image/png")
        self.assertFalse(img["stream_pending"])
        self.assertFalse(audio_stream.enqueue("abc123", "x.wav", "image", 10))

    def test_failed_transcode_leaves_nothing_behind(self):
        seed_id = uuid.uuid4().hex[:24]
        src = audio_stream.SEEDS_ORIG_DIR / f"{seed_id}_x.wav"
        src.write_bytes(WAV_HEADER + b"\x00" * 100)
        self.assertFalse(audio_stream.make_stream(seed_id, src.name, runner=failing_runner))
        self.assertIsNone(audio_stream.stream_url(seed_id))
        self.assertEqual(list(audio_stream.STREAMS_DIR.glob(f"{seed_id}*")), [])

    def test_missing_ffmpeg_is_not_an_error(self):
        seed_id = uuid.uuid4().hex[:24]
        src = audio_stream.SEEDS_ORIG_DIR / f"{seed_id}_y.wav"
        src.write_bytes(WAV_HEADER + b"\x00" * 100)
        saved = os.environ.get("GFC_FFMPEG")
        os.environ["GFC_FFMPEG"] = str(audio_stream.STREAMS_DIR / "no-such-ffmpeg")
        try:
            self.assertFalse(audio_stream.make_stream(seed_id, src.name, runner=self.real_runner))
        finally:
            os.environ.pop("GFC_FFMPEG", None)
            if saved is not None:
                os.environ["GFC_FFMPEG"] = saved
        self.assertIsNone(audio_stream.stream_url(seed_id))

    def test_feature_switch(self):
        os.environ["GFC_AUDIO_STREAMS"] = "0"
        try:
            self.assertFalse(audio_stream.enqueue("abc123", "x.wav", "audio", 10))
            self.assertEqual(audio_stream.backfill(), 0)
        finally:
            os.environ.pop("GFC_AUDIO_STREAMS")


if __name__ == "__main__":
    unittest.main(verbosity=2)
