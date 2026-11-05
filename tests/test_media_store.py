"""
Tests for media storage (media_store.py): this node's disk, or Cloudflare R2, here faked
with an httpx MockTransport that checks every request's SigV4 signature (no network).

Run from the repository root:
    python -m unittest discover -s tests -v
"""

import datetime
import hashlib
import io
import os
import sqlite3
import sys
import time
import unittest
import uuid
from contextlib import redirect_stdout
from pathlib import Path
from urllib.parse import unquote, urlsplit

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_signed_ledger  # noqa: F401  (sets up the isolated data dir and a test treasury first)

from fastapi.testclient import TestClient  # noqa: E402

import audio_stream  # noqa: E402
import config  # noqa: E402
import exclusive  # noqa: E402
import filescan  # noqa: E402
import main  # noqa: E402
import media_store  # noqa: E402
from config import AVATAR_DIR, SEEDS_ORIG_DIR, SEEDS_THUMB_DIR  # noqa: E402

ACCOUNT, BUCKET, KEY_ID, SECRET = "acct123", "gfc-media", "AKTEST", "test-secret"
PUBLIC = "https://media.example.test"
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64


class FakeR2:
    """The S3 API for one bucket (signed requests only) plus its public URL (reads)."""

    def __init__(self):
        self.objects = {}  # key -> (bytes, headers)
        self.puts = 0
        self.corrupt = False  # store the wrong bytes, as a broken upload would

    def client(self) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(self.handle))

    def handle(self, request: httpx.Request) -> httpx.Response:
        if request.url.host == urlsplit(PUBLIC).hostname:
            obj = self.objects.get(unquote(request.url.path.lstrip("/")))
            return httpx.Response(200 if obj else 404, content=b"" if request.method == "HEAD" or not obj else obj[0])
        assert request.url.host == f"{ACCOUNT}.r2.cloudflarestorage.com", request.url.host
        path = request.url.raw_path.decode().split("?")[0]
        self.check_signature(request, path)
        bucket, _, key = unquote(path).lstrip("/").partition("/")
        assert bucket == BUCKET
        if request.method == "PUT":
            assert "transfer-encoding" not in request.headers  # R2 needs a Content-Length
            body = request.read()
            assert len(body) == int(request.headers["content-length"])
            if hashlib.sha256(body).hexdigest() != request.headers["x-amz-content-sha256"]:
                return httpx.Response(400)  # what R2 does when the signed SHA-256 doesn't match
            if self.corrupt:
                body = body[:-1]
            self.puts += 1
            self.objects[key] = (body, {"sha256": request.headers.get("x-amz-meta-sha256", ""),
                                        "content-type": request.headers.get("content-type", "")})
            return httpx.Response(200, headers={"etag": f'"{hashlib.md5(body).hexdigest()}"'})
        if request.method == "HEAD":
            obj = self.objects.get(key)
            if not obj:
                return httpx.Response(404)
            if obj[1]["content-type"].startswith("text/") and \
                    "gzip" in request.headers.get("accept-encoding", ""):
                # what R2 does: a gzipped answer, with no content-length and a weak ETag
                return httpx.Response(200, headers={"content-encoding": "gzip",
                                                    "etag": f'W/"{hashlib.md5(obj[0]).hexdigest()}"',
                                                    "x-amz-meta-sha256": obj[1]["sha256"]})
            return httpx.Response(200, headers={"content-length": str(len(obj[0])),
                                                "etag": f'"{hashlib.md5(obj[0]).hexdigest()}"',
                                                "x-amz-meta-sha256": obj[1]["sha256"]})
        if request.method == "DELETE":
            self.objects.pop(key, None)
            return httpx.Response(204)
        return httpx.Response(405)

    @staticmethod
    def check_signature(request: httpx.Request, path: str):
        auth = request.headers["authorization"]
        fields = dict(p.strip().split("=", 1) for p in auth.split(" ", 1)[1].split(","))
        assert fields["Credential"].startswith(KEY_ID + "/")
        names = fields["SignedHeaders"].split(";")
        assert {"host", "x-amz-date", "x-amz-content-sha256"} <= set(names)
        when = datetime.datetime.strptime(request.headers["x-amz-date"], "%Y%m%dT%H%M%SZ")
        extra = {n: request.headers[n] for n in names if n not in ("host", "x-amz-date", "x-amz-content-sha256")}
        expected = media_store.sign_v4(request.method, request.url.host, path, [], extra,
                                       request.headers["x-amz-content-sha256"], KEY_ID, SECRET, when)
        assert expected["authorization"] == auth, "bad signature"


def r2_settings(write=True, keep_local=False) -> media_store.Settings:
    return media_store.Settings(ACCOUNT if write else "", BUCKET if write else "", KEY_ID if write else "",
                                SECRET if write else "", PUBLIC, keep_local)


def fake_teaser(src: Path, dest: Path, seconds: int = exclusive.TEASER_SECONDS):
    dest.write_bytes(b"TEASER" + src.read_bytes()[:64])


class SigV4Tests(unittest.TestCase):
    def test_the_aws_example(self):
        # "GET Object" from the AWS Signature Version 4 docs (Amazon S3 API reference)
        h = media_store.sign_v4(
            "GET", "examplebucket.s3.amazonaws.com", "/test.txt", [], {"Range": "bytes=0-9"},
            media_store.EMPTY_SHA256, "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            datetime.datetime(2013, 5, 24), region="us-east-1")
        self.assertEqual(h["authorization"],
                         "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, "
                         "SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, "
                         "Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41")


class SettingsTests(unittest.TestCase):
    def test_modes(self):
        quiet = io.StringIO()
        with redirect_stdout(quiet):
            self.assertEqual(media_store.Settings.from_env({}).mode(), "local")
            self.assertEqual(r2_settings().mode(), "r2")
            self.assertEqual(r2_settings(write=False).mode(), "r2-read-only")
            # Write settings without a public URL: nothing could be served, so R2 stays off
            self.assertEqual(media_store.Settings(ACCOUNT, BUCKET, KEY_ID, SECRET, "").mode(), "local")
            # A half-done write setup never writes
            self.assertEqual(media_store.Settings(ACCOUNT, BUCKET, "", "", PUBLIC).mode(), "r2-read-only")
        env = {"GFC_R2_ACCOUNT_ID": ACCOUNT, "GFC_R2_BUCKET": BUCKET, "GFC_R2_ACCESS_KEY_ID": KEY_ID,
               "GFC_R2_SECRET_ACCESS_KEY": SECRET, "GFC_R2_PUBLIC_URL": PUBLIC + "/", "GFC_R2_KEEP_LOCAL": "1"}
        s = media_store.Settings.from_env(env)
        self.assertEqual((s.mode(), s.public_url, s.keep_local), ("r2", PUBLIC, True))

    def test_names_cant_leave_their_folder(self):
        for bad in ("", "../x", "a/b", "a\\b", ".hidden", ".abc.part"):
            with self.assertRaises(ValueError):
                media_store.local_path("thumbs", bad)
        self.assertIsNone(media_store.split_path("/originals/..%2Fgfc_ledger.db"))
        self.assertEqual(media_store.split_path("/originals/ab_c%20d.mp4"), ("originals", "ab_c d.mp4"))


class MediaStoreTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(main.app)

    def setUp(self):
        self.fake = FakeR2()
        self.saved = (config.REQUIRE_PHONE_TO_POST, exclusive.run_teaser_ffmpeg, os.environ.get("GFC_AUDIO_STREAMS"))
        config.REQUIRE_PHONE_TO_POST = False
        exclusive.run_teaser_ffmpeg = fake_teaser
        os.environ["GFC_AUDIO_STREAMS"] = "0"  # no transcoder here: uploads go straight to the bucket

    def tearDown(self):
        media_store._queue.join()
        media_store.configure(media_store.LocalStore())
        config.REQUIRE_PHONE_TO_POST, exclusive.run_teaser_ffmpeg, streams = self.saved
        if streams is None:
            os.environ.pop("GFC_AUDIO_STREAMS", None)
        else:
            os.environ["GFC_AUDIO_STREAMS"] = streams

    def use(self, **kw):
        media_store.configure(media_store.R2Store(r2_settings(**kw), client=self.fake.client()))

    def account(self):
        name = "m" + uuid.uuid4().hex[:10]
        token = self.client.post("/auth/register", data={"username": name, "password": "pw-" + name}).json()["token"]
        self.client.post("/wallets/create", data={"name": "main", "api_token": token})
        return name, {"Authorization": f"Bearer {token}"}

    def upload(self, headers, filename, data, **extra):
        r = self.client.post("/seeds/upload", headers=headers, data=extra,
                             files={"file": (filename, data, "application/octet-stream")})
        media_store._queue.join()
        return r

    def stored_keys(self):
        conn = sqlite3.connect(main.DB_PATH)
        try:
            media_store.init_tables(conn)
            return {r[0] for r in conn.execute("SELECT key FROM media_objects")}
        finally:
            conn.close()


class OfficialNodeTests(MediaStoreTestCase):
    def test_a_post_goes_to_the_bucket_and_its_url_redirects_there(self):
        self.use()
        _, headers = self.account()
        data = os.urandom(5000)
        r = self.upload(headers, "pic.png", data)
        self.assertEqual(r.status_code, 200, r.text)
        name = r.json()["full"].removeprefix("/originals/")
        key = f"originals/{name}"
        self.assertEqual(self.fake.objects[key][0], data)
        self.assertEqual(self.fake.objects[key][1]["content-type"], "image/png")
        self.assertEqual(self.fake.objects[key][1]["sha256"], hashlib.sha256(data).hexdigest())
        self.assertFalse((SEEDS_ORIG_DIR / name).exists())  # the node's disk stays small
        self.assertIn(key, self.stored_keys())
        # Apps keep the same URLs: the node sends them on to the bucket
        got = self.client.get(f"/originals/{name}", follow_redirects=False)
        self.assertEqual(got.status_code, 302)
        self.assertEqual(got.headers["location"], f"{PUBLIC}/{key}")

    def test_keep_local_uploads_but_keeps_the_file(self):
        self.use(keep_local=True)
        _, headers = self.account()
        r = self.upload(headers, "pic.png", os.urandom(3000))
        name = r.json()["full"].removeprefix("/originals/")
        self.assertIn(f"originals/{name}", self.fake.objects)
        self.assertTrue((SEEDS_ORIG_DIR / name).is_file())
        self.assertEqual(self.client.get(f"/originals/{name}", follow_redirects=False).status_code, 200)

    def test_a_bad_upload_keeps_the_local_copy(self):
        self.use()
        self.fake.corrupt = True
        name = f"{uuid.uuid4().hex[:12]}_thumb.jpg"
        (SEEDS_THUMB_DIR / name).write_bytes(os.urandom(2000))
        quiet = io.StringIO()
        with redirect_stdout(quiet):
            self.assertEqual(media_store.offload("thumbs", name), media_store.FAILED)
        self.assertIn("doesn't match", quiet.getvalue())
        self.assertTrue((SEEDS_THUMB_DIR / name).is_file())
        self.assertNotIn(f"thumbs/{name}", self.stored_keys())
        self.assertEqual(self.client.get(f"/thumbs/{name}", follow_redirects=False).status_code, 200)

    def test_text_posts_move_although_r2_gzips_text(self):
        self.use()
        name = f"{uuid.uuid4().hex[:12]}_post.txt"
        (SEEDS_ORIG_DIR / name).write_text("a text post " * 10)
        with redirect_stdout(io.StringIO()):
            self.assertEqual(media_store.offload("originals", name), media_store.STORED)
        self.assertFalse((SEEDS_ORIG_DIR / name).exists())
        self.assertIn(f"originals/{name}", self.stored_keys())

    def test_exclusive_clips_stay_on_the_node_behind_signed_links(self):
        self.use()
        _, headers = self.account()
        r = self.upload(headers, "clip.mp4", os.urandom(4096), exclusive="true")
        self.assertEqual(r.status_code, 200, r.text)
        sid = r.json()["id"]
        conn = sqlite3.connect(main.DB_PATH)
        filename = conn.execute("SELECT filename FROM seeds WHERE id = ?", (sid,)).fetchone()[0]
        conn.close()
        # The public teaser went to the bucket; the full clip didn't
        self.assertIn(f"teasers/{sid}.mp4", self.fake.objects)
        self.assertNotIn(f"originals/{filename}", self.fake.objects)
        self.assertTrue((SEEDS_ORIG_DIR / filename).is_file())
        self.assertEqual(media_store.offload("originals", filename), media_store.KEPT)
        self.assertEqual(r.json()["teaser"], f"/teasers/{sid}.mp4")
        self.assertEqual(self.client.get(f"/teasers/{sid}.mp4", follow_redirects=False).status_code, 302)
        # The gate is unchanged: no link, no clip; a signed link opens the local file
        self.assertEqual(self.client.get(f"/originals/{filename}", follow_redirects=False).status_code, 403)
        signed = exclusive.signed_url(f"/originals/{filename}")
        self.assertEqual(self.client.get(signed, follow_redirects=False).status_code, 200)
        # Its streaming copy is exclusive too, and never leaves the node
        stream = audio_stream.STREAMS_DIR / f"{sid}.mp4"
        stream.write_bytes(b"stream")
        try:
            self.assertEqual(media_store.offload("streams", stream.name), media_store.KEPT)
        finally:
            stream.unlink()
        # A locked clip that isn't here isn't redirected (it's never in the bucket)
        self.assertIsNone(media_store.redirect_url(f"/streams/{sid}.mp4"))

    def test_downloads_stay_on_the_node_and_keep_their_virus_gate(self):
        self.use()
        _, headers = self.account()
        buf = io.BytesIO()
        import zipfile
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("readme.txt", "hello")
        saved = filescan.enqueue
        filescan.enqueue = filescan.mark_pending  # stay pending: no scan in this test
        try:
            r = self.upload(headers, "pack.zip", buf.getvalue())
        finally:
            filescan.enqueue = saved
        sid = r.json()["id"]
        conn = sqlite3.connect(main.DB_PATH)
        filename = conn.execute("SELECT filename FROM seeds WHERE id = ?", (sid,)).fetchone()[0]
        conn.close()
        self.assertFalse(any(k.startswith("originals/") and k.endswith(filename) for k in self.fake.objects))
        self.assertTrue((SEEDS_ORIG_DIR / filename).is_file())
        got = self.client.get(f"/originals/{filename}", follow_redirects=False)
        self.assertEqual(got.status_code, 403)
        self.assertIn("checked for viruses", got.json()["detail"])

    def test_stream_and_teaser_urls_see_the_bucket(self):
        self.use()
        sid = uuid.uuid4().hex[:12]
        stream = audio_stream.STREAMS_DIR / f"{sid}.m4a"
        stream.write_bytes(b"aac" * 100)
        self.assertEqual(media_store.offload("streams", stream.name), media_store.STORED)
        self.assertFalse(stream.exists())
        self.assertEqual(audio_stream.stream_url(sid, "audio"), f"/streams/{sid}.m4a")
        # ...so the startup backfill doesn't try to make it again
        self.assertFalse(audio_stream.enqueue(sid, "x.flac", "audio", 10))
        media_store.configure(media_store.LocalStore())
        self.assertIsNone(audio_stream.stream_url(sid, "audio"))

    def test_a_new_avatar_replaces_the_old_one_in_the_bucket(self):
        self.use()
        name, headers = self.account()
        first = self.client.post("/users/me/avatar", headers=headers, files={"avatar": ("a.png", PNG, "image/png")})
        media_store._queue.join()
        first_key = "avatars/" + first.json()["avatar"].removeprefix("/avatars/")
        self.assertIn(first_key, self.fake.objects)
        second = self.client.post("/users/me/avatar", headers=headers,
                                  files={"avatar": ("b.png", PNG + b"2", "image/png")})
        media_store._queue.join()
        second_key = "avatars/" + second.json()["avatar"].removeprefix("/avatars/")
        self.assertIn(second_key, self.fake.objects)
        self.assertNotIn(first_key, self.fake.objects)
        self.assertNotIn(first_key, self.stored_keys())
        self.assertEqual(list(AVATAR_DIR.glob(f"{name}_avatar*")), [])

    def test_the_sweep_leaves_fresh_files_and_waits_for_streaming_copies(self):
        self.use()
        fresh = SEEDS_THUMB_DIR / f"{uuid.uuid4().hex[:12]}_thumb.jpg"
        fresh.write_bytes(b"new")
        _, headers = self.account()
        os.environ["GFC_AUDIO_STREAMS"] = "1"
        saved = audio_stream.enqueue
        audio_stream.enqueue = lambda *a: True  # a streaming copy is "on its way"
        try:
            r = self.upload(headers, "song.wav", os.urandom(2048))
        finally:
            audio_stream.enqueue = saved
        name = r.json()["full"].removeprefix("/originals/")
        old = time.time() - 2 * media_store.SETTLE_S
        os.utime(SEEDS_ORIG_DIR / name, (old, old))
        try:
            counts = media_store.offload_all()
            self.assertGreaterEqual(counts.get(media_store.SKIPPED, 0), 2)
            self.assertTrue(fresh.exists())
            self.assertTrue((SEEDS_ORIG_DIR / name).exists())  # the transcoder still needs it
            # Once the copy is made (or a day passes without one) the original goes too
            stuck = time.time() - media_store.STUCK_S - 60
            os.utime(SEEDS_ORIG_DIR / name, (stuck, stuck))
            media_store.offload_all()
            self.assertFalse((SEEDS_ORIG_DIR / name).exists())
            self.assertIn(f"originals/{name}", self.fake.objects)
        finally:
            fresh.unlink(missing_ok=True)


class MigrateTests(MediaStoreTestCase):
    def test_migrate_keep_local_then_for_real(self):
        self.use()
        tag = uuid.uuid4().hex[:12]
        kinds = ["thumbs", "avatars", "originals"]
        files = [SEEDS_THUMB_DIR / f"{tag}_thumb.jpg", AVATAR_DIR / f"{tag}_avatar_00000000.png",
                 SEEDS_ORIG_DIR / f"{tag}_orphan.png"]
        for i, f in enumerate(files):
            f.write_bytes(os.urandom(1000 + i))
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(media_store._cli(["migrate", "--dry-run"]), 0)
        self.assertEqual(self.fake.puts, 0)
        self.assertIn("would store", out.getvalue())
        with redirect_stdout(out):
            self.assertEqual(media_store._cli(["migrate", "--keep-local"]), 0)
        keys = [f"{k}/{f.name}" for k, f in zip(kinds, files)]
        for f, key in zip(files, keys):
            self.assertTrue(f.exists())
            self.assertEqual(self.fake.objects[key][0], f.read_bytes())
        puts = self.fake.puts
        with redirect_stdout(out):
            self.assertEqual(media_store._cli(["migrate"]), 0)
        self.assertEqual(self.fake.puts, puts)  # already verified: nothing uploaded twice
        for f in files:
            self.assertFalse(f.exists())
        self.assertNotIn(SECRET, out.getvalue())

    def test_migrate_needs_write_credentials(self):
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(media_store._cli(["migrate"]), 2)
            self.use(write=False)
            self.assertEqual(media_store._cli(["migrate"]), 2)
            self.assertEqual(media_store._cli(["status"]), 0)
            self.assertEqual(media_store._cli(["bogus"]), 2)
        self.assertNotIn(SECRET, out.getvalue())


class CommunityNodeTests(MediaStoreTestCase):
    def test_no_uploads_and_media_comes_from_the_public_url(self):
        self.use(write=False)
        _, headers = self.account()
        r = self.upload(headers, "pic.png", os.urandom(100))
        self.assertEqual(r.status_code, 403)
        self.assertEqual(r.json()["detail"], media_store.READ_ONLY_DETAIL)
        r = self.client.post("/users/me/avatar", headers=headers, files={"avatar": ("a.png", PNG, "image/png")})
        self.assertEqual(r.status_code, 403)
        # A file it doesn't have is fetched from the bucket's public URL
        got = self.client.get("/thumbs/abc_thumb.jpg", follow_redirects=False)
        self.assertEqual((got.status_code, got.headers["location"]), (302, f"{PUBLIC}/thumbs/abc_thumb.jpg"))
        # ...and one it does have (synced from a peer) is served from disk, as before
        mine = SEEDS_THUMB_DIR / f"{uuid.uuid4().hex[:12]}_thumb.jpg"
        mine.write_bytes(b"local")
        try:
            self.assertEqual(self.client.get(f"/thumbs/{mine.name}").content, b"local")
        finally:
            mine.unlink()
        # Streams are found with a HEAD on the public URL
        sid = uuid.uuid4().hex[:12]
        self.assertIsNone(audio_stream.stream_url(sid, "audio"))
        self.fake.objects[f"streams/{sid}.m4a"] = (b"aac", {"sha256": ""})
        media_store.store()._heads.clear()
        self.assertEqual(audio_stream.stream_url(sid, "audio"), f"/streams/{sid}.m4a")
        # It never writes, so nothing is offloaded
        self.assertEqual(media_store.offload_seed("anything"), {})
        self.assertEqual(self.fake.puts, 0)


class PagePolicyTests(MediaStoreTestCase):
    """Browsers check a redirect's target against the page's CSP: R2's origin must be allowed."""

    @staticmethod
    def directives(csp):
        return {d.split()[0]: d.split()[1:] for d in csp.split("; ")}

    def test_web_pages_and_the_web_app_allow_the_bucket(self):
        for write in (True, False):  # official and community nodes both serve from the bucket
            self.use(write=write)
            for path in ("/web", "/app/web/"):
                csp = self.directives(self.client.get(path, headers={"Accept": "text/html"}).headers["content-security-policy"])
                for d in ("img-src", "media-src", "connect-src"):
                    self.assertIn(PUBLIC, csp[d], f"{path} {d}")
                self.assertNotIn(PUBLIC, csp.get("script-src", []))
                self.assertNotIn(PUBLIC, csp.get("default-src", []))

    def test_local_nodes_keep_their_policy(self):
        media_store.configure(media_store.LocalStore())
        self.assertEqual(media_store.public_origin(), "")
        csp = self.client.get("/web", headers={"Accept": "text/html"}).headers["content-security-policy"]
        self.assertIn("media-src 'self';", csp)


class LocalNodeTests(MediaStoreTestCase):
    def test_local_mode_is_unchanged(self):
        media_store.configure(media_store.LocalStore())
        self.assertIsNone(media_store.redirect_url("/thumbs/abc_thumb.jpg"))
        self.assertEqual(self.client.get("/thumbs/nope_thumb.jpg", follow_redirects=False).status_code, 404)
        _, headers = self.account()
        r = self.upload(headers, "pic.png", os.urandom(100))
        self.assertTrue((SEEDS_ORIG_DIR / r.json()["full"].removeprefix("/originals/")).is_file())


if __name__ == "__main__":
    unittest.main()
