"""
Tests for the iPhone web app (app_webapp.py): serving the published build at /app/web/ with
its security headers, the SPA fallback, path safety, and publish's checks and atomic swap.

Run from the repository root:
    python -m unittest discover -s tests -v
"""

import io
import shutil
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_signed_ledger  # noqa: F401  (sets up the isolated data dir first)

from fastapi.testclient import TestClient  # noqa: E402

import app_webapp  # noqa: E402
import main  # noqa: E402

INDEX = b"<!doctype html><title>GFC</title><div id=app></div>"


def build_zip(files: dict) -> Path:
    path = Path(tempfile.mkdtemp()) / "web.zip"
    with zipfile.ZipFile(path, "w") as z:
        for name, data in files.items():
            z.writestr(name, data)
    return path


GOOD = {"index.html": INDEX, "assets/index-abc123.js": b"console.log(1)", "sw.js": b"//sw",
        "manifest.webmanifest": b"{}", "icons/apple-touch-icon.png": b"\x89PNG"}


class WebAppTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(main.app)

    def setUp(self):
        self.app_dir = Path(tempfile.mkdtemp())
        self.patches = [mock.patch.object(app_webapp, "APP_DIR", self.app_dir),
                        mock.patch.object(app_webapp, "WEB_DIR", self.app_dir / "web")]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        shutil.rmtree(self.app_dir, ignore_errors=True)

    def test_not_published_yet(self):
        r = self.client.get("/app/web/")
        self.assertEqual(r.status_code, 503)
        self.assertIn("coming", r.text)
        self.assertIn("Content-Security-Policy", r.headers)

    def test_serves_the_app_with_strict_headers(self):
        app_webapp.publish(build_zip(GOOD), "0.2.5")
        r = self.client.get("/app/web/")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.content, INDEX)
        csp = r.headers["Content-Security-Policy"]
        self.assertIn("script-src 'self' 'wasm-unsafe-eval'", csp)
        self.assertIn("frame-ancestors 'none'", csp)
        self.assertNotIn("unsafe-eval'", csp.replace("wasm-unsafe-eval'", ""))
        self.assertEqual(r.headers["Cache-Control"], "no-cache")
        a = self.client.get("/app/web/assets/index-abc123.js")
        self.assertEqual(a.status_code, 200)
        self.assertIn("javascript", a.headers["content-type"])
        self.assertIn("immutable", a.headers["Cache-Control"])
        m = self.client.get("/app/web/manifest.webmanifest")
        self.assertIn("manifest+json", m.headers["content-type"])

    def test_without_the_slash_redirects_and_unknown_pages_get_the_app(self):
        app_webapp.publish(build_zip(GOOD), "0.2.5")
        r = self.client.get("/app/web", follow_redirects=False)
        self.assertEqual(r.status_code, 308)
        self.assertEqual(r.headers["location"], "/app/web/")
        self.assertEqual(self.client.get("/app/web/wallet").content, INDEX)  # a reload deep in the app
        self.assertEqual(self.client.get("/app/web/assets/missing.js").status_code, 404)
        self.assertEqual(self.client.get("/app/web/nope.png").status_code, 404)

    def test_paths_never_leave_the_folder(self):
        app_webapp.publish(build_zip(GOOD), "0.2.5")
        (self.app_dir / "secret.txt").write_text("not for the web")
        for p in ("/app/web/../secret.txt", "/app/web/%2e%2e/secret.txt", "/app/web/..%2fsecret.txt"):
            r = self.client.get(p)
            self.assertNotIn(b"not for the web", r.content, p)

    def test_publish_refuses_bad_zips(self):
        bad = [
            {"assets/x.js": b"1"},                                    # no index.html
            {"dist-web/index.html": INDEX, "dist-web/assets/x.js": b"1"},  # the folder, not its contents
            {"index.html": INDEX},                                    # no assets/
            {"index.html": INDEX, "assets/x.js": b"1", "../evil": b"x"},  # escapes the folder
        ]
        for files in bad:
            with self.assertRaises(ValueError, msg=list(files)):
                app_webapp.publish(build_zip(files), "0.2.5")
        self.assertFalse((self.app_dir / "web").exists())

    def test_publish_replaces_the_old_release_whole(self):
        app_webapp.publish(build_zip({**GOOD, "assets/old-only.js": b"old"}), "0.2.4")
        info = app_webapp.publish(build_zip(GOOD), "0.2.5")
        self.assertEqual(info["version"], "0.2.5")
        self.assertEqual(self.client.get("/app/web/assets/old-only.js").status_code, 404)
        self.assertEqual(sorted(p.name for p in self.app_dir.iterdir()), ["web"])  # no leftovers
        self.assertIn("0.2.5", (self.app_dir / "web" / "release.json").read_text())


if __name__ == "__main__":
    unittest.main(verbosity=2)
