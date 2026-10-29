"""
Tests for the public Android download (app_release.py): only release-signed APKs can be
published, and the download page, APK and release.json are served.

Run from the repository root:
    python -m unittest discover -s tests -v
"""

import datetime
import hashlib
import io
import os
import struct
import unittest
import zipfile

# Sets up the isolated data dir and test treasury key before any GFC module loads config
import test_signed_ledger  # noqa: F401

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient  # noqa: E402

import app_release  # noqa: E402
import main  # noqa: E402

TMP = app_release.DATA_DIR / "apk_tests"
TMP.mkdir(parents=True, exist_ok=True)


def make_cert(cn: str) -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=1)).sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.DER)


def lp(b: bytes) -> bytes:
    return struct.pack("<I", len(b)) + b


def make_apk(name: str, cert_der: bytes = None) -> str:
    """A minimal APK; with cert_der, an APK Signature Scheme v2 block naming that certificate."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00" + b"\x00" * 64)
        zf.writestr("classes.dex", os.urandom(4096))
    data = buf.getvalue()
    if cert_der:
        eocd = data.rfind(b"PK\x05\x06")
        (cd_offset,) = struct.unpack_from("<I", data, eocd + 16)
        signed_data = lp(b"") + lp(lp(cert_der)) + lp(b"")
        signer = lp(signed_data) + lp(b"") + lp(b"")
        value = lp(lp(signer))
        pairs = struct.pack("<Q", 4 + len(value)) + struct.pack("<I", 0x7109871A) + value
        size = len(pairs) + 8 + 16
        block = struct.pack("<Q", size) + pairs + struct.pack("<Q", size) + b"APK Sig Block 42"
        data = data[:cd_offset] + block + data[cd_offset:]
        eocd += len(block)
        data = data[:eocd + 16] + struct.pack("<I", cd_offset + len(block)) + data[eocd + 20:]
    path = TMP / name
    path.write_bytes(data)
    return str(path)


class AppReleaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(main.app)
        cls.release_cert = make_cert("GFC")
        cls.debug_cert = make_cert("Android Debug")
        cls.release_fp = app_release.fingerprint(cls.release_cert)

    def setUp(self):
        self.saved = {k: os.environ.get(k) for k in ("GFC_ANDROID_CERT_SHA256", "GFC_ANDROID_PACKAGE")}
        os.environ["GFC_ANDROID_CERT_SHA256"] = self.release_fp.lower()  # case doesn't matter
        os.environ["GFC_ANDROID_PACKAGE"] = "tech.galacticfederation.gfc"

    def tearDown(self):
        for k, v in self.saved.items():
            os.environ.pop(k, None)
            if v is not None:
                os.environ[k] = v
        for p in (app_release.APK_PATH, app_release.INFO_PATH, app_release.WINDOWS_INFO_PATH,
                  app_release.APP_DIR / "gfc-windows.exe", app_release.APP_DIR / "gfc-windows.zip"):
            p.unlink(missing_ok=True)

    def test_reads_the_signing_certificate(self):
        apk = make_apk("signed.apk", self.release_cert)
        self.assertEqual(app_release.signing_fingerprints(apk), [self.release_fp])
        self.assertEqual(self.release_fp, ":".join(f"{b:02X}" for b in hashlib.sha256(self.release_cert).digest()))

    def test_refuses_debug_unsigned_and_non_apks(self):
        with self.assertRaisesRegex(app_release.ReleaseError, "release key"):
            app_release.publish(make_apk("debug.apk", self.debug_cert), "0.1.0")
        with self.assertRaisesRegex(app_release.ReleaseError, "isn't signed"):
            app_release.publish(make_apk("unsigned.apk"), "0.1.0")
        notzip = TMP / "notes.apk"
        notzip.write_bytes(b"hello" * 1000)
        with self.assertRaisesRegex(app_release.ReleaseError, "not an APK"):
            app_release.publish(str(notzip), "0.1.0")
        with self.assertRaisesRegex(app_release.ReleaseError, "version"):
            app_release.publish(make_apk("v.apk", self.release_cert), "../1")
        os.environ.pop("GFC_ANDROID_CERT_SHA256")
        with self.assertRaisesRegex(app_release.ReleaseError, "GFC_ANDROID_CERT_SHA256"):
            app_release.publish(make_apk("signed2.apk", self.release_cert), "0.1.0")
        self.assertIsNone(app_release.info())
        self.assertEqual(self.client.get("/app/gfc.apk").status_code, 404)
        self.assertIn("coming soon", self.client.get("/app").text)

    def test_publish_and_download(self):
        apk = make_apk("release.apk", self.release_cert)
        self.assertEqual(app_release._cli(["publish", apk, "0.1.0"]), 0)
        body = open(apk, "rb").read()
        rel = self.client.get("/app/release.json").json()
        self.assertTrue(rel["published"])
        self.assertEqual(rel["version"], "0.1.0")
        self.assertEqual(rel["sha256"], hashlib.sha256(body).hexdigest())
        self.assertEqual(rel["cert_sha256"], self.release_fp)
        r = self.client.get("/app/gfc.apk")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.content, body)
        self.assertEqual(r.headers["content-type"], "application/vnd.android.package-archive")
        self.assertIn("GFC-0.1.0.apk", r.headers["content-disposition"])
        part = self.client.get("/app/gfc.apk", headers={"Range": "bytes=0-99"})
        self.assertEqual(part.status_code, 206)
        self.assertEqual(part.content, body[:100])
        page = self.client.get("/app")
        self.assertIn('href="/app/gfc.apk"', page.text)
        self.assertIn(rel["sha256"], page.text)
        self.assertNotIn("<script", page.text)
        self.assertIn("default-src 'none'", page.headers["content-security-policy"])

    def test_header_downloads_are_always_there(self):
        # Nothing published yet: the buttons still show, and open the "coming soon" page
        web = self.client.get("/web", headers={"Accept": "text/html"}).text
        self.assertIn('<a href="/app#android">Get GFC for Android</a>', web)
        self.assertIn('<a href="/app#windows">Get GFC for Windows</a>', web)
        self.assertIn('href="https://galacticfederation.tech" rel="noopener">Learn more about GFC</a>', web)
        self.assertIn("1,100 GFC for signing up and your first post!", web)
        self.assertIn("position:sticky", web)

        # Published: direct downloads, on the feed and on a share page (where people from X land)
        app_release.publish(make_apk("release2.apk", self.release_cert), "0.1.1")
        app_release.publish_windows(make_windows("GFC-Setup.zip", zipped=True), "0.1.1")
        web = self.client.get("/web", headers={"Accept": "text/html"}).text
        self.assertIn('<a href="/app/gfc.apk" download>Get GFC for Android</a>', web)
        self.assertIn('<a href="/app/windows" download>Get GFC for Windows</a>', web)
        import app_web
        self.assertIn('<a href="/app/windows" download>Get GFC for Windows</a>', app_web.site_header())

        # Android without the app: "Open in GFC" falls back to the download page
        import app_share
        link = app_share.android_open_link("abc123", "https://example.org/p/abc123")
        self.assertIn("S.browser_fallback_url=" + app_share.quote(app_share.public_base_url() + "/app", safe=""), link)

    def test_bonus_line_follows_the_node_settings(self):
        import app_web
        saved = {k: os.environ.get(k) for k in ("GFC_FIRST_POST_BONUS_GFC", "GFC_FIRST_POST_BONUS_ENABLED")}
        try:
            os.environ["GFC_FIRST_POST_BONUS_GFC"] = "500"
            self.assertEqual(app_web.bonus_text(), "600 GFC for signing up and your first post!")
            os.environ["GFC_FIRST_POST_BONUS_ENABLED"] = "0"
            self.assertEqual(app_web.bonus_text(), "100 GFC for signing up!")
        finally:
            for k, v in saved.items():
                os.environ.pop(k, None)
                if v is not None:
                    os.environ[k] = v

    def test_windows_publish_and_download(self):
        for zipped in (False, True):
            src = make_windows("GFC-Setup-0.1.5" + (".zip" if zipped else ".exe"), zipped=zipped)
            self.assertEqual(app_release._cli(["publish-windows", src, "0.1.5"]), 0)
            body = open(src, "rb").read()
            rel = self.client.get("/app/windows.json").json()
            self.assertTrue(rel["published"])
            self.assertEqual((rel["version"], rel["ext"]), ("0.1.5", ".zip" if zipped else ".exe"))
            self.assertEqual(rel["sha256"], hashlib.sha256(body).hexdigest())
            r = self.client.get("/app/windows")
            self.assertEqual(r.status_code, 200)
            self.assertEqual(r.content, body)
            self.assertIn("GFC-Setup-0.1.5-Windows" + rel["ext"], r.headers["content-disposition"])
            page = self.client.get("/app").text
            self.assertIn('href="/app/windows"', page)
            self.assertIn(rel["sha256"], page)
            self.assertIn("SmartScreen", page)
        # Switching from .exe to .zip leaves no stale .exe behind
        self.assertFalse((app_release.APP_DIR / "gfc-windows.exe").exists())

    def test_windows_publish_refuses_wrong_files(self):
        notes = TMP / "notes.exe"
        notes.write_bytes(b"hello" * 1000)
        with self.assertRaisesRegex(app_release.ReleaseError, "isn't a Windows program"):
            app_release.publish_windows(str(notes), "0.1.5")
        two = TMP / "two.zip"
        with zipfile.ZipFile(two, "w") as zf:
            zf.writestr("a.exe", b"MZ" + os.urandom(4096))
            zf.writestr("b.exe", b"MZ" + os.urandom(4096))
        with self.assertRaisesRegex(app_release.ReleaseError, "one .exe"):
            app_release.publish_windows(str(two), "0.1.5")
        apk = make_apk("wrong.apk", self.release_cert)
        with self.assertRaisesRegex(app_release.ReleaseError, ".exe or the .zip"):
            app_release.publish_windows(apk, "0.1.5")
        with self.assertRaisesRegex(app_release.ReleaseError, "version"):
            app_release.publish_windows(make_windows("ok.exe"), "../1")
        self.assertIsNone(app_release.windows_info())
        self.assertEqual(self.client.get("/app/windows").status_code, 404)
        self.assertIn("Windows app is coming soon", self.client.get("/app").text)


def make_windows(name: str, zipped: bool = False) -> str:
    """A stand-in installer: an .exe starting with the Windows "MZ" header, or a zip of one."""
    exe = b"MZ" + os.urandom(8192)
    path = TMP / name
    if zipped:
        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr("GFC-Setup-0.1.5-abc1234.exe", exe)
    else:
        path.write_bytes(exe)
    return str(path)


if __name__ == "__main__":
    unittest.main(verbosity=2)
