"""
GFC Android app download - the public APK, straight from the node.

- GET /app               download page: version, size, date, checksums, how to install
- GET /app/gfc.apk       the APK itself (Range supported, so big downloads resume)
- GET /app/release.json  version, size, SHA-256 and signing certificate, for clients that
                         check for updates

Publishing (on the node, as root, normally through `gfc publish-app FILE VERSION`):
    python app_release.py publish /tmp/gfc.apk 0.1.0
    python app_release.py info

publish refuses an APK unless its signing certificate is one of GFC_ANDROID_CERT_SHA256 (the
release key, also used for App Links). So a development build, signed with Unreal's debug key,
can't be published by mistake: phones that installed it could never take a release update.
This reads the certificate from the APK Signature Scheme v2/v3 block (or the v1 JAR signature);
Android itself checks the signature when installing.

The APK lives in DATA_DIR/app/ (not in git, not in backups); a publish replaces it atomically.
"""

import datetime
import hashlib
import html
import json
import os
import re
import secrets
import struct
import sys
import zipfile
from pathlib import Path
from typing import List, Optional

from cryptography import x509
from cryptography.hazmat.primitives.serialization import pkcs7
from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse

from config import DATA_DIR

router = APIRouter()

APP_DIR = DATA_DIR / "app"
APK_PATH = APP_DIR / "gfc.apk"
INFO_PATH = APP_DIR / "release.json"
MAX_APK_BYTES = 512 * 1024 * 1024
VERSION_RE = re.compile(r"^[0-9A-Za-z][0-9A-Za-z.+-]{0,31}$")

_SIG_BLOCK_MAGIC = b"APK Sig Block 42"
_SIGNATURE_IDS = (0x7109871A, 0xF05368C0, 0x1B93AD61)  # v2, v3, v3.1


class ReleaseError(ValueError):
    pass


def fingerprint(der: bytes) -> str:
    """SHA-256 of a certificate, as AA:BB:... (the form App Links and keytool use)."""
    return ":".join(f"{b:02X}" for b in hashlib.sha256(der).digest())


def _lp(buf: bytes, pos: int):
    """A uint32-length-prefixed field: (value, next position)."""
    if pos + 4 > len(buf):
        raise ReleaseError("APK signing block is damaged")
    (n,) = struct.unpack_from("<I", buf, pos)
    if pos + 4 + n > len(buf):
        raise ReleaseError("APK signing block is damaged")
    return buf[pos + 4:pos + 4 + n], pos + 4 + n


def _v2_certificates(path: Path) -> List[bytes]:
    """Signer certificates from the APK Signing Block (schemes v2/v3), or [] if there is none."""
    with open(path, "rb") as f:
        f.seek(0, os.SEEK_END)
        size = f.tell()
        tail_len = min(size, 65_557)
        f.seek(size - tail_len)
        tail = f.read(tail_len)
        eocd = tail.rfind(b"PK\x05\x06")
        if eocd < 0 or eocd + 22 > len(tail):
            raise ReleaseError("not a zip file")
        (cd_offset,) = struct.unpack_from("<I", tail, eocd + 16)
        if cd_offset < 32:
            return []
        f.seek(cd_offset - 24)
        footer = f.read(24)
        if footer[8:] != _SIG_BLOCK_MAGIC:
            return []
        (block_size,) = struct.unpack_from("<Q", footer, 0)
        if block_size > cd_offset or block_size > 64 * 1024 * 1024:
            raise ReleaseError("APK signing block is damaged")
        f.seek(cd_offset - block_size - 8)
        block = f.read(block_size - 24 + 8)[8:]  # the id-value pairs
    pos = 0
    while pos + 12 <= len(block):
        (pair_len,) = struct.unpack_from("<Q", block, pos)
        (pair_id,) = struct.unpack_from("<I", block, pos + 8)
        value = block[pos + 12:pos + 8 + pair_len]
        pos += 8 + pair_len
        if pair_id not in _SIGNATURE_IDS:
            continue
        signers, _ = _lp(value, 0)
        certs, spos = [], 0
        while spos < len(signers):
            signer, spos = _lp(signers, spos)
            signed_data, _ = _lp(signer, 0)
            _digests, dpos = _lp(signed_data, 0)
            cert_seq, _ = _lp(signed_data, dpos)
            cpos = 0
            while cpos < len(cert_seq):
                der, cpos = _lp(cert_seq, cpos)
                certs.append(der)
                break  # the first certificate of each signer is its signing certificate
        if certs:
            return certs
    return []


def _v1_certificates(zf: zipfile.ZipFile) -> List[bytes]:
    from cryptography.hazmat.primitives.serialization import Encoding
    certs = []
    for name in zf.namelist():
        if re.fullmatch(r"META-INF/[^/]+\.(RSA|DSA|EC)", name, re.I):
            for cert in pkcs7.load_der_pkcs7_certificates(zf.read(name)):
                certs.append(cert.public_bytes(Encoding.DER))
    return certs


def signing_fingerprints(path: Path) -> List[str]:
    """Fingerprints of the certificates the APK is signed with (raises ReleaseError if unsigned)."""
    try:
        zf = zipfile.ZipFile(path)
    except zipfile.BadZipFile:
        raise ReleaseError("not an APK (not a zip file)")
    with zf:
        if "AndroidManifest.xml" not in zf.namelist():
            raise ReleaseError("not an APK (no AndroidManifest.xml)")
        certs = _v2_certificates(path) or _v1_certificates(zf)
    if not certs:
        raise ReleaseError("the APK isn't signed")
    for der in certs:
        x509.load_der_x509_certificate(der)  # raises on garbage
    return [fingerprint(der) for der in certs]


def release_fingerprints() -> List[str]:
    return [f.strip().upper() for f in os.environ.get("GFC_ANDROID_CERT_SHA256", "").split(",") if f.strip()]


def info() -> Optional[dict]:
    """The published release, or None."""
    try:
        data = json.loads(INFO_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if APK_PATH.is_file() else None


def publish(src: str, version: str) -> dict:
    """Check src is a release-signed GFC APK, then make it the public download."""
    path = Path(src)
    if not path.is_file():
        raise ReleaseError(f"no such file: {src}")
    if not VERSION_RE.match(version or ""):
        raise ReleaseError("version should look like 0.1.0 (letters, digits, . + -)")
    size = path.stat().st_size
    if not 1024 < size <= MAX_APK_BYTES:
        raise ReleaseError("that file is too small or too big to be the GFC app")
    allowed = release_fingerprints()
    if not allowed:
        raise ReleaseError("GFC_ANDROID_CERT_SHA256 isn't set: add the release key's fingerprint "
                           "(gfc config) so only release builds can be published")
    signed_with = signing_fingerprints(path)
    if not any(f in allowed for f in signed_with):
        raise ReleaseError("this APK isn't signed with the release key (a development build?). "
                           f"Signed with {signed_with[0]}")
    digest = hashlib.sha256()
    APP_DIR.mkdir(parents=True, exist_ok=True)
    tmp = APP_DIR / "gfc.apk.part"
    with open(path, "rb") as fin, open(tmp, "wb") as fout:
        for chunk in iter(lambda: fin.read(1024 * 1024), b""):
            digest.update(chunk)
            fout.write(chunk)
    os.chmod(tmp, 0o644)
    release = {"version": version, "size": size, "sha256": digest.hexdigest(),
               "cert_sha256": next(f for f in signed_with if f in allowed),
               "published_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
               "package": os.environ.get("GFC_ANDROID_PACKAGE", "").strip()}
    os.replace(tmp, APK_PATH)
    info_tmp = APP_DIR / "release.json.part"
    info_tmp.write_text(json.dumps(release, indent=2), encoding="utf-8")
    os.replace(info_tmp, INFO_PATH)
    return release


# ---------- HTTP ----------

@router.get("/app/release.json")
def release_json():
    rel = info()
    if not rel:
        return JSONResponse({"published": False}, headers={"Cache-Control": "no-cache"})
    return JSONResponse({"published": True, "url": "/app/gfc.apk", **rel}, headers={"Cache-Control": "no-cache"})


@router.get("/app/gfc.apk")
def download_apk():
    rel = info()
    if not rel:
        raise HTTPException(status_code=404, detail="the Android app isn't published yet")
    return FileResponse(APK_PATH, media_type="application/vnd.android.package-archive",
                        filename=f"GFC-{rel['version']}.apk",
                        headers={"Cache-Control": "no-cache", "X-Content-Type-Options": "nosniff"})


@router.get("/app")
def download_page():
    rel = info()
    e = lambda s: html.escape(str(s), quote=True)  # noqa: E731
    if rel:
        body = f"""<a class="button" href="/app/gfc.apk" download>Download GFC for Android</a>
<p class="meta">Version {e(rel['version'])} &middot; {rel['size'] / 1048576:.0f} MB &middot; {e(rel['published_at'][:10])}</p>
<h2>Installing</h2>
<ol>
<li>Tap <b>Download</b>, then open the file when it finishes.</li>
<li>Android asks to let your browser install apps: allow it for this install.</li>
<li>GFC isn't on Google Play yet, so Play Protect may call it an unrecognised app. It's safe to continue: the checksums below match what this node published.</li>
<li>Updates install over the old version; your account and wallet stay on the network.</li>
</ol>
<p>Android 8 or newer, 64-bit phones. Don't want an app? Everything also works on the
<a href="/web">web feed</a>.</p>
<h2>Checksums</h2>
<p class="hash">APK SHA-256<br><code>{e(rel['sha256'])}</code></p>
<p class="hash">Signing certificate SHA-256<br><code>{e(rel['cert_sha256'])}</code></p>"""
    else:
        body = """<p>The Android app is coming soon. Meanwhile everything works on the <a href="/web">web feed</a>.</p>"""
    nonce = secrets.token_urlsafe(16)
    page = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Get the GFC app</title>
<meta name="description" content="Download the GFC app for Android: post, play and earn GFC.">
<style nonce="{nonce}">
*{{box-sizing:border-box}}
body{{margin:0;font-family:system-ui,-apple-system,"Segoe UI",sans-serif;background:#000;color:#e7e9ea;line-height:1.5}}
main{{max-width:560px;margin:0 auto;padding:32px 16px}}
h1{{margin:0 0 4px;font-size:1.6rem}}
h2{{margin:28px 0 8px;font-size:1.05rem}}
p,li{{color:#a9b0b6}}
.button{{display:block;margin:20px 0 8px;padding:16px;border-radius:999px;background:#3b4fd8;color:#fff;text-align:center;font-weight:700;text-decoration:none;font-size:1.1rem}}
.meta{{margin:0;text-align:center;color:#71767b;font-size:.9rem}}
.hash code{{display:block;margin-top:4px;color:#e7e9ea;font-size:.75rem;overflow-wrap:anywhere}}
a{{color:#7f8ce0}}
</style>
</head>
<body>
<main>
<h1>GFC for Android</h1>
<p>Post music, video, photos and 3D. Earn GFC when people play what you share.</p>
{body}
</main>
</body>
</html>
"""
    csp = (f"default-src 'none'; style-src 'nonce-{nonce}'; base-uri 'none'; "
           "form-action 'none'; frame-ancestors 'none'")
    return HTMLResponse(page, headers={"Content-Security-Policy": csp, "X-Content-Type-Options": "nosniff",
                                       "Cache-Control": "no-cache"})


def _cli(argv: List[str]) -> int:
    try:
        if len(argv) == 3 and argv[0] == "publish":
            rel = publish(argv[1], argv[2])
            print(f"Published GFC {rel['version']} for Android ({rel['size'] / 1048576:.1f} MB)")
            print(f"APK SHA-256: {rel['sha256']}")
            print(f"Signed with the release key {rel['cert_sha256']}")
            print("Download page: /app")
            return 0
        if argv == ["info"]:
            rel = info()
            print(json.dumps(rel, indent=2) if rel else "no Android release published")
            return 0
        if len(argv) == 2 and argv[0] == "fingerprint":
            for f in signing_fingerprints(Path(argv[1])):
                print(f)
            return 0
    except ReleaseError as ex:
        print(f"error: {ex}")
        return 1
    print(__doc__)
    return 2


if __name__ == "__main__":
    raise SystemExit(_cli(sys.argv[1:]))
