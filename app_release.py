"""
GFC app downloads - the Android APK and the Windows installer, straight from the node.

- GET /app               download page: both apps, version, size, date, checksums, how to install
- GET /app/gfc.apk       the APK itself (Range supported, so big downloads resume)
- GET /app/release.json  version, size, SHA-256 and signing certificate, for clients that
                         check for updates
- GET /app/windows       the Windows installer (the .exe, or the .zip holding it)
- GET /app/windows.json  its version, size and SHA-256
- GET /app/windows/update.json  the app's own update check (Tauri updater format): version, the
                         installer's URL and its updater signature; 204 when nothing is signed
- GET /app/windows/update.exe   the signed installer the app downloads to update itself

Publishing (on the node, as root, normally through `gfc publish-app FILE VERSION` and
`gfc publish-windows FILE VERSION`):
    python app_release.py publish /tmp/gfc.apk 0.1.0
    python app_release.py publish-windows /tmp/GFC-Setup-0.1.0-Windows.zip 0.1.0 [/tmp/setup.exe.sig]
    python app_release.py info

publish refuses an APK unless its signing certificate is one of GFC_ANDROID_CERT_SHA256 (the
release key, also used for App Links). So a development build, signed with Unreal's debug key,
can't be published by mistake: phones that installed it could never take a release update.
This reads the certificate from the APK Signature Scheme v2/v3 block (or the v1 JAR signature);
Android itself checks the signature when installing.

The Windows installer isn't code-signed yet, so there's no Authenticode signature to check:
publish-windows checks that it's a Windows program (or a zip holding exactly one), so a wrong file
can't go out by mistake. Its SHA-256 is shown on the download page.

Self-updates: the app (Tauri's updater) only installs an update signed with the updater key, whose
public half is built into the app and set on the node as GFC_UPDATER_PUBKEY (the contents of
gfc-updater.key.pub). With that set, publish-windows needs the installer's .sig (made by the
build) and refuses one that doesn't verify, so a bad publish can't break every app's updates.

Both live in DATA_DIR/app/ (not in git, not in backups); a publish replaces them atomically.
"""

import base64
import binascii
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
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import pkcs7
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response

from config import DATA_DIR

router = APIRouter()

APP_DIR = DATA_DIR / "app"
APK_PATH = APP_DIR / "gfc.apk"
INFO_PATH = APP_DIR / "release.json"
MAX_APK_BYTES = 512 * 1024 * 1024
WINDOWS_INFO_PATH = APP_DIR / "windows.json"
WINDOWS_UPDATE_PATH = APP_DIR / "gfc-windows-update.exe"  # the bare installer, for self-updates
WINDOWS_EXTENSIONS = (".exe", ".zip")
MAX_WINDOWS_BYTES = 1024 * 1024 * 1024
SITE_URL = "https://galacticfederation.tech"
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


# ---------- Windows ----------

def _windows_path(ext: str) -> Path:
    return APP_DIR / f"gfc-windows{ext}"


def windows_info() -> Optional[dict]:
    """The published Windows installer, or None."""
    try:
        data = json.loads(WINDOWS_INFO_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    ext = data.get("ext")
    return data if ext in WINDOWS_EXTENSIONS and _windows_path(ext).is_file() else None


def _is_windows_program(head: bytes) -> bool:
    return head[:2] == b"MZ"


def _check_windows_file(path: Path) -> str:
    """The file's kind (.exe or .zip) if it's a Windows installer, else ReleaseError."""
    ext = path.suffix.lower()
    if ext not in WINDOWS_EXTENSIONS:
        raise ReleaseError("the Windows installer should be the .exe or the .zip holding it")
    if ext == ".exe":
        with open(path, "rb") as f:
            if not _is_windows_program(f.read(2)):
                raise ReleaseError("that .exe isn't a Windows program")
        return ext
    try:
        with zipfile.ZipFile(path) as zf:
            entries = [i for i in zf.infolist() if not i.is_dir()]
            if len(entries) != 1 or not entries[0].filename.lower().endswith(".exe"):
                raise ReleaseError("the zip should hold just the installer (one .exe)")
            with zf.open(entries[0]) as f:
                if not _is_windows_program(f.read(2)):
                    raise ReleaseError("the .exe in that zip isn't a Windows program")
    except zipfile.BadZipFile:
        raise ReleaseError("that .zip can't be read")
    return ext


def _b64(text: str) -> bytes:
    try:
        return base64.b64decode(text.strip(), validate=True)
    except (binascii.Error, ValueError):
        raise ReleaseError("the updater signature or key isn't valid base64")


def verify_updater_signature(data, signature: str, pubkey: str) -> None:
    """
    Check a Tauri updater signature (a base64 minisign signature file) over data (bytes or a
    binary file object) with the updater public key (the base64 .pub file). ReleaseError if not.
    """
    try:
        key = _b64(_b64(pubkey).decode().strip().splitlines()[-1])
        lines = _b64(signature).decode().strip().splitlines()
        sig_blob, trusted, global_sig = _b64(lines[1]), lines[2], _b64(lines[3])
    except (IndexError, UnicodeDecodeError):
        raise ReleaseError("the updater signature or key is malformed")
    if len(key) != 42 or key[:2] != b"Ed" or len(sig_blob) != 74 or len(global_sig) != 64 \
            or not trusted.startswith("trusted comment: "):
        raise ReleaseError("the updater signature or key is malformed")
    if sig_blob[2:10] != key[2:10]:
        raise ReleaseError("the installer was signed with a different updater key")
    if sig_blob[:2] == b"ED":  # prehashed: the signature covers the file's BLAKE2b-512
        h = hashlib.blake2b(digest_size=64)
        if isinstance(data, (bytes, bytearray)):
            h.update(data)
        else:
            for chunk in iter(lambda: data.read(1024 * 1024), b""):
                h.update(chunk)
        message = h.digest()
    elif sig_blob[:2] == b"Ed":
        message = data if isinstance(data, (bytes, bytearray)) else data.read()
    else:
        raise ReleaseError("unknown updater signature algorithm")
    pk = Ed25519PublicKey.from_public_bytes(key[10:])
    try:
        pk.verify(sig_blob[10:], message)
        pk.verify(global_sig, sig_blob[10:] + trusted[len("trusted comment: "):].encode())
    except InvalidSignature:
        raise ReleaseError("the updater signature doesn't match this installer")


def _installer_stream(path: Path, ext: str):
    """The installer .exe itself: the file, or the one inside the zip."""
    if ext == ".exe":
        return open(path, "rb")
    zf = zipfile.ZipFile(path)
    return zf.open([i for i in zf.infolist() if not i.is_dir()][0])


def publish_windows(src: str, version: str, signature: str = "") -> dict:
    """
    Check src is a Windows installer (or a zip of one), then make it the public download. With
    the updater signature of the installer (the .sig's contents), it's also offered to the apps
    as a self-update; that's required once GFC_UPDATER_PUBKEY is set.
    """
    path = Path(src)
    if not path.is_file():
        raise ReleaseError(f"no such file: {src}")
    if not VERSION_RE.match(version or ""):
        raise ReleaseError("version should look like 0.1.0 (letters, digits, . + -)")
    size = path.stat().st_size
    if not 1024 < size <= MAX_WINDOWS_BYTES:
        raise ReleaseError("that file is too small or too big to be the GFC installer")
    ext = _check_windows_file(path)
    pubkey = os.environ.get("GFC_UPDATER_PUBKEY", "").strip()
    signature = (signature or "").strip()
    if pubkey and not signature:
        raise ReleaseError("apps update themselves from this download: give the installer's .sig too "
                           "(gfc publish-windows FILE VERSION SIGFILE)")
    if signature:
        if not pubkey:
            raise ReleaseError("set GFC_UPDATER_PUBKEY (gfc config) before publishing a signed update")
        with _installer_stream(path, ext) as f:
            verify_updater_signature(f, signature, pubkey)
    digest = hashlib.sha256()
    APP_DIR.mkdir(parents=True, exist_ok=True)
    tmp = APP_DIR / f"gfc-windows{ext}.part"
    with open(path, "rb") as fin, open(tmp, "wb") as fout:
        for chunk in iter(lambda: fin.read(1024 * 1024), b""):
            digest.update(chunk)
            fout.write(chunk)
    os.chmod(tmp, 0o644)
    release = {"version": version, "size": size, "sha256": digest.hexdigest(), "ext": ext,
               "published_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")}
    if signature:
        update_tmp = APP_DIR / "gfc-windows-update.exe.part"
        with _installer_stream(path, ext) as fin, open(update_tmp, "wb") as fout:
            for chunk in iter(lambda: fin.read(1024 * 1024), b""):
                fout.write(chunk)
        os.chmod(update_tmp, 0o644)
        os.replace(update_tmp, WINDOWS_UPDATE_PATH)
        release["updater_signature"] = signature
    elif WINDOWS_UPDATE_PATH.exists():
        WINDOWS_UPDATE_PATH.unlink()  # an unsigned release isn't offered as an update
    os.replace(tmp, _windows_path(ext))
    for other in WINDOWS_EXTENSIONS:  # a .zip replacing an .exe (or the reverse) leaves no stale file
        if other != ext and _windows_path(other).exists():
            _windows_path(other).unlink()
    info_tmp = APP_DIR / "windows.json.part"
    info_tmp.write_text(json.dumps(release, indent=2), encoding="utf-8")
    os.replace(info_tmp, WINDOWS_INFO_PATH)
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


@router.get("/app/windows.json")
def windows_json():
    rel = windows_info()
    if not rel:
        return JSONResponse({"published": False}, headers={"Cache-Control": "no-cache"})
    return JSONResponse({"published": True, "url": "/app/windows", **rel}, headers={"Cache-Control": "no-cache"})


@router.get("/app/windows/update.json")
def windows_update(request: Request):
    """Tauri's updater manifest. 204 (no update) when the release isn't signed for updates."""
    rel = windows_info()
    if not rel or not rel.get("updater_signature") or not WINDOWS_UPDATE_PATH.is_file():
        return Response(status_code=204, headers={"Cache-Control": "no-cache"})
    from app_share import public_base_url  # app_share imports this module
    base = (public_base_url() if os.environ.get("GFC_PUBLIC_BASE_URL", "").strip()
            else str(request.base_url).rstrip("/"))
    return JSONResponse({
        "version": rel["version"],
        "notes": f"GFC {rel['version']}",
        "pub_date": rel["published_at"],
        "platforms": {"windows-x86_64": {"signature": rel["updater_signature"],
                                         "url": f"{base}/app/windows/update.exe"}},
    }, headers={"Cache-Control": "no-cache"})


@router.get("/app/windows/update.exe")
def windows_update_exe():
    rel = windows_info()
    if not rel or not rel.get("updater_signature") or not WINDOWS_UPDATE_PATH.is_file():
        raise HTTPException(status_code=404, detail="no signed Windows update is published")
    return FileResponse(WINDOWS_UPDATE_PATH, media_type="application/vnd.microsoft.portable-executable",
                        filename=f"GFC-Setup-{rel['version']}.exe",
                        headers={"Cache-Control": "no-cache", "X-Content-Type-Options": "nosniff"})


@router.get("/app/windows")
def download_windows():
    rel = windows_info()
    if not rel:
        raise HTTPException(status_code=404, detail="the Windows app isn't published yet")
    media = "application/zip" if rel["ext"] == ".zip" else "application/vnd.microsoft.portable-executable"
    return FileResponse(_windows_path(rel["ext"]), media_type=media,
                        filename=f"GFC-Setup-{rel['version']}-Windows{rel['ext']}",
                        headers={"Cache-Control": "no-cache", "X-Content-Type-Options": "nosniff"})


def _android_section(rel: Optional[dict]) -> str:
    """The Android download and step-by-step install (APKs from outside Google Play take a few taps)."""
    e = lambda s: html.escape(str(s), quote=True)  # noqa: E731
    if not rel:
        return """<h2 id="android">Android</h2>
<p>The Android app is coming soon. Meanwhile everything works on the <a href="/web">web feed</a>.</p>"""
    return f"""<h2 id="android">Android</h2>
<a class="button" href="/app/gfc.apk" download>Download GFC for Android</a>
<p class="meta">Version {e(rel['version'])} &middot; {rel['size'] / 1048576:.0f} MB &middot; {e(rel['published_at'][:10])}</p>
<p class="tip"><b>Opened this from X or another app?</b> Downloads may not start there. Tap the
<b>&#8942;</b> or <b>&middot;&middot;&middot;</b> menu, choose <b>Open in browser</b> (Chrome), then tap Download.</p>
<h2>How to install it</h2>
<ol class="steps">
<li><b>Tap Download GFC for Android.</b> If Chrome asks whether to keep the file, tap <b>Download</b> (or <b>Download anyway</b>).</li>
<li><b>Open the file</b> when it finishes: tap <b>Open</b> in the message at the bottom, or find
<b>GFC-{e(rel['version'])}.apk</b> in your notifications or the <b>Downloads</b> folder of the Files app.</li>
<li><b>Allow the install.</b> The first time, Android says your browser isn't allowed to install apps:
tap <b>Settings</b>, turn on <b>Allow from this source</b>, then go back.</li>
<li><b>Tap Install.</b> GFC isn't on Google Play yet, so Play Protect may call it an unrecognised app:
tap <b>More details</b>, then <b>Install anyway</b>. The checksums below match what this node published.</li>
<li><b>Open GFC</b> and create your account. You get 1,100 GFC for signing up and your first post.</li>
</ol>
<p>Updates install the same way, over the old version: your account and wallet stay on the network.</p>
<p>Android 8 or newer, 64-bit phones. Don't want an app? Everything also works on the
<a href="/web">web feed</a>.</p>
<h2>Checksums</h2>
<p class="hash">APK SHA-256<br><code>{e(rel['sha256'])}</code></p>
<p class="hash">Signing certificate SHA-256<br><code>{e(rel['cert_sha256'])}</code></p>"""


@router.get("/app/android")
def android_page():
    """Where every "Get GFC for Android" button goes: the download plus how to install it."""
    body = _android_section(info()) + """
<p class="site">Using Windows? <a href="/app#windows">Get GFC for Windows</a></p>"""
    return _page("Get GFC for Android", "Download and install the GFC app on your Android phone.", body)


@router.get("/app")
def download_page():
    win = windows_info()
    e = lambda s: html.escape(str(s), quote=True)  # noqa: E731
    body = _android_section(info())
    if win:
        zipped = win["ext"] == ".zip"
        first_step = ("<li>Open the downloaded .zip and run the GFC-Setup file inside it.</li>" if zipped
                      else "<li>Run the downloaded GFC-Setup file.</li>")
        body += f"""
<h2 id="windows">Windows</h2>
<a class="button" href="/app/windows" download>Download GFC for Windows</a>
<p class="meta">Version {e(win['version'])} &middot; {win['size'] / 1048576:.0f} MB &middot; {e(win['published_at'][:10])}</p>
<ol>
{first_step}
<li>The installer isn't code-signed yet, so Windows SmartScreen may warn about it. Choose <b>More info</b>, then <b>Run anyway</b>: the checksum below matches what this node published.</li>
<li>Updates install over the old version; your account and wallet stay on the network.</li>
</ol>
<p>Windows 10 or 11, 64-bit.</p>
<p class="hash">{"Zip" if zipped else "Installer"} SHA-256<br><code>{e(win['sha256'])}</code></p>"""
    else:
        body += """
<h2 id="windows">Windows</h2>
<p>The Windows app is coming soon.</p>"""
    return _page("Get the GFC app", "Download the GFC app for Android and Windows: post, play and earn GFC.", body)


def _page(title: str, description: str, body: str) -> HTMLResponse:
    body += f"""
<p class="site">Learn more about GFC at <a href="{SITE_URL}" rel="noopener">GalacticFederation.tech</a></p>"""
    nonce = secrets.token_urlsafe(16)
    page = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)}</title>
<meta name="description" content="{html.escape(description, quote=True)}">
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
.site{{margin-top:32px;text-align:center}}
.tip{{margin:16px 0 0;padding:12px 14px;border:1px solid #2f3336;border-radius:12px;background:#15181c}}
.steps li{{margin:0 0 10px}}
.steps b,.tip b{{color:#e7e9ea}}
a{{color:#7f8ce0}}
</style>
</head>
<body>
<main>
<h1>{html.escape(title)}</h1>
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
        if len(argv) in (3, 4) and argv[0] == "publish-windows":
            sig = Path(argv[3]).read_text(encoding="utf-8") if len(argv) == 4 else ""
            rel = publish_windows(argv[1], argv[2], sig)
            print(f"Published GFC {rel['version']} for Windows ({rel['size'] / 1048576:.1f} MB, {rel['ext']})")
            print(f"SHA-256: {rel['sha256']}")
            print("Apps update themselves to it" if rel.get("updater_signature")
                  else "Not offered as a self-update (no updater signature)")
            print("Download: /app/windows  (page: /app#windows)")
            return 0
        if argv == ["info"]:
            rel = info()
            print(json.dumps(rel, indent=2) if rel else "no Android release published")
            win = windows_info()
            print(json.dumps(win, indent=2) if win else "no Windows release published")
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
