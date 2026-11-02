"""
GFC web app - the GFC app for iPhone (and any browser), served by the node at /app/web/.

Apple doesn't list crypto creator apps like this one, so iPhones get the same app as a web app:
open https://node.galacticfederation.tech/app/web/ in Safari, then Share → Add to Home Screen.
It's the GFC-Tauri front end built with `npm run build:web` (base /app/web/): the same screens,
with web versions of the native parts (files, uploads, downloads; GFC-Tauri src/native.ts).

- GET /app/web/            the app (index.html); any other path under it that isn't a file also
                           gets index.html, so a reload never 404s
- GET /app/web/{file}      its files: assets/ (hashed, cached for a year), manifest, icons, sw.js

Same origin as the API, so no CORS, and the login token it keeps on the phone is only readable by
this origin. Every response carries a strict Content-Security-Policy: scripts only from this
node ('wasm-unsafe-eval' and blob: workers for the bundled 3D decoders), nothing framed, no
plugins, so injected markup can't run script and read that token.

Publishing (on the node, as root, normally `gfc publish-web FILE.zip VERSION`):
    python app_webapp.py publish /tmp/gfc-web-0.2.5.zip 0.2.5
    python app_webapp.py info
The zip is the contents of dist-web/ (index.html at its top level). publish checks it (index.html
present, no paths escaping the folder, no symlinks, a size limit), unpacks it next to the live
copy and swaps the two directories, so a visitor never sees half a release. It lives in
DATA_DIR/app/web/ (not in git, not in backups).
"""

import datetime
import json
import mimetypes
import os
import shutil
import sys
import zipfile
from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse

from config import DATA_DIR

router = APIRouter()

APP_DIR = DATA_DIR / "app"  # as in app_release.py
WEB_DIR = APP_DIR / "web"
INFO_FILE = "release.json"          # inside WEB_DIR: version and when it was published
MAX_ZIP_BYTES = 200 * 1024 * 1024   # the build is ~3 MB; anything near this is a wrong file
MAX_FILES = 2000

CSP = "; ".join([
    "default-src 'self'",
    "script-src 'self' 'wasm-unsafe-eval'",
    "worker-src 'self' blob:",
    "style-src 'self' 'unsafe-inline'",   # the app sets style attributes on its elements
    "img-src 'self' data: blob:",
    "media-src 'self' blob:",
    "connect-src 'self' blob: data:",
    "font-src 'self' data:",
    "manifest-src 'self'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
])
SECURITY_HEADERS = {
    "Content-Security-Policy": CSP,
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
}

mimetypes.add_type("application/manifest+json", ".webmanifest")
mimetypes.add_type("application/wasm", ".wasm")
mimetypes.add_type("text/javascript", ".js")

NOT_PUBLISHED = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>GFC</title></head>
<body style="background:#05010f;color:#e8e6ff;font-family:system-ui,sans-serif;padding:24px">
<h1>GFC for iPhone is coming</h1><p>The web app isn't published on this node yet.
<a style="color:#7df9ff" href="/app">Get the Windows or Android app</a>.</p></body></html>"""


def _headers(path: str) -> dict:
    h = dict(SECURITY_HEADERS)
    if path.startswith("assets/"):
        h["Cache-Control"] = "public, max-age=31536000, immutable"  # hashed names
    else:
        h["Cache-Control"] = "no-cache"  # index.html, sw.js, manifest: always revalidated
    return h


def _resolve(path: str):
    """The file under WEB_DIR for a URL path, or None. Never outside WEB_DIR."""
    root = WEB_DIR.resolve()
    target = (root / path).resolve()
    if root != target and root not in target.parents:
        return None
    return target if target.is_file() else None


def _serve(path: str):
    path = path.lstrip("/")
    f = _resolve(path) if path else None
    if f is None:
        if path.startswith("assets/") or "." in path.rsplit("/", 1)[-1]:
            raise HTTPException(status_code=404, detail="not found")  # a missing file, not a page
        f = _resolve("index.html")
        path = "index.html"
        if f is None:
            return HTMLResponse(NOT_PUBLISHED, status_code=503, headers=_headers(path))
    media = mimetypes.guess_type(f.name)[0] or "application/octet-stream"
    return FileResponse(f, media_type=media, headers=_headers(path))


@router.get("/app/web")
def web_root_redirect():
    return RedirectResponse("/app/web/", status_code=308)  # relative asset URLs need the slash


@router.get("/app/web/")
def web_index():
    return _serve("")


@router.get("/app/web/{path:path}")
def web_file(path: str):
    return _serve(path)


# ---------------------------------------------------------------- publishing

def check_zip(zpath: Path) -> list:
    """The zip's file names if it's a sane build of the web app; ValueError otherwise."""
    if zpath.stat().st_size > MAX_ZIP_BYTES:
        raise ValueError(f"{zpath.name} is {zpath.stat().st_size // 1024 // 1024} MB: not a web app build")
    with zipfile.ZipFile(zpath) as z:
        infos = z.infolist()
        if len(infos) > MAX_FILES:
            raise ValueError(f"{len(infos)} files: not a web app build")
        names = []
        for i in infos:
            n = i.filename
            if n.startswith("/") or "\\" in n or any(part == ".." for part in n.split("/")):
                raise ValueError(f"unsafe path in the zip: {n}")
            if (i.external_attr >> 16) & 0o170000 == 0o120000:
                raise ValueError(f"symlink in the zip: {n}")
            if not n.endswith("/"):
                names.append(n)
    if "index.html" not in names:
        raise ValueError("index.html isn't at the top of the zip: zip the contents of dist-web/, not the folder")
    if not any(n.startswith("assets/") for n in names):
        raise ValueError("no assets/ folder: is this `npm run build:web` output?")
    return names


def publish(zpath: Path, version: str) -> dict:
    names = check_zip(zpath)
    APP_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d%H%M%S")
    staging = APP_DIR / f"web.new-{stamp}"
    old = APP_DIR / f"web.old-{stamp}"
    with zipfile.ZipFile(zpath) as z:
        z.extractall(staging)
    info = {"version": version, "published": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "files": len(names)}
    (staging / INFO_FILE).write_text(json.dumps(info))
    if WEB_DIR.exists():
        os.replace(WEB_DIR, old)
    os.replace(staging, WEB_DIR)
    shutil.rmtree(old, ignore_errors=True)
    return info


def main(argv) -> int:
    if len(argv) == 3 and argv[0] == "publish":
        try:
            info = publish(Path(argv[1]), argv[2])
        except (ValueError, zipfile.BadZipFile, OSError) as e:
            print(f"Not published: {e}", file=sys.stderr)
            return 1
        print(f"Published GFC web app {info['version']} ({info['files']} files)")
        print("Open on iPhone: https://node.galacticfederation.tech/app/web/  (Share → Add to Home Screen)")
        return 0
    if argv == ["info"]:
        f = WEB_DIR / INFO_FILE
        print(f.read_text() if f.exists() else "not published")
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
