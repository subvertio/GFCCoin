"""
Firebase phone sign-in for tests: a key generated here stands in for Google's signing key, and
its certificate is served by a mock in place of Google's cert URL. verify_phone() verifies an
account the way the browser page does (/verify/link, then /verify/web/fb/start and /check).

Import test_signed_ledger first: it sets up the isolated data dir before GFC modules load.
"""

import base64
import contextlib
import datetime
import json
import os
import re
import time
import uuid

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

import phone_verify

PROJECT = "gfc-test"
CONFIG = {"apiKey": "AIzaTestKey", "authDomain": f"{PROJECT}.firebaseapp.com", "projectId": PROJECT,
          "appId": "1:1:web:1"}


def _keypair(kid):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, kid)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=1)).sign(key, hashes.SHA256()))
    return key, cert.public_bytes(serialization.Encoding.PEM).decode()


GOOGLE_KEY, GOOGLE_CERT = _keypair("google-kid")
OTHER_KEY, _ = _keypair("other-kid")


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def make_token(phone, key=GOOGLE_KEY, kid="google-kid", alg="RS256", **overrides):
    """A Firebase ID token for a phone sign-in to `phone` just now, signed with `key`."""
    now = int(time.time())
    claims = {"iss": f"https://securetoken.google.com/{PROJECT}", "aud": PROJECT, "sub": uuid.uuid4().hex,
              "iat": now, "exp": now + 3600, "auth_time": now, "phone_number": phone,
              "firebase": {"sign_in_provider": "phone", "identities": {"phone": [phone]}}}
    claims.update(overrides)
    head = b64(json.dumps({"alg": alg, "kid": kid, "typ": "JWT"}).encode())
    body = b64(json.dumps(claims).encode())
    sig = key.sign(f"{head}.{body}".encode(), padding.PKCS1v15(), hashes.SHA256())
    return f"{head}.{body}.{b64(sig)}"


def cert_client(on_fetch=None) -> httpx.Client:
    """An HTTP client that answers Google's cert URL with GOOGLE_CERT."""
    def certs(request):
        if on_fetch:
            on_fetch()
        return httpx.Response(200, json={"google-kid": GOOGLE_CERT},
                              headers={"cache-control": "public, max-age=19000, must-revalidate"})
    return httpx.Client(transport=httpx.MockTransport(certs))


@contextlib.contextmanager
def enabled():
    """Firebase configured for the test project, with the stand-in key, until the block ends."""
    saved = os.environ.get("GFC_FIREBASE_CONFIG")
    os.environ["GFC_FIREBASE_CONFIG"] = json.dumps(CONFIG)
    phone_verify.set_firebase_client(cert_client())
    try:
        yield
    finally:
        phone_verify.set_firebase_client(httpx.Client(timeout=5.0))
        if saved is None:
            os.environ.pop("GFC_FIREBASE_CONFIG", None)
        else:
            os.environ["GFC_FIREBASE_CONFIG"] = saved


def link_code(client, token) -> str:
    body = client.post("/verify/link", headers={"Authorization": f"Bearer {token}"}).json()
    return re.search(r"[?&]c=([^&]+)", body["url"]).group(1)


def start(client, token, phone):
    """/verify/web/fb/start for the account with this API token (a fresh link each time)."""
    with enabled():
        return client.post("/verify/web/fb/start", data={"c": link_code(client, token), "phone": phone})


def verify_phone(client, token, phone):
    """Verify the account with this API token on `phone`, as the browser page does. Returns the last page."""
    with enabled():
        code = link_code(client, token)
        r = client.post("/verify/web/fb/start", data={"c": code, "phone": phone})
        if r.status_code != 200:
            return r
        return client.post("/verify/web/fb/check", data={"c": code, "id_token": make_token(r.json()["phone"])})
