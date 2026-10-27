"""
GFC Play Integrity - checks that an Echo Hunt submission came from the genuine
GFC Android app, installed from Google Play, on a real device.

- A verifier decodes an integrity token into Google's verdict payload:
  GoogleIntegrityVerifier calls decodeIntegrityToken with a service account
  (GFC_PLAY_INTEGRITY_SA_FILE) for the package in GFC_ANDROID_PACKAGE.
  FakeIntegrityVerifier is used in tests and when unconfigured.
- check_verdict() is pure: it requires PLAY_RECOGNIZED, MEETS_DEVICE_INTEGRITY,
  the right package, and a requestHash (or nonce) equal to the Echo Hunt
  challenge id, so a token can't be replayed for another challenge.
- When unconfigured, the check is skipped (warned once). Third-party front ends
  can never pass it; on nodes that require it they can't earn Echo Hunt passes
  and rely on phone verification alone for anything not gated on Echo Hunt.
"""

import base64
import json
import os
import secrets
import threading
import time
from typing import Optional

import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

DECODE_URL = "https://playintegrity.googleapis.com/v1/{package}:decodeIntegrityToken"
TOKEN_URL = "https://oauth2.googleapis.com/token"
SCOPE = "https://www.googleapis.com/auth/playintegrity"

# A token must be requested after its challenge was issued (allowing for clock skew)
CLOCK_SKEW_MS = 30_000


class IntegrityError(Exception):
    """The token could not be decoded or the verdict is not good enough."""


# ============================================================================
# VERDICT (pure)
# ============================================================================

def check_verdict(payload: dict, package_name: str, expected_request_hash: str,
                  not_before_ms: Optional[int] = None) -> Optional[str]:
    """Why a decoded tokenPayloadExternal is not acceptable (None if it is)."""
    if not isinstance(payload, dict):
        return "malformed verdict"
    request = payload.get("requestDetails") or {}
    app = payload.get("appIntegrity") or {}
    device = payload.get("deviceIntegrity") or {}

    if request.get("requestPackageName") != package_name:
        return "wrong package"
    # Standard requests carry requestHash, classic requests carry nonce
    bound = request.get("requestHash") or request.get("nonce") or ""
    if not expected_request_hash or not secrets.compare_digest(str(bound), expected_request_hash):
        return "request hash does not match the challenge"
    if not_before_ms is not None:
        try:
            ts = int(request.get("timestampMillis"))
        except (TypeError, ValueError):
            return "missing request timestamp"
        if ts < not_before_ms - CLOCK_SKEW_MS:
            return "token requested before the challenge"
    if app.get("appRecognitionVerdict") != "PLAY_RECOGNIZED":
        return "app not recognized by Play"
    if "MEETS_DEVICE_INTEGRITY" not in (device.get("deviceRecognitionVerdict") or []):
        return "device integrity not met"
    return None


# ============================================================================
# VERIFIERS
# ============================================================================

class FakeIntegrityVerifier:
    """
    In-memory verifier. issue() mints a token for a payload; decode() returns it.
    `enforced` says whether a passing verdict is required (False when the node
    is simply unconfigured, True in tests that exercise the requirement).
    """
    name = "fake"

    def __init__(self, package_name: str = "tech.galacticfederation.gfc", enforced: bool = False):
        self.package_name = package_name
        self.enforced = enforced
        self.tokens = {}

    def issue(self, request_hash: str, timestamp_ms: Optional[int] = None, app_verdict: str = "PLAY_RECOGNIZED",
              device_verdicts=("MEETS_DEVICE_INTEGRITY",), package_name: Optional[str] = None) -> str:
        token = "fake-integrity-" + secrets.token_urlsafe(16)
        self.tokens[token] = {
            "requestDetails": {
                "requestPackageName": package_name or self.package_name,
                "requestHash": request_hash,
                "timestampMillis": str(timestamp_ms if timestamp_ms is not None else int(time.time() * 1000)),
            },
            "appIntegrity": {"appRecognitionVerdict": app_verdict, "packageName": package_name or self.package_name},
            "deviceIntegrity": {"deviceRecognitionVerdict": list(device_verdicts)},
        }
        return token

    def decode(self, token: str) -> dict:
        if token not in self.tokens:
            raise IntegrityError("unknown integrity token")
        return self.tokens[token]


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class GoogleIntegrityVerifier:
    """
    Calls Google's decodeIntegrityToken. The service account (a JSON key file
    from Google Cloud, linked to the app in Play Console) signs an OAuth JWT
    with RS256; the access token is cached until shortly before it expires.
    """
    name = "google"
    enforced = True

    def __init__(self, sa_file: str, package_name: str, timeout: float = 10.0):
        with open(sa_file) as f:
            sa = json.load(f)
        self.client_email = sa["client_email"]
        self.token_uri = sa.get("token_uri") or TOKEN_URL
        self._key = serialization.load_pem_private_key(sa["private_key"].encode(), password=None)
        self.package_name = package_name
        self.client = httpx.Client(timeout=timeout)
        self._access_token = None
        self._access_expiry = 0.0
        self._lock = threading.Lock()

    def _assertion(self) -> str:
        now = int(time.time())
        header = {"alg": "RS256", "typ": "JWT"}
        claims = {"iss": self.client_email, "scope": SCOPE, "aud": self.token_uri, "iat": now, "exp": now + 3600}
        signing_input = (_b64url(json.dumps(header).encode()) + "." + _b64url(json.dumps(claims).encode())).encode()
        signature = self._key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
        return signing_input.decode() + "." + _b64url(signature)

    def _bearer(self) -> str:
        with self._lock:
            if self._access_token and time.time() < self._access_expiry - 60:
                return self._access_token
            try:
                r = self.client.post(self.token_uri, data={
                    "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                    "assertion": self._assertion(),
                })
            except httpx.HTTPError as ex:
                raise IntegrityError(f"Google OAuth unreachable: {type(ex).__name__}")
            if r.status_code >= 400:
                raise IntegrityError(f"Google OAuth error ({r.status_code})")
            body = r.json()
            self._access_token = body["access_token"]
            self._access_expiry = time.time() + float(body.get("expires_in", 3600))
            return self._access_token

    def decode(self, token: str) -> dict:
        try:
            r = self.client.post(DECODE_URL.format(package=self.package_name),
                                 headers={"Authorization": f"Bearer {self._bearer()}"},
                                 json={"integrity_token": token})
        except httpx.HTTPError as ex:
            raise IntegrityError(f"Play Integrity unreachable: {type(ex).__name__}")
        if r.status_code == 400:
            raise IntegrityError("invalid integrity token")
        if r.status_code >= 400:
            raise IntegrityError(f"Play Integrity error ({r.status_code})")
        return (r.json() or {}).get("tokenPayloadExternal") or {}


_verifier = None
_warned = False


def is_configured() -> bool:
    return bool(os.environ.get("GFC_PLAY_INTEGRITY_SA_FILE") and os.environ.get("GFC_ANDROID_PACKAGE"))


def get_verifier():
    """Google's verifier when configured, else a non-enforcing fake (logged once)."""
    global _verifier, _warned
    if _verifier is None:
        if is_configured():
            _verifier = GoogleIntegrityVerifier(os.environ["GFC_PLAY_INTEGRITY_SA_FILE"],
                                                os.environ["GFC_ANDROID_PACKAGE"])
        else:
            if not _warned:
                print("[PlayIntegrity] GFC_PLAY_INTEGRITY_SA_FILE / GFC_ANDROID_PACKAGE not set: "
                      "skipping the Play Integrity check for Echo Hunt")
                _warned = True
            _verifier = FakeIntegrityVerifier(enforced=False)
    return _verifier


def set_verifier(verifier):
    """Replace the verifier (tests). None goes back to the environment's choice."""
    global _verifier
    _verifier = verifier


def verify(token: str, challenge_id: str, issued_ms: Optional[int] = None) -> Optional[str]:
    """
    Why this submission fails Play Integrity (None if it passes, or if the node
    doesn't enforce it).
    """
    verifier = get_verifier()
    if not verifier.enforced:
        return None
    if not token:
        return "play integrity token required"
    try:
        payload = verifier.decode(token)
    except IntegrityError as ex:
        return str(ex)
    return check_verdict(payload, verifier.package_name, challenge_id, issued_ms)
