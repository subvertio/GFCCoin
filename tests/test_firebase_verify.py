"""
Tests for Firebase phone verification: the ID token check (phone_verify.verify_firebase_token)
and the browser flow (/verify/web/fb/*). firebase_stub's key stands in for Google's signing
key; its certificate is served by a mock in place of Google's cert URL.

Run from the repository root:
    python -m unittest discover -s tests -v
"""

import json
import os
import re
import time
import unittest
import uuid

import httpx

# Sets up the isolated data dir and test treasury key before any GFC module loads config
import test_signed_ledger  # noqa: F401
from test_signed_ledger import as_treasury_node, unique_phone

from fastapi.testclient import TestClient  # noqa: E402

import main  # noqa: E402
import phone_verify  # noqa: E402
from firebase_stub import CONFIG, OTHER_KEY, PROJECT, b64 as _b64, cert_client, make_token  # noqa: E402


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


class FirebaseTestCase(unittest.TestCase):
    def setUp(self):
        self.cert_fetches = 0

        def fetched():
            self.cert_fetches += 1

        phone_verify.set_firebase_client(cert_client(fetched))
        self.addCleanup(phone_verify.set_firebase_client, httpx.Client(timeout=5.0))
        os.environ["GFC_FIREBASE_CONFIG"] = json.dumps(CONFIG)
        self.addCleanup(os.environ.pop, "GFC_FIREBASE_CONFIG", None)


class TokenTests(FirebaseTestCase):
    def assertRejected(self, token):
        with self.assertRaises(phone_verify.FlowError) as cm:
            phone_verify.verify_firebase_token(token)
        self.assertEqual(cm.exception.status, 400)

    def test_valid_token_gives_the_number(self):
        self.assertEqual(phone_verify.verify_firebase_token(make_token("+14155550123")), "+14155550123")

    def test_keys_are_cached(self):
        phone_verify.verify_firebase_token(make_token("+14155550123"))
        phone_verify.verify_firebase_token(make_token("+14155550124"))
        self.assertEqual(self.cert_fetches, 1)

    def test_wrong_signing_key(self):
        self.assertRejected(make_token("+14155550123", key=OTHER_KEY))

    def test_unknown_kid(self):
        self.assertRejected(make_token("+14155550123", key=OTHER_KEY, kid="other-kid"))

    def test_alg_must_be_rs256(self):
        self.assertRejected(make_token("+14155550123", alg="none"))

    def test_tampered_claims(self):
        head, _, sig = make_token("+14155550123").split(".")
        forged = _b64(json.dumps({"aud": PROJECT, "phone_number": "+14155550999"}).encode())
        self.assertRejected(f"{head}.{forged}.{sig}")

    def test_other_project(self):
        self.assertRejected(make_token("+14155550123", aud="someone-else"))
        self.assertRejected(make_token("+14155550123", iss="https://securetoken.google.com/someone-else"))

    def test_expired(self):
        self.assertRejected(make_token("+14155550123", exp=int(time.time()) - 3600))

    def test_old_sign_in(self):
        self.assertRejected(make_token("+14155550123", auth_time=int(time.time()) - 3600))

    def test_must_be_phone_sign_in(self):
        self.assertRejected(make_token("+14155550123", firebase={"sign_in_provider": "anonymous"}))

    def test_needs_a_phone_number(self):
        self.assertRejected(make_token(""))

    def test_garbage(self):
        for token in ("", "abc", "a.b.c", "x" * 9000):
            self.assertRejected(token)

    def test_not_configured(self):
        os.environ.pop("GFC_FIREBASE_CONFIG")
        with self.assertRaises(phone_verify.FlowError) as cm:
            phone_verify.verify_firebase_token(make_token("+14155550123"))
        self.assertEqual(cm.exception.status, 503)

    def test_bad_config_is_off(self):
        os.environ["GFC_FIREBASE_CONFIG"] = "{not json"
        self.assertIsNone(phone_verify.firebase_config())
        os.environ["GFC_FIREBASE_CONFIG"] = json.dumps({"apiKey": "x"})
        self.assertIsNone(phone_verify.firebase_config())

    def test_google_unreachable(self):
        def down(request):
            raise httpx.ConnectError("down")
        phone_verify.set_firebase_client(httpx.Client(transport=httpx.MockTransport(down)))
        with self.assertRaises(phone_verify.FlowError) as cm:
            phone_verify.verify_firebase_token(make_token("+14155550123"))
        self.assertEqual(cm.exception.status, 503)


class WebFlowTests(FirebaseTestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(main.app)

    def register(self):
        name = "f" + uuid.uuid4().hex[:10]
        r = self.client.post("/auth/register", data={"username": name, "password": "pw-" + name})
        self.assertEqual(r.status_code, 200, r.text)
        token = r.json()["token"]
        with as_treasury_node():
            self.assertEqual(self.client.post("/wallets/create", data={"name": "main"},
                                              headers=bearer(token)).status_code, 200)
        return name, token

    def link_code(self, token):
        body = self.client.post("/verify/link", headers=bearer(token)).json()
        return re.search(r"[?&]c=([^&]+)", body["url"]).group(1)

    def test_page_uses_firebase(self):
        _, token = self.register()
        page = self.client.get("/verify", params={"c": self.link_code(token)})
        self.assertEqual(page.status_code, 200)
        self.assertIn('"projectId": "gfc-test"', page.text)
        self.assertIn("signInWithPhoneNumber", page.text)
        csp = page.headers["content-security-policy"]
        nonce = re.search(r"script-src 'nonce-([^']+)'", csp).group(1)
        self.assertIn(f'<script type="module" nonce="{nonce}">', page.text)
        self.assertIn(f"https://{PROJECT}.firebaseapp.com", csp)
        self.assertIn("form-action 'self'", csp)

    def test_full_flow_pays_the_grant(self):
        name, token = self.register()
        code = self.link_code(token)
        phone = unique_phone()
        r = self.client.post("/verify/web/fb/start", data={"c": code, "phone": phone})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json(), {"phone": phone})

        done = self.client.post("/verify/web/fb/check", data={"c": code, "id_token": make_token(phone)})
        self.assertIn("You're verified", done.text)
        self.assertIn("+100 GFC welcome grant", done.text)
        status = self.client.get("/verify/status", headers=bearer(token)).json()
        self.assertTrue(status["verified"])
        self.assertEqual(status["rewards"]["grant"], 100.0)
        # The link is spent
        self.assertIn("expired", self.client.get("/verify", params={"c": code}).text)

    def test_token_for_another_number_is_refused(self):
        _, token = self.register()
        code = self.link_code(token)
        self.client.post("/verify/web/fb/start", data={"c": code, "phone": unique_phone()})
        page = self.client.post("/verify/web/fb/check", data={"c": code, "id_token": make_token(unique_phone())})
        self.assertIn("No verification started for this number", page.text)
        self.assertFalse(self.client.get("/verify/status", headers=bearer(token)).json()["verified"])

    def test_check_without_start_is_refused(self):
        _, token = self.register()
        code = self.link_code(token)
        page = self.client.post("/verify/web/fb/check", data={"c": code, "id_token": make_token(unique_phone())})
        self.assertIn("No verification started", page.text)

    def test_forged_token_is_refused(self):
        _, token = self.register()
        code = self.link_code(token)
        phone = unique_phone()
        self.client.post("/verify/web/fb/start", data={"c": code, "phone": phone})
        page = self.client.post("/verify/web/fb/check",
                                data={"c": code, "id_token": make_token(phone, key=OTHER_KEY)})
        self.assertIn("didn&#x27;t verify", page.text)
        self.assertFalse(self.client.get("/verify/status", headers=bearer(token)).json()["verified"])

    def test_one_account_per_phone(self):
        phone = unique_phone()
        _, first = self.register()
        c1 = self.link_code(first)
        self.client.post("/verify/web/fb/start", data={"c": c1, "phone": phone})
        self.client.post("/verify/web/fb/check", data={"c": c1, "id_token": make_token(phone)})
        _, second = self.register()
        r = self.client.post("/verify/web/fb/start", data={"c": self.link_code(second), "phone": phone})
        self.assertEqual(r.status_code, 409)
        self.assertIn("already verified on another account", r.json()["error"])

    def test_start_is_rate_limited(self):
        _, token = self.register()
        code = self.link_code(token)
        for _ in range(phone_verify.MAX_STARTS_PER_USER):
            self.assertEqual(self.client.post("/verify/web/fb/start",
                                              data={"c": code, "phone": unique_phone()}).status_code, 200)
        r = self.client.post("/verify/web/fb/start", data={"c": code, "phone": unique_phone()})
        self.assertEqual(r.status_code, 429)

    def test_bad_number(self):
        _, token = self.register()
        r = self.client.post("/verify/web/fb/start", data={"c": self.link_code(token), "phone": "12"})
        self.assertEqual(r.status_code, 400)
        self.assertIn("10-digit", r.json()["error"])

    def test_expired_link(self):
        r = self.client.post("/verify/web/fb/start", data={"c": "nope", "phone": unique_phone()})
        self.assertEqual(r.json(), {"reload": True})
        page = self.client.post("/verify/web/fb/check", data={"c": "nope", "id_token": "x"})
        self.assertIn("expired", page.text)

    def test_without_firebase_verification_is_off(self):
        os.environ.pop("GFC_FIREBASE_CONFIG")
        _, token = self.register()
        page = self.client.get("/verify", params={"c": self.link_code(token)})
        self.assertNotIn("signInWithPhoneNumber", page.text)
        self.assertIn("isn't set up", page.text)
        r = self.client.post("/verify/web/fb/start", data={"c": self.link_code(token), "phone": unique_phone()})
        self.assertEqual(r.json(), {"reload": True})


if __name__ == "__main__":
    unittest.main()
