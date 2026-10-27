"""
Tests for phone verification in a browser (app_webverify.py): the one-time link the app
opens, the Turnstile + SMS pages, and the rewards paid at the end.

Run from the repository root:
    python -m unittest discover -s tests -v
"""

import os
import re
import sqlite3
import unittest
import uuid

import httpx

# Sets up the isolated data dir and test treasury key before any GFC module loads config
import test_signed_ledger  # noqa: F401
from test_signed_ledger import FAKE_SMS, as_treasury_node, unique_phone

from fastapi.testclient import TestClient  # noqa: E402

import app_webverify  # noqa: E402
import main  # noqa: E402
import phone_verify  # noqa: E402

TURNSTILE_PASS_SECRET = "1x0000000000000000000000000000000AA"
TURNSTILE_FAIL_SECRET = "2x0000000000000000000000000000000AA"


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


class WebVerifyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(main.app)

    def setUp(self):
        def siteverify(request):
            form = dict(httpx.QueryParams(request.content.decode()))
            ok = form.get("secret") == TURNSTILE_PASS_SECRET and bool(form.get("response"))
            return httpx.Response(200, json={"success": ok})

        phone_verify.set_turnstile_client(httpx.Client(transport=httpx.MockTransport(siteverify)))
        self.addCleanup(phone_verify.set_turnstile_client, httpx.Client(timeout=5.0))
        for var in ("GFC_TURNSTILE_SECRET", "GFC_TURNSTILE_SITEKEY"):
            self.addCleanup(os.environ.pop, var, None)

    def register(self, wallet=True):
        name = "w" + uuid.uuid4().hex[:10]
        r = self.client.post("/auth/register", data={"username": name, "password": "pw-" + name})
        self.assertEqual(r.status_code, 200, r.text)
        token = r.json()["token"]
        if wallet:
            with as_treasury_node():
                self.assertEqual(self.client.post("/wallets/create", data={"name": "main"},
                                                  headers=bearer(token)).status_code, 200)
        return name, token

    def link_code(self, token):
        r = self.client.post("/verify/link", headers=bearer(token))
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        self.assertFalse(body["verified"])
        self.assertEqual(body["expires_in"], 900)
        return re.search(r"[?&]c=([^&]+)", body["url"]).group(1)

    def test_full_flow_pays_the_grant(self):
        os.environ["GFC_TURNSTILE_SECRET"] = TURNSTILE_PASS_SECRET
        os.environ["GFC_TURNSTILE_SITEKEY"] = "1x00000000000000000000AA"
        name, token = self.register()
        before = self.client.get("/verify/status", headers=bearer(token)).json()
        self.assertFalse(before["verified"])
        self.assertEqual(before["rewards"], {"grant": 0.0, "first_post_bonus": 0.0})
        self.assertEqual(len(before["wallets"]), 1)  # the wallet register() made
        code = self.link_code(token)

        page = self.client.get("/verify", params={"c": code})
        self.assertEqual(page.status_code, 200)
        self.assertIn(f"@{name}", page.text)
        self.assertIn('data-sitekey="1x00000000000000000000AA"', page.text)
        csp = page.headers["content-security-policy"]
        self.assertIn("script-src https://challenges.cloudflare.com", csp)
        self.assertIn("form-action 'self'", csp)
        self.assertEqual(page.headers["referrer-policy"], "no-referrer")
        self.assertEqual(page.headers["cache-control"], "no-store")

        phone = unique_phone()
        with as_treasury_node():
            # Without the Turnstile token: no SMS, the phone step again with a hint
            r = self.client.post("/verify/web/start", data={"c": code, "phone": phone})
            self.assertIn("complete the check", r.text)
            self.assertNotIn(phone, FAKE_SMS.sent)

            r = self.client.post("/verify/web/start", data={"c": code, "phone": phone,
                                                             "cf-turnstile-response": "XXXX.DUMMY"})
            self.assertIn("Enter the code", r.text)
            self.assertIn(phone, FAKE_SMS.sent)

            r = self.client.post("/verify/web/check", data={"c": code, "phone": phone, "code": "000000"})
            self.assertIn("Check the text and try again", r.text)

            r = self.client.post("/verify/web/check", data={"c": code, "phone": phone,
                                                             "code": FAKE_SMS.sent[phone]})
        self.assertIn("You're verified", r.text)
        self.assertIn("welcome grant", r.text)
        self.assertIn("gfc://verified", r.text)
        after = self.client.get("/verify/status", headers=bearer(token)).json()
        self.assertTrue(after["verified"])
        self.assertEqual(after["rewards"]["grant"], 100.0)  # what verifying paid, for the app's coin burst
        self.assertEqual(after["wallets"], before["wallets"])

        # The link is used up, and a new one isn't needed
        self.assertIn("expired", self.client.get("/verify", params={"c": code}).text)
        self.assertEqual(self.client.post("/verify/link", headers=bearer(token)).json(), {"verified": True, "url": ""})

    def test_new_link_replaces_the_old_one(self):
        _, token = self.register(wallet=False)
        first = self.link_code(token)
        second = self.link_code(token)
        self.assertIsNone(app_webverify.link_user(first))
        self.assertIsNotNone(app_webverify.link_user(second))

    def test_expired_and_bogus_links(self):
        _, token = self.register(wallet=False)
        code = self.link_code(token)
        conn = sqlite3.connect(main.DB_PATH)
        conn.execute("UPDATE verify_links SET expires_at = '2000-01-01T00:00:00+00:00'")
        conn.commit()
        conn.close()
        for c in (code, "", "x" * 100):
            r = self.client.get("/verify", params={"c": c})
            self.assertEqual(r.status_code, 200)
            self.assertIn("expired", r.text)
        r = self.client.post("/verify/web/start", data={"c": code, "phone": unique_phone(),
                                                         "cf-turnstile-response": "t"})
        self.assertIn("expired", r.text)

    def test_refused_check_says_why(self):
        # The widget can show "Success!" and Cloudflare still refuse the token (an expired token, or a
        # site key and secret from different widgets): the page shouldn't tell them to do the check
        os.environ["GFC_TURNSTILE_SECRET"] = TURNSTILE_PASS_SECRET
        os.environ["GFC_TURNSTILE_SITEKEY"] = "1x00000000000000000000AA"
        _, token = self.register(wallet=False)
        code = self.link_code(token)
        for codes, message in ((["invalid-input-response"], "go through"),  # the page escapes apostrophes
                               (["timeout-or-duplicate"], "expired"),
                               (["invalid-input-secret"], "working on this node")):
            phone_verify.set_turnstile_client(httpx.Client(transport=httpx.MockTransport(
                lambda request, c=codes: httpx.Response(200, json={"success": False, "error-codes": c}))))
            phone = unique_phone()
            with self.subTest(codes=codes):
                r = self.client.post("/verify/web/start", data={"c": code, "phone": phone,
                                                                 "cf-turnstile-response": "XXXX.DUMMY"})
                self.assertIn(message, r.text)
                self.assertNotIn("complete the check", r.text)
                self.assertIn('class="cf-turnstile"', r.text)  # a fresh widget to try again
                self.assertNotIn(phone, FAKE_SMS.sent)

    def test_link_needs_a_post_token(self):
        self.assertEqual(self.client.post("/verify/link").status_code, 401)

    def test_page_escapes_and_without_sitekey_says_not_set_up(self):
        os.environ["GFC_TURNSTILE_SECRET"] = TURNSTILE_PASS_SECRET
        _, token = self.register(wallet=False)
        code = self.link_code(token)
        r = self.client.get("/verify", params={"c": code})
        self.assertIn("isn't set up", r.text)
        self.assertNotIn("<form", r.text)

    def test_no_turnstile_secret_means_no_widget(self):
        _, token = self.register(wallet=False)
        code = self.link_code(token)
        r = self.client.get("/verify", params={"c": code})
        self.assertIn("<form", r.text)
        self.assertNotIn('class="cf-turnstile"', r.text)


if __name__ == "__main__":
    unittest.main()
