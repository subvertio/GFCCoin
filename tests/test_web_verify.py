"""
Tests for phone verification in a browser (app_webverify.py): the one-time link the app
opens, the page's headers, the rewards paid at the end, and the page without Firebase.
The Firebase side (the ID token check, refusals) is in test_firebase_verify.py.

Run from the repository root:
    python -m unittest discover -s tests -v
"""

import sqlite3
import unittest
import uuid

# Sets up the isolated data dir and test treasury key before any GFC module loads config
import test_signed_ledger  # noqa: F401
from test_signed_ledger import as_treasury_node, unique_phone

from fastapi.testclient import TestClient  # noqa: E402

import app_webverify  # noqa: E402
import firebase_stub  # noqa: E402
import main  # noqa: E402


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


class WebVerifyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(main.app)

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
        return firebase_stub.link_code(self.client, token)

    def test_full_flow_pays_the_grant(self):
        name, token = self.register()
        before = self.client.get("/verify/status", headers=bearer(token)).json()
        self.assertFalse(before["verified"])
        self.assertEqual(before["rewards"], {"grant": 0.0, "first_post_bonus": 0.0})
        self.assertEqual(len(before["wallets"]), 1)  # the wallet register() made

        with firebase_stub.enabled():
            code = self.link_code(token)
            page = self.client.get("/verify", params={"c": code})
            self.assertEqual(page.status_code, 200)
            self.assertIn(f"@{name}", page.text)
            self.assertEqual(page.headers["referrer-policy"], "no-referrer")
            self.assertEqual(page.headers["cache-control"], "no-store")

            phone = unique_phone()
            with as_treasury_node():
                self.assertEqual(self.client.post("/verify/web/fb/start", data={"c": code, "phone": phone})
                                 .status_code, 200)
                r = self.client.post("/verify/web/fb/check",
                                     data={"c": code, "id_token": firebase_stub.make_token(phone)})
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
        with firebase_stub.enabled():
            r = self.client.post("/verify/web/fb/start", data={"c": code, "phone": unique_phone()})
        self.assertEqual(r.json(), {"reload": True})

    def test_link_needs_a_post_token(self):
        self.assertEqual(self.client.post("/verify/link").status_code, 401)

    def test_without_firebase_says_not_set_up(self):
        _, token = self.register(wallet=False)
        code = self.link_code(token)
        r = self.client.get("/verify", params={"c": code})
        self.assertIn("isn't set up", r.text)
        self.assertNotIn("<form", r.text)
        self.assertNotIn("<script", r.text)
        csp = r.headers["content-security-policy"]
        self.assertNotIn("script-src", csp)  # default-src 'none': no script at all
        self.assertIn("form-action 'self'", csp)
        r = self.client.post("/verify/web/fb/start", data={"c": code, "phone": unique_phone()})
        self.assertEqual(r.json(), {"reload": True})

    def test_sms_endpoints_are_gone(self):
        _, token = self.register(wallet=False)
        for path in ("/verify/phone/start", "/verify/phone/check", "/verify/web/start", "/verify/web/check"):
            self.assertEqual(self.client.post(path, headers=bearer(token),
                                              data={"phone": unique_phone(), "code": "1"}).status_code, 404, path)


if __name__ == "__main__":
    unittest.main()
