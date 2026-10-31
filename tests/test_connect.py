"""
Tests for GFC Connect (app_connect.py): one-time codes a partner site checks server to server
to require a phone-verified GFC account, and the public member status.

Run from the repository root:
    python -m unittest discover -s tests -v
"""

import datetime
import os
import sqlite3
import sys
import unittest
import uuid
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_signed_ledger  # noqa: F401  (sets up the isolated data dir and a test treasury first)
from test_signed_ledger import mark_verified

from fastapi.testclient import TestClient  # noqa: E402

import app_connect  # noqa: E402
import main  # noqa: E402

KEY = "cw-test-key-" + "x" * 24
OTHER_KEY = "other-test-key-" + "y" * 24
PARTNERS = f"creator-world.org=Creator World:{KEY},other.example:{OTHER_KEY}"


class ConnectTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(main.app)

    def setUp(self):
        self.env = mock.patch.dict(os.environ, {"GFC_PARTNERS": PARTNERS})
        self.env.start()
        app_connect._verify_calls.clear()

    def tearDown(self):
        self.env.stop()

    def account(self, verified=True):
        name = "Cw" + uuid.uuid4().hex[:9]
        token = self.client.post("/auth/register", data={"username": name, "password": "pw-" + name}).json()["token"]
        if verified:
            mark_verified(main.DB_PATH, name)
        return name, {"Authorization": f"Bearer {token}"}

    def code(self, h, partner="creator-world.org"):
        return self.client.post("/connect/code", headers=h, data={"partner": partner})

    def verify(self, code, key=KEY, partner="creator-world.org"):
        return self.client.post("/connect/verify", json={"code": code},
                                headers={"Authorization": f"Bearer {key}", "X-GFC-Partner": partner})

    def test_partners_are_listed_without_their_keys(self):
        r = self.client.get("/connect/partners").json()
        self.assertEqual(r["partners"], [{"id": "creator-world.org", "name": "Creator World"},
                                         {"id": "other.example", "name": "other.example"}])
        self.assertNotIn(KEY, self.client.get("/connect/partners").text)

    def test_a_verified_member_is_confirmed_once(self):
        name, h = self.account()
        r = self.code(h)
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        self.assertRegex(body["code"], r"^GFC-[2-9A-HJKMNP-Z]{4}-[2-9A-HJKMNP-Z]{4}$")
        self.assertEqual((body["partner"], body["name"], body["expiresIn"]), ("creator-world.org", "Creator World", 900))
        ok = self.verify(body["code"].lower().replace("-", " "))  # people retype codes
        self.assertEqual(ok.status_code, 200, ok.text)
        self.assertEqual(ok.json()["memberId"], name)
        self.assertTrue(ok.json()["confirmed"])
        self.assertTrue(ok.json()["verifiedAt"].endswith("Z"))
        # Single use
        again = self.verify(body["code"])
        self.assertEqual((again.status_code, again.json()), (404, {"error": "invalid_or_expired_code"}))

    def test_an_unverified_member_is_not_confirmed(self):
        name, h = self.account(verified=False)
        r = self.verify(self.code(h).json()["code"]).json()
        self.assertEqual(r, {"confirmed": False, "memberId": name, "reason": "phone_not_verified"})

    def test_codes_are_bound_to_one_partner_and_expire(self):
        _, h = self.account()
        code = self.code(h).json()["code"]
        self.assertEqual(self.verify(code, key=OTHER_KEY, partner="other.example").status_code, 404)  # not theirs
        self.assertEqual(self.verify(code).status_code, 200)
        expired = self.code(h).json()["code"]
        conn = sqlite3.connect(main.DB_PATH)
        conn.execute("UPDATE connect_codes SET expires_at = ? WHERE code_hash = ?",
                     ((datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=1)).isoformat(),
                      app_connect._hash(expired)))
        conn.commit()
        conn.close()
        self.assertEqual(self.verify(expired).status_code, 404)
        # A new code replaces the member's previous one for that partner
        first = self.code(h).json()["code"]
        second = self.code(h).json()["code"]
        self.assertEqual(self.verify(first).status_code, 404)
        self.assertEqual(self.verify(second).status_code, 200)

    def test_partner_key_and_header_must_match(self):
        _, h = self.account()
        code = self.code(h).json()["code"]
        self.assertEqual(self.verify(code, key="wrong-" + "z" * 30).status_code, 401)
        self.assertEqual(self.verify(code, partner="other.example").status_code, 401)  # creator-world's key, wrong name
        self.assertEqual(self.client.post("/connect/verify", json={"code": code}).status_code, 401)
        self.assertEqual(self.verify(code).status_code, 200)  # still usable: failed checks didn't burn it

    def test_logged_out_or_unknown_partner_gets_no_code(self):
        _, h = self.account()
        self.assertEqual(self.client.post("/connect/code", data={"partner": "creator-world.org"}).status_code, 401)
        self.assertEqual(self.code(h, partner="evil.example").status_code, 404)

    def test_rate_limits(self):
        _, h = self.account()
        for _ in range(app_connect.CODES_PER_USER_PER_HOUR):
            self.assertEqual(self.code(h).status_code, 200)
        self.assertEqual(self.code(h).status_code, 429)
        for _ in range(app_connect.VERIFY_PER_PARTNER_PER_MINUTE):
            self.verify("GFC-AAAA-AAAA")
        self.assertEqual(self.verify("GFC-AAAA-AAAA").json(), {"error": "rate_limited"})

    def test_public_member_status(self):
        name, _ = self.account()
        r = self.client.get(f"/members/{name.lower()}").json()
        self.assertEqual((r["memberId"], r["confirmed"]), (name, True))
        unverified, _ = self.account(verified=False)
        self.assertEqual(self.client.get(f"/members/{unverified}").json(), {"memberId": unverified, "confirmed": False})
        self.assertEqual(self.client.get("/members/nobody-xyz").status_code, 404)

    def test_usernames_that_differ_only_by_case_are_refused(self):
        name, _ = self.account()
        r = self.client.post("/auth/register", data={"username": name.upper(), "password": "pw-x"})
        self.assertEqual((r.status_code, r.json()["detail"]), (409, "username already exists"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
