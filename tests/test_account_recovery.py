"""
Tests for account recovery (account_recovery.py, app_recovery.py): password reset with the
verified phone or email, recovery codes that bring the wallets back, verifying an email, and
changing the verified phone. Firebase is stubbed (firebase_stub.py).

Run from the repository root:
    python -m unittest discover -s tests -v
"""

import re
import sqlite3
import unittest
import uuid

# Sets up the isolated data dir and test treasury key before any GFC module loads config
import test_signed_ledger  # noqa: F401

from fastapi.testclient import TestClient  # noqa: E402

import account_recovery  # noqa: E402
import firebase_stub as fb  # noqa: E402
import keystore  # noqa: E402
import main  # noqa: E402


def email_token(email, verified=True, provider="password"):
    return fb.make_token("", email=email, email_verified=verified,
                         firebase={"sign_in_provider": provider, "identities": {"email": [email]}})


class AccountRecoveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(main.app)

    def register(self, password="first-password"):
        name = "r" + uuid.uuid4().hex[:10]
        r = self.client.post("/auth/register", data={"username": name, "password": password})
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        return name, body["token"], body["recovery_code"]

    def phone(self):
        return "+1555" + str(uuid.uuid4().int)[:7]

    def verified_user(self):
        name, token, code = self.register()
        number = self.phone()
        self.assertIn("verified", fb.verify_phone(self.client, token, number).text.lower())
        return name, token, code, number

    def auth(self, token):
        return {"Authorization": f"Bearer {token}"}

    def verify_email(self, token, email):
        with fb.enabled():
            url = self.client.post("/email/link", headers=self.auth(token)).json()["url"]
            f = re.search(r"[?&]f=([^&]+)", url).group(1)
            self.assertIn("Verify your email", self.client.get(f"/account/email?f={f}").text)
            r = self.client.post("/account/email/start", data={"f": f, "email": email})
            self.assertEqual(r.status_code, 200, r.text)
            return self.client.post("/account/email/prove", data={"f": f, "id_token": email_token(email)})

    def reset(self, name, method, contact, token, password, recovery_code="", accept_locked=False):
        with fb.enabled():
            r = self.client.post("/reset/start", data={"username": name, "method": method, method: contact})
            if r.status_code != 200:
                return r
            f = r.json()["flow"]
            page = self.client.post("/reset/prove", data={"f": f, "id_token": token})
            if "Choose a new password" not in page.text:
                return page
            return self.client.post("/reset/complete", data={
                "f": f, "password": password, "password2": password, "recovery_code": recovery_code,
                "accept_locked": "1" if accept_locked else ""})

    def login(self, name, password):
        return self.client.post("/auth/login", data={"username": name, "password": password})

    # ---------- tests ----------

    def test_register_gives_a_recovery_code(self):
        name, token, code = self.register()
        self.assertRegex(code, r"^([A-Z2-9]{5}-){5}[A-Z2-9]{5}$")
        status = self.client.get("/account/security", headers=self.auth(token)).json()
        self.assertEqual(status, {"recovery_code": True, "email": "", "email_verified": False, "phone_verified": False})

    def test_reset_by_phone_with_recovery_code_keeps_wallets(self):
        name, token, code, number = self.verified_user()
        before = keystore.unlock_user_keys(name, "first-password", main.DB_PATH)
        page = self.reset(name, "phone", number, fb.make_token(number), "second-password", code)
        self.assertIn("Password changed", page.text)
        self.assertIn("unlocked with your new password", page.text)
        new_code = re.search(r'class="code">([^<]+)<', page.text).group(1)
        self.assertNotEqual(new_code, code)
        # Same data key under the new password; the old code is gone, the new one works
        self.assertEqual(keystore.unlock_user_keys(name, "second-password", main.DB_PATH), before)
        self.assertIsNone(keystore.unlock_with_recovery_code(name, code, main.DB_PATH))
        self.assertEqual(keystore.unlock_with_recovery_code(name, new_code.lower().replace("-", " "), main.DB_PATH), before)
        # Signed out everywhere; the old password no longer works
        self.assertEqual(self.client.get("/account/security", headers=self.auth(token)).status_code, 401)
        self.assertEqual(self.login(name, "first-password").status_code, 401)
        self.assertEqual(self.login(name, "second-password").status_code, 200)

    def test_reset_without_code_needs_consent_and_locks_old_wallets(self):
        name, token, code, number = self.verified_user()
        before = keystore.unlock_user_keys(name, "first-password", main.DB_PATH)
        page = self.reset(name, "phone", number, fb.make_token(number), "second-password")
        self.assertIn("Tick the box", page.text)
        page = self.reset(name, "phone", number, fb.make_token(number), "second-password", accept_locked=True)
        self.assertIn("previous wallets are locked", page.text)
        self.assertNotEqual(keystore.unlock_user_keys(name, "second-password", main.DB_PATH), before)
        self.assertEqual(self.login(name, "second-password").status_code, 200)

    def test_wrong_code_and_short_password(self):
        name, _, _, number = self.verified_user()
        page = self.reset(name, "phone", number, fb.make_token(number), "second-password", "AAAAA-AAAAA-AAAAA-AAAAA-AAAAA-AAAAA")
        self.assertIn("recovery code isn", page.text)
        page = self.reset(name, "phone", number, fb.make_token(number), "short")
        self.assertIn("at least 8", page.text)
        self.assertEqual(self.login(name, "first-password").status_code, 200)

    def test_mismatches_look_the_same_and_proof_must_match(self):
        name, _, _, number = self.verified_user()
        unknown = self.reset("nobody-" + uuid.uuid4().hex[:6], "phone", number, "", "x" * 10)
        wrong = self.reset(name, "phone", self.phone(), "", "x" * 10)
        no_email = self.reset(name, "email", "me@example.com", "", "x" * 10)
        for r in (unknown, wrong, no_email):
            self.assertEqual(r.status_code, 400)
            self.assertEqual(r.json()["error"], account_recovery.NO_MATCH)
        # A Firebase proof for another number doesn't prove this account
        page = self.reset(name, "phone", number, fb.make_token(self.phone()), "second-password")
        self.assertIn("the phone number or email on this account", page.text)
        self.assertEqual(self.login(name, "first-password").status_code, 200)

    def test_rate_limit(self):
        name, _, _, number = self.verified_user()
        with fb.enabled():
            for _ in range(account_recovery.STARTS_PER_DAY):
                self.assertEqual(self.client.post("/reset/start", data={"username": name, "method": "phone",
                                                                        "phone": number}).status_code, 200)
            r = self.client.post("/reset/start", data={"username": name, "method": "phone", "phone": number})
        self.assertEqual(r.status_code, 429)

    def test_verified_email_then_reset_by_email(self):
        name, token, code, _ = self.verified_user()
        email = f"{name}@example.com"
        self.assertIn("Email verified", self.verify_email(token, email.upper()).text)
        status = self.client.get("/account/security", headers=self.auth(token)).json()
        self.assertTrue(status["email_verified"])
        self.assertEqual(status["email"], f"{name[0]}***@example.com")
        # An unverified Firebase email, or another address, doesn't count
        self.assertIn("Email sign-in didn", self.reset(name, "email", email, email_token(email, verified=False), "pw-123456789").text)
        self.assertIn("the phone number or email on this account", self.reset(name, "email", email, email_token("x@example.com"), "pw-123456789").text)
        page = self.reset(name, "email", email, email_token(email, provider="emailLink"), "pw-123456789", code)
        self.assertIn("Password changed", page.text)
        self.assertEqual(self.login(name, "pw-123456789").status_code, 200)

    def test_one_account_per_email(self):
        _, token1, _ = self.register()
        _, token2, _ = self.register()
        email = f"shared-{uuid.uuid4().hex[:6]}@example.com"
        self.verify_email(token1, email)
        with fb.enabled():
            url = self.client.post("/email/link", headers=self.auth(token2)).json()["url"]
            f = re.search(r"[?&]f=([^&]+)", url).group(1)
            r = self.client.post("/account/email/start", data={"f": f, "email": email})
        self.assertEqual(r.status_code, 409)

    def test_change_phone_with_verified_email(self):
        name, token, _, old = self.verified_user()
        email = f"{name}@example.com"
        self.verify_email(token, email)
        other_name, other_token, _, taken = self.verified_user()
        new = self.phone()
        with fb.enabled():
            r = self.client.post("/account/phone/start", data={"username": name, "email": email})
            f = r.json()["flow"]
            self.assertIn("Your new number", self.client.post("/account/phone/prove",
                                                               data={"f": f, "id_token": email_token(email)}).text)
            self.assertEqual(self.client.post("/account/phone/new", data={"f": f, "phone": taken}).status_code, 409)
            self.assertEqual(self.client.post("/account/phone/new", data={"f": f, "phone": new}).status_code, 200)
            wrong = self.client.post("/account/phone/prove-new", data={"f": f, "id_token": fb.make_token(old)})
            self.assertIn("different number", wrong.text)
            done = self.client.post("/account/phone/prove-new", data={"f": f, "id_token": fb.make_token(new)})
        self.assertIn("Phone number changed", done.text)
        # The new number resets the password now; the old one doesn't
        self.assertEqual(self.reset(name, "phone", old, "", "x" * 10).status_code, 400)
        self.assertIn("Password changed", self.reset(name, "phone", new, fb.make_token(new), "pw-123456789",
                                                     accept_locked=True).text)

    def test_new_recovery_code_needs_password(self):
        name, token, code = self.register()
        self.assertEqual(self.client.post("/account/recovery-code", data={"password": "nope"},
                                          headers=self.auth(token)).status_code, 401)
        new = self.client.post("/account/recovery-code", data={"password": "first-password"},
                               headers=self.auth(token)).json()["recovery_code"]
        self.assertIsNone(keystore.unlock_with_recovery_code(name, code, main.DB_PATH))
        self.assertIsNotNone(keystore.unlock_with_recovery_code(name, new, main.DB_PATH))

    def test_flows_expire_and_are_single_use(self):
        name, _, _, number = self.verified_user()
        with fb.enabled():
            f = self.client.post("/reset/start", data={"username": name, "method": "phone", "phone": number}).json()["flow"]
            conn = sqlite3.connect(main.DB_PATH)
            conn.execute("UPDATE recovery_flows SET created_at = '2020-01-01T00:00:00+00:00' WHERE code_hash = ?",
                         (account_recovery._hash(f),))
            conn.commit()
            conn.close()
            self.assertIn("expired", self.client.post("/reset/prove", data={"f": f, "id_token": fb.make_token(number)}).text)
        page = self.reset(name, "phone", number, fb.make_token(number), "pw-123456789", accept_locked=True)
        self.assertIn("Password changed", page.text)

    def test_pages(self):
        with fb.enabled():
            page = self.client.get("/reset")
        self.assertIn('id="start-form"', page.text)
        self.assertIn(fb.CONFIG["apiKey"], page.text)
        self.assertEqual(page.headers["referrer-policy"], "no-referrer")
        self.assertIn("isn't set up", self.client.get("/reset").text)
        self.assertIn("expired", self.client.get("/account/email?f=nope").text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
