"""
Tests for phone verification and the reward rules that depend on it: one account per number,
start limits, grants only after verification, play rewards only from verified, aged viewers,
and a daily cap per creator. Verifies through the Firebase browser flow with firebase_stub's
stand-in key; Firebase and Google are never called.

Run from the repository root:
    python -m unittest discover -s tests -v
"""

import hashlib
import os
import sqlite3
import unittest
import uuid
from datetime import datetime, timedelta, timezone

# Shares the isolated data dir and treasury env set up by the ledger tests
from test_signed_ledger import backdate_user, unique_phone

from fastapi.testclient import TestClient  # noqa: E402
import blockchain  # noqa: E402
import firebase_stub  # noqa: E402
import main  # noqa: E402
import phone_verify  # noqa: E402
from sync_ingest import SYNCABLE_TABLES, select_rows_since  # noqa: E402


def name(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:8]}"


class PhoneVerifyTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(main.app)

    def register(self, username=None):
        username = username or name("user")
        r = self.client.post("/auth/register", data={"username": username, "password": "pw-" + username})
        self.assertEqual(r.status_code, 200, r.text)
        return username, r.json()["token"]

    def start(self, token, phone):
        return firebase_stub.start(self.client, token, phone)

    def verify(self, token, phone=None):
        """Verify the account; returns the done page's text."""
        page = firebase_stub.verify_phone(self.client, token, phone or unique_phone())
        self.assertIn("You're verified", page.text)
        return page.text

    def link(self, token):
        return self.client.post("/verify/link", headers={"Authorization": f"Bearer {token}"}).json()

    def wallet(self, token):
        r = self.client.post("/wallets/create", data={"name": "main", "api_token": token})
        self.assertEqual(r.status_code, 200, r.text)
        return r.json()

    def balance(self, wallet_id):
        return blockchain.get_balance_cents(main.DB_PATH, wallet_id)

    def is_verified(self, username):
        conn = sqlite3.connect(main.DB_PATH)
        try:
            return phone_verify.is_verified(conn, username)
        finally:
            conn.close()


class NumberTests(PhoneVerifyTestCase):

    def test_bad_number_refused(self):
        _, token = self.register()
        self.assertEqual(self.start(token, "555-0123").status_code, 400)  # too short (10 digits are taken as +1)

    def test_normalize_phone(self):
        self.assertEqual(phone_verify.normalize_phone("+1 (415) 555-0123"), "+14155550123")
        self.assertEqual(phone_verify.normalize_phone("0044 20 7946 0958"), "+442079460958")
        # No + means US/Canada
        self.assertEqual(phone_verify.normalize_phone("415-555-0123"), "+14155550123")
        self.assertEqual(phone_verify.normalize_phone("(415) 555 0123"), "+14155550123")
        self.assertEqual(phone_verify.normalize_phone("1 415 555 0123"), "+14155550123")
        for bad in ("", "+0123456789", "+1", "+1415555012x", "555-0123", "4155550123x", "2415550123456"):
            with self.assertRaises(phone_verify.VerifyError, msg=bad):
                phone_verify.normalize_phone(bad)
        self.assertEqual(phone_verify.phone_hash("+1 415 555 0123"), phone_verify.phone_hash("+14155550123"))


class PhoneUniquenessTests(PhoneVerifyTestCase):

    def test_phone_reused_across_accounts_rejected(self):
        _, token_a = self.register()
        user_b, token_b = self.register()
        phone = "+1555" + str(uuid.uuid4().int)[:7]
        self.verify(token_a, phone)
        # Same number, different formatting
        spaced = phone[:2] + " " + phone[2:5] + "-" + phone[5:]
        r = self.start(token_b, spaced)
        self.assertEqual(r.status_code, 409, r.text)
        self.assertFalse(self.is_verified(user_b))

    def test_reuse_rejected_when_both_started_before_either_finished(self):
        user_a, token_a = self.register()
        user_b, token_b = self.register()
        phone = unique_phone()
        with firebase_stub.enabled():
            code_a = firebase_stub.link_code(self.client, token_a)
            code_b = firebase_stub.link_code(self.client, token_b)
            for code in (code_a, code_b):
                self.assertEqual(self.client.post("/verify/web/fb/start", data={"c": code, "phone": phone})
                                 .status_code, 200)
            done = self.client.post("/verify/web/fb/check",
                                    data={"c": code_b, "id_token": firebase_stub.make_token(phone)})
            self.assertIn("You're verified", done.text)
            # Even with a valid Firebase sign-in for the number, A can't take it
            page = self.client.post("/verify/web/fb/check",
                                    data={"c": code_a, "id_token": firebase_stub.make_token(phone)})
        self.assertIn("already verified on another account", page.text)
        self.assertTrue(self.is_verified(user_b))
        self.assertFalse(self.is_verified(user_a))

    def test_one_phone_per_account(self):
        _, token = self.register()
        self.verify(token)
        self.assertEqual(self.link(token), {"verified": True, "url": ""})

    def test_raw_number_never_stored_or_synced(self):
        user, token = self.register()
        phone = unique_phone()
        self.verify(token, phone)
        digits = phone.lstrip("+")
        with open(main.DB_PATH, "rb") as f:
            raw = f.read()
        self.assertNotIn(digits.encode(), raw)
        self.assertNotIn(digits.encode("utf-16-le"), raw)

        conn = sqlite3.connect(main.DB_PATH)
        stored = conn.execute("SELECT phone_hash FROM phone_verifications WHERE username = ?", (user,)).fetchone()[0]
        self.assertEqual(stored, phone_verify.phone_hash(phone))
        self.assertNotEqual(stored, hashlib.sha256(phone.encode()).hexdigest())  # keyed, not plain
        for table in SYNCABLE_TABLES:
            self.assertFalse(table.startswith("phone_"), table)
            payload = repr([list(r) for r in select_rows_since(conn, table, "", 5000)])
            self.assertNotIn(stored, payload, table)
            self.assertNotIn(digits, payload, table)
        conn.close()

    def test_start_rate_limited_per_user_and_per_phone(self):
        _, token = self.register()
        for _ in range(phone_verify.MAX_STARTS_PER_USER):
            self.assertEqual(self.start(token, unique_phone()).status_code, 200)
        self.assertEqual(self.start(token, unique_phone()).status_code, 429)

        phone = unique_phone()
        for _ in range(phone_verify.MAX_STARTS_PER_PHONE):
            _, t = self.register()
            self.assertEqual(self.start(t, phone).status_code, 200)
        _, t = self.register()
        self.assertEqual(self.start(t, phone).status_code, 429)


class GrantTests(PhoneVerifyTestCase):

    def test_grant_only_after_verification(self):
        user, token = self.register()
        w = self.wallet(token)
        self.assertEqual(w["gfc_balance"], 0.0)
        self.assertEqual(self.balance(w["id"]), 0)
        self.assertIsNone(blockchain.process_user_grant(main.DB_PATH, user, w["id"]))

        self.assertIn("+100 GFC welcome grant", self.verify(token))
        self.assertEqual(self.balance(w["id"]), blockchain.NEW_USER_GRANT_CENTS)
        # Nothing more to verify, and a second wallet doesn't grant again
        self.assertTrue(self.link(token)["verified"])
        self.assertEqual(self.wallet(token)["gfc_balance"], 0.0)
        self.assertEqual(self.balance(w["id"]), blockchain.NEW_USER_GRANT_CENTS)

    def test_verified_before_wallet_gets_grant_at_creation(self):
        _, token = self.register()
        self.assertNotIn("welcome grant", self.verify(token))  # no wallet yet
        self.assertEqual(self.wallet(token)["gfc_balance"], 100.0)


class PlayRewardTests(PhoneVerifyTestCase):

    def creator(self):
        user, token = self.register()
        self.verify(token)
        return user, token, self.wallet(token)

    def viewer(self, verified=True, aged=True):
        user, token = self.register()
        if verified:
            self.verify(token)
        if aged:
            backdate_user(main.DB_PATH, user)
        return user, token

    def upload(self, token):
        files = {"file": ("model.glb", os.urandom(200_000), "model/gltf-binary")}
        r = self.client.post("/seeds/upload", data={"api_token": token, "title": "t"}, files=files)
        self.assertEqual(r.status_code, 200, r.text)
        return r.json()["id"]

    def play(self, token, seed_id):
        return self.client.post(f"/seeds/{seed_id}/played", data={"api_token": token}).json()

    def test_unverified_viewer_play_pays_nothing(self):
        _, ctoken, cwallet = self.creator()
        seed = self.upload(ctoken)
        before = self.balance(cwallet["id"])
        _, unverified = self.viewer(verified=False)
        r = self.play(unverified, seed)
        self.assertFalse(r["credited"])
        self.assertEqual(r["reason"], "viewer phone not verified")
        self.assertEqual(self.balance(cwallet["id"]), before)

    def test_new_account_play_pays_nothing(self):
        _, ctoken, cwallet = self.creator()
        seed = self.upload(ctoken)
        before = self.balance(cwallet["id"])
        user, fresh = self.viewer(aged=False)
        r = self.play(fresh, seed)
        self.assertEqual(r["reason"], "viewer account too new")
        backdate_user(main.DB_PATH, user, hours=23)
        self.assertEqual(self.play(fresh, seed)["reason"], "viewer account too new")
        self.assertEqual(self.balance(cwallet["id"]), before)
        backdate_user(main.DB_PATH, user, hours=25)
        self.assertTrue(self.play(fresh, seed)["credited"])

    def test_daily_cap_per_creator(self):
        _, ctoken, cwallet = self.creator()
        seed1, seed2 = self.upload(ctoken), self.upload(ctoken)
        _, other_token, other_wallet = self.creator()
        other_seed = self.upload(other_token)
        viewer, vtoken = self.viewer()

        before = self.balance(cwallet["id"])
        self.assertTrue(self.play(vtoken, seed1)["credited"])
        paid = self.balance(cwallet["id"]) - before
        self.assertGreater(paid, 0)
        # Same creator, another seed, same day: capped
        r = self.play(vtoken, seed2)
        self.assertFalse(r["credited"])
        self.assertEqual(r["reason"], "daily limit for this creator reached")
        # A different creator is still paid
        self.assertTrue(self.play(vtoken, other_seed)["credited"])
        # Replaying the paid seed doesn't use up or reset anything
        self.assertEqual(self.play(vtoken, seed1)["reason"], "already credited")
        self.assertEqual(self.balance(cwallet["id"]) - before, paid)

        # Next day: seed2 pays; seed1 still never pays twice
        yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).date().isoformat()
        conn = sqlite3.connect(main.DB_PATH)
        conn.execute("UPDATE play_reward_slots SET day = ? WHERE viewer = ?", (yesterday, viewer))
        conn.commit()
        conn.close()
        self.assertEqual(self.play(vtoken, seed1)["reason"], "already credited")
        self.assertTrue(self.play(vtoken, seed2)["credited"])
        self.assertEqual(self.balance(cwallet["id"]) - before, 2 * paid)


if __name__ == "__main__":
    unittest.main()
