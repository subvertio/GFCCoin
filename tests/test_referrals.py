"""
Tests for invite rewards: 1,000 GFC to the inviter and a 100 GFC bonus to the
friend, paid once, only when the friend is real and active.

Run from the repository root:
    python -m unittest discover -s tests -v
"""

import os
import sqlite3
import unittest
import uuid
from datetime import datetime, timedelta, timezone

# Sets up the isolated data dir and test treasury key before any GFC module loads config
import test_signed_ledger  # noqa: F401
from test_signed_ledger import FAKE_SMS, as_treasury_node, backdate_user, unique_phone

from fastapi.testclient import TestClient  # noqa: E402

import blockchain  # noqa: E402
import main  # noqa: E402
import phone_verify  # noqa: E402
import referrals  # noqa: E402
import signing  # noqa: E402


class ReferralTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(main.app)

    def register(self, ref=""):
        name = "u" + uuid.uuid4().hex[:10]
        r = self.client.post("/auth/register", data={"username": name, "password": "pw-" + name, "ref": ref})
        self.assertEqual(r.status_code, 200, r.text)
        token = r.json()["token"]
        wallet = self.client.post("/wallets/create", data={"name": "main", "api_token": token}).json()["id"]
        return name, token, wallet, r.json()

    def verify_phone(self, token):
        phone = unique_phone()
        self.client.post("/verify/phone/start", data={"phone": phone, "api_token": token})
        code = FAKE_SMS.sent[phone]
        r = self.client.post("/verify/phone/check", data={"phone": phone, "code": code, "api_token": token})
        self.assertTrue(r.json()["verified"], r.text)

    def balance(self, wallet):
        return blockchain.get_balance_cents(main.DB_PATH, wallet)

    def referral_txs(self, wallet):
        conn = sqlite3.connect(main.DB_PATH)
        rows = conn.execute("SELECT amount_cents, signature FROM transactions WHERE tx_type = 'REFERRAL' "
                            "AND recipient = ?", (wallet,)).fetchall()
        conn.close()
        return rows

    def play_someone_elses_seed(self, viewer_token):
        """A qualifying play: a signed seed from a third creator."""
        name, token, wallet, _ = self.register()
        files = {"file": ("model.glb", os.urandom(200_000), "model/gltf-binary")}
        seed = self.client.post("/seeds/upload", data={"api_token": token}, files=files).json()
        return self.client.post(f"/seeds/{seed['id']}/played", data={"api_token": viewer_token}).json()

    def test_register_records_inviter_and_ignores_bad_refs(self):
        inviter, _, _, _ = self.register()
        _, _, _, resp = self.register(ref=inviter.upper())  # case-insensitive
        self.assertEqual(resp["invited_by"], inviter)
        self.assertIsNone(self.register(ref="nobody-" + uuid.uuid4().hex[:6])[3]["invited_by"])
        self.assertIsNone(self.register(ref="")[3]["invited_by"])
        # Can't invite yourself
        self.assertIsNone(referrals.record_invite(main.DB_PATH, inviter, inviter))

    def test_paid_once_when_friend_is_real_and_active(self):
        inviter, inviter_token, inviter_wallet, _ = self.register()
        friend, friend_token, friend_wallet, _ = self.register(ref=inviter)
        start_inviter, start_friend = self.balance(inviter_wallet), self.balance(friend_wallet)

        # Not verified yet: a play pays nobody
        with as_treasury_node():
            self.play_someone_elses_seed(friend_token)
        self.assertEqual(self.balance(inviter_wallet), start_inviter)

        # Verified but the account is too new: still nothing
        with as_treasury_node():
            self.verify_phone(friend_token)
            after_grant = self.balance(friend_wallet)
            self.play_someone_elses_seed(friend_token)
        self.assertEqual(self.balance(inviter_wallet), start_inviter)

        # Real and active: inviter +1,000, friend +100, both treasury-signed REFERRAL mints
        backdate_user(main.DB_PATH, friend)
        with as_treasury_node():
            self.play_someone_elses_seed(friend_token)
        self.assertEqual(self.balance(inviter_wallet) - start_inviter, blockchain.REFERRAL_REWARD_CENTS)
        self.assertEqual(self.balance(friend_wallet) - after_grant, blockchain.REFERRAL_BONUS_CENTS)
        [(amount, sig)] = self.referral_txs(inviter_wallet)
        self.assertEqual(amount, blockchain.REFERRAL_REWARD_CENTS)
        self.assertTrue(sig)

        # More plays never pay again
        with as_treasury_node():
            self.play_someone_elses_seed(friend_token)
            self.play_someone_elses_seed(friend_token)
        self.assertEqual(len(self.referral_txs(inviter_wallet)), 1)

        stats = self.client.get("/referrals/me", params={"api_token": inviter_token}).json()
        self.assertEqual((stats["invited"], stats["active"], stats["pending"]), (1, 1, 0))
        self.assertEqual(stats["earned_gfc"], 1000.0)
        self.assertIn(f"/join?ref={inviter}", stats["invite_url"])

    def test_no_cap_per_inviter(self):
        inviter, _, inviter_wallet, _ = self.register()
        start = self.balance(inviter_wallet)
        for _ in range(3):
            friend, token, _, _ = self.register(ref=inviter)
            with as_treasury_node():
                self.verify_phone(token)
            backdate_user(main.DB_PATH, friend)
            with as_treasury_node():
                self.play_someone_elses_seed(token)
        self.assertEqual(self.balance(inviter_wallet) - start, 3 * blockchain.REFERRAL_REWARD_CENTS)

    def test_network_accepts_only_exact_treasury_signed_referral_amounts(self):
        wallet = signing.generate_keypair()[1]
        db = test_signed_ledger.new_node("ref_peer_" + uuid.uuid4().hex[:6])

        def mint(amount, priv=test_signed_ledger.TREASURY_PRIV):
            tx = {"id": str(uuid.uuid4()), "sender": blockchain.TREASURY_WALLET_ID, "recipient": wallet,
                  "amount": amount / 100, "amount_cents": amount, "reason": "Invite reward",
                  "timestamp": datetime.now(timezone.utc).isoformat(), "tx_type": blockchain.TX_TYPE_REFERRAL}
            tx["tx_hash"] = blockchain.compute_tx_hash(tx)
            tx["signer"] = signing.public_key_of(priv)
            tx["signature"] = signing.sign_tx_hash(priv, tx["tx_hash"])
            return tx

        self.assertEqual(blockchain.check_synced_transaction(db, mint(blockchain.REFERRAL_REWARD_CENTS))[0],
                         blockchain.ACCEPTED)
        self.assertEqual(blockchain.check_synced_transaction(db, mint(blockchain.REFERRAL_BONUS_CENTS))[0],
                         blockchain.ACCEPTED)
        self.assertEqual(blockchain.check_synced_transaction(db, mint(5_000_000)),
                         (blockchain.REJECTED, "wrong referral amount"))
        attacker = signing.generate_keypair()[0]
        self.assertEqual(blockchain.check_synced_transaction(db, mint(blockchain.REFERRAL_REWARD_CENTS, attacker))[0],
                         blockchain.REJECTED)

    def test_join_page_names_inviter_and_escapes(self):
        inviter, _, _, _ = self.register()
        r = self.client.get("/join", params={"ref": inviter})
        self.assertEqual(r.status_code, 200)
        self.assertIn(f"{inviter} invited you to GFC", r.text)
        self.assertIn(f"gfc://join?ref={inviter}", r.text)
        bad = self.client.get("/join", params={"ref": '<script>alert(1)</script>'})
        self.assertNotIn("<script>", bad.text)
        self.assertIn("Join GFC", bad.text)

    def test_share_page_passes_ref_to_app(self):
        _, token, _, _ = self.register()
        files = {"file": ("pic.png", os.urandom(5000), "image/png")}
        seed = self.client.post("/seeds/upload", data={"api_token": token}, files=files).json()
        r = self.client.get(f"/p/{seed['id']}", params={"ref": "alice"})
        self.assertIn(f"gfc://seed/{seed['id']}?ref=alice", r.text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
