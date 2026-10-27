"""
Tests for the first post bonus: 1,000 GFC (by default) for an account's first
original post, paid once, held as pending until the account can be paid.

Run from the repository root:
    python -m unittest discover -s tests -v
"""

import os
import sqlite3
import threading
import unittest
import uuid
from datetime import datetime, timezone

# Sets up the isolated data dir and test treasury key before any GFC module loads config
import test_signed_ledger  # noqa: F401
from test_signed_ledger import FAKE_SMS, TREASURY_PRIV, as_treasury_node, unique_phone

from fastapi.testclient import TestClient  # noqa: E402

import blockchain  # noqa: E402
import first_post  # noqa: E402
import main  # noqa: E402
import signing  # noqa: E402


class FirstPostBonusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(main.app)

    def tearDown(self):
        os.environ.pop("GFC_FIRST_POST_BONUS_ENABLED", None)
        os.environ.pop("GFC_FIRST_POST_BONUS_GFC", None)

    def register(self, verified=True, wallet=True):
        name = "u" + uuid.uuid4().hex[:10]
        r = self.client.post("/auth/register", data={"username": name, "password": "pw-" + name})
        self.assertEqual(r.status_code, 200, r.text)
        token = r.json()["token"]
        if verified:
            self.verify_phone(token)
        wallet_id = self.create_wallet(token)["id"] if wallet else None
        return name, token, wallet_id

    def verify_phone(self, token):
        phone = unique_phone()
        with as_treasury_node():
            self.client.post("/verify/phone/start", data={"phone": phone, "api_token": token})
            r = self.client.post("/verify/phone/check", data={"phone": phone, "code": FAKE_SMS.sent[phone],
                                                               "api_token": token})
        self.assertTrue(r.json()["verified"], r.text)
        return r.json()

    def create_wallet(self, token):
        with as_treasury_node():
            r = self.client.post("/wallets/create", data={"name": "main", "api_token": token})
        self.assertEqual(r.status_code, 200, r.text)
        return r.json()

    def upload(self, token, data=None, filename="clip.mp4"):
        files = {"file": (filename, data if data is not None else os.urandom(50_000), "application/octet-stream")}
        with as_treasury_node():
            r = self.client.post("/seeds/upload", data={"api_token": token}, files=files)
        self.assertEqual(r.status_code, 200, r.text)
        return r.json()

    def bonus_txs(self, wallet):
        conn = sqlite3.connect(main.DB_PATH)
        rows = conn.execute("SELECT amount_cents, reason, signature FROM transactions WHERE tx_type = ? "
                            "AND recipient = ?", (blockchain.TX_TYPE_FIRST_POST, wallet)).fetchall()
        conn.close()
        return rows

    def all_bonus_txs_for(self, username):
        conn = sqlite3.connect(main.DB_PATH)
        rows = conn.execute("SELECT transactions.id FROM transactions JOIN wallets ON wallets.id = transactions.recipient "
                            "WHERE transactions.tx_type = ? AND wallets.owner = ?",
                            (blockchain.TX_TYPE_FIRST_POST, username)).fetchall()
        conn.close()
        return rows

    def balance(self, wallet):
        return blockchain.get_balance_cents(main.DB_PATH, wallet)

    # --- paid once ---

    def test_first_post_pays_1000_once(self):
        _, token, wallet = self.register()
        start = self.balance(wallet)

        first = self.upload(token)
        self.assertEqual(first["first_post_bonus"], 1000.0)
        self.assertNotIn("first_post_bonus_pending", first)
        self.assertEqual(self.balance(wallet) - start, 100_000)
        [(amount, reason, sig)] = self.bonus_txs(wallet)
        self.assertEqual((amount, reason), (100_000, "First post bonus"))
        self.assertTrue(sig)  # treasury-signed, so every node accepts it

        # Shows in wallet history with its memo
        history = self.client.get("/transactions/history", params={"wallet_id": wallet}).json()
        self.assertIn("First post bonus", str(history))

        second = self.upload(token)
        self.assertNotIn("first_post_bonus", second)
        self.assertNotIn("first_post_bonus_pending", second)
        self.assertEqual(len(self.bonus_txs(wallet)), 1)

    # --- never twice ---

    def test_deleted_and_reposted_first_seed_does_not_pay_again(self):
        _, token, wallet = self.register()
        data = os.urandom(40_000)
        first = self.upload(token, data)
        self.assertEqual(first["first_post_bonus"], 1000.0)
        conn = sqlite3.connect(main.DB_PATH)
        conn.execute("DELETE FROM seeds WHERE id = ?", (first["id"],))
        conn.commit()
        conn.close()
        again = self.upload(token, os.urandom(40_000))
        self.assertNotIn("first_post_bonus", again)
        self.assertEqual(len(self.bonus_txs(wallet)), 1)

    def test_concurrent_and_retried_payouts_pay_once(self):
        name, _, wallet = self.register()
        results = []

        def post(i):
            results.append(first_post.on_upload(main.DB_PATH, name, f"seed-{i}-{uuid.uuid4().hex[:6]}", False))

        with as_treasury_node():
            threads = [threading.Thread(target=post, args=(i,)) for i in range(8)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            # Retries after the fact pay nothing either
            self.assertIsNone(first_post.pay_pending(main.DB_PATH, name))
            self.assertIsNone(first_post.on_upload(main.DB_PATH, name, "seed-retry", False))

        paid = [r for r in results if r and not r["pending"]]
        self.assertEqual(len(paid), 1, results)
        self.assertEqual(len(self.bonus_txs(wallet)), 1)

    # --- reposts ---

    def test_repost_gets_no_bonus_but_a_later_original_does(self):
        _, alice_token, _ = self.register()
        _, bob_token, bob_wallet = self.register()
        video = os.urandom(300_000)
        self.upload(alice_token, video)

        copy = self.upload(bob_token, video, "my_clip.mp4")
        self.assertIsNotNone(copy["repost_of"])
        self.assertNotIn("first_post_bonus", copy)
        self.assertNotIn("first_post_bonus_pending", copy)
        self.assertEqual(self.bonus_txs(bob_wallet), [])

        original = self.upload(bob_token)
        self.assertIsNone(original["repost_of"])
        self.assertEqual(original["first_post_bonus"], 1000.0)
        self.assertEqual(len(self.bonus_txs(bob_wallet)), 1)

    # --- pending -> paid ---

    def test_no_wallet_is_pending_then_paid_on_first_wallet(self):
        name, token, _ = self.register(verified=True, wallet=False)
        first = self.upload(token)
        self.assertEqual(first["first_post_bonus"], 1000.0)
        self.assertIs(first["first_post_bonus_pending"], True)
        self.assertEqual(self.all_bonus_txs_for(name), [])

        # Later posts don't earn a second one while it waits
        self.assertNotIn("first_post_bonus", self.upload(token))

        wallet = self.create_wallet(token)
        self.assertEqual(wallet["gfc_balance"], 100.0 + 1000.0)  # new-user grant + bonus
        self.assertEqual(len(self.bonus_txs(wallet["id"])), 1)
        self.assertEqual(self.balance(wallet["id"]), 110_000)

        # A second wallet gets nothing more
        other = self.create_wallet(token)
        self.assertEqual(self.bonus_txs(other["id"]), [])

    def test_unverified_is_pending_then_paid_on_phone_verification(self):
        name, token, wallet = self.register(verified=False, wallet=True)
        first = self.upload(token)
        self.assertEqual(first["first_post_bonus"], 1000.0)
        self.assertIs(first["first_post_bonus_pending"], True)
        self.assertEqual(self.bonus_txs(wallet), [])

        result = self.verify_phone(token)
        self.assertEqual(result["first_post_bonus"], 1000.0)
        self.assertEqual(len(self.bonus_txs(wallet)), 1)
        self.assertEqual(self.balance(wallet), 10_000 + 100_000)

    def test_short_treasury_leaves_it_pending_for_retry(self):
        name, token, wallet = self.register()
        real_mint = blockchain.process_first_post_mint
        blockchain.process_first_post_mint = lambda *a, **k: None  # treasury short
        try:
            first = self.upload(token)
        finally:
            blockchain.process_first_post_mint = real_mint
        self.assertIs(first["first_post_bonus_pending"], True)
        self.assertEqual(self.bonus_txs(wallet), [])

        # Next upload pays the bonus that was waiting
        later = self.upload(token)
        self.assertEqual(later["first_post_bonus"], 1000.0)
        self.assertNotIn("first_post_bonus_pending", later)
        self.assertEqual(len(self.bonus_txs(wallet)), 1)

    # --- config ---

    def test_disabled_switch(self):
        os.environ["GFC_FIRST_POST_BONUS_ENABLED"] = "0"
        name, token, wallet = self.register()
        first = self.upload(token)
        self.assertNotIn("first_post_bonus", first)
        self.assertNotIn("first_post_bonus_pending", first)
        self.assertEqual(self.bonus_txs(wallet), [])

        # A bonus already pending waits while the switch is off
        os.environ["GFC_FIRST_POST_BONUS_ENABLED"] = "1"
        other, other_token, _ = self.register(wallet=False)
        self.assertTrue(self.upload(other_token)["first_post_bonus_pending"])
        os.environ["GFC_FIRST_POST_BONUS_ENABLED"] = "0"
        w = self.create_wallet(other_token)
        self.assertEqual(self.bonus_txs(w["id"]), [])
        os.environ["GFC_FIRST_POST_BONUS_ENABLED"] = "1"
        with as_treasury_node():
            self.assertIsNotNone(first_post.pay_pending(main.DB_PATH, other))
        self.assertEqual(len(self.bonus_txs(w["id"])), 1)

    def test_amount_is_configurable_and_capped(self):
        os.environ["GFC_FIRST_POST_BONUS_GFC"] = "250"
        _, token, wallet = self.register()
        self.assertEqual(self.upload(token)["first_post_bonus"], 250.0)
        self.assertEqual(self.bonus_txs(wallet)[0][0], 25_000)

        os.environ["GFC_FIRST_POST_BONUS_GFC"] = "5000"
        self.assertEqual(first_post.amount_cents(), blockchain.FIRST_POST_BONUS_MAX_CENTS)

    # --- peers ---

    def first_post_mint(self, recipient, amount_cents):
        tx = {
            "id": str(uuid.uuid4()), "sender": blockchain.TREASURY_WALLET_ID, "recipient": recipient,
            "amount": amount_cents / 100.0, "amount_cents": amount_cents, "reason": "First post bonus",
            "timestamp": datetime.now(timezone.utc).isoformat(), "tx_type": blockchain.TX_TYPE_FIRST_POST,
        }
        tx["tx_hash"] = blockchain.compute_tx_hash(tx)
        tx["signer"] = signing.public_key_of(TREASURY_PRIV)
        tx["signature"] = signing.sign_tx_hash(TREASURY_PRIV, tx["tx_hash"])
        return tx

    def test_peers_reject_oversized_or_second_bonus(self):
        check = blockchain.check_synced_transaction
        fresh = "w" + uuid.uuid4().hex
        self.assertEqual(check(main.DB_PATH, self.first_post_mint(fresh, 100_000))[0], blockchain.ACCEPTED)
        self.assertEqual(check(main.DB_PATH, self.first_post_mint(fresh, 100_001))[0], blockchain.REJECTED)

        _, token, wallet = self.register()
        self.upload(token)
        self.assertEqual(check(main.DB_PATH, self.first_post_mint(wallet, 1_000))[0], blockchain.REJECTED)


if __name__ == "__main__":
    unittest.main()
