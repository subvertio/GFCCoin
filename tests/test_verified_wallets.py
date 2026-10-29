"""
Tests for network-wide proof of phone verification (verified_wallets.py): the treasury
node signs records, and on the real network peers only take posts from verified accounts.

Run from the repository root:
    python -m unittest discover -s tests -v
"""

import os
import sqlite3
import sys
import unittest
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_signed_ledger  # noqa: F401  (sets up the isolated data dir and a test treasury first)
from test_signed_ledger import as_treasury_node, mark_verified, new_node

from fastapi.testclient import TestClient  # noqa: E402

import config  # noqa: E402
import main  # noqa: E402
import signing  # noqa: E402
import verified_wallets  # noqa: E402
from sync_ingest import TABLE_COLUMNS, ingest_rows, select_rows_since  # noqa: E402

RECORD_COLUMNS = [c.strip() for c in TABLE_COLUMNS["verified_wallets"].split(",")]


class VerifiedWalletTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(main.app)

    def setUp(self):
        self._saved = config.REQUIRE_PHONE_TO_POST

    def tearDown(self):
        config.REQUIRE_PHONE_TO_POST = self._saved

    # ---------- helpers ----------

    def account(self, verified=True):
        """An account on the treasury node (main.DB_PATH) with a wallet and one post."""
        name = "v" + uuid.uuid4().hex[:10]
        token = self.client.post("/auth/register", data={"username": name, "password": "pw-" + name}).json()["token"]
        wallet = self.client.post("/wallets/create", data={"name": "main", "api_token": token}).json()["id"]
        if verified:
            mark_verified(main.DB_PATH, name)
        files = {"file": ("art.bin", os.urandom(4096), "application/octet-stream")}
        config.REQUIRE_PHONE_TO_POST = False  # post on the home node regardless; peers decide
        seed = self.client.post("/seeds/upload", data={"api_token": token, "title": "art"}, files=files).json()
        return name, wallet, seed["id"]

    def export(self, table, key, value):
        conn = sqlite3.connect(main.DB_PATH)
        try:
            rows = select_rows_since(conn, table, "", 10_000)
        finally:
            conn.close()
        cols = [c.strip() for c in TABLE_COLUMNS[table].split(",")]
        return cols, [list(r) for r in rows if r[cols.index(key)] == value]

    def in_seeds(self, db, sid):
        conn = sqlite3.connect(db)
        try:
            return conn.execute("SELECT 1 FROM seeds WHERE id = ?", (sid,)).fetchone() is not None
        finally:
            conn.close()

    def in_quarantine(self, db, sid):
        conn = sqlite3.connect(db)
        try:
            verified_wallets.init_tables(conn)
            return conn.execute("SELECT 1 FROM seed_quarantine WHERE id = ?", (sid,)).fetchone() is not None
        finally:
            conn.close()

    # ---------- issuing ----------

    def test_treasury_node_issues_records_for_verified_accounts(self):
        name, wallet, _ = self.account()
        with as_treasury_node():
            self.assertEqual(verified_wallets.attest(main.DB_PATH, name), 1)
            self.assertEqual(verified_wallets.attest(main.DB_PATH, name), 0)  # once per wallet
        conn = sqlite3.connect(main.DB_PATH)
        try:
            self.assertTrue(verified_wallets.is_verified_wallet(conn, name, wallet))
            self.assertTrue(verified_wallets.is_verified_wallet(conn, name.upper(), wallet))
            self.assertFalse(verified_wallets.is_verified_wallet(conn, "someone_else", wallet))
        finally:
            conn.close()

    def test_no_records_without_the_treasury_key_or_a_verified_phone(self):
        name, _, _ = self.account()
        self.assertEqual(verified_wallets.attest(main.DB_PATH, name), 0)  # not a treasury node
        unverified, _, _ = self.account(verified=False)
        with as_treasury_node():
            self.assertEqual(verified_wallets.attest(main.DB_PATH, unverified), 0)

    def test_backfill_covers_accounts_verified_before_records_existed(self):
        name, wallet, _ = self.account()
        with as_treasury_node():
            self.assertGreaterEqual(verified_wallets.backfill(main.DB_PATH), 1)
        _, rows = self.export("verified_wallets", "wallet", wallet)
        self.assertEqual(len(rows), 1)

    # ---------- peers on the real network ----------

    def test_verified_accounts_posts_sync_normally(self):
        name, wallet, sid = self.account()
        with as_treasury_node():
            verified_wallets.attest(main.DB_PATH, name)
        peer = new_node("vw_ok_" + uuid.uuid4().hex[:6])
        config.REQUIRE_PHONE_TO_POST = True
        cols, rows = self.export("verified_wallets", "wallet", wallet)
        self.assertEqual(ingest_rows("verified_wallets", cols, rows, db_path=peer)["inserted"], 1)
        cols, rows = self.export("seeds", "id", sid)
        result = ingest_rows("seeds", cols, rows, db_path=peer)
        self.assertEqual(result["inserted"], 1, result)
        self.assertTrue(self.in_seeds(peer, sid))

    def test_unverified_posts_wait_until_the_account_verifies(self):
        name, wallet, sid = self.account(verified=False)
        peer = new_node("vw_wait_" + uuid.uuid4().hex[:6])
        config.REQUIRE_PHONE_TO_POST = True
        cols, rows = self.export("seeds", "id", sid)
        result = ingest_rows("seeds", cols, rows, db_path=peer)
        self.assertEqual((result["inserted"], result["pending"]), (0, 1), result)
        self.assertFalse(self.in_seeds(peer, sid))
        self.assertTrue(self.in_quarantine(peer, sid))
        # Held posts aren't passed on to other peers
        conn = sqlite3.connect(peer)
        try:
            ids = [r[0] for r in select_rows_since(conn, "seeds", "", 10_000)]
        finally:
            conn.close()
        self.assertNotIn(sid, ids)

        # The account verifies on the treasury node; its record reaches the peer
        mark_verified(main.DB_PATH, name)
        with as_treasury_node():
            verified_wallets.attest(main.DB_PATH, name)
        cols, rows = self.export("verified_wallets", "wallet", wallet)
        ingest_rows("verified_wallets", cols, rows, db_path=peer)
        self.assertTrue(self.in_seeds(peer, sid))
        self.assertFalse(self.in_quarantine(peer, sid))

    def test_forged_and_borrowed_records_dont_count(self):
        name, wallet, sid = self.account()
        peer = new_node("vw_forged_" + uuid.uuid4().hex[:6])
        config.REQUIRE_PHONE_TO_POST = True

        # Signed by a key that isn't a pinned treasury key
        fake_priv, fake_pub = signing.generate_keypair()
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        record = {"username": name, "wallet": wallet, "verified_at": "2026-10-29T00:00:00", "signer": fake_pub}
        record["signature"] = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(fake_priv)).sign(
            verified_wallets._message(record)).hex()
        record["id"] = verified_wallets.record_id(record)
        result = ingest_rows("verified_wallets", RECORD_COLUMNS, [[record[c] for c in RECORD_COLUMNS]], db_path=peer)
        self.assertEqual(result["rejected"], 1)

        # A genuine record for another account's wallet doesn't verify this post
        other, other_wallet, _ = self.account()
        config.REQUIRE_PHONE_TO_POST = True
        with as_treasury_node():
            verified_wallets.attest(main.DB_PATH, other)
        cols, rows = self.export("verified_wallets", "wallet", other_wallet)
        ingest_rows("verified_wallets", cols, rows, db_path=peer)
        cols, rows = self.export("seeds", "id", sid)
        self.assertEqual(ingest_rows("seeds", cols, rows, db_path=peer)["pending"], 1)
        self.assertFalse(self.in_seeds(peer, sid))

    def test_edits_apply_when_a_held_post_is_released(self):
        name, wallet, sid = self.account(verified=False)
        token = self.client.post("/auth/login", data={"username": name, "password": "pw-" + name}).json()["token"]
        r = self.client.post(f"/seeds/{sid}/edit", data={"api_token": token, "title": "fixed title"})
        self.assertEqual(r.status_code, 200, r.text)
        peer = new_node("vw_edit_" + uuid.uuid4().hex[:6])
        config.REQUIRE_PHONE_TO_POST = True
        cols, rows = self.export("seeds", "id", sid)
        rows[0][cols.index("title")] = "art"  # arrives with its original text
        ingest_rows("seeds", cols, rows, db_path=peer)
        cols, rows = self.export("seed_edits", "seed_id", sid)
        ingest_rows("seed_edits", cols, rows, db_path=peer)

        mark_verified(main.DB_PATH, name)
        with as_treasury_node():
            verified_wallets.attest(main.DB_PATH, name)
        cols, rows = self.export("verified_wallets", "wallet", wallet)
        ingest_rows("verified_wallets", cols, rows, db_path=peer)
        conn = sqlite3.connect(peer)
        try:
            self.assertEqual(conn.execute("SELECT title FROM seeds WHERE id = ?", (sid,)).fetchone()[0], "fixed title")
        finally:
            conn.close()

    def test_test_networks_take_unverified_posts(self):
        _, _, sid = self.account(verified=False)
        peer = new_node("vw_testnet_" + uuid.uuid4().hex[:6])
        config.REQUIRE_PHONE_TO_POST = False
        cols, rows = self.export("seeds", "id", sid)
        self.assertEqual(ingest_rows("seeds", cols, rows, db_path=peer)["inserted"], 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
