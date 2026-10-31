"""
Ledger side of the bridge: the escrow rules every node enforces, the cross-wallet hold on
fresh free credit, refunds, and the "Bridge to Base" API. No chain needed.

Run from the repository root:
    python -m unittest tests.test_bridge_ledger -v
"""

import os
import sqlite3
import sys
import tempfile
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

_TMP = tempfile.mkdtemp(prefix="gfc_bridge_ledger_")
_treasury = Ed25519PrivateKey.generate()
TREASURY_PRIV = _treasury.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex()
TREASURY_PUB = _treasury.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
os.environ.setdefault("GFC_DATA_DIR", _TMP)
os.environ.setdefault("GFC_TREASURY_PUBKEYS", TREASURY_PUB)
os.environ.setdefault("GFC_TREASURY_KEY_FILE", str(Path(_TMP) / "no_treasury_key.hex"))
os.environ.pop("GFC_FIREBASE_CONFIG", None)
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))  # firebase_stub

from fastapi.testclient import TestClient  # noqa: E402

import blockchain  # noqa: E402
import config  # noqa: E402
import main  # noqa: E402
import signing  # noqa: E402
from bridge import deposits, releases  # noqa: E402
from bridge.config import BridgeConfig  # noqa: E402
from bridge.store import REFUND, REFUNDED, Store  # noqa: E402
from firebase_stub import verify_phone  # noqa: E402

CHAIN = 84532
EVM = "0x" + "ab" * 20
NOW = datetime.now(timezone.utc)
OLD = NOW - timedelta(days=60)


def new_ledger() -> str:
    path = str(Path(_TMP) / f"node-{uuid.uuid4().hex[:8]}.db")
    saved = main.DB_PATH
    main.DB_PATH = path
    try:
        main.init_db()
    finally:
        main.DB_PATH = saved
    return path


def signed(priv: str, signer: str, **tx) -> dict:
    tx.setdefault("id", str(uuid.uuid4()))
    tx.setdefault("tx_type", blockchain.TX_TYPE_TRANSFER)
    tx.setdefault("timestamp", (NOW - timedelta(hours=2)).isoformat())
    tx["amount"] = tx["amount_cents"] / 100.0
    tx["tx_hash"] = blockchain.compute_tx_hash(tx)
    tx["signer"] = signer
    tx["signature"] = signing.sign_tx_hash(priv, tx["tx_hash"])
    return tx


def mint(db: str, wallet: str, cents: int, tx_type=blockchain.TX_TYPE_OPERATOR, when=OLD):
    reason = "Operator grant (other): bridge ledger test" if tx_type == blockchain.TX_TYPE_OPERATOR else "test"
    tx = signed(TREASURY_PRIV, TREASURY_PUB, sender=blockchain.TREASURY_WALLET_ID, recipient=wallet,
                amount_cents=cents, reason=reason, tx_type=tx_type, timestamp=when.isoformat())
    return blockchain.accept_synced_transaction(db, tx)


def send(db: str, priv: str, pub: str, to: str, cents: int, reason: str = "test", when=None):
    tx = signed(priv, pub, sender=pub, recipient=to, amount_cents=cents, reason=reason,
                timestamp=(when or NOW - timedelta(hours=2)).isoformat())
    return blockchain.accept_synced_transaction(db, tx), tx


class EscrowTestCase(unittest.TestCase):
    """Pins a test escrow for CHAIN, and our test treasury key, for each test."""

    def setUp(self):
        self.escrow_priv, self.escrow_pub = signing.generate_keypair()
        self._saved_escrows = dict(config.BRIDGE_ESCROWS)
        config.BRIDGE_ESCROWS.clear()
        config.BRIDGE_ESCROWS[CHAIN] = self.escrow_pub
        self._saved_pubkeys = signing.TREASURY_PUBKEYS
        signing.TREASURY_PUBKEYS = tuple(signing.TREASURY_PUBKEYS) + (TREASURY_PUB,)

    def tearDown(self):
        config.BRIDGE_ESCROWS.clear()
        config.BRIDGE_ESCROWS.update(self._saved_escrows)
        signing.TREASURY_PUBKEYS = self._saved_pubkeys


class EscrowRuleTests(EscrowTestCase):
    def setUp(self):
        super().setUp()
        self.db = new_ledger()
        self.priv, self.pub = signing.generate_keypair()
        mint(self.db, self.pub, 1_000_00)

    def test_deposit_must_name_the_escrow_chain_and_an_address(self):
        ok = lambda reason: send(self.db, self.priv, self.pub, self.escrow_pub, 100_00, reason)[0][0]
        self.assertEqual(ok("for the bridge"), blockchain.REJECTED)
        self.assertEqual(ok(f"bridge:v1:8453:{EVM}"), blockchain.REJECTED)  # another chain's escrow
        self.assertEqual(ok(f"bridge:v1:{CHAIN}:0x" + "0" * 40), blockchain.REJECTED)
        self.assertEqual(ok(f"bridge:v1:{CHAIN}:{EVM}"), blockchain.ACCEPTED)

    def test_rest_transfer_to_escrow_uses_the_same_rule(self):
        conn = sqlite3.connect(self.db)
        signing.init_wallet_keys_table(conn)
        conn.execute("INSERT INTO wallet_keys (wallet_id, private_key, created_at) VALUES (?, ?, ?)",
                     (self.pub, self.priv, NOW.isoformat()))
        conn.commit()
        conn.close()
        with self.assertRaisesRegex(ValueError, "bridge deposit needs"):
            blockchain.process_transfer(self.db, self.pub, self.escrow_pub, 100_00, "oops")
        tx = blockchain.process_transfer(self.db, self.pub, self.escrow_pub, 100_00, f"bridge:v1:{CHAIN}:{EVM}")
        self.assertTrue(tx["signature"])

    def test_no_mints_to_escrow(self):
        status, why = mint(self.db, self.escrow_pub, 100_00)
        self.assertEqual(status, blockchain.REJECTED)
        self.assertIn("escrow", why)

    def test_escrow_funds_leave_only_as_payouts_or_refunds(self):
        (status, _), dep = send(self.db, self.priv, self.pub, self.escrow_pub, 500_00, f"bridge:v1:{CHAIN}:{EVM}")
        self.assertEqual(status, blockchain.ACCEPTED)
        out = lambda reason, to=self.pub, cents=10_00: send(self.db, self.escrow_priv, self.escrow_pub, to,
                                                            cents, reason)[0][0]
        self.assertEqual(out("thanks"), blockchain.REJECTED)
        self.assertEqual(out(f"bridge-out:v1:8453:1:0x{'aa' * 32}"), blockchain.REJECTED)  # wrong chain
        self.assertEqual(out(f"bridge-out:v1:{CHAIN}:1:0x{'aa' * 32}"), blockchain.ACCEPTED)
        self.assertEqual(out(f"bridge-refund:v1:{dep['tx_hash']}"), blockchain.ACCEPTED)

        _, other_escrow = signing.generate_keypair()
        config.BRIDGE_ESCROWS[8453] = other_escrow
        self.assertEqual(out(f"bridge:v1:8453:{EVM}", to=other_escrow), blockchain.REJECTED)

    def test_no_rules_without_a_pinned_escrow(self):
        config.BRIDGE_ESCROWS.clear()
        self.assertIsNone(blockchain.bridge_rule_violation(self.pub, self.escrow_pub, "anything"))


class FreshCreditTraceTests(EscrowTestCase):
    def setUp(self):
        super().setUp()
        self.db = new_ledger()
        self.conn = sqlite3.connect(self.db)
        self.wallets = [signing.generate_keypair() for _ in range(6)]

    def tearDown(self):
        self.conn.close()
        super().tearDown()

    def clean(self, i: int, hold=14) -> tuple:
        return deposits.clean_cents(self.conn, self.wallets[i][1], NOW, hold, exclude=frozenset([self.escrow_pub]))

    def test_direct_grant_is_held_until_it_ages(self):
        a = self.wallets[0][1]
        mint(self.db, a, blockchain.NEW_USER_GRANT_CENTS, blockchain.TX_TYPE_GRANT, when=NOW - timedelta(days=3))
        mint(self.db, a, 500_00)
        self.assertEqual(self.clean(0), (600_00, 500_00))
        self.assertEqual(self.clean(0, hold=2), (600_00, 600_00))

    def test_grant_passed_through_other_wallets_is_still_held(self):
        (pa, a), (pb, b), (pc, c) = self.wallets[:3]
        mint(self.db, a, blockchain.NEW_USER_GRANT_CENTS, blockchain.TX_TYPE_GRANT, when=NOW - timedelta(days=1))
        mint(self.db, c, 500_00)
        send(self.db, pa, a, b, 100_00)
        send(self.db, pb, b, c, 100_00)
        # c holds 600: 500 clean, 100 that is the grant passed on twice
        self.assertEqual(self.clean(2), (600_00, 500_00))

    def test_only_the_fresh_part_of_a_transfer_counts(self):
        (pa, a), (pb, b) = self.wallets[:2]
        mint(self.db, a, blockchain.NEW_USER_GRANT_CENTS, blockchain.TX_TYPE_GRANT, when=NOW - timedelta(days=1))
        mint(self.db, a, 900_00)
        send(self.db, pa, a, b, 400_00)  # at most 100 of it can be the grant
        self.assertEqual(self.clean(1), (400_00, 300_00))

    def test_beyond_the_trace_depth_counts_as_fresh(self):
        keys = self.wallets
        mint(self.db, keys[0][1], 500_00)  # old, clean money
        for i in range(3):  # 0 -> 1 -> 2 -> 3, all recent: traced back to clean money
            send(self.db, keys[i][0], keys[i][1], keys[i + 1][1], 500_00)
        self.assertEqual(self.clean(3), (500_00, 500_00))
        for i in range(3, 5):  # -> 4 -> 5: wallet 0 is now beyond FRESH_TRACE_DEPTH hops
            send(self.db, keys[i][0], keys[i][1], keys[i + 1][1], 500_00)
        self.assertEqual(self.clean(5), (500_00, 0))

    def test_cycles_and_old_transfers_are_fine(self):
        (pa, a), (pb, b) = self.wallets[:2]
        mint(self.db, a, 500_00)
        send(self.db, pa, a, b, 300_00, when=NOW - timedelta(days=30))
        send(self.db, pb, b, a, 100_00)
        send(self.db, pa, a, b, 100_00)
        self.assertEqual(self.clean(0), (200_00, 200_00))
        self.assertEqual(self.clean(1), (300_00, 300_00))

    def test_bridge_payouts_are_clean(self):
        (pa, a), (pb, b) = self.wallets[:2]
        mint(self.db, a, 500_00)
        send(self.db, pa, a, self.escrow_pub, 500_00, f"bridge:v1:{CHAIN}:{EVM}")
        send(self.db, self.escrow_priv, self.escrow_pub, b, 200_00, f"bridge-out:v1:{CHAIN}:1:0x{'aa' * 32}")
        self.assertEqual(self.clean(1), (200_00, 200_00))


class RefundTests(EscrowTestCase):
    def test_refund_is_paid_once(self):
        db = new_ledger()
        priv, pub = signing.generate_keypair()
        mint(db, pub, 1_000_00)
        (status, _), dep = send(db, priv, pub, self.escrow_pub, 50_00, f"bridge:v1:{CHAIN}:{EVM}")
        self.assertEqual(status, blockchain.ACCEPTED)
        cfg = BridgeConfig(rpc_url="", chain_id=CHAIN, bridge_address="0x" + "11" * 20,
                           escrow_wallet=self.escrow_pub, ledger_db=db,
                           state_db=str(Path(_TMP) / f"state-{uuid.uuid4().hex[:8]}.db"), finality_seconds=60)
        store = Store(cfg.state_db)
        conn = sqlite3.connect(db)
        result, _, d = deposits.validate_deposit(deposits.deposit_by_hash(conn, dep["tx_hash"]), cfg)
        conn.close()
        self.assertEqual(result, deposits.REFUND)  # under the 100 GFC minimum
        store.add_deposit(d, REFUND)

        releases.refund_deposit(cfg, store, self.escrow_priv, dep["tx_hash"])
        self.assertEqual(store.deposit(dep["tx_hash"])["status"], REFUNDED)
        self.assertEqual(blockchain.get_balance_cents(db, pub), 1_000_00)
        with self.assertRaises(ValueError):
            releases.refund_deposit(cfg, store, self.escrow_priv, dep["tx_hash"])
        self.assertEqual(blockchain.get_balance_cents(db, self.escrow_pub), 0)


class BridgeApiTests(EscrowTestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(main.app)

    def register(self, username: str):
        r = self.client.post("/auth/register", data={"username": username, "password": "pw-" + username})
        self.assertEqual(r.status_code, 200, r.text)
        token = r.json()["token"]
        self.assertIn("You're verified", verify_phone(self.client, token, "+1555" + str(uuid.uuid4().int)[:7]).text)
        w = self.client.post("/wallets/create", data={"name": "main"}, headers=self.auth(token))
        self.assertEqual(w.status_code, 200, w.text)
        return token, w.json()["id"]

    @staticmethod
    def auth(token: str) -> dict:
        return {"Authorization": f"Bearer {token}"}

    def deposit(self, token: str, wallet: str, amount: float, chain=CHAIN, evm=EVM):
        return self.client.post("/bridge/deposit", headers=self.auth(token), json={
            "wallet_id": wallet, "chain_id": chain, "evm_address": evm, "amount": amount})

    def test_info_lists_pinned_chains(self):
        info = self.client.get("/bridge/info").json()
        self.assertTrue(info["enabled"])
        self.assertEqual(info["chains"][0]["chain_id"], CHAIN)
        self.assertEqual(info["chains"][0]["name"], "Base Sepolia")
        self.assertEqual(info["chains"][0]["escrow_wallet"], self.escrow_pub)
        self.assertIsNone(info["chains"][0]["token_address"])
        config.BRIDGE_ESCROWS.clear()
        self.assertFalse(self.client.get("/bridge/info").json()["enabled"])

    def test_deposit_flow(self):
        name = "br" + uuid.uuid4().hex[:8]
        token, wallet = self.register(name)  # 100 GFC welcome grant: fresh, so held
        self.assertEqual(mint(main.DB_PATH, wallet, 500_00)[0], blockchain.ACCEPTED)

        quote = self.client.get("/bridge/quote", params={"wallet_id": wallet}).json()
        self.assertEqual((quote["balance_cents"], quote["bridgeable_cents"]), (600_00, 500_00))

        r = self.deposit(token, wallet, 150)
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        self.assertEqual(body["mint_cents"], 150_00 - config.BRIDGE_RELAY_FEE_CENTS)
        conn = sqlite3.connect(main.DB_PATH)
        row = conn.execute("SELECT recipient, reason, signature, block_index FROM transactions WHERE id = ?",
                           (body["tx_id"],)).fetchone()
        conn.close()
        self.assertEqual(row[0], self.escrow_pub)
        self.assertEqual(row[1], f"bridge:v1:{CHAIN}:{EVM}")
        self.assertTrue(row[2])
        self.assertIsNotNone(row[3])

        held = self.deposit(token, wallet, 400)  # 350 bridgeable left; the other 100 is the grant
        self.assertEqual(held.status_code, 400)
        self.assertIn("only 350.00 GFC can be bridged now", held.json()["detail"])
        self.assertEqual(self.deposit(token, wallet, 50).status_code, 400)               # under the minimum
        self.assertEqual(self.deposit(token, wallet, 150, chain=8453).status_code, 400)  # no escrow there
        self.assertEqual(self.deposit(token, wallet, 150, evm="0x1234").status_code, 400)

        other_token, _ = self.register("bo" + uuid.uuid4().hex[:8])
        self.assertEqual(self.deposit(other_token, wallet, 150).status_code, 403)
        self.assertEqual(self.client.post("/bridge/deposit", json={
            "wallet_id": wallet, "chain_id": CHAIN, "evm_address": EVM, "amount": 150}).status_code, 401)


if __name__ == "__main__":
    unittest.main()
