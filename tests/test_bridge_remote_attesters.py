"""
Attesters on their own machines (bridge/attester_http.py): a real signing endpoint on a
local port, with its own ledger, and the relayer's client for it. No chain needed.

Run from the repository root:
    python -m unittest discover -s tests -p "test_bridge_remote_attesters.py" -v
"""

import json
import threading
import time
import unittest
import uuid
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from test_bridge_ledger import CHAIN, EVM, _TMP, EscrowTestCase, mint, new_ledger, send  # noqa: E402

import httpx  # noqa: E402
from eth_account import Account  # noqa: E402

import signing  # noqa: E402
from bridge import attester_http, eip712, relayer  # noqa: E402
from bridge.attester import Attester  # noqa: E402
from bridge.config import BridgeConfig  # noqa: E402
from bridge.store import Store  # noqa: E402

BRIDGE = "0x" + "12" * 20
SECRET = attester_http.new_secret().encode()


class FakeBridge:
    """Just enough of GFCBridge for relay(): nothing minted yet, threshold 2."""
    class chain:
        @staticmethod
        def final_block(tag):
            return 0

    def paused(self):
        return False

    def processed(self, h, block="latest"):
        return False

    def threshold(self):
        return 2

    def max_mint_cents(self):
        return 10 ** 12

    def remaining_in_window_cents(self):
        return 10 ** 12


class RemoteAttesterTests(EscrowTestCase):
    def setUp(self):
        super().setUp()
        self.db = new_ledger()  # the attester machine's own ledger node
        self.priv, self.pub = signing.generate_keypair()
        mint(self.db, self.pub, 1_000_00)
        (_, _), self.dep = send(self.db, self.priv, self.pub, self.escrow_pub, 200_00, f"bridge:v1:{CHAIN}:{EVM}")
        self.cfg = BridgeConfig(rpc_url="", chain_id=CHAIN, bridge_address=BRIDGE, escrow_wallet=self.escrow_pub,
                                ledger_db=self.db, state_db=str(Path(_TMP) / f"state-{uuid.uuid4().hex[:8]}.db"),
                                finality_seconds=0)
        self.key = Account.create()
        self.server = self.serve(Attester(self.cfg, key=self.key.key.hex()))
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"

    def serve(self, attester, secret=SECRET):
        server = attester_http.make_server(attester, secret, "127.0.0.1", 0)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server

    def client(self, secret=SECRET, url=None, cfg=None):
        return attester_http.RemoteAttester(cfg or self.cfg, url or self.url, secret)

    def ask(self, client, cents=200_00, deadline=None, tx_hash=None):
        return client.attest(tx_hash or self.dep["tx_hash"], EVM, cents, deadline or int(time.time()) + 600)

    def test_a_real_deposit_is_signed_by_that_attester(self):
        c = self.client()
        self.assertEqual(c.address, self.key.address)
        deadline = int(time.time()) + 600
        result = self.ask(c, deadline=deadline)
        self.assertIsNotNone(result.signature, result.refusal)
        req = eip712.mint_request(self.dep["tx_hash"], EVM, 200_00, deadline)
        self.assertEqual(eip712.recover_signer(CHAIN, BRIDGE, req, result.signature), self.key.address)

    def test_the_attester_signs_only_what_its_own_ledger_shows(self):
        c = self.client()
        self.assertIn("request does not match", self.ask(c, cents=300_00).refusal)
        missing = self.ask(c, tx_hash="ab" * 32)
        self.assertIn("not on this attester's ledger", missing.refusal)
        self.assertTrue(missing.retry)
        self.assertIn("deadline", self.ask(c, deadline=int(time.time()) + 10 * 3600).refusal)

    def test_requests_without_the_shared_secret_are_refused(self):
        result = self.ask(self.client(secret=attester_http.new_secret().encode()))
        self.assertIsNone(result.signature)
        self.assertIn("HTTP 401", result.refusal)

        # A correctly signed request that's too old (a replay) is refused too
        body = json.dumps({"tx_hash": self.dep["tx_hash"], "evm_to": EVM, "mint_cents": 200_00,
                           "deadline": int(time.time()) + 600}).encode()
        old = int(time.time()) - 120
        resp = httpx.post(self.url + "/attest", content=body, headers={
            "X-GFC-Time": str(old), "X-GFC-Auth": attester_http.auth_header(SECRET, old, body)})
        self.assertEqual(resp.status_code, 401)

    def test_the_client_trusts_only_the_attesters_own_signature(self):
        class Impostor(Attester):  # a server that signs with some other key
            def attest(inner, *a, **kw):
                result = super().attest(*a, **kw)
                req = eip712.mint_request(a[0], a[1], a[2], a[3])
                result.signature = eip712.sign_mint(Account.create().key.hex(), CHAIN, BRIDGE, req)[1]
                return result
        server = self.serve(Impostor(self.cfg, key=self.key.key.hex()))
        c = self.client(url=f"http://127.0.0.1:{server.server_address[1]}")
        self.assertIn("bad signature", self.ask(c).refusal)

    def test_the_client_refuses_an_attester_for_another_bridge(self):
        with self.assertRaises(SystemExit):
            self.client(cfg=replace(self.cfg, bridge_address="0x" + "34" * 20))

    def test_the_deadline_is_recorded_before_any_attester_is_asked(self):
        """Even if every reply is lost, no refund before the deadline (audit F07)."""
        store = Store(self.cfg.state_db)
        relayer.scan_deposits(self.cfg, store)
        unreachable = self.client()
        unreachable.url = "http://127.0.0.1:9"
        relayer.relay(self.cfg, store, FakeBridge(), [unreachable], "0x" + "11" * 32)
        d = store.deposit(self.dep["tx_hash"])
        self.assertGreater(d["attested_until"], datetime.now(timezone.utc).timestamp())
        self.assertIn("unreachable", d["detail"])

    def test_mainnet_refuses_a_plain_http_attester_elsewhere(self):
        main = replace(self.cfg, chain_id=8453, chain_finality="finalized", rpc_url="https://a",
                       verify_rpc_urls=["https://b"], checkpoint_url="https://node", checkpoint_pubkeys=["ab" * 32])
        self.assertEqual(replace(main, remote_attester_urls=["https://att.example", "http://127.0.0.1:8300"]
                                 ).mainnet_problems(), [])
        self.assertTrue(replace(main, remote_attester_urls=["http://10.0.0.5:8300"]).mainnet_problems())


if __name__ == "__main__":
    unittest.main(verbosity=2)
