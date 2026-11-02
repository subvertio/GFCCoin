"""
RPC trust, key separation and service limits (audit F09, F12, F14): GPT's demonstrations,
turned into checks that the attack no longer works. No chain needed: fake RPC providers
answer with whatever the test says.

Run from the repository root:
    python -m unittest tests.test_bridge_rpc_trust -v
"""

import json
import os
from datetime import datetime, timezone
import unittest
import uuid
from pathlib import Path
from unittest import mock

from test_bridge_ledger import CHAIN, EVM, _TMP, EscrowTestCase, mint, new_ledger, send  # noqa: E402

import blockchain  # noqa: E402
import signing  # noqa: E402
from bridge import __main__ as cli  # noqa: E402
from bridge import keyfiles, releases  # noqa: E402
from bridge.chain import TOPIC_BRIDGED_OUT, Chain, BridgeContract, RPCError  # noqa: E402
from bridge.config import BridgeConfig, read_evm_key  # noqa: E402
from bridge.store import HELD, PAID, WAITING, Store  # noqa: E402

BRIDGE = "0x" + "12" * 20
EVM_TX = "0x" + "78" * 32


def burn_log(wallet, cents=100_00, nonce=1, block=99, tx=EVM_TX, index=0, **changes):
    log = {"address": BRIDGE, "topics": [TOPIC_BRIDGED_OUT, "0x" + format(nonce, "064x"), "0x" + "00" * 12 + EVM[2:],
                                         "0x" + wallet],
           "data": "0x" + format(cents, "064x"), "blockNumber": hex(block), "transactionHash": tx,
           "blockHash": "0x" + format(block, "064x"), "logIndex": hex(index), "removed": False}
    log.update(changes)
    return log


def receipt(*logs, status="0x1"):
    return {"status": status, "blockNumber": logs[0]["blockNumber"], "blockHash": logs[0]["blockHash"],
            "transactionHash": logs[0]["transactionHash"], "logs": list(logs)}


class FakeRPC(Chain):
    """An RPC provider that answers from the test's data: honest or not, as the test sets it up."""
    def __init__(self, label="main rpc", logs=(), receipts=None, head=100):
        self.label, self.logs_, self.receipts, self.head = label, list(logs), dict(receipts or {}), head

    def rpc(self, method, params):
        if method == "eth_getBlockByNumber":
            n = self.head if params[0] in ("finalized", "safe", "latest") else int(params[0], 16)
            return {"number": hex(n), "hash": "0x" + format(n, "064x")}
        if method == "eth_getLogs":
            return list(self.logs_)
        if method == "eth_getTransactionReceipt":
            return self.receipts.get(params[0])
        raise AssertionError(method)


class RPCTrustTests(EscrowTestCase):
    def setUp(self):
        super().setUp()
        self.db = new_ledger()
        self.priv, self.pub = signing.generate_keypair()
        self.b_priv, self.b = signing.generate_keypair()
        mint(self.db, self.pub, 1_000_00)
        (status, _), _ = send(self.db, self.priv, self.pub, self.escrow_pub, 500_00, f"bridge:v1:{CHAIN}:{EVM}")
        self.assertEqual(status, blockchain.ACCEPTED)
        self.cfg = BridgeConfig(rpc_url="", chain_id=CHAIN, bridge_address=BRIDGE, escrow_wallet=self.escrow_pub,
                                ledger_db=self.db, state_db=str(Path(_TMP) / f"state-{uuid.uuid4().hex[:8]}.db"),
                                start_block=0)
        self.store = Store(self.cfg.state_db)

    def scan_and_pay(self, main, *verifiers):
        releases.scan_bridged_out(self.cfg, self.store, BridgeContract(main, BRIDGE), verifiers)
        releases.pay_releases(self.cfg, self.store, self.escrow_priv)
        return blockchain.get_balance_cents(self.db, self.b)

    # ---- F09: one dishonest RPC can't get a burn paid ----

    def test_a_forged_log_without_a_receipt_is_never_paid(self):
        """GPT's demonstration: a made-up BridgedOut log, and nothing else behind it."""
        self.assertEqual(self.scan_and_pay(FakeRPC(logs=[burn_log(self.b)])), 0)
        r = self.store.releases()[0]
        self.assertEqual(r["status"], WAITING)
        self.assertIn("no receipt", r["detail"])
        self.assertFalse(r["verified_at"])

    def test_a_consistent_liar_is_outvoted_by_an_independent_provider(self):
        log = burn_log(self.b)
        liar = FakeRPC(logs=[log], receipts={EVM_TX: receipt(log)})
        honest = FakeRPC("verify rpc #1")  # never saw that transaction
        self.assertEqual(self.scan_and_pay(liar, honest), 0)
        self.assertIn("verify rpc #1: no receipt", self.store.releases()[0]["detail"])

        # A provider that contradicts the others stops verification for the pass
        other = burn_log(self.b, cents=1_00)
        contradicting = FakeRPC("verify rpc #1", receipts={EVM_TX: receipt(other)})
        self.assertEqual(self.scan_and_pay(liar, contradicting), 0)
        self.assertIn("differs", self.store.releases()[0]["detail"])

    def test_a_burn_every_provider_confirms_is_paid_once(self):
        log = burn_log(self.b)
        main = FakeRPC(logs=[log], receipts={EVM_TX: receipt(log)})
        verifier = FakeRPC("verify rpc #1", receipts={EVM_TX: receipt(log)})
        self.assertEqual(self.scan_and_pay(main, verifier), 100_00)
        self.assertEqual(self.store.releases()[0]["status"], PAID)
        self.assertEqual(self.scan_and_pay(main, verifier), 100_00)

    def test_a_burn_a_verifier_doesnt_treat_as_final_waits(self):
        log = burn_log(self.b)
        main = FakeRPC(logs=[log], receipts={EVM_TX: receipt(log)})
        behind = FakeRPC("verify rpc #1", receipts={EVM_TX: receipt(log)}, head=50)
        self.assertEqual(self.scan_and_pay(main, behind), 0)
        self.assertIn("not final yet", self.store.releases()[0]["detail"])
        behind.head = 100
        self.assertEqual(self.scan_and_pay(main, behind), 100_00)

    def test_a_reverted_or_moved_receipt_isnt_a_confirmation(self):
        log = burn_log(self.b)
        main = FakeRPC(logs=[log], receipts={EVM_TX: receipt(log, status="0x0")})
        self.assertEqual(self.scan_and_pay(main), 0)
        self.assertIn("reverted", self.store.releases()[0]["detail"])
        main.receipts[EVM_TX] = receipt(burn_log(self.b, blockHash="0x" + "ee" * 32))
        self.assertEqual(self.scan_and_pay(main), 0)
        self.assertIn("different block", self.store.releases()[0]["detail"])

    def test_malformed_logs_stop_the_scan_without_losing_the_cursor(self):
        for bad in (burn_log(self.b, address="0x" + "34" * 20), burn_log(self.b, removed=True),
                    burn_log(self.b, data="0x01"), burn_log(self.b, topics=[TOPIC_BRIDGED_OUT, "0x01"]),
                    burn_log(self.b, block=500)):
            with self.assertRaises(RPCError):
                releases.scan_bridged_out(self.cfg, self.store, BridgeContract(FakeRPC(logs=[bad]), BRIDGE))
            self.assertEqual(self.store.get_meta(releases.CURSOR_KEY, "0"), "0")
        self.assertEqual(self.store.releases(), [])

    def test_two_different_events_for_one_nonce_are_held(self):
        first = burn_log(self.b)
        releases.scan_bridged_out(self.cfg, self.store, BridgeContract(FakeRPC(logs=[first]), BRIDGE))
        self.store.set_meta(releases.CURSOR_KEY, "0")
        second = burn_log(self.b, cents=400_00, tx="0x" + "79" * 32)
        releases.scan_bridged_out(self.cfg, self.store, BridgeContract(FakeRPC(logs=[second]), BRIDGE))
        r = self.store.releases()[0]
        self.assertEqual((r["status"], r["amount_cents"]), (HELD, 100_00))
        self.assertIn("two different events", r["detail"])

    # ---- F09 / F14: mainnet refuses single-provider and single-machine setups ----

    def test_mainnet_needs_finalized_blocks_and_an_independent_provider(self):
        main = BridgeConfig(rpc_url="https://a", chain_id=8453, bridge_address=BRIDGE, escrow_wallet="e",
                            ledger_db="", state_db="", chain_finality="safe")
        problems = main.mainnet_problems()
        self.assertTrue(any("finalized" in p for p in problems))
        self.assertTrue(any("VERIFY_RPC_URLS" in p for p in problems))
        from dataclasses import replace
        self.assertTrue(any("CHECKPOINT" in p for p in problems))
        self.assertEqual(replace(main, chain_finality="finalized", verify_rpc_urls=["https://b"],
                                 checkpoint_url="https://node", checkpoint_pubkeys=["ab" * 32],
                                 deposits_from=datetime.now(timezone.utc)).mainnet_problems(), [])
        self.assertEqual(replace(main, chain_id=84532).mainnet_problems(), [])

    def test_key_checks_refuse_a_quorum_plain_keys_and_shared_wallets(self):
        d = Path(_TMP) / f"keys-{uuid.uuid4().hex[:8]}"
        d.mkdir()
        plain = d / "relayer.key"
        plain.write_text("0x" + "11" * 32)
        with mock.patch.dict(os.environ, {"GFC_BRIDGE_KEY_PASSPHRASE": "a test passphrase"}):
            addr = keyfiles.write_evm_keystore(str(d / "attester.json"), "a test passphrase")
            from eth_account import Account
            self.assertEqual(Account.from_key(read_evm_key(str(d / "attester.json"))).address, addr)
        self.assertNotIn("11" * 32, (d / "attester.json").read_text())

        with mock.patch.object(keyfiles, "access_problem", return_value=None):
            problems = cli.key_problems(self.cfg, {"relayer": str(plain), "attester 1": str(d / "attester.json"),
                                                   "attester 2": str(d / "attester.json")})
        self.assertTrue(any("2 attester keys in one service" in p for p in problems))
        self.assertTrue(any("relayer key file is plain text" in p for p in problems))
        self.assertFalse(any("attester 1 key file" in p for p in problems))
        with mock.patch.object(keyfiles, "access_problem", return_value="readable by everyone"):
            self.assertIn("the relayer key file is readable by everyone",
                          cli.key_problems(self.cfg, {"relayer": str(plain)}))
        self.assertTrue(cli._distinct({"relayer": "0x" + "11" * 32, "pauser": "0x" + "11" * 32}))

    # ---- F12: errors don't leak the RPC URL ----

    def test_rpc_errors_never_include_the_url(self):
        chain = Chain("http://127.0.0.1:9/secret-api-key", timeout=2, label="main rpc")
        with self.assertRaises(RPCError) as caught:
            chain.chain_id()
        self.assertNotIn("secret-api-key", str(caught.exception))
        self.assertIn("main rpc", str(caught.exception))


class StuckNonceRPC(Chain):
    """A node that already holds a tx at the next nonce and refuses equal-fee replacements, and that
    rate-limits the first receipt poll (both seen on mainnet, 2026-11-02)."""
    def __init__(self, holding_fee: int, refuse_receipts: int = 1):
        self.label, self.holding_fee, self.refuse_receipts, self.sent = "main rpc", holding_fee, refuse_receipts, []

    def chain_id(self):
        return 8453

    def rpc(self, method, params):
        if method == "eth_getBlockByNumber":
            return {"baseFeePerGas": hex(5_000_000)}
        if method == "eth_maxPriorityFeePerGas":
            return hex(1_000_000)
        if method == "eth_getTransactionCount":
            return hex(3)
        if method == "eth_sendRawTransaction":
            import rlp  # type 2: 0x02 || rlp([chainId, nonce, tip, maxFee, ...])
            fee = int.from_bytes(rlp.decode(bytes.fromhex(params[0][2:])[1:])[3], "big")
            self.sent.append(fee)
            if fee < self.holding_fee * 1.1:
                raise RPCError("eth_sendRawTransaction: replacement transaction underpriced")
            return "0x" + "ab" * 32
        if method == "eth_getTransactionReceipt":
            if self.refuse_receipts:
                self.refuse_receipts -= 1
                raise RPCError("main rpc eth_getTransactionReceipt: HTTP 403")
            return {"status": "0x1", "transactionHash": params[0]}
        raise AssertionError(method)


class StuckNonceTests(unittest.TestCase):
    KEY = "0x" + "11" * 32

    def test_resends_with_a_higher_fee_and_survives_a_refused_receipt_poll(self):
        normal = 2 * 5_000_000 + 1_000_000
        chain = StuckNonceRPC(holding_fee=normal)
        r = chain.send(self.KEY, BRIDGE, "0x", gas=100_000, max_fee_per_gas=10**9)
        self.assertEqual(r["status"], "0x1")
        self.assertEqual(chain.sent[0], normal)
        self.assertGreaterEqual(chain.sent[-1], normal * 1.1)

    def test_the_fee_cap_still_holds(self):
        chain = StuckNonceRPC(holding_fee=10**9)
        with self.assertRaises(RPCError):
            chain.send(self.KEY, BRIDGE, "0x", gas=100_000, max_fee_per_gas=20_000_000)
        self.assertTrue(all(f <= 20_000_000 for f in chain.sent))

    def test_other_send_errors_are_not_retried(self):
        class Broke(StuckNonceRPC):
            def rpc(self, method, params):
                if method == "eth_sendRawTransaction":
                    self.sent.append(1)
                    raise RPCError("eth_sendRawTransaction: insufficient funds")
                return super().rpc(method, params)
        chain = Broke(holding_fee=0)
        with self.assertRaises(RPCError):
            chain.send(self.KEY, BRIDGE, "0x", gas=100_000)
        self.assertEqual(len(chain.sent), 1)


class SwallowingRPC(StuckNonceRPC):
    """publicnode on 2026-11-02: takes a tx and returns its hash, never forwards it, and refuses
    receipt checks for it with HTTP 403."""
    def __init__(self, refuse_sends=False):
        super().__init__(holding_fee=0, refuse_receipts=0)
        self.refuse_sends, self.raw = refuse_sends, []

    def rpc(self, method, params):
        if method == "eth_sendRawTransaction":
            self.raw.append(params[0])
            if self.refuse_sends:
                raise RPCError("main rpc eth_sendRawTransaction: HTTP 403")
            return "0x" + "ab" * 32
        if method == "eth_getTransactionReceipt":
            raise RPCError("main rpc eth_getTransactionReceipt: HTTP 403")
        return super().rpc(method, params)


class HonestRPC(StuckNonceRPC):
    def __init__(self):
        super().__init__(holding_fee=0, refuse_receipts=0)
        self.label, self.raw = "verify rpc #1", []

    def rpc(self, method, params):
        if method == "eth_sendRawTransaction":
            self.raw.append(params[0])
            return "0x" + "ab" * 32
        return super().rpc(method, params)


class BroadcastTests(unittest.TestCase):
    KEY = "0x" + "11" * 32

    def test_every_tx_also_goes_out_through_the_broadcast_providers(self):
        main, other = SwallowingRPC(), HonestRPC()
        main.broadcast = [other]
        r = main.send(self.KEY, BRIDGE, "0x", gas=100_000)
        self.assertEqual(r["status"], "0x1")  # the receipt came from the honest provider
        self.assertEqual(main.raw, other.raw)  # the same signed tx went to both

    def test_a_refused_send_still_goes_out_through_another_provider(self):
        main, other = SwallowingRPC(refuse_sends=True), HonestRPC()
        main.broadcast = [other]
        self.assertEqual(main.send(self.KEY, BRIDGE, "0x", gas=100_000)["status"], "0x1")
        main.broadcast = []
        with self.assertRaises(RPCError):
            main.send(self.KEY, BRIDGE, "0x", gas=100_000)

    def test_a_refused_receipt_check_does_not_fail_the_relay_pass(self):
        from bridge import relayer

        class Bridge:
            chain = SwallowingRPC()
        self.assertTrue(relayer._no_receipt(Bridge(), "0x" + "cd" * 32))


if __name__ == "__main__":
    unittest.main(verbosity=2)
