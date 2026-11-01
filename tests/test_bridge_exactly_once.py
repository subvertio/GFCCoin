"""
Exactly-once payouts, refunds and mints (audit F04, F05, F06, F07, F10): GPT's demonstrations,
turned into checks that the attack no longer works. No chain needed: a fake bridge stands in
for the contract where one is used.

Run from the repository root:
    python -m unittest tests.test_bridge_exactly_once -v
"""

import json
import sqlite3
import unittest
import uuid
from datetime import timedelta
from pathlib import Path

from test_bridge_ledger import (CHAIN, EVM, NOW, OLD, _TMP, EscrowTestCase, mint, new_ledger, send,  # noqa: E402
                                signed)

import blockchain  # noqa: E402
import signing  # noqa: E402
from bridge import deposits, releases  # noqa: E402
from bridge.config import BridgeConfig  # noqa: E402
from bridge.store import HELD, MINTED, PAID, REFUND, REFUNDED, SEEN, SUBMITTED, WAITING, Store  # noqa: E402

BRIDGE = "0x" + "12" * 20
EVM_TX = "0x" + "56" * 32


class FakeChain:
    def __init__(self, final=100):
        self.final = final

    def final_block(self, tag):
        return self.final


class FakeBridge:
    """processed() at "latest" and at the finalized block, set by the test."""
    def __init__(self, processed_latest=False, processed_final=False):
        self.chain = FakeChain()
        self.latest, self.at_final = processed_latest, processed_final

    def processed(self, h, block="latest"):
        return self.latest if block == "latest" else self.at_final

    def paused(self):
        return True  # settle_mints runs; nothing new is relayed


class ExactlyOnceTest(EscrowTestCase):
    def setUp(self):
        super().setUp()
        self.db = new_ledger()
        self.priv, self.pub = signing.generate_keypair()          # a depositor
        self.b_priv, self.b = signing.generate_keypair()           # a bridge-out's ledger wallet
        mint(self.db, self.pub, 1_000_00)
        self.cfg = BridgeConfig(rpc_url="", chain_id=CHAIN, bridge_address=BRIDGE, escrow_wallet=self.escrow_pub,
                                ledger_db=self.db, state_db=str(Path(_TMP) / f"state-{uuid.uuid4().hex[:8]}.db"),
                                finality_seconds=60)
        self.store = Store(self.cfg.state_db)

    def fund_escrow(self, cents=500_00):
        (status, _), dep = send(self.db, self.priv, self.pub, self.escrow_pub, cents, f"bridge:v1:{CHAIN}:{EVM}")
        self.assertEqual(status, blockchain.ACCEPTED)
        return dep

    def burn(self, nonce=1, cents=100_00, wallet=None):
        self.store.add_release({"nonce": nonce, "evm_tx": EVM_TX, "block": 99, "from": EVM,
                                "ledger_wallet": wallet or self.b, "amount_cents": cents})
        self.store.mark_release_verified(nonce)  # as every RPC confirming it would (test_bridge_rpc_trust)

    def pay(self):
        return releases.pay_releases(self.cfg, self.store, self.escrow_priv)

    def balance(self, w):
        return blockchain.get_balance_cents(self.db, w)

    # ---- F04: an id someone took doesn't make a release "paid" ----

    def test_an_occupied_id_never_marks_a_release_paid(self):
        self.fund_escrow()
        # The attacker takes the id the old code would have used for (chain, nonce 1)
        old_id = str(uuid.uuid5(uuid.UUID("6f1c2b0e-8f8e-4b8e-9d3a-6a1f5e2c9b70"), f"{CHAIN}:1"))
        send_with_id = signed(self.priv, self.pub, sender=self.pub, recipient=self.b, amount_cents=1,
                              reason="occupied id", id=old_id)
        self.assertEqual(blockchain.accept_synced_transaction(self.db, send_with_id)[0], blockchain.ACCEPTED)
        before = self.balance(self.b)
        self.burn()
        self.pay()
        r = self.store.releases()[0]
        self.assertEqual(r["status"], PAID)
        self.assertEqual(self.balance(self.b), before + 100_00, "the victim really was paid")

    def test_an_id_collision_is_held_not_paid(self):
        self.fund_escrow()
        self.burn()
        taken = signed(self.priv, self.pub, sender=self.pub, recipient=self.b, amount_cents=1, reason="x")
        blockchain.accept_synced_transaction(self.db, taken)
        fixed = uuid.UUID(taken["id"])
        with unittest.mock.patch("bridge.releases.uuid.uuid4", return_value=fixed):
            self.pay()
        r = self.store.releases()[0]
        self.assertEqual(r["status"], HELD)
        self.assertIn("id", r["detail"])
        self.assertEqual(self.balance(self.b), 1)

    # ---- F05: one burn, one payout, whatever gets signed ----

    def test_a_second_signed_payout_for_the_same_burn_is_rejected(self):
        self.fund_escrow()
        reason = releases.payout_reason(self.cfg, 1, EVM_TX)
        first = signed(self.escrow_priv, self.escrow_pub, sender=self.escrow_pub, recipient=self.b,
                       amount_cents=100_00, reason=reason)
        second = signed(self.escrow_priv, self.escrow_pub, sender=self.escrow_pub, recipient=self.b,
                        amount_cents=100_00, reason=reason, timestamp=(NOW - timedelta(days=1)).isoformat())
        self.assertEqual(blockchain.accept_synced_transaction(self.db, first)[0], blockchain.ACCEPTED)
        status, why = blockchain.accept_synced_transaction(self.db, second)
        self.assertEqual(status, blockchain.REJECTED)
        self.assertIn("already been paid", why)
        self.assertEqual(self.balance(self.b), 100_00)

    def test_retries_resend_the_same_signed_payout(self):
        self.fund_escrow()
        self.burn()
        with unittest.mock.patch.object(blockchain, "accept_synced_transaction",
                                        return_value=(blockchain.PENDING, "simulated outage")):
            self.pay()
        saved = json.loads(self.store.releases()[0]["intent"])
        self.pay()
        r = self.store.releases()[0]
        self.assertEqual(r["status"], PAID)
        self.assertEqual(r["ledger_tx_hash"], saved["tx_hash"], "the retry sent the payout saved before")

    # ---- F06: paid means the ledger holds the payout ----

    def test_a_paid_release_whose_payout_vanished_is_resent_unchanged(self):
        self.fund_escrow()
        self.burn()
        self.pay()
        r = self.store.releases()[0]
        self.assertEqual(r["status"], PAID)
        # The ledger is restored from a backup taken before the payout
        conn = sqlite3.connect(self.db)
        conn.execute("DELETE FROM transactions WHERE tx_hash = ?", (r["ledger_tx_hash"],))
        conn.commit()
        conn.close()
        self.assertEqual(self.balance(self.b), 0)
        self.pay()
        again = self.store.releases()[0]
        self.assertEqual(again["status"], PAID)
        self.assertEqual(again["ledger_tx_hash"], r["ledger_tx_hash"], "the same signed payout, not a new one")
        self.assertEqual(self.balance(self.b), 100_00)

    def test_a_paid_release_without_a_saved_payout_is_held(self):
        self.fund_escrow()
        self.burn()
        self.store.set_release(1, PAID, "from an old state", "some-id", "ab" * 32)
        self.pay()
        r = self.store.releases()[0]
        self.assertEqual(r["status"], HELD)
        self.assertEqual(self.balance(self.b), 0)

    # ---- F07: a refunded deposit is never minted ----

    def refundable(self):
        # A valid 500 GFC deposit held above the per-mint cap, then refunded: GPT's scenario
        dep = self.fund_escrow(500_00)
        conn = sqlite3.connect(self.db)
        result, _, d = deposits.validate_deposit(deposits.deposit_by_hash(conn, dep["tx_hash"]), self.cfg)
        conn.close()
        self.assertEqual(result, deposits.OK)
        self.store.add_deposit(d, HELD, "above the per-mint cap: refund it")
        self.store.set_meta("created_at", (NOW - timedelta(hours=3)).isoformat())
        return dep, d

    def test_attesters_refuse_a_refunded_deposit_and_a_rebuilt_state_remembers(self):
        from bridge.attester import Attester
        from bridge import relayer
        dep, d = self.refundable()
        releases.refund_deposit(self.cfg, self.store, self.escrow_priv, dep["tx_hash"])
        # The cap goes up and the state is lost: GPT's scenario
        att = Attester(self.cfg, key="0x" + "01" * 32).attest(dep["tx_hash"], EVM, d["mint_cents"],
                                                              int(NOW.timestamp()) + 3600, NOW)
        self.assertIsNone(att.signature)
        self.assertIn("refunded", att.refusal)
        fresh = Store(str(Path(_TMP) / f"state-{uuid.uuid4().hex[:8]}.db"))
        relayer.scan_deposits(self.cfg, fresh)
        self.assertEqual(fresh.deposit(dep["tx_hash"])["status"], REFUNDED)

    def test_no_refund_while_minted_or_an_attestation_is_live(self):
        dep, _ = self.refundable()
        with self.assertRaisesRegex(ValueError, "minted on chain"):
            releases.refund_deposit(self.cfg, self.store, self.escrow_priv, dep["tx_hash"],
                                    bridge=FakeBridge(processed_latest=True))
        self.store.set_deposit(dep["tx_hash"], HELD)
        self.store.note_attested(dep["tx_hash"], int((NOW + timedelta(minutes=30)).timestamp()))
        with self.assertRaisesRegex(ValueError, "can be used until"):
            releases.refund_deposit(self.cfg, self.store, self.escrow_priv, dep["tx_hash"], bridge=FakeBridge())
        self.assertEqual(self.balance(self.pub), 1_000_00 - 500_00, "nothing was refunded")

    def test_a_new_state_waits_before_refunding_older_deposits(self):
        dep, _ = self.refundable()
        self.store.set_meta("created_at", NOW.isoformat())  # the state was just rebuilt
        with self.assertRaisesRegex(ValueError, "state started"):
            releases.refund_deposit(self.cfg, self.store, self.escrow_priv, dep["tx_hash"], bridge=FakeBridge())

    # ---- F10: a mint counts once it's final, and comes back if it disappears ----

    def test_submitted_mints_settle_or_come_back(self):
        from bridge import relayer
        dep = self.fund_escrow()
        conn = sqlite3.connect(self.db)
        _, _, d = deposits.validate_deposit(deposits.deposit_by_hash(conn, dep["tx_hash"]), self.cfg)
        conn.close()
        self.store.add_deposit(d, SUBMITTED)
        relayer.settle_mints(self.cfg, self.store, FakeBridge(processed_latest=True, processed_final=False))
        self.assertEqual(self.store.deposit(dep["tx_hash"])["status"], SUBMITTED, "not final yet")
        relayer.settle_mints(self.cfg, self.store, FakeBridge(processed_latest=False))
        self.assertEqual(self.store.deposit(dep["tx_hash"])["status"], SEEN, "a reorged-out mint is retried")
        self.store.set_deposit(dep["tx_hash"], SUBMITTED)
        relayer.settle_mints(self.cfg, self.store, FakeBridge(processed_latest=True, processed_final=True))
        self.assertEqual(self.store.deposit(dep["tx_hash"])["status"], MINTED)

    # ---- one state file per bridge contract ----

    def test_a_state_file_belongs_to_one_bridge(self):
        self.store.pin_bridge(BRIDGE)
        self.store.pin_bridge(BRIDGE.upper().replace("0X", "0x"))
        with self.assertRaisesRegex(ValueError, "belongs to"):
            self.store.pin_bridge("0x" + "34" * 20)


import unittest.mock  # noqa: E402

if __name__ == "__main__":
    unittest.main(verbosity=2)
