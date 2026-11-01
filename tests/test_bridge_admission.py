"""
Admission times and block membership (audit F02, F08): GPT's demonstrations, turned into
checks that the attack no longer works. The bridge ages deposits and free credit by when the
ledger admitted them, never by the timestamp their signer chose, follows every recent incoming
transfer, and accepts a deposit only if it's really in its block.

Run from the repository root:
    python -m unittest tests.test_bridge_admission -v
"""

import sqlite3
import unittest
import uuid
from datetime import timedelta
from pathlib import Path
from unittest import mock

from test_bridge_ledger import CHAIN, EVM, NOW, _TMP, EscrowTestCase, mint, new_ledger, send, signed  # noqa: E402

import blockchain  # noqa: E402
import signing  # noqa: E402
from bridge import deposits  # noqa: E402
from bridge.config import BridgeConfig  # noqa: E402

HOLD = 14


class AdmissionTimeTests(EscrowTestCase):
    def setUp(self):
        super().setUp()
        self.db = new_ledger()
        self.a_priv, self.a = signing.generate_keypair()
        self.b_priv, self.b = signing.generate_keypair()
        self.c_priv, self.c = signing.generate_keypair()
        self.cfg = BridgeConfig(rpc_url="", chain_id=CHAIN, bridge_address="0x" + "12" * 20,
                                escrow_wallet=self.escrow_pub, ledger_db=self.db,
                                state_db=str(Path(_TMP) / f"state-{uuid.uuid4().hex[:8]}.db"),
                                finality_seconds=1800, faucet_hold_days=HOLD)

    def deposit_row(self, tx):
        conn = sqlite3.connect(self.db)
        try:
            return deposits.deposit_by_hash(conn, tx["tx_hash"])
        finally:
            conn.close()

    def clean(self, wallet):
        conn = sqlite3.connect(self.db)
        try:
            return deposits.clean_cents(conn, wallet, NOW, HOLD, exclude=frozenset([self.escrow_pub]))
        finally:
            conn.close()

    # ---- F08 A: a backdated deposit isn't final just because its signer says it's old ----

    def test_a_backdated_deposit_waits_the_full_finality_window(self):
        mint(self.db, self.a, 500_00)  # old credit
        (status, _), dep = send(self.db, self.a_priv, self.a, self.escrow_pub, 200_00, f"bridge:v1:{CHAIN}:{EVM}",
                                when=NOW - timedelta(days=1), admit_at_timestamp=False)
        self.assertEqual(status, blockchain.ACCEPTED)
        row = self.deposit_row(dep)
        admitted = deposits.parse_ts(row["admitted_at"])
        result, detail, _ = deposits.validate_deposit(row, self.cfg, admitted + timedelta(seconds=1799))
        self.assertEqual(result, deposits.NOT_FINAL, "signed a day ago, but admitted under 30 minutes ago")
        result, _, _ = deposits.validate_deposit(row, self.cfg, admitted + timedelta(seconds=1801))
        self.assertEqual(result, deposits.OK)

    # ---- F02 A: a backdated transfer can't make a new grant look old ----

    def test_a_backdated_transfer_doesnt_launder_a_new_grant(self):
        mint(self.db, self.a, blockchain.NEW_USER_GRANT_CENTS, tx_type=blockchain.TX_TYPE_GRANT, when=NOW)
        (status, _), _ = send(self.db, self.a_priv, self.a, self.b, blockchain.NEW_USER_GRANT_CENTS,
                              when=NOW - timedelta(days=15), admit_at_timestamp=False)
        self.assertEqual(status, blockchain.ACCEPTED)
        self.assertEqual(self.clean(self.b), (blockchain.NEW_USER_GRANT_CENTS, 0), "still fresh credit")

    # ---- F02 B: many small transfers can't push fresh credit out of view ----

    def test_fan_in_doesnt_hide_fresh_credit(self):
        mint(self.db, self.a, blockchain.NEW_USER_GRANT_CENTS, tx_type=blockchain.TX_TYPE_GRANT, when=NOW)
        send(self.db, self.a_priv, self.a, self.b, blockchain.NEW_USER_GRANT_CENTS, when=NOW)
        mint(self.db, self.c, 500)  # old, clean credit
        for i in range(201):
            send(self.db, self.c_priv, self.c, self.b, 1, f"dust {i}", when=NOW)
        balance, clean = self.clean(self.b)
        self.assertEqual(balance, blockchain.NEW_USER_GRANT_CENTS + 201)
        self.assertEqual(clean, 201, "only the dust is clean; the grant is still on hold")

    def test_an_exhausted_trace_counts_as_fresh(self):
        mint(self.db, self.a, 500_00)  # old, clean credit
        send(self.db, self.a_priv, self.a, self.b, 300_00, when=NOW)
        with mock.patch.object(deposits, "FRESH_TRACE_BUDGET", 1):  # can't look behind b at all
            self.assertEqual(self.clean(self.b), (300_00, 0))
        self.assertEqual(self.clean(self.b), (300_00, 300_00))

    # ---- F08 B: a deposit must really be in its block ----

    def test_a_row_pointed_at_a_missing_or_shared_block_is_invalid(self):
        mint(self.db, self.a, 500_00)
        fake = signed(self.a_priv, self.a, sender=self.a, recipient=self.escrow_pub, amount_cents=200_00,
                      reason=f"bridge:v1:{CHAIN}:{EVM}", timestamp=(NOW - timedelta(days=1)).isoformat())
        conn = sqlite3.connect(self.db)
        blockchain._insert_tx(conn, fake)
        conn.execute("UPDATE transactions SET block_index = 999 WHERE id = ?", (fake["id"],))
        conn.commit()
        conn.close()
        result, detail, _ = deposits.validate_deposit(self.deposit_row(fake), self.cfg, NOW + timedelta(days=1))
        self.assertEqual(result, deposits.INVALID)
        self.assertIn("isn't in this ledger", detail)

        # Pointed at a real block that holds another transaction
        conn = sqlite3.connect(self.db)
        real_block = conn.execute("SELECT MAX(block_index) FROM transactions WHERE id != ?",
                                  (fake["id"],)).fetchone()[0]
        conn.execute("UPDATE transactions SET block_index = ? WHERE id = ?", (real_block, fake["id"]))
        conn.commit()
        conn.close()
        result, detail, _ = deposits.validate_deposit(self.deposit_row(fake), self.cfg, NOW + timedelta(days=1))
        self.assertEqual(result, deposits.INVALID)
        self.assertIn("doesn't hold exactly this deposit", detail)


if __name__ == "__main__":
    unittest.main(verbosity=2)
