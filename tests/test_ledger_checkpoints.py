"""
Signed ledger checkpoints (audit F08): the canonical node signs its accepted history, and
bridge attesters sign only deposits covered by an old-enough checkpoint, and halt on a rollback.

Run from the repository root:
    python -m unittest discover -s tests -p "test_ledger_checkpoints.py" -v
"""

import shutil
import sqlite3
import time
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from test_bridge_ledger import CHAIN, EVM, _TMP, EscrowTestCase, mint, new_ledger, send  # noqa: E402

from eth_account import Account  # noqa: E402

import config  # noqa: E402
import ledger_checkpoints  # noqa: E402
import signing  # noqa: E402
from bridge import reconcile as reconcile_mod  # noqa: E402
from bridge.attester import Attester  # noqa: E402
from bridge.checkpoints import CheckpointError, CheckpointMirror  # noqa: E402
from bridge.config import BridgeConfig  # noqa: E402

FINALITY = 1800


def fetcher(db_path_holder: list):
    """The node's two endpoints, served straight from a ledger file (db_path_holder[0])."""
    def fetch(path: str) -> dict:
        db = db_path_holder[0]
        if path == "/ledger/checkpoint":
            return ledger_checkpoints.latest(db)
        start = int(path.split("start=")[1].split("&")[0])
        upto = ledger_checkpoints.latest(db)["body"]["count"]
        return {"count": upto, "rows": ledger_checkpoints.log_rows(db, start, 2000, upto)}
    return fetch


class CheckpointTests(EscrowTestCase):
    def setUp(self):
        super().setUp()
        self.node = new_ledger()  # the canonical node
        self.cp_priv, self.cp_pub = signing.generate_keypair()
        self.priv, self.pub = signing.generate_keypair()
        mint(self.node, self.pub, 1_000_00)
        self.source = [self.node]
        self.mirror = CheckpointMirror(str(Path(_TMP) / f"mirror-{uuid.uuid4().hex[:8]}.db"),
                                       fetcher(self.source), [self.cp_pub], "testnet")

    def sign(self, at=None, db=None):
        with mock.patch.dict(config.BRIDGE_ESCROWS, {CHAIN: self.escrow_pub}):
            return ledger_checkpoints.make_checkpoint(db or self.node, self.cp_priv, "testnet", now=at)

    def deposit(self, db=None):
        (status, _), dep = send(db or self.node, self.priv, self.pub, self.escrow_pub, 200_00, f"bridge:v1:{CHAIN}:{EVM}")
        return dep

    # ---- the node side ----

    def test_a_checkpoint_commits_to_every_accepted_row_in_order(self):
        dep = self.deposit()
        cp = self.sign()
        conn = sqlite3.connect(self.node)
        hashes = [h for (h,) in conn.execute("SELECT tx_hash FROM transactions WHERE block_index IS NOT NULL "
                                             "AND tx_hash != '' ORDER BY block_index, tx_hash")]
        conn.close()
        acc = ledger_checkpoints.genesis_acc("testnet")
        for h in hashes:
            acc = ledger_checkpoints.next_acc(acc, h)
        self.assertEqual((cp["body"]["count"], cp["body"]["acc"]), (len(hashes), acc))
        self.assertIn(dep["tx_hash"], hashes)
        self.assertEqual(cp["body"]["escrows"], {str(CHAIN): 200_00})
        self.assertTrue(ledger_checkpoints.verify(cp, [self.cp_pub]))
        self.assertFalse(ledger_checkpoints.verify(cp, [signing.generate_keypair()[1]]))
        forged = {"body": {**cp["body"], "escrows": {str(CHAIN): 10 ** 9}}, "signature": cp["signature"]}
        self.assertFalse(ledger_checkpoints.verify(forged, [self.cp_pub]))
        self.assertEqual(self.sign()["body"]["prev"], ledger_checkpoints.digest(cp["body"]))

    def test_the_node_wont_sign_over_a_changed_history(self):
        self.sign()
        conn = sqlite3.connect(self.node)
        conn.execute("UPDATE checkpoint_log SET acc = ? WHERE position = (SELECT MAX(position) FROM checkpoint_log)",
                     ("00" * 32,))
        conn.commit()
        conn.close()
        with self.assertRaises(RuntimeError):
            self.sign()

    # ---- the attester side ----

    def test_a_deposit_counts_once_a_checkpoint_old_enough_covers_it(self):
        dep = self.deposit()
        now = datetime.now(timezone.utc)
        ok, why, retry = self.mirror.covered(dep["tx_hash"], now, FINALITY)
        self.assertFalse(ok)  # no checkpoint at all yet: the sync fails, nothing is copied
        cp = self.sign(at=now)
        self.mirror.sync(now, force=True)
        ok, why, retry = self.mirror.covered(dep["tx_hash"], now + timedelta(seconds=FINALITY - 1), FINALITY)
        self.assertEqual((ok, retry), (False, True))
        self.assertIn("finality", why)
        self.assertTrue(self.mirror.covered(dep["tx_hash"], now + timedelta(seconds=FINALITY + 1), FINALITY)[0])
        self.assertEqual(self.mirror.latest()["count"], cp["body"]["count"])

    def test_a_row_only_in_an_attesters_own_database_never_counts(self):
        self.sign()
        attester_db = Path(_TMP) / f"attester-{uuid.uuid4().hex[:8]}.db"
        shutil.copy(self.node, attester_db)
        dep = self.deposit(str(attester_db))  # accepted by that node only
        self.mirror.sync(force=True)
        ok, why, _ = self.mirror.covered(dep["tx_hash"], datetime.now(timezone.utc) + timedelta(days=1), FINALITY)
        self.assertFalse(ok)
        self.assertIn("not in a signed checkpoint", why)

    def test_a_ledger_restored_from_an_older_backup_halts_the_attesters(self):
        backup = Path(_TMP) / f"backup-{uuid.uuid4().hex[:8]}.db"
        self.sign()
        shutil.copy(self.node, backup)
        dep = self.deposit()
        self.sign()
        self.mirror.sync(force=True)
        self.assertTrue(self.mirror.covered(dep["tx_hash"], datetime.now(timezone.utc) + timedelta(days=1),
                                            FINALITY)[0])

        # The node comes back from the backup: the deposit is gone, and it signs again
        self.source[0] = str(backup)
        self.sign(db=str(backup))
        self.mirror.sync(force=True)
        self.assertIn("rolled back", self.mirror.halted())
        ok, why, retry = self.mirror.covered(dep["tx_hash"], datetime.now(timezone.utc) + timedelta(days=1), FINALITY)
        self.assertEqual((ok, retry), (False, False))
        self.assertIn("halted", why)

        # Even after the restored node grows past the old count, the halt stays until a person resets it
        for _ in range(3):
            self.deposit(str(backup))
        self.sign(db=str(backup))
        self.mirror.sync(force=True)
        self.assertTrue(self.mirror.halted())
        self.mirror.reset()
        self.mirror.sync(force=True)
        self.assertFalse(self.mirror.halted())

    def test_a_rewritten_history_halts_the_attesters(self):
        backup = Path(_TMP) / f"backup-{uuid.uuid4().hex[:8]}.db"
        self.sign()
        shutil.copy(self.node, backup)
        self.deposit()
        self.sign()
        self.mirror.sync(force=True)
        # The same number of rows, but different ones
        self.source[0] = str(backup)
        (_, _), _ = send(str(backup), self.priv, self.pub, signing.generate_keypair()[1], 200_00, "something else")
        self.sign(db=str(backup))
        self.mirror.sync(force=True)
        self.assertIn("rewritten", self.mirror.halted())

    def test_a_checkpoint_from_an_unpinned_key_is_refused_without_halting(self):
        self.sign()
        other = CheckpointMirror(str(Path(_TMP) / f"mirror-{uuid.uuid4().hex[:8]}.db"), fetcher(self.source),
                                 [signing.generate_keypair()[1]], "testnet")
        with self.assertRaises(CheckpointError):
            other.sync(force=True)
        self.assertFalse(other.halted())

    def test_an_attester_signs_only_checkpointed_deposits(self):
        dep = self.deposit()
        cfg = BridgeConfig(rpc_url="", chain_id=CHAIN, bridge_address="0x" + "12" * 20, escrow_wallet=self.escrow_pub,
                           ledger_db=self.node, state_db=str(Path(_TMP) / f"state-{uuid.uuid4().hex[:8]}.db"),
                           finality_seconds=0)
        attester = Attester(cfg, key=Account.create().key.hex())
        attester.checkpoints = self.mirror
        deadline = int(time.time()) + 600
        refused = attester.attest(dep["tx_hash"], EVM, 200_00, deadline)
        self.assertIsNone(refused.signature)
        self.assertTrue(refused.retry)
        self.sign()
        self.mirror.sync(force=True)
        self.assertIsNotNone(attester.attest(dep["tx_hash"], EVM, 200_00, deadline).signature)

    def test_reconcile_checks_the_checkpoint_escrow(self):
        self.deposit()
        self.sign()
        cfg = BridgeConfig(rpc_url="", chain_id=CHAIN, bridge_address="0x" + "12" * 20, escrow_wallet=self.escrow_pub,
                           ledger_db=self.node, state_db="")
        self.assertEqual(reconcile_mod.checkpoint_problems(cfg, self.mirror, 199_00), [])
        self.assertIn("doesn't cover", reconcile_mod.checkpoint_problems(cfg, self.mirror, 300_00)[0])
        self.mirror._halt("test")
        self.assertIn("halted", reconcile_mod.checkpoint_problems(cfg, self.mirror, 0)[0])

    def test_the_node_serves_its_checkpoints(self):
        from fastapi.testclient import TestClient
        from fastapi import FastAPI
        import app_checkpoints
        app = FastAPI()
        app.include_router(app_checkpoints.router)
        with mock.patch.object(app_checkpoints, "DB_PATH", self.node):
            client = TestClient(app)
            self.assertEqual(client.get("/ledger/checkpoint").status_code, 404)
            cp = self.sign()
            self.assertEqual(client.get("/ledger/checkpoint").json(), cp)
            log = client.get("/ledger/checkpoint/log?start=1&limit=5").json()
            self.assertEqual(log["count"], cp["body"]["count"])
            self.assertEqual([r["position"] for r in log["rows"]], list(range(1, min(5, cp["body"]["count"]) + 1)))


if __name__ == "__main__":
    unittest.main(verbosity=2)
