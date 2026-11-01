"""
Ledger writes are atomic: a balance check, the row it allows and its block commit together
(blockchain._write), so racing requests can't spend one balance twice (audit F01).

The races here are real: threads on their own SQLite connections, as the node's thread pool
and sync engine use them. Hooks only slow the first writer down inside its lock, so the
others have to arrive while it's still deciding.

Run from the repository root:
    python -m unittest discover -s tests -v
"""

import sqlite3
import threading
import time
import unittest
import uuid
from concurrent.futures import ThreadPoolExecutor
from unittest import mock

# Sets up the isolated data dir and test treasury key before any GFC module loads config
from test_signed_ledger import as_treasury_node, mark_verified, new_node, new_wallet, signed_transfer  # noqa: E402

import blockchain  # noqa: E402
import signing  # noqa: E402


def fund(db: str, wallet: str, cents: int):
    with as_treasury_node():
        assert blockchain.process_operator_mint(db, wallet, cents, "Operator grant (other): test funds")


def slow_balance_reads(delay: float = 0.3):
    """Patch _balance_cents to pause after reading, so racers pile up behind the write lock."""
    real = blockchain._balance_cents

    def slow(conn, wallet):
        value = real(conn, wallet)
        time.sleep(delay)
        return value
    return mock.patch.object(blockchain, "_balance_cents", slow)


def ledger_problems(db: str) -> list:
    """What must always hold: no negative wallets (but the treasury and genesis), every row in one block."""
    conn = sqlite3.connect(db)
    try:
        problems = []
        wallets = {r[0] for r in conn.execute("SELECT sender FROM transactions UNION SELECT recipient FROM transactions")}
        for w in wallets - {blockchain.TREASURY_WALLET_ID, "SYSTEM"}:  # SYSTEM: the genesis premine
            balance = blockchain._balance_cents(conn, w)
            if balance < 0:
                problems.append(f"{w[:8]} is at {balance}")
        if conn.execute("SELECT COUNT(*) FROM transactions WHERE block_index IS NULL").fetchone()[0]:
            problems.append("a row was accepted without a block")
        counts = conn.execute("SELECT COUNT(*), COUNT(DISTINCT block_index) FROM blocks").fetchone()
        if counts[0] != counts[1]:
            problems.append("two blocks share an index")
        per_block = conn.execute("SELECT b.block_index, b.tx_count, COUNT(t.id) FROM blocks b "
                                 "LEFT JOIN transactions t ON t.block_index = b.block_index "
                                 "WHERE b.block_index > 0 GROUP BY b.block_index").fetchall()
        problems += [f"block {i} says {n} rows, holds {m}" for i, n, m in per_block if n != m]
        return problems
    finally:
        conn.close()


class LedgerAtomicityTests(unittest.TestCase):
    def setUp(self):
        self.db = new_node("atomic-" + uuid.uuid4().hex[:8])
        self.alice = new_wallet(self.db, "alice")
        fund(self.db, self.alice, 10000)  # 100 GFC

    def transfer(self, recipient, cents=10000):
        try:
            return blockchain.process_transfer(self.db, self.alice, recipient, cents, "race")
        except ValueError as e:
            return e

    def test_concurrent_transfers_spend_a_balance_once(self):
        recipients = [new_wallet(self.db, f"r{i}") for i in range(6)]
        with slow_balance_reads(), ThreadPoolExecutor(len(recipients)) as pool:
            results = list(pool.map(self.transfer, recipients))
        paid = [r for r in results if isinstance(r, dict)]
        refused = [r for r in results if isinstance(r, ValueError)]
        self.assertEqual(len(paid), 1, results)
        self.assertEqual(len(refused), 5)
        self.assertTrue(all("Insufficient balance" in str(e) for e in refused))
        self.assertEqual(blockchain.get_balance_cents(self.db, self.alice), 0)
        self.assertEqual(sum(blockchain.get_balance_cents(self.db, r) for r in recipients), 10000)
        self.assertEqual(ledger_problems(self.db), [])

    def test_concurrent_synced_rows_spend_a_balance_once(self):
        # The audit's case: two signed transfers of the whole balance arrive at once (sync engine
        # and tracker). Only one can be accepted; the other waits as PENDING, unfunded.
        key = signing.get_wallet_private_key(self.db, self.alice)
        bob, carol = new_wallet(self.db, "bob"), new_wallet(self.db, "carol")
        txs = [signed_transfer(key, self.alice, bob, 10000), signed_transfer(key, self.alice, carol, 10000)]
        with slow_balance_reads(), ThreadPoolExecutor(2) as pool:
            statuses = sorted(s for s, _ in pool.map(lambda t: blockchain.accept_synced_transaction(self.db, t), txs))
        self.assertEqual(statuses, [blockchain.ACCEPTED, blockchain.PENDING])
        self.assertEqual(blockchain.get_balance_cents(self.db, self.alice), 0)
        self.assertEqual(ledger_problems(self.db), [])

    def test_local_and_synced_spends_race_too(self):
        key = signing.get_wallet_private_key(self.db, self.alice)
        bob, carol = new_wallet(self.db, "bob"), new_wallet(self.db, "carol")
        synced = signed_transfer(key, self.alice, carol, 10000)
        with slow_balance_reads(), ThreadPoolExecutor(2) as pool:
            local = pool.submit(self.transfer, bob)
            remote = pool.submit(blockchain.accept_synced_transaction, self.db, synced)
            outcomes = [local.result(), remote.result()]
        spent = isinstance(outcomes[0], dict) + (outcomes[1][0] == blockchain.ACCEPTED)
        self.assertEqual(spent, 1, outcomes)
        self.assertEqual(blockchain.get_balance_cents(self.db, self.alice), 0)
        self.assertEqual(ledger_problems(self.db), [])

    def test_a_failure_inside_the_write_leaves_nothing_behind(self):
        # A crash between the insert and the block used to leave an accepted row with no block
        # (audit F06 scenario A): now it's all or nothing.
        bob = new_wallet(self.db, "bob")
        with mock.patch.object(blockchain, "_append_block", side_effect=RuntimeError("simulated crash")):
            with self.assertRaises(RuntimeError):
                blockchain.process_transfer(self.db, self.alice, bob, 2500, "crash")
        conn = sqlite3.connect(self.db)
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM transactions WHERE reason = 'crash'").fetchone()[0], 0)
        conn.close()
        self.assertEqual(blockchain.get_balance_cents(self.db, self.alice), 10000)
        self.assertEqual(ledger_problems(self.db), [])

    def test_once_only_mints_pay_once_under_a_race(self):
        bob = new_wallet(self.db, "bob")
        proof = "proof-" + uuid.uuid4().hex
        with as_treasury_node(), slow_balance_reads(0.2), ThreadPoolExecutor(4) as pool:
            paid = list(pool.map(lambda _: blockchain.process_podt_reward(self.db, bob, proof, 5 * 1024 * 1024),
                                 range(4)))
        self.assertEqual(sum(p is not None for p in paid), 1)
        # The welcome grant, too: once per user however many requests race
        mark_verified(self.db, "dave")
        dave = new_wallet(self.db, "dave")
        with as_treasury_node(), ThreadPoolExecutor(4) as pool:
            grants = list(pool.map(lambda _: blockchain.process_user_grant(self.db, "dave", dave), range(4)))
        self.assertEqual(sum(g is not None for g in grants), 1)
        self.assertEqual(blockchain.get_balance_cents(self.db, dave), blockchain.NEW_USER_GRANT_CENTS)
        self.assertEqual(ledger_problems(self.db), [])

    def test_random_concurrent_traffic_keeps_the_invariants(self):
        wallets = [self.alice] + [new_wallet(self.db, f"w{i}") for i in range(4)]
        for w in wallets[1:]:
            fund(self.db, w, 3000)
        total = sum(blockchain.get_balance_cents(self.db, w) for w in wallets)
        stop = threading.Event()

        def churn(seed):
            import random
            rnd = random.Random(seed)
            done = 0
            while not stop.is_set() and done < 40:
                a, b = rnd.sample(wallets, 2)
                try:
                    blockchain.process_transfer(self.db, a, b, rnd.choice([100, 700, 2500, 9000]), "churn")
                except ValueError:
                    pass
                done += 1

        with ThreadPoolExecutor(6) as pool:
            list(pool.map(churn, range(6)))
        self.assertEqual(ledger_problems(self.db), [])
        self.assertEqual(sum(blockchain.get_balance_cents(self.db, w) for w in wallets), total)  # conserved


if __name__ == "__main__":
    unittest.main(verbosity=2)
