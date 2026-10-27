"""
Tests for operator grants (treasury_grants.py): hackathon prizes, node hosts, other.

Run from the repository root:
    python -m unittest discover -s tests -v
"""

import unittest
import uuid
from datetime import datetime, timezone

# Sets up the isolated data dir and test treasury key before any GFC module loads config
import test_signed_ledger  # noqa: F401
from test_signed_ledger import TREASURY_PRIV, as_treasury_node, new_node

from fastapi.testclient import TestClient  # noqa: E402

import blockchain  # noqa: E402
import main  # noqa: E402
import signing  # noqa: E402
import treasury_grants  # noqa: E402
from treasury_grants import GrantError, grant  # noqa: E402


def wallet() -> str:
    return signing.generate_keypair()[1]


class OperatorGrantTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(main.app)

    def balance(self, w):
        return blockchain.get_balance_cents(main.DB_PATH, w)

    def test_hackathon_and_other_grants(self):
        w = wallet()
        with as_treasury_node():
            g = grant(w, 2500, "hackathon", "GFC Jam 2026: best 3D seed")
            grant(w, 10_000, "other", "Early creator thank-you")
        self.assertEqual(g["amount"], 2500.0)
        self.assertEqual(self.balance(w), 12_500 * 100)

    def test_caps_and_memo_required(self):
        w = wallet()
        with as_treasury_node():
            with self.assertRaises(GrantError):
                grant(w, 10_000.01, "hackathon", "too big")
            with self.assertRaises(GrantError):
                grant(w, 0, "hackathon", "nothing")
            with self.assertRaises(GrantError):
                grant(w, 100, "hackathon", "  ")
            with self.assertRaises(GrantError):
                grant(w, 100, "bribe", "not a purpose")
            with self.assertRaises(GrantError):
                grant("not-a-wallet", 100, "other", "bad wallet")
        self.assertEqual(self.balance(w), 0)

    def test_node_host_exactly_10k_once_per_wallet(self):
        w = wallet()
        with as_treasury_node():
            with self.assertRaises(GrantError):
                grant(w, 5000, "node-host", "Runs node.example.org")
            grant(w, 10_000, "node-host", "Runs node.example.org")
            with self.assertRaises(GrantError):
                grant(w, 10_000, "node-host", "Second node, same wallet")
        self.assertEqual(self.balance(w), 10_000 * 100)

    def test_refuses_without_treasury_key(self):
        with self.assertRaises(GrantError):
            grant(wallet(), 100, "hackathon", "No key on this node")

    def test_peers_accept_only_valid_operator_grants(self):
        db = new_node("op_peer_" + uuid.uuid4().hex[:6])
        w = wallet()

        def mint(amount_cents, reason, priv=TREASURY_PRIV):
            tx = {"id": str(uuid.uuid4()), "sender": blockchain.TREASURY_WALLET_ID, "recipient": w,
                  "amount": amount_cents / 100, "amount_cents": amount_cents, "reason": reason,
                  "timestamp": datetime.now(timezone.utc).isoformat(), "tx_type": blockchain.TX_TYPE_OPERATOR}
            tx["tx_hash"] = blockchain.compute_tx_hash(tx)
            tx["signer"] = signing.public_key_of(priv)
            tx["signature"] = signing.sign_tx_hash(priv, tx["tx_hash"])
            return tx

        check = lambda tx: blockchain.check_synced_transaction(db, tx)  # noqa: E731
        self.assertEqual(check(mint(500_000, "Operator grant (hackathon): Jam prize"))[0], blockchain.ACCEPTED)
        self.assertEqual(check(mint(1_000_001, "Operator grant (hackathon): too much")),
                         (blockchain.REJECTED, "operator grant too large"))
        self.assertEqual(check(mint(1000, "free money")),
                         (blockchain.REJECTED, "operator grant needs a purpose and memo"))
        self.assertEqual(check(mint(500_000, "Operator grant (node-host): half")),
                         (blockchain.REJECTED, "wrong node host grant amount"))
        attacker = signing.generate_keypair()[0]
        self.assertEqual(check(mint(1000, "Operator grant (other): fake", attacker))[0], blockchain.REJECTED)
        # A node host grant once per wallet, network-wide
        first = mint(1_000_000, "Operator grant (node-host): Runs a node")
        self.assertEqual(blockchain.accept_synced_transaction(db, first)[0], blockchain.ACCEPTED)
        self.assertEqual(check(mint(1_000_000, "Operator grant (node-host): Again")),
                         (blockchain.REJECTED, "wallet already received a node host grant"))

    def test_public_page_lists_grants_and_escapes(self):
        w = wallet()
        with as_treasury_node():
            grant(w, 1234.5, "hackathon", '<script>alert(1)</script> "Jam" & co')
        page = self.client.get("/treasury/grants", headers={"Accept": "text/html"})
        self.assertEqual(page.status_code, 200)
        self.assertIn("Treasury grants", page.text)
        self.assertIn("1,234.50", page.text)
        self.assertNotIn("<script>alert", page.text)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt; &quot;Jam&quot; &amp; co", page.text)
        self.assertNotIn("script-src", page.headers["content-security-policy"])
        data = self.client.get("/treasury/grants?format=json").json()
        mine = [g for g in data["grants"] if g["wallet"] == w]
        self.assertEqual(mine[0]["purpose"], "hackathon")
        self.assertEqual(mine[0]["memo"], '<script>alert(1)</script> "Jam" & co')
        self.assertGreaterEqual(data["summary"]["by_purpose"]["hackathon"], 1234.5)
        self.assertEqual(data["summary"]["max_per_grant"], 10_000.0)

    def test_cli(self):
        w = wallet()
        with as_treasury_node():
            self.assertEqual(treasury_grants._cli(["grant", w, "42", "other", "CLI test grant"]), 0)
            self.assertEqual(treasury_grants._cli(["grant", w, "99999", "other", "too much"]), 1)
        self.assertEqual(self.balance(w), 4200)


if __name__ == "__main__":
    unittest.main(verbosity=2)
