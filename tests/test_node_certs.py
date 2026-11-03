"""
Tests for official-node certificates and the signed node directory (node_certs.py, and the
directory round in peer_discovery.py). No network: the directory is faked.

Run from the repository root:
    python -m unittest discover -s tests -v
"""

import asyncio
import json
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_signed_ledger  # noqa: F401  (sets up the isolated data dir first)

import config  # noqa: E402
import node_certs  # noqa: E402
import peer_discovery  # noqa: E402
import signing  # noqa: E402

NOW = datetime(2026, 11, 3, 18, 0, tzinfo=timezone.utc)


class Keys:
    fed_priv, fed_pub = signing.generate_keypair()
    other_fed_priv, _ = signing.generate_keypair()
    node_priv, node_pub = signing.generate_keypair()
    rogue_priv, rogue_pub = signing.generate_keypair()


def pinned():
    return mock.patch.object(config, "FEDERATION_PUBKEYS", (Keys.fed_pub,))


class CertificateTests(unittest.TestCase):
    def cert(self, **kw):
        return node_certs.make_cert(kw.pop("fed", Keys.fed_priv), kw.pop("node", Keys.node_pub), "DO node",
                                    kw.pop("days", 365), now=kw.pop("now", NOW))

    def test_a_pinned_federation_key_makes_the_node_official(self):
        with pinned():
            body = node_certs.check_cert(self.cert(), Keys.node_pub, now=NOW + timedelta(days=1))
        self.assertEqual((body["role"], body["label"]), ("official", "DO node"))

    def test_an_unpinned_issuer_is_refused(self):
        with pinned():
            self.assertIsNone(node_certs.check_cert(self.cert(fed=Keys.other_fed_priv), Keys.node_pub, now=NOW))

    def test_the_cert_is_useless_for_another_node_key(self):
        with pinned():
            self.assertIsNone(node_certs.check_cert(self.cert(), Keys.rogue_pub, now=NOW))

    def test_expired_and_revoked(self):
        with pinned():
            cert = self.cert(days=30)
            self.assertIsNone(node_certs.check_cert(cert, Keys.node_pub, now=NOW + timedelta(days=31)))
            self.assertIsNone(node_certs.check_cert(cert, Keys.node_pub, revoked={Keys.node_pub}, now=NOW))

    def test_a_tampered_body_fails(self):
        cert = self.cert()
        body = json.loads(cert["body"])
        body["node_key"] = Keys.rogue_pub
        forged = {"body": node_certs.canonical(body), "signature": cert["signature"]}
        with pinned():
            self.assertIsNone(node_certs.check_cert(forged, Keys.rogue_pub, now=NOW))

    def test_a_transaction_signature_cannot_pass_as_a_node_signature(self):
        cert = self.cert()
        tx_sig = signing.sign_tx_hash(Keys.fed_priv, "node-cert:" + cert["body"])
        with pinned():
            self.assertIsNone(node_certs.check_cert({"body": cert["body"], "signature": tx_sig}, Keys.node_pub, now=NOW))


class DirectoryEntryTests(unittest.TestCase):
    def listing(self, *items, revocations=None):
        return {"nodes": [{"address": a, "announcement": ann} for a, ann in items], "revocations": revocations}

    def test_official_and_community_nodes(self):
        cert = node_certs.make_cert(Keys.fed_priv, Keys.node_pub, "DO node", now=NOW)
        official = node_certs.make_announcement(Keys.node_priv, 6881, "https://node.example", cert=cert, now=NOW)
        community = node_certs.make_announcement(Keys.rogue_priv, 6881, now=NOW)
        with pinned():
            out = node_certs.directory_entries(self.listing(("1.2.3.4", official), ("5.6.7.8", community)), now=NOW)
        self.assertEqual([(e["address"], e["official"]) for e in out], [("1.2.3.4", True), ("5.6.7.8", False)])
        self.assertEqual(out[0]["label"], "DO node")

    def test_a_stolen_cert_on_another_key_is_just_a_community_node(self):
        cert = node_certs.make_cert(Keys.fed_priv, Keys.node_pub, "DO node", now=NOW)
        ann = node_certs.make_announcement(Keys.rogue_priv, 6881, cert=cert, now=NOW)
        with pinned():
            out = node_certs.directory_entries(self.listing(("9.9.9.9", ann)), now=NOW)
        self.assertEqual([e["official"] for e in out], [False])

    def test_stale_bad_and_revoked_entries_are_dropped(self):
        stale = node_certs.make_announcement(Keys.rogue_priv, 6881, now=NOW - timedelta(hours=2))
        bad = dict(node_certs.make_announcement(Keys.rogue_priv, 6881, now=NOW), signature="00" * 64)
        revoked_ann = node_certs.make_announcement(Keys.node_priv, 6881, now=NOW)
        rev = node_certs.make_revocations(Keys.fed_priv, 1, [Keys.node_pub], now=NOW)
        with pinned():
            out = node_certs.directory_entries(
                {"nodes": [{"address": "1.1.1.1", "announcement": stale}, {"address": "2.2.2.2", "announcement": bad},
                           {"address": "3.3.3.3", "announcement": revoked_ann}, {"address": "4.4.4.4"}, "junk"],
                 "revocations": rev}, now=NOW)
        self.assertEqual(out, [])

    def test_revocations_from_an_unpinned_key_are_ignored(self):
        ann = node_certs.make_announcement(Keys.node_priv, 6881, now=NOW)
        rev = node_certs.make_revocations(Keys.other_fed_priv, 1, [Keys.node_pub], now=NOW)
        with pinned():
            out = node_certs.directory_entries(self.listing(("3.3.3.3", ann), revocations=rev), now=NOW)
        self.assertEqual(len(out), 1)

    def test_another_networks_announcements_are_ignored(self):
        other = "mainnet" if config.NETWORK == "testnet" else "testnet"
        with mock.patch.object(config, "NETWORK", other):
            ann = node_certs.make_announcement(Keys.node_priv, 6881, now=NOW)
        self.assertIsNone(node_certs.check_announcement(ann, now=NOW))


class FakeResponse:
    def __init__(self, status, data):
        self.status_code, self._data, self.text = status, data, json.dumps(data)

    def json(self):
        return self._data


class FakeClient:
    def __init__(self, listing):
        self.listing, self.posted = listing, []

    async def post(self, url, json=None):
        self.posted.append((url, json))
        return FakeResponse(200, {"ok": True})

    async def get(self, url):
        return FakeResponse(200, self.listing)


class DirectoryRoundTests(unittest.TestCase):
    def test_announces_itself_and_adds_the_listed_nodes(self):
        cert = node_certs.make_cert(Keys.fed_priv, Keys.node_pub, "DO node")
        official = node_certs.make_announcement(Keys.node_priv, 6881, cert=cert)
        community = node_certs.make_announcement(Keys.rogue_priv, 7000)
        client = FakeClient({"nodes": [{"address": "203.0.113.5", "announcement": official},
                                       {"address": "198.51.100.9", "announcement": community}]})
        d = peer_discovery.PeerDiscovery()
        with pinned(), mock.patch.object(d, "_save_peers"):
            n = asyncio.run(d.directory_round(client, "https://dir.example"))
        self.assertEqual(n, 2)
        url, ann = client.posted[0]
        self.assertEqual(url, "https://dir.example/announce")
        self.assertIsNotNone(node_certs.check_announcement(ann))  # signed by this node's own key
        self.assertTrue(d.known_peers["203.0.113.5:6881"].official)
        self.assertFalse(d.known_peers["198.51.100.9:7000"].official)
        self.assertEqual(d.get_peer_list()[0], {"address": "203.0.113.5", "port": 6881, "official": True})

    def test_a_directory_that_is_down_changes_nothing(self):
        class Down:
            async def post(self, *a, **k):
                raise OSError("down")
            get = post
        d = peer_discovery.PeerDiscovery()
        self.assertEqual(asyncio.run(d.directory_round(Down(), "https://dir.example")), 0)
        self.assertEqual(d.known_peers, {})


if __name__ == "__main__":
    unittest.main(verbosity=2)
