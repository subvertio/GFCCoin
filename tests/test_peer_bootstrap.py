"""
Tests for built-in bootstrap peers (the public treasury/gateway node).

Run from the repository root:
    python -m unittest discover -s tests -v
"""

import asyncio
import os
import unittest

# Sets up the isolated data dir and test treasury key before any GFC module loads config
import test_signed_ledger  # noqa: F401

import peer_discovery  # noqa: E402
from peer_discovery import PeerDiscovery, bootstrap_peers  # noqa: E402


class BootstrapPeerConfigTests(unittest.TestCase):
    def tearDown(self):
        os.environ.pop("GFC_BOOTSTRAP_PEERS", None)

    def test_default_is_the_public_node(self):
        os.environ.pop("GFC_BOOTSTRAP_PEERS", None)
        self.assertEqual(bootstrap_peers(), [("node.galacticfederation.tech", 6881)])

    def test_override_and_disable(self):
        os.environ["GFC_BOOTSTRAP_PEERS"] = "a.example:7000, 198.51.100.7:6881"
        self.assertEqual(bootstrap_peers(), [("a.example", 7000), ("198.51.100.7", 6881)])
        os.environ["GFC_BOOTSTRAP_PEERS"] = ""
        self.assertEqual(bootstrap_peers(), [])

    def test_bad_entries_skipped(self):
        os.environ["GFC_BOOTSTRAP_PEERS"] = "no-port, host:abc, host:0, host:70000, :6881, good.example:6881"
        self.assertEqual(bootstrap_peers(), [("good.example", 6881)])


class BootstrapPeerDiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.discovery = PeerDiscovery(my_port=6881)
        self.discovery._local_ips = {"127.0.0.1", "0.0.0.0", "203.0.113.5"}

    def tearDown(self):
        os.environ.pop("GFC_BOOTSTRAP_PEERS", None)

    def add(self, value):
        os.environ["GFC_BOOTSTRAP_PEERS"] = value
        asyncio.run(self.discovery._add_bootstrap_peers())
        return set(self.discovery.known_peers)

    def test_added_by_ip(self):
        self.assertEqual(self.add("192.0.2.10:6881"), {"192.0.2.10:6881"})

    def test_never_adds_itself(self):
        # Loopback, and this node's own public IP (as on the treasury server itself)
        self.assertEqual(self.add("127.0.0.1:6881,203.0.113.5:6881"), set())

    def test_unresolvable_host_is_skipped(self):
        self.assertEqual(self.add("does-not-exist.invalid:6881"), set())

    def test_re_adding_keeps_it_fresh(self):
        self.add("192.0.2.10:6881")
        self.discovery.known_peers["192.0.2.10:6881"].last_seen = 0  # looks stale
        self.add("192.0.2.10:6881")
        self.assertGreater(self.discovery.known_peers["192.0.2.10:6881"].last_seen, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
