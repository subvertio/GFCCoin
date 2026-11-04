"""
Ledger-only nodes (GFC_SYNC_MEDIA=0): a node that serves the bridge or an attester keeps the
synced rows but never asks peers for posts' media. Found on the bridge's node, 2026-11-04,
pulling the whole media library onto the bridge server.

Run from the repository root:
    python -m unittest discover -s tests -p "test_ledger_only_node.py" -v
"""

import asyncio
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_signed_ledger  # noqa: F401  (sets up the isolated data dir first)

import config  # noqa: E402
from sync_engine import SyncEngine  # noqa: E402


class FakeDiscovery:
    def __init__(self):
        self.connected_peers = set()
        self.known_peers = {}


class FakePeer:
    peer_address = "203.0.113.9:6881"
    is_connected = True

    def __init__(self):
        self.sent = []

    async def send(self, msg):
        self.sent.append(msg)


class LedgerOnlyTests(unittest.TestCase):
    def run_both(self, engine, peer):
        async def go():
            await engine._request_seed_files(peer, "any-seed")
            await engine._request_missing_seed_files(peer)
        asyncio.run(go())

    def test_a_ledger_only_node_requests_no_media(self):
        engine, peer = SyncEngine(FakeDiscovery()), FakePeer()
        with mock.patch.object(config, "SYNC_MEDIA", False), \
                mock.patch("sync_engine.sqlite3.connect", side_effect=AssertionError("looked for media")):
            self.run_both(engine, peer)
        self.assertEqual(peer.sent, [])

    def test_media_sync_is_on_by_default(self):
        self.assertTrue(config.SYNC_MEDIA)


if __name__ == "__main__":
    unittest.main(verbosity=2)
