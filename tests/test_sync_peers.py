"""
Peer connections that vanish without closing (found on attester #2, 2026-11-01): a laptop
went to sleep, its connection to the canonical node stayed "connected" on the node's side,
and every reconnect was refused as a duplicate, so syncing stopped network-wide. Also, two
machines behind one router (one public IP) could not both connect.

These run real TCP connections against SyncEngine._handle_incoming on 127.0.0.1.

Run from the repository root:
    python -m unittest discover -s tests -p "test_sync_peers.py" -v
"""

import asyncio
import socket
import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import sync_engine  # noqa: E402
from sync_engine import SYNC_PORT, STALE_PEER_SECONDS, SyncEngine  # noqa: E402


class FakeDiscovery:
    def __init__(self):
        self.connected_peers = set()
        self.known_peers = {}


class SyncPeerTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.engine = SyncEngine(FakeDiscovery())
        self.engine._running = True
        self.handled = []

        async def no_sync(peer, delay=0):  # no database work in these tests
            return None

        async def record(peer, msg):
            self.handled.append((peer.peer_address, msg.get("type")))

        self.engine._delayed_sync = no_sync
        self.engine._handle_message = record
        self.server = await asyncio.start_server(self.engine._handle_incoming, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]
        self.clients = []

    async def asyncTearDown(self):
        self.engine._running = False
        for w in self.clients:
            w.close()
        for p in list(self.engine.connections.values()):
            await p.close()
        self.server.close()
        await self.server.wait_closed()

    async def connect(self):
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        self.clients.append(writer)
        await asyncio.sleep(0.2)  # let the engine register it
        return reader, writer

    def key(self):
        return f"127.0.0.1:{SYNC_PORT}"

    async def test_a_peer_that_vanished_is_replaced_when_it_reconnects(self):
        await self.connect()
        first = self.engine.connections[self.key()]
        # The peer goes to sleep: nothing arrives, and the socket never closes
        first.last_received = time.monotonic() - STALE_PEER_SECONDS - 1
        await self.connect()
        second = self.engine.connections[self.key()]
        self.assertIsNot(first, second)
        self.assertFalse(first.is_connected)
        await asyncio.sleep(0.2)  # the old message loop ends: it must not remove the new connection
        self.assertIs(self.engine.connections.get(self.key()), second)
        self.assertIn(self.key(), self.engine.discovery.connected_peers)

    async def test_a_live_outgoing_connection_still_refuses_a_duplicate(self):
        await self.connect()
        existing = self.engine.connections[self.key()]
        existing.outgoing = True  # as if we had dialed them
        reader, _ = await self.connect()
        self.assertIs(self.engine.connections[self.key()], existing)
        self.assertEqual(len(self.engine.connections), 1)
        self.assertEqual(await asyncio.wait_for(reader.read(), 2), b"")  # the duplicate was closed

    async def test_two_machines_behind_one_router_both_connect(self):
        await self.connect()
        await self.connect()  # another live machine from the same public IP
        keys = sorted(self.engine.connections)
        self.assertEqual(len(keys), 2, keys)
        self.assertEqual(keys[0], self.key())
        self.assertTrue(keys[1].startswith(self.key() + "#"))
        self.assertTrue(all(p.is_connected for p in self.engine.connections.values()))

    async def test_sync_sockets_have_tcp_keepalive(self):
        await self.connect()
        sock = self.engine.connections[self.key()].writer.get_extra_info("socket")
        self.assertTrue(sock.getsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE))

    async def test_traffic_keeps_a_connection_fresh(self):
        _, writer = await self.connect()
        peer = self.engine.connections[self.key()]
        peer.last_received = time.monotonic() - STALE_PEER_SECONDS - 1
        self.assertTrue(peer.stale())
        payload = b'{"type": "PING"}'
        writer.write(len(payload).to_bytes(4, "big") + payload)
        await writer.drain()
        await asyncio.sleep(0.2)
        self.assertFalse(peer.stale())
        self.assertIn((self.key(), "PING"), self.handled)


if __name__ == "__main__":
    unittest.main(verbosity=2)
