"""
GFC Sync Engine - P2P data synchronization over TCP

Protocol: JSON messages with 4-byte big-endian length prefix framing.
Message types:
  HELLO          - Exchange node identity (version, wallet_id)
  PEER_LIST      - Exchange known peers (Tier 3 discovery)
  SYNC_REQUEST   - "What's new since timestamp X for table Y?"
  SYNC_RESPONSE  - Here are the new rows (INSERT OR IGNORE on receiver)
  SEED_FILE_REQ  - Request a seed file by ID
  SEED_FILE_RESP - Seed file metadata response
  SEED_FILE_CHUNK- Binary file chunk (base64 encoded)

Data sync is append-only and conflict-free via INSERT OR IGNORE.
"""

import asyncio
import json
import struct
import sqlite3
import time
import base64
import logging
from typing import Dict, List, Optional, Set, TYPE_CHECKING
from pathlib import Path

from config import DB_PATH, DATA_DIR, SEEDS_ORIG_DIR, SEEDS_THUMB_DIR

if TYPE_CHECKING:
    from peer_discovery import PeerDiscovery

logger = logging.getLogger("gfc.sync")

SYNC_PORT = 6881
FRAME_HEADER_SIZE = 4  # 4-byte big-endian length prefix
MAX_MESSAGE_SIZE = 10 * 1024 * 1024  # 10 MB max message size
FILE_CHUNK_SIZE = 256 * 1024  # 256 KB chunks for file transfer

# Tables that are synced between peers (append-only or unique-constrained)
SYNCABLE_TABLES = ["users", "seeds", "transactions", "likes", "comments", "bookmarks", "wallets",
                    "blocks", "user_grants", "podt_proofs"]

# Columns for each table (used for INSERT OR IGNORE)
TABLE_COLUMNS = {
    "users": "id, username, password, first_name, last_name, email, phone, created_at, bio, avatar_filename",
    "seeds": "id, owner, title, description, tags, filename, thumb_filename, content_type, file_size, gfc_earned, likes, comments, views, created_at, reward_wallet",
    "transactions": "id, sender, recipient, amount, reason, timestamp, amount_cents, tx_hash, block_index, tx_type",
    "likes": "id, seed_id, owner, created_at",
    "comments": "id, seed_id, owner, text, created_at",
    "bookmarks": "id, seed_id, owner, created_at",
    "wallets": "id, name, owner, gfc_balance, created_at, gfc_balance_cents, is_treasury",
    "blocks": "block_index, prev_hash, merkle_root, timestamp, tx_count",
    "user_grants": "username, wallet_id, granted_at",
    "podt_proofs": "proof_id, seeder_wallet, receiver_wallet, file_hash, file_size_bytes, reward_cents, tx_id, created_at, seed_id",
}

# Timestamp column for each table (used for "since" queries)
TABLE_TIMESTAMP_COL = {
    "users": "created_at",
    "seeds": "created_at",
    "transactions": "timestamp",
    "likes": "created_at",
    "comments": "created_at",
    "bookmarks": "created_at",
    "wallets": "created_at",
    "blocks": "timestamp",
    "user_grants": "granted_at",
    "podt_proofs": "created_at",
}


class SyncPeer:
    """Represents a single peer TCP connection for sync."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, engine: 'SyncEngine'):
        self.reader = reader
        self.writer = writer
        self.engine = engine
        self.peer_address = ""
        self.peer_version = ""
        self.is_connected = True

    async def send_message(self, msg: dict):
        """Send a framed JSON message."""
        try:
            data = json.dumps(msg).encode("utf-8")
            if len(data) > MAX_MESSAGE_SIZE:
                logger.warning(f"Message too large ({len(data)} bytes), skipping")
                return
            frame = struct.pack("!I", len(data)) + data
            self.writer.write(frame)
            await self.writer.drain()
        except Exception as e:
            logger.debug(f"Send error to {self.peer_address}: {e}")
            self.is_connected = False

    async def receive_message(self) -> Optional[dict]:
        """Receive a framed JSON message. Returns None on disconnect."""
        try:
            # Read 4-byte length header
            header = await self.reader.readexactly(FRAME_HEADER_SIZE)
            msg_len = struct.unpack("!I", header)[0]

            if msg_len > MAX_MESSAGE_SIZE:
                logger.warning(f"Message too large from {self.peer_address}: {msg_len} bytes")
                return None

            # Read message body
            data = await self.reader.readexactly(msg_len)
            return json.loads(data.decode("utf-8"))
        except (asyncio.IncompleteReadError, ConnectionResetError, ConnectionAbortedError):
            self.is_connected = False
            return None
        except Exception as e:
            logger.debug(f"Receive error from {self.peer_address}: {e}")
            self.is_connected = False
            return None

    async def close(self):
        """Close the connection."""
        self.is_connected = False
        try:
            self.writer.close()
            await self.writer.wait_closed()
        except Exception:
            pass


class SyncEngine:
    """
    Manages P2P sync connections and data exchange.
    Runs a TCP server and periodically connects to discovered peers.
    """

    def __init__(self, discovery: 'PeerDiscovery'):
        self.discovery = discovery
        self.connections: Dict[str, SyncPeer] = {}
        self.last_sync_timestamps: Dict[str, str] = {}  # Per-table (global, for status display)
        self._per_peer_sync_ts: Dict[str, str] = {}  # Per-peer-per-table: "ip:port:table" -> timestamp
        self.server: Optional[asyncio.AbstractServer] = None
        self._running = False
        self._tasks: List[asyncio.Task] = []
        # Track seed files we need to download from peers
        self._pending_file_chunks: Dict[str, Dict] = {}  # seed_id -> {filename, chunks: [bytes], expected_size}
        # Connection backoff for unreachable peers (prevents constant timeout spam for WAN peers behind NAT)
        self._failed_attempts: Dict[str, int] = {}  # peer_key -> consecutive failure count
        self._backoff_until: Dict[str, float] = {}  # peer_key -> time.time() when backoff expires

    async def start(self):
        """Start TCP server and background sync tasks."""
        self._running = True

        # Enable SQLite WAL mode for concurrent access
        try:
            conn = sqlite3.connect(DB_PATH)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.close()
            logger.info("SQLite WAL mode enabled")
        except Exception as e:
            logger.warning(f"Could not enable WAL mode: {e}")

        # Start TCP server
        try:
            self.server = await asyncio.start_server(
                self._handle_incoming, "0.0.0.0", SYNC_PORT
            )
            logger.info(f"Sync server listening on TCP port {SYNC_PORT}")
        except OSError as e:
            logger.warning(f"Cannot bind sync port {SYNC_PORT}: {e}")

        # Background tasks
        self._tasks = [
            asyncio.create_task(self._connect_loop()),
            asyncio.create_task(self._sync_loop()),
        ]

    async def stop(self):
        """Stop sync engine."""
        self._running = False

        # Close all peer connections
        for peer in list(self.connections.values()):
            await peer.close()
        self.connections.clear()

        # Stop server
        if self.server:
            self.server.close()
            await self.server.wait_closed()

        # Cancel tasks
        for task in self._tasks:
            task.cancel()
        self._tasks.clear()

        logger.info("Sync engine stopped")

    # ---------- Connection management ----------

    async def _handle_incoming(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle an incoming peer connection."""
        peername = writer.get_extra_info("peername")
        if not peername:
            writer.close()
            return

        # Use the peer's IP with the standard sync port as the canonical key
        # (peername[1] is the ephemeral client port, not useful for identification)
        peer_ip = peername[0]
        peer_key = f"{peer_ip}:{SYNC_PORT}"
        logger.info(f"Incoming sync connection from {peer_ip} (canonical key: {peer_key})")

        # If we already have an outgoing connection to this peer, don't duplicate
        if peer_key in self.connections:
            existing = self.connections[peer_key]
            if existing.is_connected:
                logger.info(f"Already connected to {peer_key} (outgoing), closing incoming duplicate")
                writer.close()
                return
            else:
                # Old connection is dead, replace it
                logger.info(f"Replacing dead connection to {peer_key} with new incoming")
                del self.connections[peer_key]

        peer = SyncPeer(reader, writer, self)
        peer.peer_address = peer_key

        # Track the incoming connection so _sync_loop can use it
        self.connections[peer_key] = peer
        self.discovery.connected_peers.add(peer_key)

        # Clear any backoff for this peer since they just connected to us
        self._failed_attempts.pop(peer_key, None)
        self._backoff_until.pop(peer_key, None)

        # Send HELLO
        await peer.send_message({
            "type": "HELLO",
            "version": "3.0.0",
            "port": SYNC_PORT,
        })

        # IMPORTANT: Schedule a sync to pull data FROM this incoming peer.
        # This is critical for network-isolated peers that can only connect outbound:
        # they reach us, but we can't reach them. This is our only chance to pull their data.
        logger.info(f"Incoming connection from {peer_key}: scheduling reverse sync to pull their data")
        asyncio.create_task(self._delayed_sync(peer, delay=3))

        # Process messages (blocks until disconnect)
        await self._message_loop(peer)

    async def _connect_loop(self):
        """Periodically connect to discovered peers we're not yet connected to.

        Uses exponential backoff for peers that fail to connect (likely behind NAT).
        This prevents constant 5-second timeout waits for unreachable WAN peers.
        """
        first_run = True
        while self._running:
            try:
                # First run: short delay to let UDP discovery find LAN peers
                # Subsequent runs: check every 10 seconds
                await asyncio.sleep(3 if first_run else 10)
                first_run = False
            except asyncio.CancelledError:
                break

            now = time.time()
            peers_to_try = []
            skipped_backoff = 0
            for key, info in list(self.discovery.known_peers.items()):
                if key in self.connections:
                    continue
                # Check backoff - skip peers we've recently failed to connect to
                backoff_expires = self._backoff_until.get(key, 0)
                if now < backoff_expires:
                    skipped_backoff += 1
                    continue
                peers_to_try.append((key, info))

            if peers_to_try and not self.connections:
                logger.info(f"Connect loop: {len(peers_to_try)} peers to try, {skipped_backoff} in backoff, 0 connected")

            for key, peer_info in peers_to_try:
                if len(self.connections) >= 10:
                    break  # Max connections

                try:
                    logger.info(f"Attempting TCP connection to {peer_info.address}:{peer_info.port}...")
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(peer_info.address, peer_info.port),
                        timeout=5
                    )
                    peer = SyncPeer(reader, writer, self)
                    peer.peer_address = key
                    self.connections[key] = peer
                    self.discovery.connected_peers.add(key)

                    # Clear backoff on successful connection
                    self._failed_attempts.pop(key, None)
                    self._backoff_until.pop(key, None)

                    # Send HELLO
                    await peer.send_message({
                        "type": "HELLO",
                        "version": "3.0.0",
                        "port": SYNC_PORT,
                    })

                    # Trigger an immediate sync for this new connection
                    asyncio.create_task(self._sync_one_peer(peer))

                    # Handle messages in background
                    asyncio.create_task(self._message_loop(peer))
                    logger.info(f"Connected to peer {key}")

                except (asyncio.TimeoutError, ConnectionRefusedError, OSError) as e:
                    # Record failure and apply exponential backoff
                    fails = self._failed_attempts.get(key, 0) + 1
                    self._failed_attempts[key] = fails
                    # Backoff: 30s, 60s, 120s, 300s, 600s (max 10 min)
                    backoff_secs = min(30 * (2 ** (fails - 1)), 600)
                    self._backoff_until[key] = time.time() + backoff_secs
                    error_type = "TIMED OUT" if isinstance(e, asyncio.TimeoutError) else \
                                 "REFUSED" if isinstance(e, ConnectionRefusedError) else str(e)
                    logger.info(f"TCP to {key}: {error_type} (attempt {fails}, backoff {backoff_secs}s)")

    async def _message_loop(self, peer: SyncPeer):
        """Process messages from a connected peer."""
        try:
            while self._running and peer.is_connected:
                msg = await peer.receive_message()
                if msg is None:
                    break
                await self._handle_message(peer, msg)
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.debug(f"Message loop error for {peer.peer_address}: {e}")
        finally:
            # Clean up
            await peer.close()
            key = peer.peer_address
            if key in self.connections:
                del self.connections[key]
            self.discovery.connected_peers.discard(key)
            logger.info(f"Disconnected from peer {key}")

    # ---------- Message handling ----------

    async def _handle_message(self, peer: SyncPeer, msg: dict):
        """Route a received message to the appropriate handler."""
        msg_type = msg.get("type", "")

        if msg_type == "HELLO":
            await self._on_hello(peer, msg)
        elif msg_type == "PEER_LIST":
            self._on_peer_list(peer, msg)
        elif msg_type == "SYNC_REQUEST":
            await self._on_sync_request(peer, msg)
        elif msg_type == "SYNC_RESPONSE":
            await self._on_sync_response(peer, msg)
        elif msg_type == "SEED_FILE_REQ":
            await self._on_seed_file_request(peer, msg)
        elif msg_type == "SEED_FILE_RESP":
            self._on_seed_file_response(peer, msg)
        elif msg_type == "SEED_FILE_CHUNK":
            self._on_seed_file_chunk(peer, msg)
        else:
            logger.debug(f"Unknown message type from {peer.peer_address}: {msg_type}")

    async def _on_hello(self, peer: SyncPeer, msg: dict):
        """Handle HELLO message - exchange identity and peer lists."""
        peer.peer_version = msg.get("version", "")
        remote_port = msg.get("port", SYNC_PORT)
        logger.info(f"HELLO from {peer.peer_address} (v{peer.peer_version})")

        # Add peer to discovery with the sync port (not the ephemeral TCP port)
        addr = peer.peer_address.split(":")[0]
        self.discovery._add_peer(addr, remote_port)

        # Exchange peer lists (Tier 3)
        await peer.send_message({
            "type": "PEER_LIST",
            "peers": self.discovery.get_peer_list(),
        })

        # Trigger an immediate sync with this peer
        # This ensures BOTH sides pull data from each other:
        # - Outbound connector already syncs in _connect_loop
        # - Incoming connections need this to pull data FROM the connecting peer
        logger.info(f"Scheduling bidirectional sync with {peer.peer_address}")
        asyncio.create_task(self._delayed_sync(peer, delay=2))

    def _on_peer_list(self, peer: SyncPeer, msg: dict):
        """Handle PEER_LIST message - add received peers to discovery."""
        peers = msg.get("peers", [])
        self.discovery.receive_peer_list(peers)

    async def _on_sync_request(self, peer: SyncPeer, msg: dict):
        """Handle SYNC_REQUEST - send rows newer than the requested timestamp."""
        table = msg.get("table", "")
        since = msg.get("since", "")

        if table not in SYNCABLE_TABLES:
            return

        columns = TABLE_COLUMNS.get(table, "")
        ts_col = TABLE_TIMESTAMP_COL.get(table, "created_at")

        try:
            conn = sqlite3.connect(DB_PATH)
            if since:
                rows = conn.execute(
                    f"SELECT {columns} FROM {table} WHERE {ts_col} > ? ORDER BY {ts_col} ASC LIMIT 500",
                    (since,)
                ).fetchall()
            else:
                rows = conn.execute(
                    f"SELECT {columns} FROM {table} ORDER BY {ts_col} ASC LIMIT 500"
                ).fetchall()
            conn.close()
        except Exception as e:
            logger.warning(f"Sync query error for {table}: {e}")
            rows = []

        if rows:
            logger.info(f"Sending {len(rows)} rows from {table} to {peer.peer_address} (since={since or 'beginning'})")

        # Send response
        await peer.send_message({
            "type": "SYNC_RESPONSE",
            "table": table,
            "columns": columns.split(", "),
            "rows": [list(r) for r in rows],
        })

    async def _on_sync_response(self, peer: SyncPeer, msg: dict):
        """Handle SYNC_RESPONSE - insert received rows into local database."""
        table = msg.get("table", "")
        columns = msg.get("columns", [])
        rows = msg.get("rows", [])

        if table not in SYNCABLE_TABLES or not columns:
            return
        if not rows:
            logger.debug(f"Sync response for {table} from {peer.peer_address}: 0 rows (up to date)")
            return

        col_names = ", ".join(columns)
        placeholders = ", ".join(["?"] * len(columns))
        ts_col = TABLE_TIMESTAMP_COL.get(table, "created_at")

        inserted = 0
        skipped = 0
        errors = 0
        new_seed_ids = []
        try:
            conn = sqlite3.connect(DB_PATH)
            for row in rows:
                if len(row) != len(columns):
                    skipped += 1
                    continue  # Skip malformed rows
                try:
                    cursor = conn.execute(
                        f"INSERT OR IGNORE INTO {table} ({col_names}) VALUES ({placeholders})",
                        row
                    )
                    if cursor.rowcount > 0:
                        inserted += 1
                        # Track new seeds to request their files
                        if table == "seeds":
                            try:
                                id_idx = columns.index("id")
                                new_seed_ids.append(row[id_idx])
                            except (ValueError, IndexError):
                                pass
                except Exception as e:
                    errors += 1
                    if errors <= 3:  # Log first few errors at INFO level
                        logger.info(f"Sync insert error for {table} row: {e}")
            conn.commit()
            conn.close()
        except Exception as e:
            logger.warning(f"Sync DB error for {table}: {e}")

        logger.info(f"Sync {table} from {peer.peer_address}: {len(rows)} received, {inserted} inserted, {len(rows) - inserted - skipped - errors} duplicates, {errors} errors")

        # Update sync timestamps (both global for display and per-peer for queries)
        if rows:
            try:
                ts_idx = columns.index(ts_col)
                latest = max(r[ts_idx] for r in rows if r[ts_idx])
                self.last_sync_timestamps[table] = str(latest)
                # Per-peer timestamp so next sync with THIS peer only fetches newer data
                peer_ts_key = f"{peer.peer_address}:{table}"
                self._per_peer_sync_ts[peer_ts_key] = str(latest)
            except (ValueError, TypeError):
                pass

        if inserted:
            logger.info(f"Synced {inserted} rows into {table} from {peer.peer_address}")

        # Request files for any new seeds we received
        for seed_id in new_seed_ids:
            await self._request_seed_files(peer, seed_id)

    async def _request_seed_files(self, peer: SyncPeer, seed_id: str):
        """Request seed files (original + thumbnail) from a peer."""
        # Check if we already have the file locally
        try:
            conn = sqlite3.connect(DB_PATH)
            row = conn.execute(
                "SELECT filename, thumb_filename FROM seeds WHERE id = ?", (seed_id,)
            ).fetchone()
            conn.close()
        except Exception:
            return

        if not row:
            return

        filename, thumb_filename = row

        # Request original file if we don't have it
        if filename:
            file_path = SEEDS_ORIG_DIR / filename
            if not file_path.exists():
                logger.info(f"Requesting seed file {seed_id} ({filename}) from {peer.peer_address}")
                await peer.send_message({
                    "type": "SEED_FILE_REQ",
                    "seed_id": seed_id,
                    "file_type": "original",
                })

        # Request thumbnail if we don't have it
        if thumb_filename:
            thumb_path = SEEDS_THUMB_DIR / thumb_filename
            if not thumb_path.exists():
                logger.info(f"Requesting seed thumbnail {seed_id} ({thumb_filename}) from {peer.peer_address}")
                await peer.send_message({
                    "type": "SEED_FILE_REQ",
                    "seed_id": seed_id,
                    "file_type": "thumbnail",
                })

    async def _on_seed_file_request(self, peer: SyncPeer, msg: dict):
        """Handle SEED_FILE_REQ - send a seed file to the requesting peer."""
        seed_id = msg.get("seed_id", "")
        file_type = msg.get("file_type", "original")  # "original" or "thumbnail"
        if not seed_id:
            return

        # Look up the filename from DB
        try:
            conn = sqlite3.connect(DB_PATH)
            row = conn.execute(
                "SELECT filename, thumb_filename, file_size FROM seeds WHERE id = ?", (seed_id,)
            ).fetchone()
            conn.close()
        except Exception:
            row = None

        if not row:
            await peer.send_message({
                "type": "SEED_FILE_RESP",
                "seed_id": seed_id,
                "file_type": file_type,
                "found": False,
            })
            return

        filename, thumb_filename, file_size = row

        # Choose the right file based on type
        if file_type == "thumbnail" and thumb_filename:
            target_filename = thumb_filename
            file_path = SEEDS_THUMB_DIR / thumb_filename
        elif filename:
            target_filename = filename
            file_path = SEEDS_ORIG_DIR / filename
        else:
            await peer.send_message({
                "type": "SEED_FILE_RESP",
                "seed_id": seed_id,
                "file_type": file_type,
                "found": False,
            })
            return

        if not file_path.exists():
            await peer.send_message({
                "type": "SEED_FILE_RESP",
                "seed_id": seed_id,
                "file_type": file_type,
                "found": False,
            })
            return

        actual_size = file_path.stat().st_size

        # Send file metadata
        await peer.send_message({
            "type": "SEED_FILE_RESP",
            "seed_id": seed_id,
            "file_type": file_type,
            "found": True,
            "filename": target_filename,
            "file_size": actual_size,
        })

        # Send file data in chunks (as separate messages)
        try:
            sent_final = False
            with open(file_path, "rb") as f:
                chunk_idx = 0
                while True:
                    chunk = f.read(FILE_CHUNK_SIZE)
                    if not chunk:
                        break
                    is_last = (len(chunk) < FILE_CHUNK_SIZE)
                    await peer.send_message({
                        "type": "SEED_FILE_CHUNK",
                        "seed_id": seed_id,
                        "file_type": file_type,
                        "chunk_idx": chunk_idx,
                        "data": base64.b64encode(chunk).decode("ascii"),
                        "is_last": is_last,
                    })
                    chunk_idx += 1
                    if is_last:
                        sent_final = True
                        break

            # If file size was exact multiple of FILE_CHUNK_SIZE, the last chunk
            # read was full-sized so is_last was never True. Send an empty
            # terminator chunk so the receiver knows the transfer is complete.
            if chunk_idx > 0 and not sent_final:
                await peer.send_message({
                    "type": "SEED_FILE_CHUNK",
                    "seed_id": seed_id,
                    "file_type": file_type,
                    "chunk_idx": chunk_idx,
                    "data": "",
                    "is_last": True,
                })

            logger.info(f"Sent seed {file_type} file {seed_id} ({target_filename}, {actual_size} bytes) to {peer.peer_address}")
        except Exception as e:
            logger.warning(f"Error sending seed file {seed_id}: {e}")

    def _on_seed_file_response(self, peer: SyncPeer, msg: dict):
        """Handle SEED_FILE_RESP - receive seed file metadata and prepare for chunks."""
        seed_id = msg.get("seed_id", "")
        file_type = msg.get("file_type", "original")
        found = msg.get("found", False)

        if not found:
            logger.debug(f"Peer {peer.peer_address} does not have seed {file_type} file {seed_id}")
            return

        filename = msg.get("filename", "")
        file_size = msg.get("file_size", 0)
        logger.info(f"Peer {peer.peer_address} sending seed {file_type} {seed_id} ({filename}, {file_size} bytes)")

        # Prepare to receive chunks
        chunk_key = f"{seed_id}:{file_type}"
        self._pending_file_chunks[chunk_key] = {
            "filename": filename,
            "file_type": file_type,
            "expected_size": file_size,
            "chunks": [],
        }

    def _on_seed_file_chunk(self, peer: SyncPeer, msg: dict):
        """Handle SEED_FILE_CHUNK - receive and assemble file chunks."""
        seed_id = msg.get("seed_id", "")
        file_type = msg.get("file_type", "original")
        chunk_idx = msg.get("chunk_idx", 0)
        data_b64 = msg.get("data", "")
        is_last = msg.get("is_last", False)

        chunk_key = f"{seed_id}:{file_type}"
        pending = self._pending_file_chunks.get(chunk_key)
        if not pending:
            logger.debug(f"Received chunk for unknown seed file {chunk_key}")
            return

        # Decode and store chunk
        try:
            chunk_data = base64.b64decode(data_b64)
            pending["chunks"].append((chunk_idx, chunk_data))
        except Exception as e:
            logger.debug(f"Error decoding chunk {chunk_idx} for {chunk_key}: {e}")
            return

        if is_last:
            # Assemble the file
            self._assemble_seed_file(seed_id, file_type, pending)
            del self._pending_file_chunks[chunk_key]

    def _assemble_seed_file(self, seed_id: str, file_type: str, pending: dict):
        """Assemble received chunks into a file on disk, then award PoDT credits."""
        filename = pending["filename"]
        chunks = pending["chunks"]

        if not chunks or not filename:
            return

        # Sort chunks by index and concatenate
        chunks.sort(key=lambda x: x[0])
        file_data = b"".join(c[1] for c in chunks)

        # Write to the appropriate directory
        if file_type == "thumbnail":
            dest_dir = SEEDS_THUMB_DIR
        else:
            dest_dir = SEEDS_ORIG_DIR

        dest_path = dest_dir / filename
        try:
            dest_dir.mkdir(parents=True, exist_ok=True)
            with open(dest_path, "wb") as f:
                f.write(file_data)
            logger.info(f"Saved synced seed {file_type} file: {filename} ({len(file_data)} bytes)")
        except Exception as e:
            logger.warning(f"Failed to save seed file {filename}: {e}")
            return

        # Award PoDT credits (only for original files, not thumbnails)
        if file_type != "thumbnail" and len(file_data) >= 1024:
            self._award_podt_credits(seed_id, filename, len(file_data), pending)

    def _award_podt_credits(self, seed_id: str, filename: str, file_size: int, pending: dict):
        """Award PoDT credits to the seeder after successful file transfer."""
        try:
            import hashlib as _hashlib
            from blockchain import process_podt_reward

            # Look up the seed owner and reward wallet
            conn = sqlite3.connect(DB_PATH)
            row = conn.execute(
                "SELECT owner, reward_wallet FROM seeds WHERE id = ?", (seed_id,)
            ).fetchone()

            if not row:
                conn.close()
                return

            seed_owner = row[0]
            reward_wallet = row[1] if row[1] else ""

            # Determine which wallet gets the reward
            seeder_wallet = None

            # Priority 1: Use the seed's designated reward_wallet if set
            if reward_wallet:
                wallet_exists = conn.execute(
                    "SELECT id FROM wallets WHERE id = ?", (reward_wallet,)
                ).fetchone()
                if wallet_exists:
                    seeder_wallet = reward_wallet
                else:
                    logger.warning(f"PoDT: Reward wallet '{reward_wallet[:16]}...' not found, "
                                   f"falling back to owner lookup")

            # Priority 2: Fall back to owner's first wallet
            if not seeder_wallet:
                wallet_row = conn.execute(
                    "SELECT id FROM wallets WHERE owner = ? LIMIT 1", (seed_owner,)
                ).fetchone()
                if not wallet_row:
                    conn.close()
                    logger.debug(f"PoDT: No wallet found for seed owner '{seed_owner}', skipping reward")
                    return
                seeder_wallet = wallet_row[0]

            conn.close()

            # Compute proof ID from seed_id + filename + file_size
            proof_string = f"{seed_id}:{filename}:{file_size}"
            proof_id = _hashlib.sha256(proof_string.encode()).hexdigest()

            # Award the reward
            result = process_podt_reward(
                db_path=DB_PATH,
                seeder_wallet=seeder_wallet,
                proof_id=proof_id,
                bytes_transferred=file_size,
                file_hash=_hashlib.sha256(f"{seed_id}:{filename}".encode()).hexdigest(),
                receiver_wallet="",  # Receiver is the local node (us)
                seed_id=seed_id,
            )

            if result:
                logger.info(f"PoDT: Awarded {result['amount']:.2f} GFC to wallet {seeder_wallet[:16]}... "
                           f"for seeding {filename} ({file_size} bytes)")
            else:
                logger.debug(f"PoDT: No reward for {filename} (already claimed or too small)")

        except Exception as e:
            logger.warning(f"PoDT: Failed to award credits for {filename}: {e}")

    # ---------- Sync helpers ----------

    async def _request_missing_seed_files(self, peer: SyncPeer):
        """Scan DB for seeds whose files are missing on disk and request them.

        This is the recovery mechanism for seeds whose metadata arrived via
        sync but whose binary files were never transferred (e.g., connection
        dropped mid-transfer, app restarted, or metadata arrived via tracker
        relay which only syncs table rows, not binary files).

        Called after every sync cycle to ensure files eventually arrive.
        """
        if not peer.is_connected:
            return

        try:
            conn = sqlite3.connect(DB_PATH)
            rows = conn.execute(
                "SELECT id, filename, thumb_filename FROM seeds WHERE filename IS NOT NULL AND filename != ''"
            ).fetchall()
            conn.close()
        except Exception as e:
            logger.debug(f"Missing file scan DB error: {e}")
            return

        missing_count = 0
        for seed_id, filename, thumb_filename in rows:
            if not peer.is_connected:
                break  # Peer disconnected during scan

            needs_original = filename and not (SEEDS_ORIG_DIR / filename).exists()
            needs_thumb = thumb_filename and not (SEEDS_THUMB_DIR / thumb_filename).exists()

            if needs_original or needs_thumb:
                missing_count += 1
                await self._request_seed_files(peer, seed_id)

        if missing_count > 0:
            logger.info(f"Missing file recovery: requested files for {missing_count} seeds from {peer.peer_address}")

    async def _sync_one_peer(self, peer: SyncPeer):
        """Send sync requests to a single peer for all tables.

        Uses per-peer timestamps so that connecting to a NEW peer fetches ALL
        data from them, not just data newer than what we got from other peers.
        INSERT OR IGNORE handles duplicates safely.
        """
        if not peer.is_connected:
            logger.debug(f"Skipping sync with {peer.peer_address} - not connected")
            return
        logger.info(f"Requesting sync from {peer.peer_address} for {len(SYNCABLE_TABLES)} tables")
        for table in SYNCABLE_TABLES:
            # Use per-peer timestamp so new peers send ALL their data
            peer_ts_key = f"{peer.peer_address}:{table}"
            since = self._per_peer_sync_ts.get(peer_ts_key, "")
            try:
                await peer.send_message({
                    "type": "SYNC_REQUEST",
                    "table": table,
                    "since": since,
                })
            except Exception as e:
                logger.debug(f"Sync request error for {table} to {peer.peer_address}: {e}")
                break

    async def _delayed_sync(self, peer: SyncPeer, delay: float = 2):
        """Trigger a sync after a short delay (lets HELLO exchange finish)."""
        await asyncio.sleep(delay)
        if peer.is_connected:
            await self._sync_one_peer(peer)
            # After metadata sync, check for any seeds missing their files on disk
            # Wait a bit for sync responses to arrive and be processed
            await asyncio.sleep(5)
            if peer.is_connected:
                await self._request_missing_seed_files(peer)

    # ---------- Periodic sync ----------

    async def _sync_loop(self):
        """Periodically request new data from connected peers."""
        while self._running:
            try:
                await asyncio.sleep(30)  # Sync every 30 seconds
            except asyncio.CancelledError:
                break

            connected = [(k, p) for k, p in list(self.connections.items()) if p.is_connected]
            if connected:
                logger.info(f"Periodic sync: {len(connected)} connected peers: {[k for k,_ in connected]}")
            for key, peer in connected:
                await self._sync_one_peer(peer)

            # After metadata sync, scan for seeds missing files on disk
            # Use the first connected peer to request missing files
            if connected:
                first_key, first_peer = connected[0]
                if first_peer.is_connected:
                    await asyncio.sleep(5)  # Let sync responses arrive first
                    await self._request_missing_seed_files(first_peer)

    # ---------- Status ----------

    @property
    def connection_count(self) -> int:
        return len(self.connections)

    def status(self) -> Dict:
        """Return sync status for the /p2p/status endpoint."""
        return {
            "connections": self.connection_count,
            "last_sync": dict(self.last_sync_timestamps),
            "connected_peers": [
                {"address": p.peer_address, "version": p.peer_version}
                for p in self.connections.values()
                if p.is_connected
            ],
        }
