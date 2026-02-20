"""
GFC Peer Discovery - Three-tier peer finding system

Tier 1: Bootstrap Trackers (HTTP) - Contact well-known endpoints for initial peer list
Tier 2: LAN Discovery (UDP broadcast) - Find peers on the local network
Tier 3: Peer Exchange (Gossip) - Connected peers share their known peer lists
"""

import asyncio
import json
import os
import time
import socket
import sqlite3
import logging
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field

logger = logging.getLogger("gfc.discovery")

# Peer persistence file - stored in DATA_DIR
try:
    from config import DATA_DIR, DB_PATH
    PEERS_FILE = os.path.join(str(DATA_DIR), "known_peers.json")
except ImportError:
    PEERS_FILE = os.path.join(os.path.dirname(__file__), "data", "known_peers.json")
    DB_PATH = os.path.join(os.path.dirname(__file__), "data", "gfc_ledger.db")

# ---------- Configuration ----------

# Bootstrap trackers - HTTP endpoints that maintain peer lists.
# These can be community-run servers, Cloudflare Workers, or any HTTP endpoint.
# Empty initially; add tracker URLs as the network grows.
BOOTSTRAP_TRACKERS: List[str] = [
    "https://www.galacticfederation.tech/_functions/peers",
]

LAN_DISCOVERY_PORT = 6882
PEER_LISTEN_PORT = 6881
GFC_MAGIC = b"GFC_PEER_V1"

# How often to broadcast on LAN (seconds)
LAN_BROADCAST_INTERVAL = 30

# How long before a peer is considered stale (seconds)
PEER_TTL = 3600  # 1 hour

# Max peers to track
MAX_KNOWN_PEERS = 500

# Tracker sync relay interval (seconds) - how often to upload/download via tracker
TRACKER_SYNC_INTERVAL = 60

# Tables and columns for tracker sync (mirrors sync_engine.py SYNCABLE_TABLES)
TRACKER_SYNCABLE_TABLES = ["users", "seeds", "transactions", "likes", "comments", "bookmarks", "wallets",
                           "blocks", "user_grants", "podt_proofs"]
TRACKER_TABLE_COLUMNS = {
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
TRACKER_TABLE_TIMESTAMP_COL = {
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
# Max rows per upload bundle (to stay within Wix text field limits)
TRACKER_MAX_ROWS_PER_UPLOAD = 50


def _compute_broadcast(ip: str, mask: str) -> Optional[str]:
    """Compute broadcast address from IP and subnet mask."""
    try:
        ip_parts = [int(p) for p in ip.split(".")]
        mask_parts = [int(p) for p in mask.split(".")]
        if len(ip_parts) != 4 or len(mask_parts) != 4:
            return None
        bcast = [(ip_parts[i] | (~mask_parts[i] & 0xFF)) for i in range(4)]
        return ".".join(str(b) for b in bcast)
    except (ValueError, IndexError):
        return None


# ---------- Data structures ----------

@dataclass
class PeerInfo:
    """Represents a discovered peer node."""
    address: str
    port: int
    wallet_id: str = ""
    version: str = ""
    last_seen: float = 0.0

    @property
    def key(self) -> str:
        return f"{self.address}:{self.port}"


# ---------- Discovery engine ----------

class PeerDiscovery:
    """
    Manages peer discovery across all three tiers.
    Runs as asyncio background tasks within the FastAPI process.
    """

    def __init__(self, my_port: int = PEER_LISTEN_PORT):
        self.my_port = my_port
        self.known_peers: Dict[str, PeerInfo] = {}
        self.connected_peers: Set[str] = set()
        self._running = False
        self._tasks: List[asyncio.Task] = []
        self._local_ips: Set[str] = set()
        # Tracker sync relay state
        self._my_peer_key: str = ""  # Set after first tracker announce (our public IP:port)
        self._tracker_upload_ts: Dict[str, str] = {}  # table -> last uploaded timestamp
        self._tracker_download_ts: str = ""  # ISO timestamp of last download

    async def start(self):
        """Start all discovery mechanisms as background tasks."""
        self._running = True
        self._local_ips = self._get_local_ips()
        logger.info(f"Starting peer discovery (listen port: {self.my_port}, local IPs: {self._local_ips})")

        # Load previously known peers from disk
        self._load_peers()

        self._tasks = [
            asyncio.create_task(self._bootstrap_from_trackers()),
            asyncio.create_task(self._lan_listener_loop()),
            asyncio.create_task(self._lan_broadcast_loop()),
            asyncio.create_task(self._cleanup_loop()),
            asyncio.create_task(self._periodic_save_loop()),
            asyncio.create_task(self._tracker_sync_loop()),
        ]

    async def stop(self):
        """Stop all discovery tasks."""
        self._running = False
        # Save peers before shutting down
        self._save_peers()
        for task in self._tasks:
            task.cancel()
        self._tasks.clear()
        logger.info("Peer discovery stopped")

    # ---------- Peer Persistence ----------

    def _save_peers(self):
        """Save known peers to disk so they survive restarts."""
        try:
            peers_data = []
            now = time.time()
            for key, peer in self.known_peers.items():
                # Only save peers seen within the last TTL period
                if now - peer.last_seen < PEER_TTL:
                    peers_data.append({
                        "address": peer.address,
                        "port": peer.port,
                        "last_seen": peer.last_seen,
                    })
            os.makedirs(os.path.dirname(PEERS_FILE), exist_ok=True)
            with open(PEERS_FILE, "w") as f:
                json.dump({"peers": peers_data, "saved_at": time.time()}, f, indent=2)
            logger.debug(f"Saved {len(peers_data)} peers to {PEERS_FILE}")
        except Exception as e:
            logger.warning(f"Failed to save peers: {e}")

    def _load_peers(self):
        """Load previously known peers from disk."""
        try:
            if not os.path.exists(PEERS_FILE):
                logger.info("No saved peers file found - starting fresh")
                return
            with open(PEERS_FILE, "r") as f:
                data = json.load(f)
            peers = data.get("peers", [])
            now = time.time()
            loaded = 0
            for p in peers:
                addr = p.get("address", "")
                port = p.get("port", PEER_LISTEN_PORT)
                last_seen = p.get("last_seen", 0)
                # Only load peers that aren't too old (within 24 hours)
                if addr and (now - last_seen) < 86400 and not self._is_self(addr, port):
                    key = f"{addr}:{port}"
                    if key not in self.known_peers:
                        self.known_peers[key] = PeerInfo(
                            address=addr, port=port, last_seen=last_seen
                        )
                        loaded += 1
            if loaded:
                logger.info(f"Loaded {loaded} saved peers from disk")
        except Exception as e:
            logger.warning(f"Failed to load saved peers: {e}")

    async def _periodic_save_loop(self):
        """Periodically save known peers to disk."""
        while self._running:
            try:
                await asyncio.sleep(60)  # Save every minute
            except asyncio.CancelledError:
                break
            self._save_peers()

    # ---------- Tracker Sync Relay ----------

    async def _tracker_sync_loop(self):
        """Periodically upload local data and download remote data via the Wix tracker.

        This enables WAN sync between peers that can't establish direct TCP connections
        (both behind NAT without port forwarding). Data flows through the tracker as
        a relay/mailbox — peers POST their new rows and GET other peers' rows via HTTPS.
        """
        if not BOOTSTRAP_TRACKERS:
            logger.info("No bootstrap trackers configured - tracker sync disabled")
            return

        try:
            import httpx
        except ImportError:
            logger.warning("httpx not available - tracker sync disabled")
            return

        # Wait for the first tracker announce to complete (so we know our peer_key)
        await asyncio.sleep(10)

        tracker_sync_url = BOOTSTRAP_TRACKERS[0].replace("/peers", "")
        # e.g., "https://www.galacticfederation.tech/_functions"

        while self._running:
            try:
                if self._my_peer_key:
                    async with httpx.AsyncClient(timeout=30) as client:
                        await self._upload_to_tracker(client, tracker_sync_url)
                        await self._download_from_tracker(client, tracker_sync_url)
                else:
                    logger.debug("Tracker sync: waiting for peer_key from tracker announce")
            except Exception as e:
                logger.warning(f"Tracker sync error: {e}")

            try:
                await asyncio.sleep(TRACKER_SYNC_INTERVAL)
            except asyncio.CancelledError:
                break

    async def _upload_to_tracker(self, client, base_url: str):
        """Upload new local rows to the tracker for other peers to download."""
        upload_url = f"{base_url}/sync_upload"
        total_uploaded = 0

        for table in TRACKER_SYNCABLE_TABLES:
            try:
                columns = TRACKER_TABLE_COLUMNS.get(table, "")
                ts_col = TRACKER_TABLE_TIMESTAMP_COL.get(table, "created_at")
                since = self._tracker_upload_ts.get(table, "")

                conn = sqlite3.connect(DB_PATH)
                if since:
                    rows = conn.execute(
                        f"SELECT {columns} FROM {table} WHERE {ts_col} > ? ORDER BY {ts_col} ASC LIMIT {TRACKER_MAX_ROWS_PER_UPLOAD}",
                        (since,)
                    ).fetchall()
                else:
                    rows = conn.execute(
                        f"SELECT {columns} FROM {table} ORDER BY {ts_col} ASC LIMIT {TRACKER_MAX_ROWS_PER_UPLOAD}"
                    ).fetchall()
                conn.close()

                if not rows:
                    continue

                # Convert rows to lists (sqlite3 returns tuples)
                row_data = [list(r) for r in rows]
                col_list = [c.strip() for c in columns.split(",")]

                resp = await client.post(upload_url, json={
                    "peer_key": self._my_peer_key,
                    "table": table,
                    "columns": col_list,
                    "rows": row_data,
                })

                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("ok"):
                        total_uploaded += len(row_data)
                        # Update timestamp to the latest row's timestamp
                        ts_idx = col_list.index(ts_col)
                        latest_ts = max(r[ts_idx] for r in row_data if r[ts_idx])
                        self._tracker_upload_ts[table] = str(latest_ts)
                else:
                    logger.debug(f"Tracker upload failed for {table}: HTTP {resp.status_code}")

            except Exception as e:
                logger.debug(f"Tracker upload error for {table}: {e}")

        if total_uploaded:
            logger.info(f"Tracker sync: uploaded {total_uploaded} rows across tables")

    async def _download_from_tracker(self, client, base_url: str):
        """Download sync bundles from the tracker and INSERT OR IGNORE locally."""
        download_url = f"{base_url}/sync_download"

        params = {"exclude_peer": self._my_peer_key}
        if self._tracker_download_ts:
            params["since"] = self._tracker_download_ts

        try:
            resp = await client.get(download_url, params=params)
            if resp.status_code != 200:
                logger.debug(f"Tracker download failed: HTTP {resp.status_code}")
                return

            data = resp.json()
            if not data.get("ok"):
                return

            bundles = data.get("bundles", [])
            if not bundles:
                return

            total_inserted = 0
            latest_upload_time = self._tracker_download_ts

            for bundle in bundles:
                table = bundle.get("table", "")
                columns = bundle.get("columns", [])
                rows = bundle.get("rows", [])
                uploaded_at = bundle.get("uploaded_at", "")

                if table not in TRACKER_SYNCABLE_TABLES or not columns or not rows:
                    continue

                # Track the latest bundle time for next download
                if uploaded_at and uploaded_at > (latest_upload_time or ""):
                    latest_upload_time = uploaded_at

                # INSERT OR IGNORE into local database
                col_names = ", ".join(columns)
                placeholders = ", ".join(["?"] * len(columns))
                inserted = 0

                try:
                    conn = sqlite3.connect(DB_PATH)
                    for row in rows:
                        if len(row) != len(columns):
                            continue
                        try:
                            cursor = conn.execute(
                                f"INSERT OR IGNORE INTO {table} ({col_names}) VALUES ({placeholders})",
                                row
                            )
                            if cursor.rowcount > 0:
                                inserted += 1
                        except Exception as e:
                            logger.debug(f"Tracker sync insert error for {table}: {e}")
                    conn.commit()
                    conn.close()
                except Exception as e:
                    logger.warning(f"Tracker sync DB error for {table}: {e}")

                total_inserted += inserted

            if latest_upload_time:
                self._tracker_download_ts = latest_upload_time

            if total_inserted:
                logger.info(f"Tracker sync: downloaded and inserted {total_inserted} new rows from {len(bundles)} bundles")
            else:
                logger.debug(f"Tracker sync: {len(bundles)} bundles, 0 new rows (all duplicates)")

        except Exception as e:
            logger.warning(f"Tracker download error: {e}")

    # ---------- Tier 1: Bootstrap Trackers ----------

    async def _bootstrap_from_trackers(self):
        """Contact bootstrap trackers for initial peer list."""
        if not BOOTSTRAP_TRACKERS:
            logger.info("No bootstrap trackers configured - skipping Tier 1")
            return

        try:
            import httpx
        except ImportError:
            logger.warning("httpx not available - cannot contact trackers")
            return

        await asyncio.sleep(2)  # Let the server finish starting

        while self._running:
            async with httpx.AsyncClient(timeout=10) as client:
                for tracker_url in BOOTSTRAP_TRACKERS:
                    try:
                        # Announce ourselves to the tracker
                        resp = await client.post(tracker_url, json={
                            "action": "announce",
                            "port": self.my_port,
                            "version": "3.0.0",
                        })
                        if resp.status_code == 200:
                            data = resp.json()
                            # Capture our public IP as reported by the tracker
                            your_ip = data.get("your_ip", "")
                            if your_ip and your_ip != "unknown":
                                self._my_peer_key = f"{your_ip}:{self.my_port}"
                                logger.info(f"Tracker reports our public IP: {your_ip} (peer_key: {self._my_peer_key})")
                            for peer in data.get("peers", []):
                                addr = peer.get("address", "")
                                port = peer.get("port", PEER_LISTEN_PORT)
                                if addr:
                                    self._add_peer(addr, port)
                            logger.info(
                                f"Tracker {tracker_url}: received {len(data.get('peers', []))} peers"
                            )
                    except Exception as e:
                        logger.debug(f"Tracker {tracker_url} unreachable: {e}")

            # Re-announce every 5 minutes
            await asyncio.sleep(300)

    # ---------- Tier 2: LAN Discovery ----------

    async def _lan_listener_loop(self):
        """Listen for LAN broadcast discovery packets using asyncio UDP protocol."""
        loop = asyncio.get_event_loop()

        # Create a proper asyncio datagram endpoint instead of blocking socket in executor
        class LANProtocol(asyncio.DatagramProtocol):
            def __init__(self, discovery_ref):
                self.discovery = discovery_ref

            def datagram_received(self, data, addr):
                if data.startswith(GFC_MAGIC):
                    try:
                        payload = json.loads(data[len(GFC_MAGIC):])
                        peer_port = payload.get("port", PEER_LISTEN_PORT)
                        peer_addr = addr[0]
                        if not self.discovery._is_self(peer_addr, peer_port):
                            self.discovery._add_peer(peer_addr, peer_port)
                    except json.JSONDecodeError:
                        pass

            def error_received(self, exc):
                logger.debug(f"LAN listener error: {exc}")

        try:
            transport, protocol = await loop.create_datagram_endpoint(
                lambda: LANProtocol(self),
                local_addr=("0.0.0.0", LAN_DISCOVERY_PORT),
                allow_broadcast=True,
            )
            logger.info(f"LAN discovery listener started on UDP port {LAN_DISCOVERY_PORT}")

            # Keep the listener alive until stopped
            while self._running:
                await asyncio.sleep(1)

            transport.close()
        except OSError as e:
            logger.warning(f"Cannot bind LAN discovery port {LAN_DISCOVERY_PORT}: {e}")
        except asyncio.CancelledError:
            try:
                transport.close()
            except Exception:
                pass

    async def _lan_broadcast_loop(self):
        """Periodically broadcast presence on LAN.

        Uses directed subnet broadcasts (e.g. 192.168.1.255) instead of
        limited broadcast (255.255.255.255) which many Windows configurations
        silently drop.

        Creates a SEPARATE socket per interface and bind()s it to the local IP,
        so that on multi-NIC machines (Hyper-V, VPN, etc.) each broadcast goes
        out on the correct physical/virtual adapter.

        Also sends the first broadcast immediately on startup (no 30s wait).
        """
        logger.info("LAN broadcast started")

        while self._running:
            try:
                packet = GFC_MAGIC + json.dumps({
                    "port": self.my_port,
                    "version": "3.0.0",
                }).encode()

                # Get (local_ip, broadcast_address) pairs for each interface
                iface_targets = self._get_interface_broadcast_pairs()
                if not iface_targets:
                    # Fallback: single unbound socket to 255.255.255.255
                    iface_targets = [("0.0.0.0", "255.255.255.255")]

                for local_ip, bcast_addr in iface_targets:
                    try:
                        # Create a per-interface socket bound to the local IP
                        # so the broadcast goes out on the correct adapter
                        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                        sock.bind((local_ip, 0))  # Bind to this interface
                        sock.sendto(packet, (bcast_addr, LAN_DISCOVERY_PORT))
                        sock.close()
                    except Exception as e:
                        logger.debug(f"LAN broadcast {local_ip}->{bcast_addr} error: {e}")

                logger.debug(f"LAN broadcast sent via {[(l,b) for l,b in iface_targets]}")
            except Exception as e:
                logger.warning(f"LAN broadcast error: {e}")

            try:
                await asyncio.sleep(LAN_BROADCAST_INTERVAL)
            except asyncio.CancelledError:
                break

    @staticmethod
    def _get_interface_broadcast_pairs() -> List[tuple]:
        """Get (local_ip, broadcast_address) pairs for all local network interfaces.

        Returns pairs so the caller can bind() a socket to each local_ip before
        sending a broadcast, ensuring the packet goes out on the correct adapter.
        Critical on multi-NIC machines (Hyper-V, VPN, etc.).

        Uses multiple methods:
        1. netifaces module (if available) - most reliable
        2. ipconfig parsing on Windows - parses IP + subnet mask
        3. Fallback: derive from known local IPs assuming /24 subnet
        """
        pairs = []  # List of (local_ip, broadcast_addr)
        seen_local = set()

        # Method 1: Try netifaces (most reliable cross-platform)
        try:
            import netifaces
            for iface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs:
                    for addr_info in addrs[netifaces.AF_INET]:
                        local_ip = addr_info.get("addr", "")
                        bcast = addr_info.get("broadcast")
                        if local_ip and bcast and bcast != "127.255.255.255" and local_ip not in seen_local:
                            pairs.append((local_ip, bcast))
                            seen_local.add(local_ip)
            if pairs:
                return pairs
        except ImportError:
            pass

        # Method 2: Parse ipconfig on Windows
        import sys
        if sys.platform == "win32":
            try:
                import subprocess
                result = subprocess.run(
                    ["ipconfig"], capture_output=True, text=True, timeout=5
                )
                lines = result.stdout.split("\n")
                current_ip = None
                current_mask = None
                for line in lines:
                    line = line.strip()
                    # Look for IPv4 Address lines
                    if "IPv4" in line and ":" in line:
                        current_ip = line.split(":")[-1].strip()
                        current_mask = None
                    elif "Subnet Mask" in line and ":" in line:
                        current_mask = line.split(":")[-1].strip()
                    elif "Subnetzmaske" in line and ":" in line:
                        # German Windows
                        current_mask = line.split(":")[-1].strip()

                    if current_ip and current_mask:
                        bcast = _compute_broadcast(current_ip, current_mask)
                        if bcast and bcast != "127.255.255.255" and current_ip not in seen_local:
                            pairs.append((current_ip, bcast))
                            seen_local.add(current_ip)
                        current_ip = None
                        current_mask = None
                if pairs:
                    return pairs
            except Exception:
                pass

        # Method 3: Fallback - assume /24 for each known local IP
        try:
            hostname = socket.gethostname()
            for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
                ip = info[4][0]
                if ip.startswith("127.") or ip in seen_local:
                    continue
                # Assume /24: replace last octet with 255
                parts = ip.split(".")
                if len(parts) == 4:
                    bcast = ".".join(parts[:3] + ["255"])
                    pairs.append((ip, bcast))
                    seen_local.add(ip)
        except Exception:
            pass

        # Also try the default route IP
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            if ip not in seen_local:
                parts = ip.split(".")
                if len(parts) == 4:
                    bcast = ".".join(parts[:3] + ["255"])
                    pairs.append((ip, bcast))
        except Exception:
            pass

        return pairs

    @staticmethod
    def _get_broadcast_addresses() -> List[str]:
        """Get broadcast addresses only (for /p2p/diagnose endpoint)."""
        pairs = PeerDiscovery._get_interface_broadcast_pairs()
        return [bcast for _, bcast in pairs] if pairs else ["255.255.255.255"]

    # ---------- Tier 3: Peer Exchange ----------

    def get_peer_list(self, max_peers: int = 50) -> List[Dict]:
        """
        Return list of known active peers for peer exchange.
        Called by the sync engine when exchanging peer lists with connected peers.
        """
        now = time.time()
        active = [
            {"address": p.address, "port": p.port}
            for p in self.known_peers.values()
            if now - p.last_seen < PEER_TTL
        ]
        return active[:max_peers]

    def receive_peer_list(self, peers: List[Dict]):
        """
        Process a peer list received from another node (Tier 3 gossip).
        Called by the sync engine when a connected peer sends its known peers.
        """
        added = 0
        for p in peers:
            addr = p.get("address", "")
            port = p.get("port", PEER_LISTEN_PORT)
            if addr and not self._is_self(addr, port):
                if self._add_peer(addr, port):
                    added += 1
        if added:
            logger.info(f"Peer exchange: added {added} new peers")

    # ---------- Internal helpers ----------

    def _add_peer(self, address: str, port: int) -> bool:
        """Add or update a peer. Returns True if this is a new peer."""
        if len(self.known_peers) >= MAX_KNOWN_PEERS:
            # Evict the oldest peer
            self._evict_oldest()

        key = f"{address}:{port}"
        is_new = key not in self.known_peers
        if is_new:
            self.known_peers[key] = PeerInfo(
                address=address, port=port, last_seen=time.time()
            )
            logger.info(f"Discovered new peer: {key}")
            # Persist immediately so manually added peers survive restarts
            self._save_peers()
        else:
            self.known_peers[key].last_seen = time.time()
        return is_new

    def _is_self(self, address: str, port: int) -> bool:
        """Check if the address is our own node (loopback or any local interface IP)."""
        if port != self.my_port:
            return False
        # Check loopback addresses
        if address in ("127.0.0.1", "localhost", "0.0.0.0", "::1"):
            return True
        # Check all local network interface IPs
        return address in self._local_ips

    @staticmethod
    def _get_local_ips() -> Set[str]:
        """Get all IP addresses assigned to local network interfaces."""
        local_ips = set()
        local_ips.add("127.0.0.1")
        local_ips.add("0.0.0.0")
        try:
            # Get hostname-based IPs
            hostname = socket.gethostname()
            for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
                local_ips.add(info[4][0])
        except Exception:
            pass
        try:
            # Also try connecting to a public IP to find our default route IP
            # (doesn't actually send data - just reveals the local IP)
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ips.add(s.getsockname()[0])
            s.close()
        except Exception:
            pass
        return local_ips

    def _evict_oldest(self):
        """Remove the oldest-seen peer to make room."""
        if not self.known_peers:
            return
        oldest_key = min(self.known_peers, key=lambda k: self.known_peers[k].last_seen)
        del self.known_peers[oldest_key]

    async def _cleanup_loop(self):
        """Periodically remove stale peers."""
        while self._running:
            try:
                await asyncio.sleep(300)  # Every 5 minutes
            except asyncio.CancelledError:
                break

            now = time.time()
            stale = [
                k for k, p in self.known_peers.items()
                if now - p.last_seen > PEER_TTL
            ]
            for k in stale:
                del self.known_peers[k]
            if stale:
                logger.info(f"Cleaned up {len(stale)} stale peers")

    # ---------- Status ----------

    @property
    def peer_count(self) -> int:
        return len(self.known_peers)

    def status(self) -> Dict:
        """Return discovery status for the /p2p/status endpoint."""
        return {
            "known_peers": self.peer_count,
            "connected_peers": len(self.connected_peers),
            "peer_list": self.get_peer_list(20),
        }
