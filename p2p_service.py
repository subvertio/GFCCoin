"""
GFC P2P Service - Orchestrates peer discovery and data sync.

Ties PeerDiscovery and SyncEngine together, exposes start/stop
functions for FastAPI lifecycle hooks, and provides status endpoints.
"""

import asyncio
import logging
from typing import Dict

from peer_discovery import PeerDiscovery, PEER_LISTEN_PORT
from sync_engine import SyncEngine

logger = logging.getLogger("gfc.p2p")

# Configure logging for P2P modules
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s"
)

# Global instances (shared with main.py)
discovery = PeerDiscovery(my_port=PEER_LISTEN_PORT)
sync_engine = SyncEngine(discovery=discovery)


async def start_p2p():
    """Start P2P services. Called from FastAPI on_startup."""
    logger.info("Starting GFC P2P services...")
    await discovery.start()
    await sync_engine.start()
    logger.info("P2P services running")


async def stop_p2p():
    """Stop P2P services. Called from FastAPI on_shutdown."""
    logger.info("Stopping GFC P2P services...")
    await sync_engine.stop()
    await discovery.stop()
    logger.info("P2P services stopped")


def p2p_status() -> Dict:
    """Return combined P2P status for the API endpoint."""
    return {
        "discovery": discovery.status(),
        "sync": sync_engine.status(),
    }
