"""
GFC Backend - Shared Configuration
All data paths resolve through here so the backend works regardless of CWD.

Override the data directory by setting GFC_DATA_DIR environment variable.
Default: {backend_dir}/data (same as previous behavior in dev)
"""

import os
from pathlib import Path

_BACKEND_DIR = Path(__file__).parent.resolve()
DATA_DIR = Path(os.environ.get("GFC_DATA_DIR", str(_BACKEND_DIR / "data")))

# Subdirectories
SEEDS_ORIG_DIR = DATA_DIR / "seeds" / "originals"
SEEDS_THUMB_DIR = DATA_DIR / "seeds" / "thumbs"
AVATAR_DIR = DATA_DIR / "avatars"

# Ensure all directories exist
for _d in [DATA_DIR, SEEDS_ORIG_DIR, SEEDS_THUMB_DIR, AVATAR_DIR]:
    _d.mkdir(parents=True, exist_ok=True)

# Database paths
DB_PATH = str(DATA_DIR / "gfc_ledger.db")
PODT_DB_PATH = str(DATA_DIR / "podt.db")  # Legacy PoDT DB (no longer used — PoDT now in main DB)

# Blockchain constants
TREASURY_WALLET_ID = "GFC-TREASURY-GENESIS-001"

# Treasury public keys (Ed25519, hex). Synced GRANT/REWARD transactions are only
# accepted when signed by one of these. Generate a key with `python signing.py`
# and pin its public key here before release. Override with GFC_TREASURY_PUBKEYS
# (comma-separated) for test networks.
TREASURY_PUBKEYS = tuple(
    k.strip() for k in os.environ.get("GFC_TREASURY_PUBKEYS", "").split(",") if k.strip()
)
