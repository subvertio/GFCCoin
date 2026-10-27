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
# accepted when signed by one of these. The matching private key is held by the
# network operator only (GFC_TREASURY_KEY_FILE, default DATA_DIR/treasury_key.hex).
# To rotate: generate a new key with `python signing.py` and add its public key here.
# GFC_TREASURY_PUBKEYS (comma-separated) replaces this list, for test networks.
PINNED_TREASURY_PUBKEYS = (
    "b615b7fa89de96fa29fe83012959c6cbf5374d6d4f9d4c86a859bfedcdb05d89",
)
_env_treasury = os.environ.get("GFC_TREASURY_PUBKEYS", "")
TREASURY_PUBKEYS = tuple(
    k.strip() for k in _env_treasury.split(",") if k.strip()
) if _env_treasury.strip() else PINNED_TREASURY_PUBKEYS
