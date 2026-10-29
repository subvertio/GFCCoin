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
    "0f19ffe9cfe0bb86a1c5e0a90322b197a4df4de99104790c2997d06dd108ea21",  # rotated 2026-10-27
)
_env_treasury = os.environ.get("GFC_TREASURY_PUBKEYS", "")
TREASURY_PUBKEYS = tuple(
    k.strip() for k in _env_treasury.split(",") if k.strip()
) if _env_treasury.strip() else PINNED_TREASURY_PUBKEYS

# Bridge escrow wallets (Ed25519 public keys), one per EVM chain ID: {chain_id: wallet}.
# Every node enforces the escrow rules in blockchain.bridge_rule_violation() for these
# wallets, so this is consensus config: change it in a release all nodes take.
# Empty until an escrow key exists (`python -m bridge new-escrow-key FILE`).
# GFC_BRIDGE_ESCROWS ("84532:<pubkey>,8453:<pubkey>") replaces this, for test networks.
PINNED_BRIDGE_ESCROWS = {}
_env_escrows = os.environ.get("GFC_BRIDGE_ESCROWS", "")
BRIDGE_ESCROWS = {
    int(pair.split(":", 1)[0]): pair.split(":", 1)[1].strip().lower()
    for pair in _env_escrows.split(",") if ":" in pair
} if _env_escrows.strip() else dict(PINNED_BRIDGE_ESCROWS)

# What front ends show for the bridge (not consensus): the token contract on each chain,
# and the bridge service's deposit policy, so the node can refuse a deposit it won't mint.
CHAIN_NAMES = {8453: "Base", 84532: "Base Sepolia", 31337: "Local test chain"}
_env_tokens = os.environ.get("GFC_BRIDGE_TOKENS", "")  # "84532:0x...,8453:0x..."
BRIDGE_TOKENS = {
    int(pair.split(":", 1)[0]): pair.split(":", 1)[1].strip()
    for pair in _env_tokens.split(",") if ":" in pair
}
BRIDGE_MIN_DEPOSIT_CENTS = int(os.environ.get("GFC_BRIDGE_MIN_DEPOSIT_CENTS", "10000"))
BRIDGE_RELAY_FEE_CENTS = int(os.environ.get("GFC_BRIDGE_RELAY_FEE_CENTS", "0"))
BRIDGE_FAUCET_HOLD_DAYS = float(os.environ.get("GFC_BRIDGE_FAUCET_HOLD_DAYS", "14"))
