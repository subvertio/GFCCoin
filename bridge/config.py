"""
Bridge configuration, read from GFC_BRIDGE_* environment variables.

Keys are read from files (never from env values or the command line) and are
never logged. EVM keys are 0x-prefixed or bare hex secp256k1 keys; the escrow
key uses the treasury key file format (plain hex, or encrypted with
`python signing.py encrypt`, unlocked by GFC_BRIDGE_ESCROW_PASSPHRASE).
"""

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional


@dataclass
class BridgeConfig:
    rpc_url: str
    chain_id: int
    bridge_address: str
    escrow_wallet: str                      # ledger Ed25519 public key (64 hex)
    ledger_db: str                          # this node's ledger DB (the canonical view)
    state_db: str                           # bridge state, separate from the node DB

    # Ledger finality: a deposit counts once it is in a local block and this old
    finality_seconds: int = 30 * 60
    # Chain finality for BridgedOut: "finalized", "safe", or a number of confirmations
    chain_finality: str = "finalized"
    start_block: int = 0                    # bridge deployment block
    log_chunk_blocks: int = 5_000
    mint_ttl_seconds: int = 60 * 60         # MintRequest.deadline = now + this

    # Anti-farming / gas-drain policy (attesters and relayer)
    min_deposit_cents: int = 100_00         # 100 GFC: smaller deposits are refunded, not minted
    relay_fee_cents: int = 0                # kept in escrow; minted amount = deposit - fee
    faucet_hold_days: float = 14            # GRANT/REFERRAL/FIRST_POST/REPOST credit can't bridge sooner
    manual_review_cents: int = 10_000_00    # deposits above this need an explicit approval
    max_mints_per_sender_per_day: int = 3
    relayer_daily_gas_limit: int = 5_000_000

    # Releases (chain -> ledger)
    max_release_cents: int = 10_000_00
    daily_release_cents: int = 50_000_00

    # Key files (any may be absent: the matching role just isn't run)
    relayer_key_file: Optional[str] = None
    pauser_key_file: Optional[str] = None
    attester_key_file: Optional[str] = None
    escrow_key_file: Optional[str] = None
    denylist_file: Optional[str] = None     # one EVM address or ledger wallet per line
    approvals_file: Optional[str] = None    # ledger tx_hashes approved past manual review
    # Other nodes' ledger DBs, to check they agree on the escrow balance
    peer_ledger_dbs: List[str] = field(default_factory=list)
    # Plain-wallet (EOA) addresses that must never get code: every attester, the pauser,
    # the relayer and each Safe owner. Reconcile pauses the bridge if one does (an EIP-7702
    # delegation means someone made that key sign an authorization). The keys this service
    # holds are watched too, without being listed here. Never list the Safe itself.
    watch_addresses: List[str] = field(default_factory=list)

    @classmethod
    def from_env(cls) -> "BridgeConfig":
        e = os.environ

        def opt(name: str) -> Optional[str]:
            return e.get(name) or None

        defaults = cls.__dataclass_fields__
        def num(name: str, attr: str, kind=int):
            return kind(e[name]) if e.get(name) else defaults[attr].default

        from config import DB_PATH, DATA_DIR
        return cls(
            rpc_url=e["GFC_BRIDGE_RPC_URL"],
            chain_id=int(e["GFC_BRIDGE_CHAIN_ID"]),
            bridge_address=e["GFC_BRIDGE_ADDRESS"],
            escrow_wallet=e["GFC_BRIDGE_ESCROW_WALLET"].lower(),
            ledger_db=e.get("GFC_BRIDGE_LEDGER_DB", DB_PATH),
            state_db=e.get("GFC_BRIDGE_STATE_DB", str(Path(DATA_DIR) / "bridge_state.db")),
            finality_seconds=num("GFC_BRIDGE_FINALITY_SECONDS", "finality_seconds"),
            chain_finality=e.get("GFC_BRIDGE_CHAIN_FINALITY", "finalized"),
            start_block=num("GFC_BRIDGE_START_BLOCK", "start_block"),
            mint_ttl_seconds=num("GFC_BRIDGE_MINT_TTL_SECONDS", "mint_ttl_seconds"),
            min_deposit_cents=num("GFC_BRIDGE_MIN_DEPOSIT_CENTS", "min_deposit_cents"),
            relay_fee_cents=num("GFC_BRIDGE_RELAY_FEE_CENTS", "relay_fee_cents"),
            faucet_hold_days=num("GFC_BRIDGE_FAUCET_HOLD_DAYS", "faucet_hold_days", float),
            manual_review_cents=num("GFC_BRIDGE_MANUAL_REVIEW_CENTS", "manual_review_cents"),
            max_mints_per_sender_per_day=num("GFC_BRIDGE_MAX_MINTS_PER_SENDER_PER_DAY",
                                             "max_mints_per_sender_per_day"),
            relayer_daily_gas_limit=num("GFC_BRIDGE_RELAYER_DAILY_GAS", "relayer_daily_gas_limit"),
            max_release_cents=num("GFC_BRIDGE_MAX_RELEASE_CENTS", "max_release_cents"),
            daily_release_cents=num("GFC_BRIDGE_DAILY_RELEASE_CENTS", "daily_release_cents"),
            relayer_key_file=opt("GFC_BRIDGE_RELAYER_KEY_FILE"),
            pauser_key_file=opt("GFC_BRIDGE_PAUSER_KEY_FILE"),
            attester_key_file=opt("GFC_BRIDGE_ATTESTER_KEY_FILE"),
            escrow_key_file=opt("GFC_BRIDGE_ESCROW_KEY_FILE"),
            denylist_file=opt("GFC_BRIDGE_DENYLIST_FILE"),
            approvals_file=opt("GFC_BRIDGE_APPROVALS_FILE"),
            peer_ledger_dbs=[p for p in e.get("GFC_BRIDGE_PEER_LEDGER_DBS", "").split(",") if p],
            watch_addresses=[a.strip() for a in e.get("GFC_BRIDGE_WATCH_ADDRESSES", "").split(",") if a.strip()],
        )


def read_evm_key(path: str) -> str:
    """A secp256k1 private key from a file, as 0x-hex."""
    key = Path(path).read_text().strip()
    return key if key.startswith("0x") else "0x" + key


def read_escrow_key(path: str) -> str:
    """The escrow Ed25519 private key hex; same file format as the treasury key."""
    import signing
    return signing._read_treasury_key_file(Path(path), os.environ.get("GFC_BRIDGE_ESCROW_PASSPHRASE"))


def read_lines(path: Optional[str]) -> set:
    if not path or not Path(path).exists():
        return set()
    lines = Path(path).read_text().splitlines()
    return {ln.strip().lower() for ln in lines if ln.strip() and not ln.startswith("#")}
