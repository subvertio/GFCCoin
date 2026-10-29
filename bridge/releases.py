"""
Chain -> ledger: pay finalized BridgedOut events from the escrow wallet.

Each payout is an ordinary TRANSFER signed by the escrow key and added through
blockchain.accept_synced_transaction(), so it passes exactly the checks a peer
row would (signature, hash, funding) and the node's sync shares it like any
other signed transfer. It is paid at most once per BridgedOut nonce:
- the ledger tx id is derived from (chain id, nonce), so a second insert is a
  duplicate, and
- the ledger is searched for an existing `bridge-out:v1:<chainId>:<nonce>:` row
  before signing (covers a crash between paying and recording it).
Only blocks at or behind the configured chain finality are read, so a reorg
can't un-burn tokens that were already paid out.
"""

import logging
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Dict, Optional

import blockchain
import signing
from bridge.config import BridgeConfig
from bridge.deposits import RELEASE_REASON_PREFIX
from bridge.store import HELD, PAID, REFUND, REFUNDED, SEEN, WAITING, Store

if TYPE_CHECKING:  # payouts and refunds work without the EVM dependencies
    from bridge.chain import BridgeContract

logger = logging.getLogger("gfc.bridge.releases")

RELEASE_ID_NAMESPACE = uuid.UUID("6f1c2b0e-8f8e-4b8e-9d3a-6a1f5e2c9b70")
CURSOR_KEY = "release_cursor"


def release_tx_id(chain_id: int, nonce: int) -> str:
    return str(uuid.uuid5(RELEASE_ID_NAMESPACE, f"{chain_id}:{nonce}"))


def scan_bridged_out(cfg: BridgeConfig, store: Store, bridge: "BridgeContract") -> int:
    """Record BridgedOut events up to the final block. Returns how many were new."""
    final = bridge.chain.final_block(cfg.chain_finality)
    start = int(store.get_meta(CURSOR_KEY, str(cfg.start_block)))
    if final < start:
        return 0
    new = sum(store.add_release(ev) for ev in bridge.bridged_out_logs(start, final, cfg.log_chunk_blocks))
    store.set_meta(CURSOR_KEY, str(final + 1))
    return new


def _existing_payout(conn: sqlite3.Connection, cfg: BridgeConfig, nonce: int) -> Optional[str]:
    prefix = f"{RELEASE_REASON_PREFIX}{cfg.chain_id}:{nonce}:"
    row = conn.execute("SELECT id FROM transactions WHERE sender = ? AND substr(reason, 1, ?) = ?",
                       (cfg.escrow_wallet, len(prefix), prefix)).fetchone()
    return row[0] if row else None


def pay_releases(cfg: BridgeConfig, store: Store, escrow_key: str,
                 now: Optional[datetime] = None) -> Dict[str, int]:
    """Pay every recorded, unpaid release once. Returns counts by new status."""
    if signing.public_key_of(escrow_key) != cfg.escrow_wallet:
        raise ValueError("escrow key does not match GFC_BRIDGE_ESCROW_WALLET")
    now = now or datetime.now(timezone.utc)
    counts = {PAID: 0, WAITING: 0, HELD: 0}
    day_ago = (now - timedelta(days=1)).isoformat()

    def mark(nonce: int, status: str, detail: str = "", ledger_tx_id: str = ""):
        store.set_release(nonce, status, detail, ledger_tx_id)
        counts[status] += 1

    for r in store.releases(SEEN, WAITING):
        nonce, wallet, cents = r["nonce"], r["ledger_wallet"], r["amount_cents"]
        if not signing.is_public_key(wallet) or wallet in (cfg.escrow_wallet, blockchain.TREASURY_WALLET_ID):
            mark(nonce, HELD, "not a ledger wallet key: the tokens are burned, a person must make this right")
            continue
        if not r["approved"]:
            if cents > cfg.max_release_cents:
                mark(nonce, HELD, f"above the {cfg.max_release_cents / 100:.2f} GFC per-release limit")
                continue
            if store.released_cents_since(day_ago) + cents > cfg.daily_release_cents:
                mark(nonce, WAITING, "daily release limit reached")
                continue

        conn = sqlite3.connect(cfg.ledger_db)
        try:
            existing = _existing_payout(conn, cfg, nonce)
        finally:
            conn.close()
        if existing:
            mark(nonce, PAID, "already paid", existing)
            continue

        tx = {
            "id": release_tx_id(cfg.chain_id, nonce),
            "sender": cfg.escrow_wallet,
            "recipient": wallet,
            "amount": cents / 100.0,
            "amount_cents": cents,
            "reason": f"{RELEASE_REASON_PREFIX}{cfg.chain_id}:{nonce}:{r['evm_tx']}",
            "timestamp": now.isoformat(),
            "tx_type": blockchain.TX_TYPE_TRANSFER,
        }
        tx["tx_hash"] = blockchain.compute_tx_hash(tx)
        tx["signer"] = cfg.escrow_wallet
        tx["signature"] = signing.sign_tx_hash(escrow_key, tx["tx_hash"])

        status, why = blockchain.accept_synced_transaction(cfg.ledger_db, tx)
        if status in (blockchain.ACCEPTED, blockchain.DUPLICATE):
            mark(nonce, PAID, "", tx["id"])
            logger.info(f"Released {cents / 100:.2f} GFC to {wallet[:16]} for BridgedOut #{nonce}")
        elif status == blockchain.PENDING:
            mark(nonce, WAITING, "escrow balance too low")
            logger.error(f"Escrow can't cover BridgedOut #{nonce}: check reconcile")
        else:
            mark(nonce, HELD, f"ledger rejected the payout: {why}")
    return counts


def refund_deposit(cfg: BridgeConfig, store: Store, escrow_key: str, tx_hash: str,
                   now: Optional[datetime] = None) -> str:
    """
    Send a deposit that will never be minted (status refund or held) back to its sender,
    with reason bridge-refund:v1:<tx_hash>. Returns the refund's ledger tx id. At most
    once per deposit: an existing refund row is reused.
    """
    if signing.public_key_of(escrow_key) != cfg.escrow_wallet:
        raise ValueError("escrow key does not match GFC_BRIDGE_ESCROW_WALLET")
    d = store.deposit(tx_hash)
    if d is None or d["status"] not in (REFUND, HELD):
        raise ValueError("only deposits marked refund or held can be refunded")
    reason = f"bridge-refund:v1:{tx_hash}"
    conn = sqlite3.connect(cfg.ledger_db)
    try:
        row = conn.execute("SELECT id FROM transactions WHERE sender = ? AND reason = ?",
                           (cfg.escrow_wallet, reason)).fetchone()
    finally:
        conn.close()
    if row:
        store.set_deposit(tx_hash, REFUNDED, "already refunded")
        return row[0]
    now = now or datetime.now(timezone.utc)
    tx = {
        "id": str(uuid.uuid5(RELEASE_ID_NAMESPACE, f"refund:{tx_hash}")),
        "sender": cfg.escrow_wallet,
        "recipient": d["sender"],
        "amount": d["amount_cents"] / 100.0,
        "amount_cents": d["amount_cents"],
        "reason": reason,
        "timestamp": now.isoformat(),
        "tx_type": blockchain.TX_TYPE_TRANSFER,
    }
    tx["tx_hash"] = blockchain.compute_tx_hash(tx)
    tx["signer"] = cfg.escrow_wallet
    tx["signature"] = signing.sign_tx_hash(escrow_key, tx["tx_hash"])
    status, why = blockchain.accept_synced_transaction(cfg.ledger_db, tx)
    if status not in (blockchain.ACCEPTED, blockchain.DUPLICATE):
        raise ValueError(f"ledger refused the refund: {why}")
    store.set_deposit(tx_hash, REFUNDED)
    return tx["id"]
