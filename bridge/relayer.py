"""
Ledger -> chain: find final escrow deposits, collect attester signatures, and
submit GFCBridge.mintFromLedger.

The relayer holds only a gas wallet; the signatures are the authorization. It
pays gas for every mint it submits, so it refuses work that would let someone
drain that wallet: deposits under the minimum are never minted, each sender
gets a few mints per day, the relayer has a daily gas budget, and an optional
relay fee (kept in escrow) is taken out of the minted amount.
"""

import logging
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

from bridge import deposits, eip712
from bridge.chain import BridgeContract, RPCError
from bridge.config import BridgeConfig
from bridge.store import HELD, MINTED, REFUND, SEEN, WAITING, Store

logger = logging.getLogger("gfc.bridge.relayer")

MINT_GAS_ESTIMATE = 250_000  # worst case seen in forge gas reports is ~200k


def scan_deposits(cfg: BridgeConfig, store: Store, now: Optional[datetime] = None) -> Dict[str, int]:
    """Record new deposits from this node's ledger DB. Returns counts by result."""
    now = now or datetime.now(timezone.utc)
    counts = {deposits.OK: 0, deposits.REFUND: 0, deposits.INVALID: 0, deposits.NOT_FINAL: 0,
              deposits.OTHER_CHAIN: 0}
    conn = sqlite3.connect(cfg.ledger_db)
    try:
        for tx in deposits.deposit_rows(conn, cfg.escrow_wallet):
            if store.deposit(tx["tx_hash"]):
                continue
            result, detail, dep = deposits.validate_deposit(tx, cfg, now)
            counts[result] += 1
            if result == deposits.OK:
                store.add_deposit(dep)
            elif result == deposits.REFUND:
                store.add_deposit(dep, REFUND, detail)
                logger.warning(f"Deposit {tx['tx_hash'][:16]} needs a refund: {detail}")
            elif result == deposits.INVALID:
                logger.warning(f"Ignoring untrustworthy escrow row {tx['id']}: {detail}")
    finally:
        conn.close()
    return counts


def relay(cfg: BridgeConfig, store: Store, bridge: BridgeContract, attesters: List, relayer_key: str,
          now: Optional[datetime] = None) -> Dict[str, int]:
    """Try to mint every pending deposit once. Returns counts by new status."""
    now = now or datetime.now(timezone.utc)
    counts = {MINTED: 0, WAITING: 0, HELD: 0}
    if bridge.paused():
        logger.warning("Bridge is paused: not relaying")
        return counts
    threshold = bridge.threshold()
    max_mint = bridge.max_mint_cents()
    day_ago = (now - timedelta(days=1)).isoformat()

    def mark(tx_hash: str, status: str, detail: str = "", evm_tx: str = ""):
        store.set_deposit(tx_hash, status, detail, evm_tx)
        counts[status] += 1

    for d in store.deposits(SEEN, WAITING):
        tx_hash = d["tx_hash"]
        if bridge.processed(bytes.fromhex(tx_hash)):
            mark(tx_hash, MINTED, "already processed on chain")
            continue
        if d["mint_cents"] > max_mint:
            mark(tx_hash, HELD, f"above the per-mint cap of {max_mint / 100:.2f} GFC: refund it")
            continue
        if d["mint_cents"] > bridge.remaining_in_window_cents():
            mark(tx_hash, WAITING, "bridge window limit reached")
            continue
        if store.mints_by_sender_since(d["sender"], day_ago) >= cfg.max_mints_per_sender_per_day:
            mark(tx_hash, WAITING, "sender's daily mint limit reached")
            continue
        if store.gas_today() + MINT_GAS_ESTIMATE > cfg.relayer_daily_gas_limit:
            mark(tx_hash, WAITING, "relayer daily gas budget reached")
            continue

        deadline = int(now.timestamp()) + cfg.mint_ttl_seconds
        results = [a.attest(tx_hash, d["evm_to"], d["mint_cents"], deadline, now) for a in attesters]
        sigs = sorted(((int(r.signer, 16), r.signature) for r in results if r.signature),
                      key=lambda s: s[0])
        if len(sigs) < threshold:
            refusals = "; ".join(f"{r.signer[:10]}: {r.refusal}" for r in results if not r.signature)
            retry = any(r.retry for r in results if not r.signature)
            mark(tx_hash, WAITING if retry else HELD,
                 f"{len(sigs)}/{threshold} attestations ({refusals})")
            continue

        req = eip712.mint_request(tx_hash, d["evm_to"], d["mint_cents"], deadline)
        try:
            receipt = bridge.mint_from_ledger(relayer_key, req, [s for _, s in sigs])
        except RPCError as e:
            if e.error_name == "AlreadyProcessed":
                mark(tx_hash, MINTED, "already processed on chain")
            else:
                mark(tx_hash, WAITING, f"mint failed: {e}")
            continue
        store.add_gas(int(receipt["gasUsed"], 16))
        mark(tx_hash, MINTED, "", receipt["transactionHash"])
        logger.info(f"Minted {d['mint_cents'] / 100:.2f} GFC to {d['evm_to']} for {tx_hash[:16]}")
    return counts


def run_forever(cfg: BridgeConfig, store: Store, bridge: BridgeContract, attesters: List, relayer_key: str,
                interval: float = 30.0):
    while True:
        try:
            scan_deposits(cfg, store)
            relay(cfg, store, bridge, attesters, relayer_key)
        except Exception as e:  # keep running; the next pass retries
            logger.error(f"Relay pass failed: {e}")
        time.sleep(interval)
