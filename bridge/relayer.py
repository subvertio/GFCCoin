"""
Ledger -> chain: find final escrow deposits, collect attester signatures, and
submit GFCBridge.mintFromLedger.

The relayer holds only a gas wallet; the signatures are the authorization. It
pays gas for every mint it submits, so it refuses work that would let someone
drain that wallet: deposits under the minimum are never minted, each sender
gets a few mints per day, the relayer has a daily gas budget, and an optional
relay fee (kept in escrow) is taken out of the minted amount. Each mint has a gas
and fee-per-gas cap, and a reverted mint's gas counts against the budget too
(audit F12).
"""

import logging
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

from bridge import deposits, eip712
from bridge.chain import BridgeContract, RPCError
from bridge.config import BridgeConfig
from bridge.store import HELD, MINTED, REFUND, REFUNDED, SEEN, SUBMITTED, WAITING, Store

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
            if dep and deposits.refunded(conn, cfg.escrow_wallet, tx["tx_hash"]):
                store.add_deposit(dep, REFUNDED, "refunded on the ledger")  # a rebuilt state remembers
                continue
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
    counts = {MINTED: 0, SUBMITTED: 0, WAITING: 0, HELD: 0, SEEN: 0}
    settle_mints(cfg, store, bridge, counts, now)
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
            mark(tx_hash, SUBMITTED, "processed on chain: waiting for finality")
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
        # Recorded before asking: a signature may exist from here on, even if its reply is lost or
        # overheard, so no refund until this deadline has passed (releases.refund_deposit)
        store.note_attested(tx_hash, deadline)
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
            receipt = bridge.mint_from_ledger(relayer_key, req, [s for _, s in sigs], max_gas=cfg.max_gas_per_mint,
                                              max_fee_per_gas=cfg.max_fee_per_gas_wei)
        except RPCError as e:
            if e.receipt:  # sent and reverted: its gas is spent all the same
                store.add_gas(int(e.receipt["gasUsed"], 16))
            if e.error_name == "AlreadyProcessed":
                mark(tx_hash, SUBMITTED, "processed on chain: waiting for finality")
            elif e.tx_hash and not e.receipt:  # sent, no receipt yet: it may still land
                mark(tx_hash, SUBMITTED, "sent, no receipt yet", e.tx_hash)
            else:
                mark(tx_hash, WAITING, f"mint failed: {e}")
            continue
        store.add_gas(int(receipt["gasUsed"], 16))
        mark(tx_hash, SUBMITTED, "sent: minted once it's in a finalized block", receipt["transactionHash"])
        logger.info(f"Mint sent: {d['mint_cents'] / 100:.2f} GFC to {d['evm_to']} for {tx_hash[:16]}")
    return counts


def settle_mints(cfg: BridgeConfig, store: Store, bridge: BridgeContract, counts: Optional[Dict[str, int]] = None,
                 now: Optional[datetime] = None):
    """
    Submitted mints become minted once `processed` is set in a finalized block. One that's no
    longer processed even at the latest block (a reorg dropped it, or it reverted) goes back
    to seen and is tried again; the contract's `processed` still stops a double mint
    (audit F10: a mint marked done on its receipt alone was never retried). A mint sent
    without a receipt yet is left alone while its attestations can still be used: sending
    another would only pay gas for a revert.
    """
    pending = store.deposits(SUBMITTED)
    if not pending:
        return
    now = now or datetime.now(timezone.utc)
    final = bridge.chain.final_block(cfg.chain_finality)
    for d in pending:
        h = bytes.fromhex(d["tx_hash"])
        if bridge.processed(h, final):
            store.set_deposit(d["tx_hash"], MINTED, "")
            status = MINTED
        elif d["evm_tx"] and d["attested_until"] > now.timestamp() and not bridge.processed(h) and \
                bridge.chain.receipt(d["evm_tx"]) is None:
            continue  # still in flight
        elif not bridge.processed(h):
            store.set_deposit(d["tx_hash"], SEEN, "the mint isn't on chain any more (reorg or revert): retrying")
            logger.warning(f"Mint for {d['tx_hash'][:16]} disappeared from the chain: retrying")
            status = SEEN
        else:
            continue  # on chain, not final yet
        if counts is not None:
            counts[status] += 1


def run_forever(cfg: BridgeConfig, store: Store, bridge: BridgeContract, attesters: List, relayer_key: str,
                interval: float = 30.0):
    while True:
        try:
            scan_deposits(cfg, store)
            relay(cfg, store, bridge, attesters, relayer_key)
        except Exception as e:  # keep running; the next pass retries
            logger.error(f"Relay pass failed: {e}")
        time.sleep(interval)
