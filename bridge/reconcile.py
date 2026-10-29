"""
Is every wrapped GFC backed by escrow? Run it often; it pauses the bridge when
the answer is no.

Checks:
  a. token.totalSupply() == (totalMintedCents - totalBridgedOutCents) * CENT
  b. escrow balance on this node >= wrapped supply + burned-but-unpaid releases
  c. every peer ledger DB (other attesters' nodes) also sees escrow >= wrapped supply
  d. every MintedFromLedger event matches a valid escrow deposit on this ledger
     (same destination and amount less the relay fee)
Escrow may hold more than that (relay fees, deposits awaiting mint or refund).
"""

import logging
import sqlite3
from dataclasses import dataclass, field
from typing import List, Optional

import blockchain
from bridge import deposits
from bridge.chain import BridgeContract, RPCError, token_total_supply
from bridge.config import BridgeConfig
from bridge.store import Store

logger = logging.getLogger("gfc.bridge.reconcile")

CENT = 10 ** 16


@dataclass
class Report:
    outstanding_cents: int = 0
    escrow_cents: int = 0
    unpaid_release_cents: int = 0
    problems: List[str] = field(default_factory=list)
    paused: bool = False

    @property
    def ok(self) -> bool:
        return not self.problems


def reconcile(cfg: BridgeConfig, store: Store, bridge: BridgeContract,
              pauser_key: Optional[str] = None) -> Report:
    report = Report()
    minted, out = bridge.total_minted_cents(), bridge.total_bridged_out_cents()
    report.outstanding_cents = minted - out
    supply = token_total_supply(bridge.chain, bridge.token())
    if supply != report.outstanding_cents * CENT:
        report.problems.append(f"token supply {supply} != bridge books {report.outstanding_cents} cents")

    report.escrow_cents = blockchain.get_balance_cents(cfg.ledger_db, cfg.escrow_wallet)
    report.unpaid_release_cents = store.unpaid_release_cents()
    owed = report.outstanding_cents + report.unpaid_release_cents
    if report.escrow_cents < owed:
        report.problems.append(f"escrow {report.escrow_cents} cents < owed {owed} cents")
    for peer_db in cfg.peer_ledger_dbs:
        peer_escrow = blockchain.get_balance_cents(peer_db, cfg.escrow_wallet)
        if peer_escrow < report.outstanding_cents:
            report.problems.append(f"peer {peer_db}: escrow {peer_escrow} cents < supply "
                                   f"{report.outstanding_cents} cents")

    head = bridge.chain.block_number()
    conn = sqlite3.connect(cfg.ledger_db)
    try:
        for ev in bridge.minted_logs(cfg.start_block, head, cfg.log_chunk_blocks):
            tx = deposits.deposit_by_hash(conn, ev["ledger_tx_hash"])
            if tx is None:
                report.problems.append(f"mint {ev['evm_tx']} has no ledger deposit {ev['ledger_tx_hash'][:16]}")
                continue
            # Finality doesn't matter here: the mint already happened
            result, detail, dep = deposits.validate_deposit(tx, _no_finality(cfg))
            if result != deposits.OK:
                report.problems.append(f"mint {ev['evm_tx']} is for a bad deposit: {detail or result}")
            elif dep["evm_to"].lower() != ev["to"].lower() or ev["amount_cents"] > dep["amount_cents"]:
                report.problems.append(f"mint {ev['evm_tx']} does not match its deposit")
    finally:
        conn.close()

    if report.problems:
        for p in report.problems:
            logger.error(f"Reconcile: {p}")
        if pauser_key and not bridge.paused():
            try:
                bridge.pause(pauser_key)
                report.paused = True
                logger.error("Reconcile: bridge paused")
            except RPCError as e:
                logger.error(f"Reconcile: pause failed: {e}")
    return report


def _no_finality(cfg: BridgeConfig) -> BridgeConfig:
    from dataclasses import replace
    return replace(cfg, finality_seconds=0, min_deposit_cents=0)
