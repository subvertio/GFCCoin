"""
Chain -> ledger: pay finalized BridgedOut events from the escrow wallet.

Each payout is an ordinary TRANSFER signed by the escrow key and added through
blockchain.accept_synced_transaction(), so it passes exactly the checks a peer
row would (signature, hash, funding) and the node's sync shares it like any
other signed transfer. One burn is paid once:
- the payout's reason names the bridge-out (bridge-out:v2:<chain>:<bridge>:<nonce>:<evm tx>),
  and every node accepts only one payout per (chain, bridge, nonce): a retry, a replayed
  old signature or a payout under another id is rejected (blockchain._escrow_outflow_problem);
- the payout is signed once and saved (releases.intent) before it's submitted; every retry
  resends exactly those bytes, so a crash, a timeout or a restored state never signs a second
  payout for the same burn;
- a release is paid only when the ledger holds a confirmed row with that payout's tx_hash
  (and the right recipient and amount). An id that happens to exist proves nothing: ids
  aren't signed, anyone can take one (audit F04);
- every pass re-checks paid releases against the ledger, and resends the saved payout if its
  row has gone (a ledger restored from an older backup: audit F06).
Only blocks at or behind the configured chain finality are read, so a reorg
can't un-burn tokens that were already paid out.

A burn is paid only once it's confirmed (audit F09: one dishonest RPC could invent a
BridgedOut log and be paid for it). Every configured provider (the main RPC and each
GFC_BRIDGE_VERIFY_RPC_URLS) must return the burn's receipt: successful, in the same block,
with exactly that log at that index, in a block it treats as final. A provider that can't
answer yet leaves the release waiting; one that contradicts the others stops all verification
for that pass and is logged as an error. Nothing is lost: the release stays recorded and is
checked again next pass. With a single provider this only catches inconsistent answers: a
consistent liar has to be outvoted by independently run providers, which mainnet requires.
"""

import json
import logging
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Dict, Optional, Sequence

import blockchain
import signing
from bridge.config import BridgeConfig
from bridge.store import HELD, MINTED, PAID, REFUND, REFUNDED, WAITING, SEEN, Store

if TYPE_CHECKING:  # payouts and refunds work without the EVM dependencies
    from bridge.chain import BridgeContract, Chain

logger = logging.getLogger("gfc.bridge.releases")

CURSOR_KEY = "release_cursor"


def payout_reason(cfg: BridgeConfig, nonce: int, evm_tx: str) -> str:
    """The signed reason of a payout: it names the bridge-out it pays (blockchain.bridge_payout_key)."""
    return f"bridge-out:v2:{cfg.chain_id}:{cfg.bridge_address.lower()}:{nonce}:{evm_tx}"


def refund_reason(deposit_hash: str) -> str:
    return f"bridge-refund:v1:{deposit_hash}"


_SAME_EVENT = ("evm_tx", "ledger_wallet", "amount_cents")


def scan_bridged_out(cfg: BridgeConfig, store: Store, bridge: "BridgeContract",
                     verifiers: Sequence["Chain"] = ()) -> int:
    """
    Record BridgedOut events up to the final block, then confirm unverified ones with every
    provider (verify_releases). Returns how many were new.
    """
    final = bridge.chain.final_block(cfg.chain_finality)
    start = int(store.get_meta(CURSOR_KEY, str(cfg.start_block)))
    new = 0
    if final >= start:
        for ev in bridge.bridged_out_logs(start, final, cfg.log_chunk_blocks):
            if store.add_release(ev):
                new += 1
                continue
            known = store.release(ev["nonce"])
            if any(str(known[f]).lower() != str(ev[f]).lower() for f in _SAME_EVENT):
                logger.error(f"Two different BridgedOut events for nonce {ev['nonce']}: {known['evm_tx']} and "
                             f"{ev['evm_tx']}. An RPC is lying or the bridge is broken")
                if known["status"] != PAID:
                    store.set_release(ev["nonce"], HELD, f"two different events for this nonce "
                                                         f"({ev['evm_tx'][:12]}): a person must check")
        store.set_meta(CURSOR_KEY, str(final + 1))
    verify_releases(cfg, store, [bridge.chain, *verifiers])
    return new


def _burn_problem(chain: "Chain", cfg: BridgeConfig, r) -> Optional[str]:
    """Why this provider doesn't confirm the release's burn as final, or None if it does."""
    from bridge.chain import decode_bridged_out
    receipt = chain.receipt(r["evm_tx"])
    if not receipt:
        return "no receipt"
    if int(receipt.get("status", "0x0"), 16) != 1:
        return "the transaction reverted"
    if int(receipt["blockNumber"], 16) != r["block"] or \
            (r["block_hash"] and receipt.get("blockHash", "").lower() != r["block_hash"]):
        return "the receipt is in a different block"
    found = []
    for log in receipt.get("logs") or []:
        try:
            ev = decode_bridged_out(log, cfg.bridge_address)
        except Exception:
            continue  # other events in the same transaction
        if ev["nonce"] == r["nonce"] and (r["log_index"] < 0 or ev["log_index"] == r["log_index"]):
            found.append(ev)
    if len(found) != 1:
        return f"{len(found)} matching BridgedOut logs in the receipt"
    ev = found[0]
    if ev["from"].lower() != r["evm_from"].lower() or ev["ledger_wallet"] != r["ledger_wallet"] or \
            ev["amount_cents"] != r["amount_cents"] or ev["evm_tx"] != r["evm_tx"].lower():
        return "the receipt's BridgedOut differs from the recorded one"
    if r["block"] > chain.final_block(cfg.chain_finality):
        return "not final yet"
    if chain.block_hash(r["block"]) != receipt.get("blockHash", "").lower():
        return "its block isn't on this provider's chain"
    return None


_NOT_YET = ("no receipt", "not final yet")  # a lagging provider, not a contradiction


def verify_releases(cfg: BridgeConfig, store: Store, chains: Sequence["Chain"]) -> Dict[str, int]:
    """Confirm each recorded, unverified, unpaid release with every provider. Returns counts."""
    counts = {"verified": 0, "waiting": 0, "disputed": 0}
    for r in store.releases(SEEN, WAITING):
        if r["verified_at"] or r["intent"]:
            continue
        problems = []
        for chain in chains:
            try:
                why = _burn_problem(chain, cfg, r)
            except Exception as e:  # an RPC error or a malformed answer: not a confirmation
                why = f"error: {e}"
            if why:
                problems.append((getattr(chain, "label", "rpc"), why))
        if not problems:
            store.mark_release_verified(r["nonce"])
            counts["verified"] += 1
            continue
        detail = "; ".join(f"{label}: {why}" for label, why in problems)
        store.set_release(r["nonce"], WAITING, f"burn not confirmed ({detail})")
        if all(why in _NOT_YET for _, why in problems):
            counts["waiting"] += 1
            continue
        counts["disputed"] += 1
        logger.error(f"BridgedOut #{r['nonce']} ({r['evm_tx']}) isn't confirmed: {detail}. Stopping "
                     "release verification for this pass")
        break
    return counts


def _payouts_for(conn: sqlite3.Connection, cfg: BridgeConfig, nonce: int) -> list:
    """Confirmed escrow rows paying this bridge-out: (tx_hash, id, recipient, amount_cents)."""
    key = blockchain.bridge_payout_key(payout_reason(cfg, nonce, "0x" + "00" * 32))
    return conn.execute("SELECT tx_hash, id, recipient, amount_cents FROM transactions WHERE sender = ? "
                        "AND substr(reason, 1, ?) = ? AND block_index IS NOT NULL",
                        (cfg.escrow_wallet, len(key), key)).fetchall()


def _confirmed(conn: sqlite3.Connection, tx_hash: str, sender: str, recipient: str, cents: int) -> bool:
    """The ledger holds this exact signed transaction, in a block, paying what it should."""
    return conn.execute("SELECT 1 FROM transactions WHERE tx_hash = ? AND sender = ? AND recipient = ? "
                        "AND amount_cents = ? AND block_index IS NOT NULL",
                        (tx_hash, sender, recipient, cents)).fetchone() is not None


def audit_paid(cfg: BridgeConfig, store: Store) -> int:
    """
    Check every paid release against the ledger. A payout row that's gone (a ledger restored
    from an older backup) goes back to waiting, to resend the same saved payout; without a
    saved payout, a person has to look. Returns how many came back.
    """
    back = 0
    conn = sqlite3.connect(cfg.ledger_db)
    try:
        for r in store.releases(PAID):
            if r["ledger_tx_hash"] and _confirmed(conn, r["ledger_tx_hash"], cfg.escrow_wallet,
                                                  r["ledger_wallet"], r["amount_cents"]):
                continue
            if not r["ledger_tx_hash"] and _payouts_for(conn, cfg, r["nonce"]):
                continue  # paid before payouts were tracked by hash
            if r["intent"]:
                store.set_release(r["nonce"], WAITING, "its payout is missing from the ledger: resending the "
                                                       "same signed payout")
            else:
                store.set_release(r["nonce"], HELD, "marked paid but no payout is on the ledger: a person "
                                                    "must check before anything is resent")
            logger.error(f"BridgedOut #{r['nonce']} was marked paid but its payout isn't on the ledger")
            back += 1
    finally:
        conn.close()
    return back


def pay_releases(cfg: BridgeConfig, store: Store, escrow_key: str,
                 now: Optional[datetime] = None) -> Dict[str, int]:
    """Pay every recorded, unpaid release once. Returns counts by new status."""
    if signing.public_key_of(escrow_key) != cfg.escrow_wallet:
        raise ValueError("escrow key does not match GFC_BRIDGE_ESCROW_WALLET")
    now = now or datetime.now(timezone.utc)
    counts = {PAID: 0, WAITING: 0, HELD: 0}
    day_ago = (now - timedelta(days=1)).isoformat()
    audit_paid(cfg, store)

    def mark(nonce: int, status: str, detail: str = "", tx: Optional[dict] = None):
        store.set_release(nonce, status, detail, tx["id"] if tx else "", tx["tx_hash"] if tx else "")
        counts[status] += 1

    for r in store.releases(SEEN, WAITING):
        nonce, wallet, cents = r["nonce"], r["ledger_wallet"], r["amount_cents"]
        intent = json.loads(r["intent"]) if r["intent"] else None
        if intent is None and not r["verified_at"]:
            continue  # its burn isn't confirmed by every provider yet (verify_releases)
        if not signing.is_public_key(wallet) or wallet in (cfg.escrow_wallet, blockchain.TREASURY_WALLET_ID):
            mark(nonce, HELD, "not a ledger wallet key: the tokens are burned, a person must make this right")
            continue
        if intent is None and not r["approved"]:  # a saved payout already passed the limits
            if cents > cfg.max_release_cents:
                mark(nonce, HELD, f"above the {cfg.max_release_cents / 100:.2f} GFC per-release limit")
                continue
            if store.released_cents_since(day_ago) + cents > cfg.daily_release_cents:
                mark(nonce, WAITING, "daily release limit reached")
                continue

        conn = sqlite3.connect(cfg.ledger_db)
        try:
            existing = _payouts_for(conn, cfg, nonce)
        finally:
            conn.close()
        if existing:
            tx_hash, tx_id, recipient, amount = existing[0]
            if recipient == wallet and amount == cents:
                mark(nonce, PAID, "already paid", {"id": tx_id, "tx_hash": tx_hash})
            else:
                mark(nonce, HELD, f"the ledger has a different payout for this bridge-out ({tx_hash[:16]}): "
                                  "a person must check")
            continue

        if intent is None:
            # Signed once: saved before it's submitted, resent unchanged on every retry
            intent = {
                "id": str(uuid.uuid4()),
                "sender": cfg.escrow_wallet,
                "recipient": wallet,
                "amount": cents / 100.0,
                "amount_cents": cents,
                "reason": payout_reason(cfg, nonce, r["evm_tx"]),
                "timestamp": now.isoformat(),
                "tx_type": blockchain.TX_TYPE_TRANSFER,
            }
            intent["tx_hash"] = blockchain.compute_tx_hash(intent)
            intent["signer"] = cfg.escrow_wallet
            intent["signature"] = signing.sign_tx_hash(escrow_key, intent["tx_hash"])
            intent = store.save_release_intent(nonce, intent)  # an earlier saved one wins

        status, why = blockchain.accept_synced_transaction(cfg.ledger_db, intent)
        conn = sqlite3.connect(cfg.ledger_db)
        try:
            paid = _confirmed(conn, intent["tx_hash"], cfg.escrow_wallet, wallet, cents)
        finally:
            conn.close()
        if paid:
            mark(nonce, PAID, "", intent)
            logger.info(f"Released {cents / 100:.2f} GFC to {wallet[:16]} for BridgedOut #{nonce}")
        elif status == blockchain.PENDING:
            mark(nonce, WAITING, "escrow balance too low")
            logger.error(f"Escrow can't cover BridgedOut #{nonce}: check reconcile")
        elif status == blockchain.DUPLICATE:
            mark(nonce, HELD, "another ledger transaction has this payout's id: a person must check")
        else:
            mark(nonce, HELD, f"ledger rejected the payout: {why}")
    return counts


def refund_deposit(cfg: BridgeConfig, store: Store, escrow_key: str, tx_hash: str,
                   now: Optional[datetime] = None, bridge: Optional["BridgeContract"] = None) -> str:
    """
    Send a deposit that will never be minted (status refund or held) back to its sender,
    with reason bridge-refund:v1:<tx_hash>. Returns the refund's ledger tx id. Every node
    accepts one refund per deposit, of exactly that deposit, to its sender.

    A deposit must never be both refunded and minted (audit F07), so a refund is refused
    while it could still be minted:
    - when `bridge` is given, if it's already processed on chain;
    - while an attestation issued for it hasn't expired (deposits.attested_until), or, if it
      was ever attested, when the chain can't be checked;
    - for a deposit older than this state file while the state is younger than one mint TTL:
      a lost or restored state may not remember attestations issued before it.
    """
    if signing.public_key_of(escrow_key) != cfg.escrow_wallet:
        raise ValueError("escrow key does not match GFC_BRIDGE_ESCROW_WALLET")
    d = store.deposit(tx_hash)
    if d is None or d["status"] not in (REFUND, HELD):
        raise ValueError("only deposits marked refund or held can be refunded")
    reason = refund_reason(tx_hash)
    conn = sqlite3.connect(cfg.ledger_db)
    try:
        row = conn.execute("SELECT id FROM transactions WHERE sender = ? AND reason = ? AND block_index IS NOT NULL",
                           (cfg.escrow_wallet, reason)).fetchone()
    finally:
        conn.close()
    if row:
        store.set_deposit(tx_hash, REFUNDED, "already refunded")
        return row[0]

    now = now or datetime.now(timezone.utc)
    if bridge is not None and bridge.processed(bytes.fromhex(tx_hash)):
        store.set_deposit(tx_hash, MINTED, "minted on chain: not refunding")
        raise ValueError("this deposit was minted on chain: it can't be refunded")
    if d["attested_until"]:
        if d["attested_until"] > now.timestamp():
            raise ValueError(f"an attestation for this deposit can be used until "
                             f"{datetime.fromtimestamp(d['attested_until'], timezone.utc):%Y-%m-%d %H:%M} UTC: "
                             "refund it after that")
        if bridge is None:
            raise ValueError("this deposit was attested: check the chain (pass the bridge) before refunding")
    created = blockchain._parse_timestamp(store.created_at())
    deposited = blockchain._parse_timestamp(d["ledger_ts"])
    if created and deposited and deposited < created and now - created < timedelta(seconds=cfg.mint_ttl_seconds):
        raise ValueError(f"this bridge state started {created:%H:%M} UTC, after the deposit: attestations from "
                         f"before it may still be usable, so wait until "
                         f"{created + timedelta(seconds=cfg.mint_ttl_seconds):%H:%M} UTC")

    tx = {
        "id": str(uuid.uuid4()),
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
    conn = sqlite3.connect(cfg.ledger_db)
    try:
        done = _confirmed(conn, tx["tx_hash"], cfg.escrow_wallet, d["sender"], d["amount_cents"])
    finally:
        conn.close()
    if not done:
        raise ValueError(f"ledger refused the refund: {why or status}")
    store.set_deposit(tx_hash, REFUNDED)
    return tx["id"]
