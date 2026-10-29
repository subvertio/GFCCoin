"""
Finding and checking escrow deposits on a ledger DB.

A deposit is a TRANSFER to the escrow wallet with reason
`bridge:v1:<chainId>:<0xEVMaddress>`. The reason is part of tx_hash, so the
destination is covered by the depositor's Ed25519 signature.

The checks here don't rely on how the row got into the DB: the hash and the
signature are re-verified, so a row written straight into SQLite (a tampered
node, a bad sync) is rejected like a forged peer row would be. Funding was
checked by the node when it accepted the row into a block (block_index set).
"""

import re
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Iterator, Optional, Tuple

import blockchain
import signing

REASON_RE = re.compile(r"^bridge:v1:(\d{1,12}):(0x[0-9a-fA-F]{40})$")
RELEASE_REASON_PREFIX = "bridge-out:v1:"

# Mints a farmer can collect with a fresh account: these can't be bridged until they age
FAUCET_TX_TYPES = (blockchain.TX_TYPE_GRANT, blockchain.TX_TYPE_REFERRAL, blockchain.TX_TYPE_FIRST_POST,
                   blockchain.TX_TYPE_REPOST)

# validate_deposit results
OK = "ok"                # mint it (subject to policy and limits)
NOT_FINAL = "not_final"  # retry later
OTHER_CHAIN = "other"    # a deposit for another chain's bridge: not ours
REFUND = "refund"        # a real, signed deposit we will never mint: a person refunds it
INVALID = "invalid"      # not a trustworthy row at all: ignore and alert

TX_FIELDS = ("id", "sender", "recipient", "amount_cents", "reason", "timestamp", "tx_hash", "tx_type",
             "signature", "signer", "block_index")


def parse_ts(value: str) -> Optional[datetime]:
    return blockchain._parse_timestamp(value)


def deposit_rows(conn: sqlite3.Connection, escrow: str) -> Iterator[dict]:
    cur = conn.execute(
        f"SELECT {', '.join(TX_FIELDS)} FROM transactions WHERE recipient = ? AND tx_type = ? "
        "AND block_index IS NOT NULL ORDER BY timestamp", (escrow, blockchain.TX_TYPE_TRANSFER))
    for row in cur:
        yield dict(zip(TX_FIELDS, row))


def deposit_by_hash(conn: sqlite3.Connection, tx_hash: str) -> Optional[dict]:
    row = conn.execute(f"SELECT {', '.join(TX_FIELDS)} FROM transactions WHERE tx_hash = ?",
                       (tx_hash,)).fetchone()
    return dict(zip(TX_FIELDS, row)) if row else None


def validate_deposit(tx: dict, cfg, now: Optional[datetime] = None) -> Tuple[str, str, Optional[dict]]:
    """(result, detail, deposit). `deposit` adds evm_to and mint_cents to the row."""
    now = now or datetime.now(timezone.utc)
    sender = tx.get("sender") or ""
    amount = tx.get("amount_cents")

    if tx.get("tx_type") != blockchain.TX_TYPE_TRANSFER or tx.get("recipient") != cfg.escrow_wallet:
        return INVALID, "not a transfer to escrow", None
    if tx.get("block_index") is None:
        return NOT_FINAL, "not in a block", None
    if not isinstance(amount, int) or isinstance(amount, bool) or amount <= 0:
        return INVALID, "bad amount", None
    if not signing.is_public_key(sender) or sender == cfg.escrow_wallet:
        return INVALID, "sender is not a wallet key", None
    if tx.get("tx_hash") != blockchain.compute_tx_hash(tx):
        return INVALID, "tx_hash does not match contents", None
    if tx.get("signer") not in ("", None, sender) or \
            not signing.verify_tx_signature(sender, tx["tx_hash"], tx.get("signature") or ""):
        return INVALID, "bad or missing signature", None
    ts = parse_ts(tx.get("timestamp"))
    if ts is None:
        return INVALID, "bad timestamp", None

    m = REASON_RE.match(tx.get("reason") or "")
    if m and int(m.group(1)) != cfg.chain_id:
        return OTHER_CHAIN, f"for chain {m.group(1)}", None
    if not m:
        return REFUND, "reason is not bridge:v1:<chainId>:<0xaddress>", _deposit(tx, "", 0)
    evm_to = m.group(2)
    if int(evm_to, 16) == 0:
        return REFUND, "zero destination address", _deposit(tx, evm_to, 0)
    if amount < cfg.min_deposit_cents or amount <= cfg.relay_fee_cents:
        return REFUND, f"below the {cfg.min_deposit_cents / 100:.2f} GFC minimum", _deposit(tx, evm_to, 0)
    if now - ts < timedelta(seconds=cfg.finality_seconds):
        return NOT_FINAL, "inside the finality window", None
    return OK, "", _deposit(tx, evm_to, amount - cfg.relay_fee_cents)


def _deposit(tx: dict, evm_to: str, mint_cents: int) -> dict:
    return {**tx, "evm_to": evm_to, "mint_cents": mint_cents}


def faucet_hold_until(conn: sqlite3.Connection, wallet: str, hold_days: float) -> Optional[datetime]:
    """When the wallet's newest faucet credit (grant, referral, first post, repost) is old enough to bridge."""
    if hold_days <= 0:
        return None
    row = conn.execute(
        f"SELECT MAX(timestamp) FROM transactions WHERE recipient = ? AND block_index IS NOT NULL "
        f"AND tx_type IN ({','.join('?' * len(FAUCET_TX_TYPES))})", (wallet, *FAUCET_TX_TYPES)).fetchone()
    newest = parse_ts(row[0]) if row and row[0] else None
    return newest + timedelta(days=hold_days) if newest else None
