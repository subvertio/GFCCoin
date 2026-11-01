"""
Finding and checking escrow deposits on a ledger DB.

A deposit is a TRANSFER to the escrow wallet with reason
`bridge:v1:<chainId>:<0xEVMaddress>`. The reason is part of tx_hash, so the
destination is covered by the depositor's Ed25519 signature.

The checks here don't rely on how the row got into the DB: the hash and the
signature are re-verified, so a row written straight into SQLite (a tampered
node, a bad sync) is rejected like a forged peer row would be. Funding was
checked by the node when it accepted the row into a block (block_index set).

Times are admission times: when the row entered this ledger, its block's timestamp. The
timestamp inside a transaction is chosen by whoever signs it, so a sender could backdate a
deposit past the finality wait, or a transfer past the free-credit hold (audit F02, F08).
A deposit must also really be in its block: the block exists, holds exactly that deposit,
and its Merkle root is that deposit's hash (F08: a row pointed at a made-up block number).
That still trusts this node's database as a whole; signed checkpoints are what would let
attesters on other nodes check it (docs/ledger-checkpoints.md).
"""

import re
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Iterator, Optional, Tuple

import blockchain
import signing

REASON_RE = blockchain.BRIDGE_DEPOSIT_RE

# Mints a farmer can collect with a fresh account: these can't be bridged until they age
FAUCET_TX_TYPES = (blockchain.TX_TYPE_GRANT, blockchain.TX_TYPE_REFERRAL, blockchain.TX_TYPE_FIRST_POST,
                   blockchain.TX_TYPE_REPOST)

# validate_deposit results
OK = "ok"                # mint it (subject to policy and limits)
NOT_FINAL = "not_final"  # retry later
OTHER_CHAIN = "other"    # a deposit for another chain's bridge, or for an earlier bridge contract: not ours
REFUND = "refund"        # a real, signed deposit we will never mint: a person refunds it
INVALID = "invalid"      # not a trustworthy row at all: ignore and alert

TX_FIELDS = ("id", "sender", "recipient", "amount_cents", "reason", "timestamp", "tx_hash", "tx_type",
             "signature", "signer", "block_index")
# Read with every deposit: its block's timestamp (admission time), Merkle root and size
BLOCK_FIELDS = ("admitted_at", "block_merkle_root", "block_tx_count", "block_rows")
_ROW_SQL = (f"SELECT {', '.join('t.' + f for f in TX_FIELDS)}, b.timestamp, b.merkle_root, b.tx_count, "
            "(SELECT COUNT(*) FROM transactions x WHERE x.block_index = t.block_index) "
            "FROM transactions t LEFT JOIN blocks b ON b.block_index = t.block_index")


def parse_ts(value: str) -> Optional[datetime]:
    return blockchain._parse_timestamp(value)


def deposit_rows(conn: sqlite3.Connection, escrow: str) -> Iterator[dict]:
    cur = conn.execute(f"{_ROW_SQL} WHERE t.recipient = ? AND t.tx_type = ? AND t.block_index IS NOT NULL "
                       "ORDER BY t.block_index", (escrow, blockchain.TX_TYPE_TRANSFER))
    for row in cur:
        yield dict(zip(TX_FIELDS + BLOCK_FIELDS, row))


def refunded(conn: sqlite3.Connection, escrow: str, tx_hash: str) -> bool:
    """The ledger has a refund of this deposit (every node accepts at most one)."""
    return conn.execute("SELECT 1 FROM transactions WHERE sender = ? AND reason = ?",
                        (escrow, f"bridge-refund:v1:{tx_hash}")).fetchone() is not None


def deposit_by_hash(conn: sqlite3.Connection, tx_hash: str) -> Optional[dict]:
    row = conn.execute(f"{_ROW_SQL} WHERE t.tx_hash = ?", (tx_hash,)).fetchone()
    return dict(zip(TX_FIELDS + BLOCK_FIELDS, row)) if row else None


def _block_problem(tx: dict) -> Optional[str]:
    """Why the deposit isn't really in the block its row names, or None."""
    if "admitted_at" not in tx:
        return "read without its block (use deposit_rows / deposit_by_hash)"
    if tx["admitted_at"] is None:
        return f"its block {tx['block_index']} isn't in this ledger"
    if tx["block_rows"] != 1 or tx["block_tx_count"] != 1 or \
            tx["block_merkle_root"] != blockchain.compute_merkle_root([tx["tx_hash"]]):
        return f"block {tx['block_index']} doesn't hold exactly this deposit"
    return None


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
    problem = _block_problem(tx)
    if problem:
        return INVALID, problem, None
    admitted = parse_ts(tx["admitted_at"])
    if admitted is None:
        return INVALID, "its block has a bad timestamp", None

    m = REASON_RE.match(tx.get("reason") or "")
    if m and int(m.group(1)) != cfg.chain_id:
        return OTHER_CHAIN, f"for chain {m.group(1)}", None
    # A deposit names its chain, not its bridge contract. One admitted before this contract's
    # cutoff was for an earlier contract on the same chain, which may already have minted it:
    # a redeployed bridge must never mint it again
    if cfg.deposits_from is not None and admitted < cfg.deposits_from:
        return OTHER_CHAIN, "deposited before this bridge contract's cutoff (GFC_BRIDGE_DEPOSITS_FROM)", None
    if not m:
        return REFUND, "reason is not bridge:v1:<chainId>:<0xaddress>", _deposit(tx, "", 0)
    evm_to = m.group(2)
    if int(evm_to, 16) == 0:
        return REFUND, "zero destination address", _deposit(tx, evm_to, 0)
    if amount < cfg.min_deposit_cents or amount <= cfg.relay_fee_cents:
        return REFUND, f"below the {cfg.min_deposit_cents / 100:.2f} GFC minimum", _deposit(tx, evm_to, 0)
    if now - admitted < timedelta(seconds=cfg.finality_seconds):  # the signed timestamp doesn't count
        return NOT_FINAL, "inside the finality window", None
    return OK, "", _deposit(tx, evm_to, amount - cfg.relay_fee_cents)


def _deposit(tx: dict, evm_to: str, mint_cents: int) -> dict:
    return {**tx, "evm_to": evm_to, "mint_cents": mint_cents}


# Free credit (grants, referrals, first-post and repost bonuses) younger than the hold can't
# be bridged, including when it was passed on through other wallets first. Each incoming
# transfer is counted as fresh up to the fresh credit its sender held when it was sent,
# followed this many hops back, with a lookup budget so a wallet with a huge history can't
# make the check expensive (past the budget, incoming transfers count as fresh).
# Ages are admission times, so a backdated transfer can't make fresh credit look old, and
# every incoming transfer inside the hold is looked at: nothing is dropped unseen (audit F02:
# 200 one-cent transfers used to push a fresh 100 GFC out of view).
FRESH_TRACE_DEPTH = 3
FRESH_TRACE_BUDGET = 500


def fresh_faucet_cents(conn: sqlite3.Connection, wallet: str, now: datetime, hold_days: float,
                       before_block: Optional[int] = None, exclude: frozenset = frozenset()) -> int:
    """
    How much of `wallet`'s incoming GFC (in blocks before `before_block`, or all) is free
    credit from the last `hold_days`, received directly or through up to FRESH_TRACE_DEPTH
    hops of transfers. Transfers from wallets in `exclude` (escrows: bridge payouts) are clean.
    """
    if hold_days <= 0:
        return 0
    since = now - timedelta(days=hold_days)
    budget = [FRESH_TRACE_BUDGET]
    return _fresh(conn, wallet, since, before_block, FRESH_TRACE_DEPTH, exclude, frozenset([wallet]), budget)


def _admitted_after(ts: Optional[str], since: datetime) -> bool:
    """Admitted inside the hold. An unreadable time counts as inside: fail closed."""
    t = parse_ts(ts)
    return t is None or t > since


def _fresh(conn, wallet, since, before_block, depth, exclude, path, budget) -> int:
    budget[0] -= 1
    block_sql = " AND t.block_index < ?" if before_block is not None else ""
    block_arg = (before_block,) if before_block is not None else ()
    fresh = 0
    for amount, admitted in conn.execute(
            f"SELECT t.amount_cents, b.timestamp FROM transactions t JOIN blocks b ON b.block_index = t.block_index "
            f"WHERE t.recipient = ? AND t.tx_type IN ({','.join('?' * len(FAUCET_TX_TYPES))}){block_sql}",
            (wallet, *FAUCET_TX_TYPES, *block_arg)):
        if _admitted_after(admitted, since):
            fresh += amount
    incoming = conn.execute(
        f"SELECT t.sender, t.amount_cents, b.timestamp, t.block_index FROM transactions t "
        f"JOIN blocks b ON b.block_index = t.block_index WHERE t.recipient = ? AND t.tx_type = ?{block_sql} "
        f"ORDER BY t.block_index DESC", (wallet, blockchain.TX_TYPE_TRANSFER, *block_arg))
    for sender, amount, admitted, block in incoming:
        if not _admitted_after(admitted, since) or sender in exclude or sender in path:
            continue
        if depth <= 0 or budget[0] <= 0:
            fresh += amount  # can't look further back: assume the worst
            continue
        fresh += min(amount, _fresh(conn, sender, since, block, depth - 1, exclude, path | {sender}, budget))
    return fresh


def balance_before_cents(conn: sqlite3.Connection, wallet: str, before_block: Optional[int] = None) -> int:
    """The wallet's confirmed balance from blocks before `before_block` (or all blocks)."""
    block_sql = " AND block_index < ?" if before_block is not None else ""
    block_arg = (before_block,) if before_block is not None else ()
    received = conn.execute(f"SELECT COALESCE(SUM(amount_cents), 0) FROM transactions WHERE recipient = ? "
                            f"AND block_index IS NOT NULL{block_sql}", (wallet, *block_arg)).fetchone()[0]
    sent = conn.execute(f"SELECT COALESCE(SUM(amount_cents), 0) FROM transactions WHERE sender = ? "
                        f"AND block_index IS NOT NULL{block_sql}", (wallet, *block_arg)).fetchone()[0]
    return received - sent


def clean_cents(conn: sqlite3.Connection, wallet: str, now: datetime, hold_days: float,
                before_block: Optional[int] = None, exclude: frozenset = frozenset()) -> Tuple[int, int]:
    """(balance, the part of it that can be bridged now). Fresh credit is assumed spent last."""
    balance = balance_before_cents(conn, wallet, before_block)
    fresh = fresh_faucet_cents(conn, wallet, now, hold_days, before_block, exclude)
    return balance, max(balance - fresh, 0)
