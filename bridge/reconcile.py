"""
Is every wrapped GFC backed by escrow? Run it often; it pauses the bridge when
the answer is no.

Checks:
  a. token.totalSupply() == (totalMintedCents - totalBridgedOutCents) * CENT
  b. escrow balance on this node >= wrapped supply + burned-but-unpaid releases
  c. every peer ledger DB (other attesters' nodes) also sees escrow >= wrapped supply
  d. every MintedFromLedger event matches a valid escrow deposit on this ledger
     (same destination, and exactly the amount recorded for it: the deposit less the relay fee)
  e. no watched wallet (attesters, pauser, relayer, Safe owners) has code. Under EIP-7702 a
     plain wallet that signs an authorization hands its account to a contract (how Binance's
     hot wallet was swept in October 2026): its code becomes 0xef0100 + that contract.
     A signature from the key is still needed, so code here means the key's signing was
     abused, and everything it can do should be treated as hostile.
  f. no quiet wallet (one that never sends transactions: the attesters, the pauser) has a new
     nonce. An EIP-7702 authorization raises its signer's nonce, so a delegation that was set
     and cleared between two checks still shows here (audit F13)
  g. every independent RPC provider (GFC_BRIDGE_VERIFY_RPC_URLS) agrees on the bridge's
     totals and the token supply at a block both treat as final (audit F09)
Escrow may hold more than that (relay fees, deposits awaiting mint or refund).

Chain reads are pinned to one block, and the escrow balance and unpaid releases are read in
one SQLite snapshot, so a mint or payout landing mid-check can't look like a mismatch (audit
F12). Alarms from e and f are latched: they stay problems, and keep the bridge paused, until
a person clears them with `python -m bridge clear-incident ADDRESS` after rotating the key.
These checks happen after the fact: they can't stop a key that's already abused, only stop
the bridge acting on it. The defence is never letting those keys sign authorizations
(docs/testnet-checklist.md, A2b).
"""

import logging
import sqlite3
from dataclasses import dataclass, field
from typing import Iterable, List, Optional

import blockchain
from bridge import deposits
from bridge.chain import BridgeContract, RPCError, token_total_supply
from bridge.config import BridgeConfig
from bridge.store import Store

logger = logging.getLogger("gfc.bridge.reconcile")

CENT = 10 ** 16
DELEGATION_PREFIX = bytes.fromhex("ef0100")  # EIP-7702: 0xef0100 || 20-byte delegate address


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


INCIDENT = "incident:"
NONCE = "nonce:"


def takeover_problems(chain, addresses: Iterable[str], store: Optional[Store] = None) -> List[str]:
    """Check e: watched plain wallets that have code (an EIP-7702 delegation, or anything else)."""
    problems, seen = [], set()
    for addr in addresses:
        if not addr or addr.lower() in seen:
            continue
        seen.add(addr.lower())
        try:
            code = chain.code(addr)
        except RPCError as e:
            problems.append(f"could not read the code of watched wallet {addr}: {e}")
            continue
        if code.startswith(DELEGATION_PREFIX) and len(code) == 23:
            _latch(store, addr, f"watched wallet {addr} is delegated to 0x{code[3:].hex()} (EIP-7702): "
                                "its key signed an authorization; rotate it", problems)
        elif code:
            _latch(store, addr, f"watched wallet {addr} has contract code: it should be a plain wallet", problems)
    return problems


def quiet_problems(chain, addresses: Iterable[str], store: Store, block) -> List[str]:
    """Check f: wallets that never send transactions, whose nonce went up."""
    problems, seen = [], set()
    for addr in addresses:
        if not addr or addr.lower() in seen:
            continue
        seen.add(addr.lower())
        try:
            nonce = chain.nonce(addr, block)
        except RPCError as e:
            problems.append(f"could not read the nonce of quiet wallet {addr}: {e}")
            continue
        known = store.get_meta(NONCE + addr.lower())
        if not known:
            store.set_meta(NONCE + addr.lower(), str(nonce))  # first sight: the baseline
        elif nonce > int(known):
            _latch(store, addr, f"quiet wallet {addr} has used its key on chain ({nonce - int(known)} new "
                                "transaction(s) or EIP-7702 authorization(s)): treat it as compromised", problems)
    return problems


def _latch(store: Optional[Store], addr: str, problem: str, problems: List[str]):
    """Record an incident so it stays a problem after the evidence is gone, and report it."""
    if store is not None and not store.get_meta(INCIDENT + addr.lower()):
        store.set_meta(INCIDENT + addr.lower(), problem)
    problems.append(problem)


def latched_problems(store: Store, already: Iterable[str]) -> List[str]:
    """Incidents recorded earlier that this pass didn't see again (a delegation since cleared)."""
    return [f"{text} (latched: clear it with `python -m bridge clear-incident {addr}` once it's dealt with)"
            for addr, text in store.meta_like(INCIDENT).items() if text not in already]


def clear_incident(store: Store, address: str) -> bool:
    """A person has rotated the key: forget the incident and take a new nonce baseline."""
    store.delete_meta(NONCE + address.lower())
    return store.delete_meta(INCIDENT + address.lower())


def watched_addresses(cfg: BridgeConfig, own_keys: Iterable[Optional[str]] = ()) -> List[str]:
    """The configured watch list plus the addresses of the EVM keys this service holds."""
    from eth_account import Account
    return list(cfg.watch_addresses) + [Account.from_key(k).address for k in own_keys if k]


def _address(key: Optional[str]) -> Optional[str]:
    from eth_account import Account
    return Account.from_key(key).address if key else None


def _ledger_and_state(cfg: BridgeConfig, store: Store):
    """The escrow balance and unpaid releases, read in one snapshot of both files."""
    conn = sqlite3.connect(cfg.ledger_db)
    try:
        conn.execute("ATTACH DATABASE ? AS state", (store.path,))
        conn.execute("BEGIN")
        escrow = blockchain._balance_cents(conn, cfg.escrow_wallet)
        unpaid = conn.execute("SELECT COALESCE(SUM(amount_cents), 0) FROM state.releases WHERE status != 'paid'"
                              ).fetchone()[0]
        conn.execute("COMMIT")
        return escrow, unpaid
    finally:
        conn.close()


def _totals(chain, bridge_address: str, block: int):
    b = BridgeContract(chain, bridge_address)
    return (b.total_minted_cents(block), b.total_bridged_out_cents(block),
            token_total_supply(chain, b.token(block), block))


def verifier_problems(cfg: BridgeConfig, bridge: BridgeContract, verifiers) -> List[str]:
    """Check g: each independent provider agrees with the main one at a block both treat as final."""
    problems = []
    if not verifiers:
        return problems
    final = bridge.chain.final_block(cfg.chain_finality)
    for v in verifiers:
        label = getattr(v, "label", "verifier")
        try:
            block = min(final, v.final_block(cfg.chain_finality))
            if block < cfg.start_block:
                continue
            if v.block_hash(block) != bridge.chain.block_hash(block):
                problems.append(f"{label} and the main RPC disagree on final block {block}")
                continue
            ours, theirs = _totals(bridge.chain, bridge.address, block), _totals(v, bridge.address, block)
            if ours != theirs:
                problems.append(f"{label} disagrees with the main RPC at block {block}: minted/out/supply "
                                f"{theirs} vs {ours}")
        except Exception as e:
            problems.append(f"could not cross-check with {label}: {e}")
    return problems


def reconcile(cfg: BridgeConfig, store: Store, bridge: BridgeContract,
              pauser_key: Optional[str] = None, own_keys: Iterable[Optional[str]] = (),
              quiet_keys: Iterable[Optional[str]] = (), verifiers=()) -> Report:
    """
    own_keys: the other EVM keys this service holds (relayer, in-process attesters), to watch too.
    quiet_keys: those of them that never send transactions (the attesters); the pauser is quiet too.
    verifiers: Chain objects for the independent RPC providers.
    """
    report = Report()
    head = bridge.chain.block_number()  # every chain read below is at this one block
    report.problems += takeover_problems(bridge.chain, watched_addresses(cfg, [pauser_key, *own_keys]), store)
    quiet = list(cfg.quiet_addresses) + [a for a in map(_address, [pauser_key, *quiet_keys]) if a]
    report.problems += quiet_problems(bridge.chain, quiet, store, head)
    report.problems += latched_problems(store, report.problems)

    minted, out = bridge.total_minted_cents(head), bridge.total_bridged_out_cents(head)
    report.outstanding_cents = minted - out
    supply = token_total_supply(bridge.chain, bridge.token(head), head)
    if supply != report.outstanding_cents * CENT:
        report.problems.append(f"token supply {supply} != bridge books {report.outstanding_cents} cents")
    report.problems += verifier_problems(cfg, bridge, verifiers)

    report.escrow_cents, report.unpaid_release_cents = _ledger_and_state(cfg, store)
    owed = report.outstanding_cents + report.unpaid_release_cents
    if report.escrow_cents < owed:
        report.problems.append(f"escrow {report.escrow_cents} cents < owed {owed} cents")
    for peer_db in cfg.peer_ledger_dbs:
        peer_escrow = blockchain.get_balance_cents(peer_db, cfg.escrow_wallet)
        if peer_escrow < report.outstanding_cents:
            report.problems.append(f"peer {peer_db}: escrow {peer_escrow} cents < supply "
                                   f"{report.outstanding_cents} cents")

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
            elif dep["evm_to"].lower() != ev["to"].lower():
                report.problems.append(f"mint {ev['evm_tx']} went to {ev['to']}, not its deposit's address")
            elif ev["amount_cents"] != _expected_mint(store, dep):
                report.problems.append(f"mint {ev['evm_tx']} is {ev['amount_cents']} cents; its deposit should "
                                       f"mint {_expected_mint(store, dep)}")
    finally:
        conn.close()

    if report.problems:
        for p in report.problems:
            logger.error(f"Reconcile: {p}")
        if pauser_key and not bridge.paused():
            try:
                bridge.pause(pauser_key)  # the bridge only: the token, and so the pool, keep working
                report.paused = True
                logger.error("Reconcile: bridge paused")
                pauser = _address(pauser_key)
                store.set_meta(NONCE + pauser.lower(), str(bridge.chain.nonce(pauser)))  # our own transaction
            except RPCError as e:
                logger.error(f"Reconcile: pause failed: {e}")
    return report


def _expected_mint(store: Store, dep: dict) -> int:
    """
    What a deposit mints: the amount recorded when it was first seen. A deposit this state
    never saw is judged by the current relay fee: a person may have to check if the fee changed.
    """
    known = store.deposit(dep["tx_hash"])
    return known["mint_cents"] if known else dep["mint_cents"]


def _no_finality(cfg: BridgeConfig) -> BridgeConfig:
    from dataclasses import replace
    return replace(cfg, finality_seconds=0, min_deposit_cents=0)
