"""
An attester: re-checks a deposit against its own ledger DB and, if it passes
validity and policy, signs the EIP-712 MintRequest for it.

Each production attester runs on its own machine with its own ledger node and
key; the relayer only collects their signatures. A relayer can't make an
attester sign anything the attester's own ledger doesn't show.

Policy (on top of validity):
- the destination address and the sender wallet aren't on the denylist;
- the deposit is covered by GFC that isn't fresh free credit: grants, referrals,
  first-post and repost bonuses younger than faucet_hold_days don't count, also
  when they were passed through other wallets (deposits.fresh_faucet_cents);
- deposits above manual_review_cents need their tx_hash in the approvals file.
"""

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from eth_account import Account

from bridge import deposits, eip712
from bridge.config import BridgeConfig, read_evm_key, read_lines


@dataclass
class Attestation:
    signer: str
    signature: Optional[bytes]   # None when refused
    refusal: str = ""
    retry: bool = False          # refused for now (not final, on hold), not forever


class Attester:
    def __init__(self, cfg: BridgeConfig, ledger_db: Optional[str] = None, key: Optional[str] = None):
        self.cfg = cfg
        self.ledger_db = ledger_db or cfg.ledger_db
        self._key = key or read_evm_key(cfg.attester_key_file)
        self.address = Account.from_key(self._key).address

    def attest(self, tx_hash: str, evm_to: str, mint_cents: int, deadline: int,
               now: Optional[datetime] = None) -> Attestation:
        now = now or datetime.now(timezone.utc)
        conn = sqlite3.connect(self.ledger_db)
        try:
            tx = deposits.deposit_by_hash(conn, tx_hash)
            if tx is None:
                return Attestation(self.address, None, "deposit not on this attester's ledger", retry=True)
            result, detail, dep = deposits.validate_deposit(tx, self.cfg, now)
            if result == deposits.NOT_FINAL:
                return Attestation(self.address, None, detail, retry=True)
            if result != deposits.OK:
                return Attestation(self.address, None, detail or result)
            # The relayer's request must be exactly what the ledger says
            if dep["evm_to"].lower() != evm_to.lower() or dep["mint_cents"] != mint_cents:
                return Attestation(self.address, None, "request does not match the ledger deposit")

            denied = read_lines(self.cfg.denylist_file)
            if evm_to.lower() in denied or dep["sender"].lower() in denied:
                return Attestation(self.address, None, "denylisted")
            _, clean = deposits.clean_cents(conn, dep["sender"], now, self.cfg.faucet_hold_days,
                                            before_block=dep["block_index"],
                                            exclude=frozenset([self.cfg.escrow_wallet]))
            if dep["amount_cents"] > clean:
                return Attestation(self.address, None,
                                   f"faucet credit on hold: only {clean / 100:.2f} GFC of the sender's balance "
                                   f"is older than {self.cfg.faucet_hold_days:g} days", retry=True)
            if dep["amount_cents"] > self.cfg.manual_review_cents and \
                    tx_hash.lower() not in read_lines(self.cfg.approvals_file):
                return Attestation(self.address, None, "needs manual approval", retry=True)
        finally:
            conn.close()

        req = eip712.mint_request(tx_hash, evm_to, mint_cents, deadline)
        signer, sig = eip712.sign_mint(self._key, self.cfg.chain_id, self.cfg.bridge_address, req)
        return Attestation(signer, sig)
