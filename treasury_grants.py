"""
GFC Operator Grants - GFC the network operator hands out on purpose, in public

Purposes:
- hackathon  prizes and rewards for events (up to 10,000 GFC per grant)
- node-host  a one-time 10,000 GFC thank-you to someone running a GFC node,
             once per wallet; the operator grants it after checking the node is
             real (reachable and running). Automatic node rewards would need node
             identity keys and an uptime proof - not built yet.
- other      anything else (up to 10,000 GFC), explained in the memo

Every grant is a treasury-signed OPERATOR transaction whose reason is
"Operator grant (<purpose>): <memo>". Every node checks the 10,000 GFC cap, the
purpose/memo format and node-host's exact amount and once-per-wallet rule, so a
leaked treasury key can't mint more than 10,000 per transaction this way.
Grants are listed publicly at /treasury/grants (from the ledger itself).

Run on the treasury node (normally through the `gfc grant` helper):
    python treasury_grants.py grant <wallet> <amount GFC> <purpose> "<memo>"
    python treasury_grants.py list
"""

import sqlite3
import sys
from typing import Dict, List

import blockchain
import signing
from config import DB_PATH

MIN_MEMO = 3


class GrantError(ValueError):
    pass


def grant(wallet_id: str, amount_gfc: float, purpose: str, memo: str, db_path: str = DB_PATH) -> Dict:
    """Mint an operator grant. Raises GrantError when a rule isn't met."""
    purpose = (purpose or "").strip().lower()
    memo = " ".join((memo or "").split())  # one line
    if not signing.is_public_key(wallet_id):
        raise GrantError("recipient must be a wallet ID (64 hex characters)")
    if purpose not in blockchain.OPERATOR_PURPOSES:
        raise GrantError(f"purpose must be one of: {', '.join(blockchain.OPERATOR_PURPOSES)}")
    if len(memo) < MIN_MEMO:
        raise GrantError("give a memo saying what the grant is for (it's public)")
    try:
        cents = round(float(amount_gfc) * 100)
    except (TypeError, ValueError):
        raise GrantError("amount must be a number of GFC")
    if purpose == "node-host" and cents != blockchain.NODE_HOST_GRANT_CENTS:
        raise GrantError(f"node-host grants are exactly {blockchain.NODE_HOST_GRANT_CENTS / 100:,.0f} GFC")
    if not 0 < cents <= blockchain.OPERATOR_GRANT_MAX_CENTS:
        raise GrantError(f"amount must be more than 0 and at most {blockchain.OPERATOR_GRANT_MAX_CENTS / 100:,.0f} GFC")
    reason = f"Operator grant ({purpose}): {memo}"
    if len(reason) > blockchain.MAX_REASON_LEN:
        raise GrantError(f"memo too long (max {blockchain.MAX_REASON_LEN - len(reason) + len(memo)} characters)")
    if not signing.load_treasury_private_key():
        raise GrantError("this node can't sign treasury grants (treasury key not loaded: gfc check)")
    if purpose == "node-host":
        conn = sqlite3.connect(db_path)
        try:
            if conn.execute("SELECT 1 FROM transactions WHERE tx_type = ? AND recipient = ? "
                            "AND reason LIKE 'Operator grant (node-host)%'",
                            (blockchain.TX_TYPE_OPERATOR, wallet_id)).fetchone():
                raise GrantError("this wallet already received its node-host grant")
        finally:
            conn.close()
    tx = blockchain.process_operator_mint(db_path, wallet_id, cents, reason)
    if not tx:
        raise GrantError("the treasury couldn't pay this grant")
    return {"tx_id": tx["id"], "wallet": wallet_id, "amount": cents / 100.0,
            "purpose": purpose, "memo": memo, "timestamp": tx["timestamp"]}


def list_grants(db_path: str = DB_PATH) -> List[Dict]:
    """All operator grants on this node's ledger, newest first."""
    conn = sqlite3.connect(db_path)
    try:
        rows = conn.execute(
            "SELECT id, recipient, amount_cents, reason, timestamp FROM transactions "
            "WHERE tx_type = ? AND block_index IS NOT NULL ORDER BY timestamp DESC",
            (blockchain.TX_TYPE_OPERATOR,)).fetchall()
    finally:
        conn.close()
    grants = []
    for tx_id, wallet, cents, reason, ts in rows:
        m = blockchain.OPERATOR_REASON_RE.match(reason or "")
        purpose = m.group(1) if m else "other"
        memo = (reason or "").split("): ", 1)[1] if "): " in (reason or "") else ""
        grants.append({"tx_id": tx_id, "wallet": wallet, "amount": cents / 100.0,
                       "purpose": purpose, "memo": memo, "timestamp": ts})
    return grants


def _cli(argv: List[str]) -> int:
    if len(argv) == 5 and argv[0] == "grant":
        try:
            g = grant(argv[1], argv[2], argv[3], argv[4])
        except GrantError as ex:
            print(f"error: {ex}")
            return 1
        print(f"Granted {g['amount']:,.2f} GFC ({g['purpose']}) to {g['wallet']}")
        print(f"Memo: {g['memo']}")
        print(f"Transaction: {g['tx_id']} - listed publicly at /treasury/grants")
        return 0
    if argv == ["list"]:
        for g in list_grants():
            print(f"{g['timestamp'][:16]}  {g['amount']:>10,.2f} GFC  {g['purpose']:<9}  "
                  f"{g['wallet'][:12]}...  {g['memo']}")
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    raise SystemExit(_cli(sys.argv[1:]))
