"""
Bridge state: a SQLite file of its own, never the node's ledger DB.

deposits: ledger -> chain, keyed by the deposit's ledger tx_hash
  seen -> submitted (mint sent) -> minted (in a finalized block), or waiting (retried), or held
  (needs a person), or refund (never minted); submitted goes back to seen if the mint
  disappears (a reorg or a revert)
  refund/held -> refunded (`python -m bridge refund TX_HASH`)
  attested_until: the latest deadline of any attestation issued for it (no refund before then)
releases: chain -> ledger, keyed by BridgedOut nonce
  seen -> paid, or waiting (retried), or held (needs a person)
  block_hash, log_index: the event's exact identity; verified_at: when every configured RPC
  confirmed that event's receipt in a final block. Nothing is signed for a release before that
  (audit F09: one lying RPC could invent a burn)
  intent: the payout exactly as signed, saved before it's submitted and resent byte for byte on
  every retry, so one burn has one signed payout; paid only once the ledger holds its tx_hash
meta: bridge_address pins the file to one bridge contract (its nonces and deposits aren't
  another bridge's); created_at is when this state started; incident:<address> latches a
  watched-wallet alarm until a person clears it; nonce:<address> is a quiet key's last nonce
"""

import json
import sqlite3
from datetime import datetime, timezone
from typing import List, Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS deposits (
    tx_hash TEXT PRIMARY KEY,
    ledger_tx_id TEXT NOT NULL,
    sender TEXT NOT NULL,
    evm_to TEXT NOT NULL,
    amount_cents INTEGER NOT NULL,
    mint_cents INTEGER NOT NULL,
    ledger_ts TEXT NOT NULL,
    status TEXT NOT NULL,
    detail TEXT DEFAULT '',
    evm_tx TEXT DEFAULT '',
    updated_at TEXT NOT NULL,
    attested_until INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS releases (
    nonce INTEGER PRIMARY KEY,
    evm_tx TEXT NOT NULL,
    block INTEGER NOT NULL,
    evm_from TEXT NOT NULL,
    ledger_wallet TEXT NOT NULL,
    amount_cents INTEGER NOT NULL,
    status TEXT NOT NULL,
    detail TEXT DEFAULT '',
    ledger_tx_id TEXT DEFAULT '',
    approved INTEGER DEFAULT 0,
    updated_at TEXT NOT NULL,
    intent TEXT DEFAULT '',
    ledger_tx_hash TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS gas_spent (
    day TEXT PRIMARY KEY,
    gas INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""

# Deposit statuses
SEEN, MINTED, WAITING, HELD, REFUND, REFUNDED = "seen", "minted", "waiting", "held", "refund", "refunded"
SUBMITTED = "submitted"  # mint sent; minted once it's in a finalized block

# Columns added after the first version: (table, column, definition)
MIGRATIONS = (
    ("deposits", "attested_until", "INTEGER DEFAULT 0"),
    ("releases", "intent", "TEXT DEFAULT ''"),
    ("releases", "ledger_tx_hash", "TEXT DEFAULT ''"),
    ("releases", "block_hash", "TEXT DEFAULT ''"),
    ("releases", "log_index", "INTEGER DEFAULT -1"),
    ("releases", "verified_at", "TEXT DEFAULT ''"),
)
# Release statuses (also SEEN, WAITING, HELD)
PAID = "paid"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Store:
    def __init__(self, path: str):
        self.path = path
        conn = self._conn()
        conn.executescript(SCHEMA)
        for table, column, definition in MIGRATIONS:
            if column not in {r["name"] for r in conn.execute(f"PRAGMA table_info({table})")}:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
        conn.execute("INSERT OR IGNORE INTO meta (key, value) VALUES ('created_at', ?)", (_now(),))
        conn.commit()
        conn.close()

    def pin_bridge(self, bridge_address: str):
        """
        Tie this state file to one bridge contract. A replacement contract restarts its
        nonces, so another bridge's state would mark its releases paid or its deposits done.
        """
        pinned = self.get_meta("bridge_address")
        if not pinned:
            self.set_meta("bridge_address", bridge_address.lower())
        elif pinned != bridge_address.lower():
            raise ValueError(f"this bridge state belongs to {pinned}, not {bridge_address}: "
                             "use a new GFC_BRIDGE_STATE_DB for a new bridge")

    def created_at(self) -> str:
        return self.get_meta("created_at")

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        return conn

    # ----------------------------------------------------------------- meta

    def get_meta(self, key: str, default: str = "") -> str:
        conn = self._conn()
        row = conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        conn.close()
        return row["value"] if row else default

    def set_meta(self, key: str, value: str):
        conn = self._conn()
        conn.execute("INSERT INTO meta (key, value) VALUES (?, ?) "
                     "ON CONFLICT(key) DO UPDATE SET value = excluded.value", (key, value))
        conn.commit()
        conn.close()

    def meta_like(self, prefix: str) -> dict:
        conn = self._conn()
        rows = conn.execute("SELECT key, value FROM meta WHERE substr(key, 1, ?) = ?", (len(prefix), prefix)).fetchall()
        conn.close()
        return {r["key"][len(prefix):]: r["value"] for r in rows}

    def delete_meta(self, key: str) -> bool:
        conn = self._conn()
        cur = conn.execute("DELETE FROM meta WHERE key = ?", (key,))
        conn.commit()
        conn.close()
        return cur.rowcount > 0

    # ----------------------------------------------------------------- deposits

    def add_deposit(self, d: dict, status: str = SEEN, detail: str = "") -> bool:
        """Record a deposit the first time it is seen. Returns True if it was new."""
        conn = self._conn()
        cur = conn.execute(
            "INSERT OR IGNORE INTO deposits (tx_hash, ledger_tx_id, sender, evm_to, amount_cents, mint_cents, "
            "ledger_ts, status, detail, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (d["tx_hash"], d["id"], d["sender"], d["evm_to"], d["amount_cents"], d["mint_cents"],
             d["timestamp"], status, detail, _now()))
        conn.commit()
        conn.close()
        return cur.rowcount > 0

    def set_deposit(self, tx_hash: str, status: str, detail: str = "", evm_tx: str = ""):
        conn = self._conn()
        conn.execute("UPDATE deposits SET status = ?, detail = ?, evm_tx = COALESCE(NULLIF(?, ''), evm_tx), "
                     "updated_at = ? WHERE tx_hash = ?", (status, detail, evm_tx, _now(), tx_hash))
        conn.commit()
        conn.close()

    def deposits(self, *statuses: str) -> List[sqlite3.Row]:
        conn = self._conn()
        q = "SELECT * FROM deposits"
        if statuses:
            q += f" WHERE status IN ({','.join('?' * len(statuses))})"
        rows = conn.execute(q + " ORDER BY ledger_ts", statuses).fetchall()
        conn.close()
        return rows

    def deposit(self, tx_hash: str) -> Optional[sqlite3.Row]:
        conn = self._conn()
        row = conn.execute("SELECT * FROM deposits WHERE tx_hash = ?", (tx_hash,)).fetchone()
        conn.close()
        return row

    def mints_by_sender_since(self, sender: str, since_iso: str) -> int:
        conn = self._conn()
        n = conn.execute("SELECT COUNT(*) FROM deposits WHERE sender = ? AND status IN (?, ?) AND updated_at >= ?",
                         (sender, MINTED, SUBMITTED, since_iso)).fetchone()[0]
        conn.close()
        return n

    def note_attested(self, tx_hash: str, deadline: int):
        """Remember the latest deadline of an attestation issued for this deposit."""
        conn = self._conn()
        conn.execute("UPDATE deposits SET attested_until = MAX(attested_until, ?) WHERE tx_hash = ?",
                     (deadline, tx_hash))
        conn.commit()
        conn.close()

    # ----------------------------------------------------------------- gas budget

    def gas_today(self) -> int:
        conn = self._conn()
        row = conn.execute("SELECT gas FROM gas_spent WHERE day = ?", (_now()[:10],)).fetchone()
        conn.close()
        return row["gas"] if row else 0

    def add_gas(self, gas: int):
        conn = self._conn()
        conn.execute("INSERT INTO gas_spent (day, gas) VALUES (?, ?) "
                     "ON CONFLICT(day) DO UPDATE SET gas = gas + excluded.gas", (_now()[:10], gas))
        conn.commit()
        conn.close()

    # ----------------------------------------------------------------- releases

    def add_release(self, ev: dict) -> bool:
        conn = self._conn()
        cur = conn.execute(
            "INSERT OR IGNORE INTO releases (nonce, evm_tx, block, evm_from, ledger_wallet, amount_cents, "
            "status, updated_at, block_hash, log_index) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (ev["nonce"], ev["evm_tx"], ev["block"], ev["from"], ev["ledger_wallet"], ev["amount_cents"],
             SEEN, _now(), ev.get("block_hash", ""), ev.get("log_index", -1)))
        conn.commit()
        conn.close()
        return cur.rowcount > 0

    def release(self, nonce: int) -> Optional[sqlite3.Row]:
        conn = self._conn()
        row = conn.execute("SELECT * FROM releases WHERE nonce = ?", (nonce,)).fetchone()
        conn.close()
        return row

    def mark_release_verified(self, nonce: int):
        conn = self._conn()
        conn.execute("UPDATE releases SET verified_at = ? WHERE nonce = ?", (_now(), nonce))
        conn.commit()
        conn.close()

    def set_release(self, nonce: int, status: str, detail: str = "", ledger_tx_id: str = "",
                    ledger_tx_hash: str = ""):
        conn = self._conn()
        conn.execute("UPDATE releases SET status = ?, detail = ?, "
                     "ledger_tx_id = COALESCE(NULLIF(?, ''), ledger_tx_id), "
                     "ledger_tx_hash = COALESCE(NULLIF(?, ''), ledger_tx_hash), updated_at = ? WHERE nonce = ?",
                     (status, detail, ledger_tx_id, ledger_tx_hash, _now(), nonce))
        conn.commit()
        conn.close()

    def save_release_intent(self, nonce: int, intent: dict) -> dict:
        """
        Save the signed payout before it's submitted, and return the one saved: an earlier
        saved payout is never replaced, so every retry resends the same signed bytes.
        """
        conn = self._conn()
        conn.execute("UPDATE releases SET intent = ? WHERE nonce = ? AND intent = ''", (json.dumps(intent), nonce))
        conn.commit()
        saved = conn.execute("SELECT intent FROM releases WHERE nonce = ?", (nonce,)).fetchone()["intent"]
        conn.close()
        return json.loads(saved)

    def approve_release(self, nonce: int) -> bool:
        conn = self._conn()
        cur = conn.execute("UPDATE releases SET approved = 1, status = ?, updated_at = ? "
                           "WHERE nonce = ? AND status = ?", (SEEN, _now(), nonce, HELD))
        conn.commit()
        conn.close()
        return cur.rowcount > 0

    def releases(self, *statuses: str) -> List[sqlite3.Row]:
        conn = self._conn()
        q = "SELECT * FROM releases"
        if statuses:
            q += f" WHERE status IN ({','.join('?' * len(statuses))})"
        rows = conn.execute(q + " ORDER BY nonce", statuses).fetchall()
        conn.close()
        return rows

    def released_cents_since(self, since_iso: str) -> int:
        conn = self._conn()
        n = conn.execute("SELECT COALESCE(SUM(amount_cents), 0) FROM releases WHERE status = ? AND updated_at >= ?",
                         (PAID, since_iso)).fetchone()[0]
        conn.close()
        return n

    def unpaid_release_cents(self) -> int:
        conn = self._conn()
        n = conn.execute("SELECT COALESCE(SUM(amount_cents), 0) FROM releases WHERE status != ?",
                         (PAID,)).fetchone()[0]
        conn.close()
        return n
