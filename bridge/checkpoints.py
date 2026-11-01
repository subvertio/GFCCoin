"""
An attester's copy of the canonical node's checkpoint log (ledger_checkpoints.py; audit F08).

The canonical node signs a checkpoint every few minutes: how many accepted transactions
its log holds and a running hash over them. Each attester keeps its own copy of that log,
built only from checkpoints signed by a pinned key, and checks each new checkpoint
*extends* the copy it already has: the same rows, in the same order, plus new ones.

- A deposit is signed only once it's in the log and a checkpoint at least
  `finality_seconds` old covers it. So every attester judges deposits against the same
  history, and a row that only exists in one node's database (written straight into
  SQLite, say) never counts.
- A checkpoint that doesn't extend the copy (fewer rows, a different running hash, a time
  going backwards) means the canonical history changed: a ledger restored from an older
  backup, or a rewrite. The mirror **halts**: no deposit is signed until a person checks
  and runs `python -m bridge reset-checkpoints`.

The canonical node's checkpoint key is trusted to sign only what it accepted; a halt is how
a rollback becomes an alarm instead of a silent loss.
"""

import json
import logging
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from typing import Callable, Iterable, Optional, Tuple

import blockchain
import ledger_checkpoints

logger = logging.getLogger("gfc.bridge.checkpoints")

SCHEMA = """
CREATE TABLE IF NOT EXISTS mirror_log (position INTEGER PRIMARY KEY, tx_hash TEXT NOT NULL, acc TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_mirror_log_hash ON mirror_log (tx_hash);
CREATE TABLE IF NOT EXISTS mirror_checkpoints (
    id INTEGER PRIMARY KEY AUTOINCREMENT, count INTEGER NOT NULL, acc TEXT NOT NULL, time TEXT NOT NULL,
    body TEXT NOT NULL, signature TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS mirror_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
"""

PAGE = 2000
SYNC_EVERY_SECONDS = 30
MAX_CLOCK_SKEW = timedelta(minutes=5)


class CheckpointError(Exception):
    pass


def http_fetcher(base_url: str, timeout: float = 20.0) -> Callable[[str], dict]:
    import httpx
    client = httpx.Client(timeout=timeout)

    def fetch(path: str) -> dict:
        try:
            resp = client.get(base_url.rstrip("/") + path)
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPStatusError as e:  # httpx's own message holds the URL
            raise CheckpointError(f"checkpoint node: HTTP {e.response.status_code}") from None
        except (httpx.HTTPError, ValueError) as e:
            raise CheckpointError(f"checkpoint node unreachable: {type(e).__name__}") from None
    return fetch


class CheckpointMirror:
    def __init__(self, path: str, fetch: Callable[[str], dict], pubkeys: Iterable[str], network: str):
        self.path, self.fetch, self.pubkeys, self.network = path, fetch, frozenset(pubkeys), network
        self._last_sync = 0.0
        conn = self._conn()
        conn.executescript(SCHEMA)
        conn.close()

    def _conn(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path, timeout=30)

    # ----------------------------------------------------------------- state

    def halted(self) -> str:
        conn = self._conn()
        try:
            row = conn.execute("SELECT value FROM mirror_meta WHERE key = 'halt'").fetchone()
        finally:
            conn.close()
        return row[0] if row else ""

    def _halt(self, why: str):
        conn = self._conn()
        try:
            conn.execute("INSERT OR IGNORE INTO mirror_meta (key, value) VALUES ('halt', ?)", (why,))
            conn.commit()
        finally:
            conn.close()
        logger.critical(f"Checkpoints halted: {why}. No deposit is signed until a person checks "
                        "(python -m bridge reset-checkpoints)")

    def reset(self):
        """A person has checked: forget the copy and the halt, and rebuild from the node."""
        conn = self._conn()
        try:
            conn.executescript("DELETE FROM mirror_log; DELETE FROM mirror_checkpoints; DELETE FROM mirror_meta;")
        finally:
            conn.close()

    def latest(self) -> Optional[dict]:
        conn = self._conn()
        try:
            row = conn.execute("SELECT body FROM mirror_checkpoints ORDER BY id DESC LIMIT 1").fetchone()
        finally:
            conn.close()
        return json.loads(row[0]) if row else None

    # ----------------------------------------------------------------- sync

    def sync(self, now: Optional[datetime] = None, force: bool = False):
        """Take the node's latest checkpoint if it extends this copy; halt if it doesn't."""
        if self.halted():
            return
        if not force and time.monotonic() - self._last_sync < SYNC_EVERY_SECONDS:
            return
        now = now or datetime.now(timezone.utc)
        cp = self.fetch("/ledger/checkpoint")
        if not ledger_checkpoints.verify(cp, self.pubkeys):
            raise CheckpointError("the node's checkpoint isn't signed by a pinned checkpoint key")
        body = cp["body"]
        if body.get("v") != ledger_checkpoints.VERSION or body.get("network") != self.network:
            raise CheckpointError(f"checkpoint for network {body.get('network')!r}, not {self.network!r}")
        signed_at = blockchain._parse_timestamp(body["time"])
        if signed_at is None or signed_at > now + MAX_CLOCK_SKEW:
            raise CheckpointError("checkpoint time is unreadable or in the future")

        last = self.latest()
        if last:
            if body["count"] < last["count"]:
                return self._halt(f"the node's checkpoint has {body['count']} rows, fewer than the "
                                  f"{last['count']} already checkpointed: its history was rolled back")
            if blockchain._parse_timestamp(last["time"]) > signed_at:
                return self._halt("checkpoint time went backwards")
        conn = self._conn()
        try:
            have, acc = conn.execute("SELECT COUNT(*), (SELECT acc FROM mirror_log ORDER BY position DESC LIMIT 1) "
                                     "FROM mirror_log").fetchone()
            acc = acc or ledger_checkpoints.genesis_acc(self.network)
            if body["count"] < have:
                at = conn.execute("SELECT acc FROM mirror_log WHERE position = ?", (body["count"],)).fetchone()
                expected = at[0] if at else ledger_checkpoints.genesis_acc(self.network)
                if expected != body["acc"]:
                    conn.close()
                    return self._halt("a checkpoint doesn't match the history already copied")
            new = []
            while have + len(new) < body["count"]:
                start = have + len(new) + 1
                page = self.fetch(f"/ledger/checkpoint/log?start={start}&limit={PAGE}")
                rows = page.get("rows") or []
                if not rows:
                    raise CheckpointError("the node's checkpoint log ended early")
                for r in rows:
                    if have + len(new) >= body["count"]:
                        break
                    if r["position"] != have + len(new) + 1:
                        raise CheckpointError("the node's checkpoint log is out of order")
                    acc = ledger_checkpoints.next_acc(acc, r["tx_hash"])
                    new.append((r["position"], r["tx_hash"].lower(), acc))
            if body["count"] >= have and acc != body["acc"]:
                conn.close()
                return self._halt("the node's checkpoint doesn't extend the history already copied: "
                                  "its ledger was rewritten")
            conn.executemany("INSERT INTO mirror_log (position, tx_hash, acc) VALUES (?, ?, ?)", new)
            conn.execute("INSERT INTO mirror_checkpoints (count, acc, time, body, signature) VALUES (?, ?, ?, ?, ?)",
                         (body["count"], body["acc"], body["time"], json.dumps(body), cp["signature"]))
            conn.commit()
        finally:
            conn.close()
        self._last_sync = time.monotonic()

    # ----------------------------------------------------------------- queries

    def covered(self, tx_hash: str, now: datetime, finality_seconds: int) -> Tuple[bool, str, bool]:
        """
        (ok, why not, retry): is this transaction in the canonical log, under a checkpoint
        signed at least finality_seconds ago?
        """
        why = self.halted()
        if why:
            return False, f"checkpoints halted: {why}", False
        try:
            self.sync(now)
        except CheckpointError as e:
            logger.warning(f"Checkpoint sync failed: {e}")  # judge on what's already copied
        conn = self._conn()
        try:
            row = conn.execute("SELECT position FROM mirror_log WHERE tx_hash = ?", (tx_hash.lower(),)).fetchone()
            if row is None:
                return False, "not in a signed checkpoint of the canonical ledger yet", True
            first = conn.execute("SELECT MIN(time) FROM mirror_checkpoints WHERE count >= ?", (row[0],)).fetchone()[0]
        finally:
            conn.close()
        signed_at = blockchain._parse_timestamp(first)
        if signed_at is None or now - signed_at < timedelta(seconds=finality_seconds):
            return False, "checkpointed less than the finality window ago", True
        return True, "", False


def from_config(cfg) -> Optional[CheckpointMirror]:
    """The mirror the bridge config asks for, or None when checkpoints aren't configured."""
    if not cfg.checkpoint_url:
        return None
    return CheckpointMirror(cfg.checkpoint_db, http_fetcher(cfg.checkpoint_url), cfg.checkpoint_pubkeys,
                            cfg.checkpoint_network)
