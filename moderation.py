"""
GFC Moderation - reports, blocks, and hiding posts.

- Anyone logged in can report a post (once per post) or block an account.
- A blocked account's posts disappear from the blocker's feed, search and seed list.
- A post reported by GFC_REPORT_HIDE_THRESHOLD different accounts (default 3) is hidden
  everywhere on this node, pending review. Its creator still sees it, marked as hidden.
- The node operator reviews with `gfc reports` and `gfc moderate <seed> remove|restore`
  (python moderation.py ...). Remove keeps the post hidden for good; restore clears its
  reports and shows it again.

Moderation is local to this node: peers make their own decisions, and a hidden post is
still synced (its file is untouched) so an operator can review it.
"""
import datetime
import os
import sqlite3
import sys
from typing import Iterable, List, Optional, Set

REASONS = ("spam", "nudity", "violence", "harassment", "hate", "scam", "copyright", "other")
DETAIL_LIMIT = 500
DEFAULT_HIDE_THRESHOLD = 3

STATUS_HIDDEN = "hidden"    # auto-hidden by reports, waiting for review
STATUS_REMOVED = "removed"  # the operator confirmed it
STATUS_CLEARED = "cleared"  # the operator restored it; older reports no longer count


def hide_threshold() -> int:
    try:
        return max(1, int(os.environ.get("GFC_REPORT_HIDE_THRESHOLD", DEFAULT_HIDE_THRESHOLD)))
    except ValueError:
        return DEFAULT_HIDE_THRESHOLD


def _now() -> str:
    return datetime.datetime.utcnow().isoformat()


def init_tables(conn: sqlite3.Connection):
    conn.execute('''CREATE TABLE IF NOT EXISTS seed_reports (
        seed_id TEXT NOT NULL,
        reporter TEXT NOT NULL,
        reason TEXT NOT NULL,
        detail TEXT DEFAULT '',
        created_at TEXT NOT NULL,
        PRIMARY KEY (seed_id, reporter)
    )''')
    conn.execute('''CREATE TABLE IF NOT EXISTS seed_moderation (
        seed_id TEXT PRIMARY KEY,
        status TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        note TEXT DEFAULT ''
    )''')
    conn.execute('''CREATE TABLE IF NOT EXISTS user_blocks (
        blocker TEXT NOT NULL,
        blocked TEXT NOT NULL,
        created_at TEXT NOT NULL,
        PRIMARY KEY (blocker, blocked)
    )''')


class ModerationError(Exception):
    def __init__(self, status: int, detail: str):
        super().__init__(detail)
        self.status = status
        self.detail = detail


# ---------- reports ----------

def report_seed(conn: sqlite3.Connection, seed_id: str, reporter: str, reason: str, detail: str = "") -> dict:
    """Record (or update) the reporter's report; hides the post once enough accounts have reported it."""
    init_tables(conn)
    reason = (reason or "").strip().lower()
    if reason not in REASONS:
        raise ModerationError(400, f"reason must be one of: {', '.join(REASONS)}")
    row = conn.execute("SELECT owner FROM seeds WHERE id = ?", (seed_id,)).fetchone()
    if not row:
        raise ModerationError(404, "seed not found")
    if (row[0] or "").lower() == reporter.lower():
        raise ModerationError(400, "you can't report your own post")
    conn.execute("INSERT INTO seed_reports (seed_id, reporter, reason, detail, created_at) VALUES (?, ?, ?, ?, ?) "
                 "ON CONFLICT(seed_id, reporter) DO UPDATE SET reason = excluded.reason, detail = excluded.detail, "
                 "created_at = excluded.created_at",
                 (seed_id, reporter, reason, (detail or "").strip()[:DETAIL_LIMIT], _now()))
    status = seed_status(conn, seed_id)
    since = _cleared_at(conn, seed_id) or ""
    reporters = conn.execute("SELECT COUNT(*) FROM seed_reports WHERE seed_id = ? AND created_at > ?",
                             (seed_id, since)).fetchone()[0]
    hidden = status in (STATUS_HIDDEN, STATUS_REMOVED)
    if not hidden and reporters >= hide_threshold():
        _set_status(conn, seed_id, STATUS_HIDDEN, f"{reporters} reports")
        hidden = True
    conn.commit()
    return {"reported": True, "hidden": hidden}


def _cleared_at(conn, seed_id) -> Optional[str]:
    row = conn.execute("SELECT updated_at FROM seed_moderation WHERE seed_id = ? AND status = ?",
                       (seed_id, STATUS_CLEARED)).fetchone()
    return row[0] if row else None


def _set_status(conn, seed_id: str, status: str, note: str = ""):
    conn.execute("INSERT INTO seed_moderation (seed_id, status, updated_at, note) VALUES (?, ?, ?, ?) "
                 "ON CONFLICT(seed_id) DO UPDATE SET status = excluded.status, updated_at = excluded.updated_at, "
                 "note = excluded.note", (seed_id, status, _now(), note))


def seed_status(conn: sqlite3.Connection, seed_id: str) -> str:
    init_tables(conn)
    row = conn.execute("SELECT status FROM seed_moderation WHERE seed_id = ?", (seed_id,)).fetchone()
    return row[0] if row else ""


def hidden_seed_ids(conn: sqlite3.Connection) -> Set[str]:
    init_tables(conn)
    return {r[0] for r in conn.execute("SELECT seed_id FROM seed_moderation WHERE status IN (?, ?)",
                                       (STATUS_HIDDEN, STATUS_REMOVED))}


def is_hidden(conn: sqlite3.Connection, seed_id: str) -> bool:
    return seed_status(conn, seed_id) in (STATUS_HIDDEN, STATUS_REMOVED)


# ---------- blocks ----------

def block(conn: sqlite3.Connection, blocker: str, blocked: str) -> dict:
    init_tables(conn)
    if blocker.lower() == (blocked or "").lower():
        raise ModerationError(400, "you can't block yourself")
    row = conn.execute("SELECT username FROM users WHERE LOWER(username) = LOWER(?)", (blocked,)).fetchone()
    if not row:
        raise ModerationError(404, "user not found")
    conn.execute("INSERT OR IGNORE INTO user_blocks (blocker, blocked, created_at) VALUES (?, ?, ?)",
                 (blocker, row[0], _now()))
    conn.commit()
    return {"blocked": row[0]}


def unblock(conn: sqlite3.Connection, blocker: str, blocked: str) -> dict:
    init_tables(conn)
    conn.execute("DELETE FROM user_blocks WHERE blocker = ? AND LOWER(blocked) = LOWER(?)", (blocker, blocked))
    conn.commit()
    return {"unblocked": blocked}


def blocked_by(conn: sqlite3.Connection, blocker: str) -> List[str]:
    init_tables(conn)
    return [r[0] for r in conn.execute("SELECT blocked FROM user_blocks WHERE blocker = ? ORDER BY created_at",
                                       (blocker,))]


# ---------- filtering ----------

def visible_items(conn: sqlite3.Connection, items: Iterable[dict], viewer: str = "anonymous") -> List[dict]:
    """Drops hidden posts (except the viewer's own) and posts by accounts the viewer blocked."""
    hidden = hidden_seed_ids(conn)
    me = (viewer or "").lower() if viewer and viewer != "anonymous" else ""
    blocked = {b.lower() for b in blocked_by(conn, viewer)} if me else set()
    out = []
    for item in items:
        owner = (item.get("owner") or "").lower()
        if owner in blocked:
            continue
        if item.get("id") in hidden and owner != me:
            continue
        out.append(item)
    return out


# ---------- operator review (CLI) ----------

def open_reports(conn: sqlite3.Connection) -> List[dict]:
    """Posts with reports since they were last restored, most reported first."""
    init_tables(conn)
    rows = conn.execute(
        "SELECT r.seed_id, COUNT(*), GROUP_CONCAT(r.reason), MAX(r.created_at), "
        "COALESCE(m.status, ''), s.owner, s.title "
        "FROM seed_reports r LEFT JOIN seed_moderation m ON m.seed_id = r.seed_id "
        "LEFT JOIN seeds s ON s.id = r.seed_id "
        "WHERE m.status IS NULL OR m.status = ? OR (m.status = ? AND r.created_at > m.updated_at) "
        "GROUP BY r.seed_id ORDER BY COUNT(*) DESC, MAX(r.created_at) DESC",
        (STATUS_HIDDEN, STATUS_CLEARED)).fetchall()
    out = []
    for seed_id, count, reasons, last, status, owner, title in rows:
        tally = {}
        for reason in (reasons or "").split(","):
            tally[reason] = tally.get(reason, 0) + 1
        out.append({"seed_id": seed_id, "reports": count, "reasons": tally, "last": last,
                    "status": status if status != STATUS_CLEARED else "", "owner": owner or "?",
                    "title": title or ""})
    return out


def set_decision(conn: sqlite3.Connection, seed_id: str, decision: str) -> str:
    init_tables(conn)
    status = {"remove": STATUS_REMOVED, "hide": STATUS_HIDDEN, "restore": STATUS_CLEARED}.get(decision)
    if not status:
        raise ModerationError(400, "decision must be remove, hide or restore")
    if not conn.execute("SELECT 1 FROM seeds WHERE id = ?", (seed_id,)).fetchone():
        raise ModerationError(404, "seed not found")
    _set_status(conn, seed_id, status, "operator")
    conn.commit()
    return status


def main(argv: List[str]) -> int:
    from config import DB_PATH
    conn = sqlite3.connect(DB_PATH)
    try:
        if argv == ["list"]:
            reports = open_reports(conn)
            if not reports:
                print("No open reports.")
            for r in reports:
                reasons = ", ".join(f"{k} x{v}" for k, v in sorted(r["reasons"].items(), key=lambda kv: -kv[1]))
                state = f" [{r['status']}]" if r["status"] else ""
                print(f"{r['seed_id']}  {r['reports']} report(s){state}  @{r['owner']}  "
                      f"\"{r['title'][:50]}\"  ({reasons})")
            return 0
        if len(argv) == 2 and argv[1] in ("remove", "hide", "restore"):
            print(f"{argv[0]}: {set_decision(conn, argv[0], argv[1])}")
            return 0
        print("usage: moderation.py list | <seed_id> remove|hide|restore", file=sys.stderr)
        return 2
    except ModerationError as ex:
        print(ex.detail, file=sys.stderr)
        return 1
    finally:
        conn.close()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
