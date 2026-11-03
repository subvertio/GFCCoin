"""
Tests for deleting posts (seed_deletions.py): the owner deletes, the signed deletion
syncs to peers, files go from disk and the (faked) R2 bucket, and the ledger stays put.

Run from the repository root:
    python -m unittest discover -s tests -v
"""

import datetime
import os
import sqlite3
import sys
import unittest
import uuid
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_signed_ledger  # noqa: F401  (sets up the isolated data dir first)
from test_signed_ledger import new_node
from test_media_store import FakeR2, r2_settings

from fastapi.testclient import TestClient  # noqa: E402

import audio_stream  # noqa: E402
import config  # noqa: E402
import exclusive  # noqa: E402
import main  # noqa: E402
import media_store  # noqa: E402
import seed_deletions  # noqa: E402
import signing  # noqa: E402
import sync_engine  # noqa: E402
from config import SEEDS_ORIG_DIR, SEEDS_THUMB_DIR  # noqa: E402
from sync_ingest import TABLE_COLUMNS, ingest_rows, select_rows_since  # noqa: E402

JPEG = b"\xff\xd8\xff\xe0" + b"\x00" * 64


class SeedDeletionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(main.app)

    def setUp(self):
        self.saved = (config.REQUIRE_PHONE_TO_POST, os.environ.get("GFC_AUDIO_STREAMS"))
        config.REQUIRE_PHONE_TO_POST = False
        os.environ["GFC_AUDIO_STREAMS"] = "0"

    def tearDown(self):
        media_store._queue.join()
        media_store.configure(media_store.LocalStore())
        config.REQUIRE_PHONE_TO_POST, streams = self.saved
        if streams is None:
            os.environ.pop("GFC_AUDIO_STREAMS", None)
        else:
            os.environ["GFC_AUDIO_STREAMS"] = streams

    # --- helpers ---

    def register(self, wallet=True):
        name = "d" + uuid.uuid4().hex[:10]
        r = self.client.post("/auth/register", data={"username": name, "password": "pw-" + name})
        self.assertEqual(r.status_code, 200, r.text)
        token = r.json()["token"]
        if wallet:
            w = self.client.post("/wallets/create", data={"name": "main", "api_token": token})
            self.assertEqual(w.status_code, 200, w.text)
        return name, {"Authorization": f"Bearer {token}"}

    def upload(self, auth, name="piece.bin"):
        files = {"file": (name, os.urandom(4096), "application/octet-stream"),
                 "thumbnail": ("t.jpg", JPEG, "image/jpeg")}
        r = self.client.post("/seeds/upload", headers=auth, data={"title": "Mine"}, files=files)
        self.assertEqual(r.status_code, 200, r.text)
        return r.json()

    def delete(self, auth, sid):
        return self.client.delete(f"/seeds/{sid}", headers=auth)

    def rows(self, table, where_seed, db=None):
        conn = sqlite3.connect(db or main.DB_PATH)
        try:
            rows = select_rows_since(conn, table, "", 10_000)
        finally:
            conn.close()
        cols = [c.strip() for c in TABLE_COLUMNS[table].split(",")]
        key = "id" if table == "seeds" else "seed_id"
        return cols, [list(r) for r in rows if r[cols.index(key)] == where_seed]

    def seed_exists(self, sid, db=None):
        conn = sqlite3.connect(db or main.DB_PATH)
        try:
            return conn.execute("SELECT 1 FROM seeds WHERE id = ?", (sid,)).fetchone() is not None
        finally:
            conn.close()

    def ledger(self, db=None):
        conn = sqlite3.connect(db or main.DB_PATH)
        try:
            return (conn.execute("SELECT * FROM transactions ORDER BY id").fetchall(),
                    conn.execute("SELECT COUNT(*) FROM blocks").fetchone()[0])
        finally:
            conn.close()

    def files_of(self, seed):
        return SEEDS_ORIG_DIR / seed["full"].rsplit("/", 1)[1], SEEDS_THUMB_DIR / seed["thumb"].rsplit("/", 1)[1]

    # --- the owner deletes ---

    def test_owner_deletes_and_everything_goes(self):
        _, auth = self.register()
        _, fan = self.register()
        seed = self.upload(auth)
        sid = seed["id"]
        original, thumb = self.files_of(seed)
        self.assertTrue(original.is_file() and thumb.is_file())
        self.assertEqual(self.client.post(f"/seeds/{sid}/like", headers=fan).status_code, 200)
        self.assertEqual(self.client.post(f"/seeds/{sid}/comments", headers=fan, data={"text": "nice"}).status_code, 200)
        self.assertEqual(self.client.post(f"/seeds/{sid}/bookmark", headers=fan).status_code, 200)
        ledger_before = self.ledger()

        r = self.delete(auth, sid)
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        self.assertTrue(body["deleted"] and body["synced"] and body["files_removed"] and body["ledger_unchanged"])
        self.assertFalse(body["already_deleted"])
        self.assertIn("never removed or reversed", body["note"])

        self.assertFalse(self.seed_exists(sid))
        self.assertFalse(original.exists() or thumb.exists())
        self.assertNotIn(sid, [s["id"] for s in self.client.get("/feed").json()["items"]])
        self.assertNotIn(sid, [s["id"] for s in self.client.get("/seeds").json()["items"]])
        self.assertNotIn(sid, [s["id"] for s in self.client.get("/bookmarks", headers=fan).json().get("items", [])])
        self.assertEqual(self.client.get(f"/seeds/{sid}").status_code, 410)
        self.assertEqual(self.client.get(f"/seeds/{sid}/comments").json().get("comments", []), [])
        for table in ("likes", "comments", "bookmarks"):
            self.assertEqual(self.rows(table, sid)[1], [], table)
        # Nothing new can land on it
        self.assertEqual(self.client.post(f"/seeds/{sid}/like", headers=fan).status_code, 410)
        self.assertEqual(self.client.post(f"/seeds/{sid}/comments", headers=fan, data={"text": "?"}).status_code, 410)
        # Its media URLs are gone, not 404-then-redirect
        self.assertEqual(self.client.get(seed["full"]).status_code, 410)
        self.assertEqual(self.client.get(seed["thumb"]).status_code, 410)
        # The ledger is untouched
        self.assertEqual(self.ledger(), ledger_before)

    def test_deleting_again_is_the_same_answer(self):
        _, auth = self.register()
        sid = self.upload(auth)["id"]
        first = self.delete(auth, sid).json()
        again = self.delete(auth, sid)
        self.assertEqual(again.status_code, 200, again.text)
        self.assertTrue(again.json()["already_deleted"])
        self.assertEqual(again.json()["deleted_at"], first["deleted_at"])
        conn = sqlite3.connect(main.DB_PATH)
        try:
            n = conn.execute("SELECT COUNT(*) FROM seed_deletions WHERE seed_id = ?", (sid,)).fetchone()[0]
        finally:
            conn.close()
        self.assertEqual(n, 1)

    def test_only_the_owner_can_delete(self):
        _, auth = self.register()
        _, other = self.register()
        seed = self.upload(auth)
        self.assertEqual(self.delete(other, seed["id"]).status_code, 403)
        self.assertEqual(self.client.delete(f"/seeds/{seed['id']}").status_code, 401)
        self.assertEqual(self.delete(auth, "no-such-seed").status_code, 404)
        self.assertTrue(self.seed_exists(seed["id"]))
        self.assertTrue(self.files_of(seed)[0].is_file())
        # After the owner deletes, others still learn nothing about it
        self.delete(auth, seed["id"])
        self.assertEqual(self.delete(other, seed["id"]).status_code, 404)

    def test_needs_the_unlocked_wallet_key(self):
        _, auth = self.register()
        seed = self.upload(auth)
        # The key is locked (e.g. a password reset without the recovery code)
        real = signing.get_wallet_private_key
        signing.get_wallet_private_key = lambda *a, **k: None
        try:
            r = self.delete(auth, seed["id"])
        finally:
            signing.get_wallet_private_key = real
        self.assertEqual(r.status_code, 409, r.text)
        self.assertTrue(self.seed_exists(seed["id"]))

    def test_unsigned_post_is_deleted_here_only(self):
        _, auth = self.register(wallet=False)
        seed = self.upload(auth)
        self.assertFalse(seed["rewards_enabled"])
        r = self.delete(auth, seed["id"])
        self.assertEqual(r.status_code, 200, r.text)
        self.assertFalse(r.json()["synced"])
        self.assertFalse(self.seed_exists(seed["id"]))
        self.assertEqual(self.rows("seed_deletions", seed["id"])[1], [])  # never sent to peers

    # --- sync ---

    def test_deletion_reaches_a_peer(self):
        _, auth = self.register()
        seed = self.upload(auth)
        sid = seed["id"]
        peer = new_node("del_peer_" + uuid.uuid4().hex[:6])
        cols, rows = self.rows("seeds", sid)
        ingest_rows("seeds", cols, rows, db_path=peer)
        _, fan = self.register()
        self.client.post(f"/seeds/{sid}/like", headers=fan)
        lcols, likes = self.rows("likes", sid)
        ingest_rows("likes", lcols, likes, db_path=peer)
        ledger_before = self.ledger(peer)

        self.assertEqual(self.delete(auth, sid).status_code, 200)
        # The peer's synced copies of the files (same data dir in tests: put them back)
        original, thumb = self.files_of(seed)
        original.write_bytes(b"synced copy")
        thumb.write_bytes(JPEG)

        dcols, deletions = self.rows("seed_deletions", sid)
        self.assertEqual(len(deletions), 1)
        result = ingest_rows("seed_deletions", dcols, deletions, db_path=peer)
        self.assertEqual((result["inserted"], result["rejected"]), (1, 0))
        self.assertFalse(self.seed_exists(sid, peer))
        self.assertEqual(self.rows("likes", sid, peer)[1], [])
        self.assertFalse(original.exists() or thumb.exists())
        self.assertEqual(self.ledger(peer), ledger_before)

        # A peer that hasn't heard sends the seed (and a like) again: neither comes back
        self.assertEqual(ingest_rows("seeds", cols, rows, db_path=peer)["inserted"], 0)
        self.assertEqual(ingest_rows("likes", lcols, likes, db_path=peer)["inserted"], 0)
        self.assertFalse(self.seed_exists(sid, peer))
        # ...and the peer passes the deletion on
        self.assertEqual(len(self.rows("seed_deletions", sid, peer)[1]), 1)
        # Same deletion again: a duplicate, nothing changes
        self.assertEqual(ingest_rows("seed_deletions", dcols, deletions, db_path=peer)["duplicates"], 1)

    def test_deletion_before_the_seed(self):
        _, auth = self.register()
        sid = self.upload(auth)["id"]
        cols, rows = self.rows("seeds", sid)
        self.delete(auth, sid)
        peer = new_node("del_early_" + uuid.uuid4().hex[:6])
        dcols, deletions = self.rows("seed_deletions", sid)
        ingest_rows("seed_deletions", dcols, deletions, db_path=peer)
        self.assertEqual(ingest_rows("seeds", cols, rows, db_path=peer)["inserted"], 0)
        self.assertFalse(self.seed_exists(sid, peer))

    def test_forged_deletions_are_rejected(self):
        _, auth = self.register()
        seed = self.upload(auth)
        sid = seed["id"]
        peer = new_node("del_forge_" + uuid.uuid4().hex[:6])
        cols, rows = self.rows("seeds", sid)
        ingest_rows("seeds", cols, rows, db_path=peer)
        dcols = [c.strip() for c in TABLE_COLUMNS["seed_deletions"].split(",")]

        # Signed by someone else's key: valid on its own, but not the post's wallet
        conn = sqlite3.connect(peer)
        attacker = signing.create_wallet_key(conn)
        conn.commit()
        conn.close()
        attacker_key = signing.get_wallet_private_key(peer, attacker)
        record = {"seed_id": sid, "signer": attacker, "deleted_at": datetime.datetime.utcnow().isoformat()}
        record["signature"] = seed_deletions.sign_deletion(attacker_key, record)
        record["id"] = seed_deletions.deletion_id_for(record)
        ingest_rows("seed_deletions", dcols, [[record[c] for c in dcols]], db_path=peer)
        self.assertTrue(self.seed_exists(sid, peer))

        # Claims to be the post's wallet, but isn't signed by it
        record = {"seed_id": sid, "signer": seed["reward_wallet"], "deleted_at": datetime.datetime.utcnow().isoformat()}
        record["signature"] = seed_deletions.sign_deletion(attacker_key, record)
        record["id"] = seed_deletions.deletion_id_for(record)
        result = ingest_rows("seed_deletions", dcols, [[record[c] for c in dcols]], db_path=peer)
        self.assertEqual(result["rejected"], 1)
        # Unsigned, and dated far ahead
        unsigned = {**record, "signature": ""}
        self.assertEqual(ingest_rows("seed_deletions", dcols, [[unsigned[c] for c in dcols]],
                                     db_path=peer)["rejected"], 1)
        self.assertTrue(self.seed_exists(sid, peer))
        self.assertTrue(self.files_of(seed)[0].is_file())

    # --- R2 and work in flight ---

    def test_files_leave_the_bucket(self):
        fake = FakeR2()
        media_store.configure(media_store.R2Store(r2_settings(), client=fake.client()))
        _, auth = self.register()
        seed = self.upload(auth)
        media_store._queue.join()
        sid = seed["id"]
        mine = {k for k in fake.objects if sid in k or seed["full"].rsplit("/", 1)[1] in k}
        self.assertEqual(len(mine), 2, fake.objects.keys())  # original and thumb
        # A teaser in the bucket too (as an exclusive's would be)
        teaser = exclusive.teaser_path(sid)
        teaser.write_bytes(b"TEASER")
        self.assertEqual(media_store.offload("teasers", teaser.name), media_store.STORED)

        r = self.delete(auth, sid)
        self.assertEqual(r.status_code, 200, r.text)
        self.assertTrue(r.json()["files_removed"])
        self.assertFalse([k for k in fake.objects if k in mine or k == f"teasers/{teaser.name}"])
        conn = sqlite3.connect(main.DB_PATH)
        try:
            left = conn.execute("SELECT COUNT(*) FROM media_objects WHERE key LIKE ?", (f"%{sid}%",)).fetchone()[0]
        finally:
            conn.close()
        self.assertEqual(left, 0)

    def test_bucket_down_is_retried(self):
        fake = FakeR2()
        media_store.configure(media_store.R2Store(r2_settings(), client=fake.client()))
        _, auth = self.register()
        seed = self.upload(auth)
        media_store._queue.join()
        handle = fake.handle
        fake.handle = lambda req: httpx.Response(503) if req.method == "DELETE" else handle(req)
        media_store.configure(media_store.R2Store(r2_settings(), client=httpx.Client(
            transport=httpx.MockTransport(lambda req: fake.handle(req)))))
        r = self.delete(auth, seed["id"])
        self.assertEqual(r.status_code, 200, r.text)
        self.assertFalse(r.json()["files_removed"])
        self.assertFalse(self.seed_exists(seed["id"]))  # gone from feeds anyway
        self.assertTrue(any(seed["id"] in k for k in fake.objects))

        fake.handle = handle
        self.assertGreaterEqual(seed_deletions.retry_purges(), 1)
        self.assertFalse(any(seed["id"] in k for k in fake.objects))
        again = self.delete(auth, seed["id"]).json()
        self.assertTrue(again["already_deleted"] and again["files_removed"])

    def test_files_made_after_the_delete_are_dropped(self):
        fake = FakeR2()
        media_store.configure(media_store.R2Store(r2_settings(), client=fake.client()))
        _, auth = self.register()
        seed = self.upload(auth)
        media_store._queue.join()
        sid = seed["id"]
        self.delete(auth, sid)

        # A transcode that was still running finishes now
        stream = audio_stream.stream_path(sid, "video")
        stream.write_bytes(b"late stream")
        self.assertEqual(self.client.get(f"/streams/{stream.name}").status_code, 410)
        self.assertEqual(media_store.offload("streams", stream.name), media_store.MISSING)  # the sweep's view
        self.assertFalse(stream.exists())
        self.assertFalse(any(stream.name in k for k in fake.objects))
        stream.write_bytes(b"late stream")
        self.assertTrue(seed_deletions.purge_if_deleted(sid))  # the worker's own check
        self.assertFalse(stream.exists())

        # A synced copy of the original that was still on its way
        part = SEEDS_ORIG_DIR / f".{uuid.uuid4().hex}.part"
        part.write_bytes(b"x" * 2048)
        pending = {"filename": seed["full"].rsplit("/", 1)[1], "file_type": "original", "expected_size": 2048,
                   "part": part, "handle": open(part, "ab"), "received": 2048}
        sync_engine.SyncEngine._assemble_seed_file(None, sid, "original", pending)
        self.assertFalse(part.exists())
        self.assertFalse((SEEDS_ORIG_DIR / pending["filename"]).exists())


if __name__ == "__main__":
    unittest.main()
