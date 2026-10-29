"""
Tests for post editing (seed_edits.py) and account names on top earners.

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

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_signed_ledger  # noqa: F401  (sets up the isolated data dir first)
from test_signed_ledger import mark_verified, new_node

from fastapi.testclient import TestClient  # noqa: E402

import config  # noqa: E402
import keystore  # noqa: E402
import main  # noqa: E402
import seed_edits  # noqa: E402
import signing  # noqa: E402
from sync_ingest import TABLE_COLUMNS, ingest_rows, select_rows_since  # noqa: E402

EDIT_COLUMNS = [c.strip() for c in TABLE_COLUMNS["seed_edits"].split(",")]
SEED_COLUMNS = [c.strip() for c in TABLE_COLUMNS["seeds"].split(",")]


class SeedEditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(main.app)

    def register(self, wallet=True):
        name = "u" + uuid.uuid4().hex[:10]
        r = self.client.post("/auth/register", data={"username": name, "password": "pw-" + name})
        self.assertEqual(r.status_code, 200, r.text)
        token = r.json()["token"]
        wallet_id = None
        if wallet:
            w = self.client.post("/wallets/create", data={"name": "main", "api_token": token})
            self.assertEqual(w.status_code, 200, w.text)
            wallet_id = w.json()["id"]
        return name, token, wallet_id

    def upload(self, token, title="Helo wrold", description="My frist post", tags="art"):
        files = {"file": ("piece.bin", os.urandom(4096), "application/octet-stream")}
        r = self.client.post("/seeds/upload", data={"api_token": token, "title": title,
                                                     "description": description, "tags": tags}, files=files)
        self.assertEqual(r.status_code, 200, r.text)
        return r.json()

    def edit(self, token, sid, **fields):
        return self.client.post(f"/seeds/{sid}/edit", data={"api_token": token, **fields})

    def rows(self, table, db=None, where_id=None):
        conn = sqlite3.connect(db or main.DB_PATH)
        try:
            rows = select_rows_since(conn, table, "", 10_000)
        finally:
            conn.close()
        cols = [c.strip() for c in TABLE_COLUMNS[table].split(",")]
        if where_id:
            key = "seed_id" if table == "seed_edits" else "id"
            rows = [r for r in rows if r[cols.index(key)] == where_id]
        return cols, [list(r) for r in rows]

    def text_on(self, db, sid):
        conn = sqlite3.connect(db)
        try:
            return conn.execute("SELECT title, description, tags, edited_at FROM seeds WHERE id = ?", (sid,)).fetchone()
        finally:
            conn.close()

    # --- editing on the home node ---

    def test_owner_fixes_a_typo(self):
        _, token, _ = self.register()
        seed = self.upload(token)
        self.assertTrue(seed["rewards_enabled"])
        r = self.edit(token, seed["id"], title="Hello world")
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        self.assertEqual(body["title"], "Hello world")
        self.assertEqual(body["description"], "My frist post")  # left out: unchanged
        self.assertEqual(body["tags"], ["art"])
        self.assertTrue(body["synced"])

        got = self.client.get(f"/seeds/{seed['id']}").json()
        self.assertEqual(got["title"], "Hello world")
        self.assertEqual(got["edited_at"], body["edited_at"])
        feed = {s["id"]: s for s in self.client.get("/feed").json()["items"]}
        self.assertEqual(feed[seed["id"]]["edited_at"], body["edited_at"])

        r = self.edit(token, seed["id"], description="My first post", tags="art, 3d ,")
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["tags"], ["art", "3d"])
        history = self.client.get(f"/seeds/{seed['id']}/edits").json()["edits"]
        self.assertEqual([h["title"] for h in history], ["Hello world", "Hello world"])
        self.assertEqual(history[0]["description"], "My first post")
        self.assertGreater(history[0]["edited_at"], history[1]["edited_at"])

        # Unedited posts say so
        other = self.upload(token)
        self.assertEqual(self.client.get(f"/seeds/{other['id']}").json()["edited_at"], "")
        self.assertEqual(self.client.get(f"/seeds/{other['id']}/edits").json()["edits"], [])

    def test_only_the_poster_can_edit(self):
        _, token, _ = self.register()
        _, other_token, _ = self.register()
        seed = self.upload(token)
        self.assertEqual(self.edit(other_token, seed["id"], title="hijacked").status_code, 403)
        self.assertEqual(self.client.post(f"/seeds/{seed['id']}/edit", data={"title": "x"}).status_code, 401)
        self.assertEqual(self.edit(token, "no-such-seed", title="x").status_code, 404)
        self.assertEqual(self.client.get(f"/seeds/{seed['id']}").json()["title"], "Helo wrold")

    def test_bad_edits_are_refused(self):
        _, token, _ = self.register()
        seed = self.upload(token)
        self.assertEqual(self.edit(token, seed["id"], title="Helo wrold").status_code, 400)  # nothing changed
        self.assertEqual(self.edit(token, seed["id"], title="x" * (seed_edits.MAX_TITLE + 1)).status_code, 400)

    # --- sync ---

    def test_edit_reaches_a_peer_that_already_has_the_post(self):
        _, token, _ = self.register()
        seed = self.upload(token)
        peer = new_node("edit_peer_" + uuid.uuid4().hex[:6])
        cols, rows = self.rows("seeds", where_id=seed["id"])
        ingest_rows("seeds", cols, rows, db_path=peer)
        self.assertEqual(self.text_on(peer, seed["id"])[0], "Helo wrold")

        self.assertEqual(self.edit(token, seed["id"], title="Hello world").status_code, 200)
        cols, rows = self.rows("seed_edits", where_id=seed["id"])
        result = ingest_rows("seed_edits", cols, rows, db_path=peer)
        self.assertEqual(result["inserted"], 1)
        title, _, _, edited_at = self.text_on(peer, seed["id"])
        self.assertEqual(title, "Hello world")
        self.assertTrue(edited_at)

    def test_edit_arriving_before_its_post_applies_later(self):
        _, token, _ = self.register()
        seed = self.upload(token)
        self.assertEqual(self.edit(token, seed["id"], title="Hello world").status_code, 200)
        peer = new_node("early_edit_" + uuid.uuid4().hex[:6])
        cols, rows = self.rows("seed_edits", where_id=seed["id"])
        self.assertEqual(ingest_rows("seed_edits", cols, rows, db_path=peer)["inserted"], 1)

        # The seed row arrives later, still carrying its original text
        cols, rows = self.rows("seeds", where_id=seed["id"])
        rows[0][cols.index("title")] = "Helo wrold"
        ingest_rows("seeds", cols, rows, db_path=peer)
        self.assertEqual(self.text_on(peer, seed["id"])[0], "Hello world")

    def test_newest_edit_wins_in_any_order(self):
        _, token, _ = self.register()
        seed = self.upload(token)
        self.edit(token, seed["id"], title="first fix")
        self.edit(token, seed["id"], title="second fix")
        peer = new_node("order_" + uuid.uuid4().hex[:6])
        cols, rows = self.rows("seeds", where_id=seed["id"])
        ingest_rows("seeds", cols, rows, db_path=peer)
        cols, rows = self.rows("seed_edits", where_id=seed["id"])
        rows.sort(key=lambda r: r[cols.index("edited_at")], reverse=True)  # newest first
        for row in rows:
            ingest_rows("seed_edits", cols, [row], db_path=peer)
        self.assertEqual(self.text_on(peer, seed["id"])[0], "second fix")

    def test_forged_and_tampered_edits_are_ignored(self):
        _, token, _ = self.register()
        seed = self.upload(token)
        self.edit(token, seed["id"], title="Hello world")
        peer = new_node("forged_" + uuid.uuid4().hex[:6])
        cols, rows = self.rows("seeds", where_id=seed["id"])
        ingest_rows("seeds", cols, rows, db_path=peer)
        _, edit_rows = self.rows("seed_edits", where_id=seed["id"])
        genuine = dict(zip(EDIT_COLUMNS, edit_rows[0]))

        # Text changed after signing
        tampered = dict(genuine, title="Buy my scam coin")
        self.assertEqual(ingest_rows("seed_edits", EDIT_COLUMNS, [[tampered[c] for c in EDIT_COLUMNS]],
                                     db_path=peer)["rejected"], 1)

        # Validly signed, but by someone else's wallet
        priv, pub = signing.generate_keypair()
        later = (datetime.datetime.fromisoformat(genuine["edited_at"]) + datetime.timedelta(seconds=1)).isoformat()
        forged = {"seed_id": seed["id"], "title": "Buy my scam coin", "description": "", "tags": "",
                  "edited_at": later, "signer": pub}
        forged["signature"] = seed_edits.sign_edit(priv, forged)
        forged["id"] = seed_edits.edit_id_for(forged)
        self.assertEqual(ingest_rows("seed_edits", EDIT_COLUMNS, [[forged[c] for c in EDIT_COLUMNS]],
                                     db_path=peer)["inserted"], 1)  # well formed, so it's kept...
        ingest_rows("seed_edits", EDIT_COLUMNS, [[genuine[c] for c in EDIT_COLUMNS]], db_path=peer)
        self.assertEqual(self.text_on(peer, seed["id"])[0], "Hello world")  # ...but never applied
        conn = sqlite3.connect(peer)
        try:
            self.assertEqual([h["title"] for h in seed_edits.history(conn, seed["id"])], ["Hello world"])
        finally:
            conn.close()

    def test_far_future_edits_are_rejected(self):
        _, token, wallet = self.register()
        seed = self.upload(token)
        priv = signing.get_wallet_private_key(main.DB_PATH, wallet, keystore.data_key_for_token(token))
        self.assertIsNotNone(priv)
        future = (datetime.datetime.utcnow() + datetime.timedelta(days=365)).isoformat()
        edit = {"seed_id": seed["id"], "title": "locked forever", "description": "", "tags": "",
                "edited_at": future, "signer": wallet}
        edit["signature"] = seed_edits.sign_edit(priv, edit)
        edit["id"] = seed_edits.edit_id_for(edit)
        peer = new_node("future_" + uuid.uuid4().hex[:6])
        self.assertEqual(ingest_rows("seed_edits", EDIT_COLUMNS, [[edit[c] for c in EDIT_COLUMNS]],
                                     db_path=peer)["rejected"], 1)

    def test_unsigned_posts_edit_locally_only(self):
        _, token, _ = self.register(wallet=False)
        seed = self.upload(token)
        self.assertFalse(seed["rewards_enabled"])
        r = self.edit(token, seed["id"], title="Hello world")
        self.assertEqual(r.status_code, 200, r.text)
        self.assertFalse(r.json()["synced"])
        self.assertEqual(self.client.get(f"/seeds/{seed['id']}").json()["title"], "Hello world")
        _, rows = self.rows("seed_edits", where_id=seed["id"])
        self.assertEqual(rows, [])  # never sent to peers


class TopEarnerNameTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(main.app)

    def add_proof(self, wallet, cents):
        conn = sqlite3.connect(main.DB_PATH)
        conn.execute(
            "INSERT INTO podt_proofs (proof_id, seeder_wallet, receiver_wallet, file_hash, file_size_bytes, "
            "reward_cents, tx_id, created_at, seed_id) VALUES (?, ?, '', 'h', 2048, ?, '', ?, '')",
            (uuid.uuid4().hex, wallet, cents, datetime.datetime.utcnow().isoformat()))
        conn.commit()
        conn.close()

    def earners(self):
        r = self.client.get("/podt/stats")
        self.assertEqual(r.status_code, 200, r.text)
        return {e["wallet"]: e for e in r.json()["top_seeders"]}

    def test_local_wallet_shows_its_account_name(self):
        name = "earner" + uuid.uuid4().hex[:6]
        token = self.client.post("/auth/register", data={"username": name, "password": "pw-x"}).json()["token"]
        wallet = self.client.post("/wallets/create", data={"name": "main", "api_token": token}).json()["id"]
        self.add_proof(wallet, 10_000_000)
        self.assertEqual(self.earners()[wallet]["owner"], name)

    def test_peer_wallet_named_by_its_signed_post(self):
        priv, pub = signing.generate_keypair()
        filename = "abc_piece.bin"
        seed = {"id": signing.seed_id_for(pub, filename), "owner": "faraway", "filename": filename,
                "file_size": 10, "created_at": datetime.datetime.utcnow().isoformat(), "reward_wallet": pub}
        seed["signature"] = signing.sign_seed(priv, seed)
        row = [seed.get(c, "") for c in SEED_COLUMNS]
        ingest_rows("seeds", SEED_COLUMNS, [row], db_path=main.DB_PATH)
        self.add_proof(pub, 9_000_000)
        self.assertEqual(self.earners()[pub]["owner"], "faraway")

    def test_borrowed_name_on_a_synced_wallet_row_is_not_trusted(self):
        _, pub = signing.generate_keypair()
        ingest_rows("wallets", ["id", "name", "owner", "created_at"],
                    [[pub, "main", "famous_creator", datetime.datetime.utcnow().isoformat()]],
                    db_path=main.DB_PATH)
        self.add_proof(pub, 8_000_000)
        self.assertNotIn(pub, self.earners())  # not a confirmed account: left out

    def test_wallets_without_an_account_are_left_out(self):
        _, pub = signing.generate_keypair()
        self.add_proof(pub, 7_000_000)
        self.assertNotIn(pub, self.earners())

    def test_real_network_lists_only_phone_verified_earners(self):
        saved = config.REQUIRE_PHONE_TO_POST
        config.REQUIRE_PHONE_TO_POST = True
        try:
            name = "earner" + uuid.uuid4().hex[:6]
            token = self.client.post("/auth/register", data={"username": name, "password": "pw-x"}).json()["token"]
            wallet = self.client.post("/wallets/create", data={"name": "main", "api_token": token}).json()["id"]
            self.add_proof(wallet, 6_000_000)
            self.assertNotIn(wallet, self.earners())
            mark_verified(main.DB_PATH, name)
            self.assertEqual(self.earners()[wallet]["owner"], name)
        finally:
            config.REQUIRE_PHONE_TO_POST = saved


class ProfilePostsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(main.app)

    def test_profile_lists_that_accounts_posts_newest_first(self):
        names = []
        for _ in range(2):
            name = "poster" + uuid.uuid4().hex[:6]
            token = self.client.post("/auth/register", data={"username": name, "password": "pw-x"}).json()["token"]
            self.client.post("/wallets/create", data={"name": "main", "api_token": token})
            for i in range(2):
                files = {"file": (f"p{i}.bin", os.urandom(2048), "application/octet-stream")}
                r = self.client.post("/seeds/upload", data={"api_token": token, "title": f"{name} {i}"}, files=files)
                self.assertEqual(r.status_code, 200, r.text)
            names.append(name)
        items = self.client.get(f"/users/{names[0].upper()}/seeds").json()["items"]
        self.assertEqual([i["title"] for i in items], [f"{names[0]} 1", f"{names[0]} 0"])
        self.assertEqual({i["owner"] for i in items}, {names[0]})
        self.assertEqual(self.client.get("/users/nobody_here/seeds").json()["items"], [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
