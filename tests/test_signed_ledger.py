"""
Tests for the signed ledger: normal REST transfers, and forged vs valid rows
arriving through P2P / tracker sync.

Run from the repository root:
    python -m unittest discover -s tests -v
"""

import json
import os
import sqlite3
import sys
import tempfile
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

# --- Isolated data dir and a test treasury key, set before any GFC module loads config ---
_TMP = tempfile.mkdtemp(prefix="gfc_signed_ledger_")
_treasury = Ed25519PrivateKey.generate()
TREASURY_PRIV = _treasury.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex()
TREASURY_PUB = _treasury.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
TREASURY_KEY_FILE = Path(_TMP) / "treasury_key.hex"
TREASURY_KEY_FILE.write_text(TREASURY_PRIV)
NO_KEY_FILE = Path(_TMP) / "no_treasury_key.hex"  # never created: nodes without the key

os.environ["GFC_DATA_DIR"] = _TMP
os.environ["GFC_TREASURY_PUBKEYS"] = TREASURY_PUB
os.environ["GFC_TREASURY_KEY_FILE"] = str(NO_KEY_FILE)
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient  # noqa: E402

import blockchain  # noqa: E402
import main  # noqa: E402
import keystore  # noqa: E402
import signing  # noqa: E402
from sync_ingest import TABLE_COLUMNS, ingest_rows, select_rows_since  # noqa: E402

TX_COLUMNS = [c.strip() for c in TABLE_COLUMNS["transactions"].split(",")]
SEED_COLUMNS = [c.strip() for c in TABLE_COLUMNS["seeds"].split(",")]


def new_node(name: str) -> str:
    """Create a fresh node database with the full schema and its own genesis block."""
    path = str(Path(_TMP) / f"{name}.db")
    saved = main.DB_PATH
    main.DB_PATH = path
    try:
        main.init_db()
    finally:
        main.DB_PATH = saved
    return path


def new_wallet(db: str, owner: str) -> str:
    conn = sqlite3.connect(db)
    wallet_id = signing.create_wallet_key(conn)
    conn.execute("INSERT INTO wallets (id, name, owner, gfc_balance, created_at, gfc_balance_cents) "
                 "VALUES (?, ?, ?, 0, ?, 0)", (wallet_id, "w", owner, datetime.now(timezone.utc).isoformat()))
    conn.commit()
    conn.close()
    return wallet_id


class as_treasury_node:
    """Context manager: this process temporarily holds the treasury private key."""
    def __enter__(self):
        os.environ["GFC_TREASURY_KEY_FILE"] = str(TREASURY_KEY_FILE)

    def __exit__(self, *exc):
        os.environ["GFC_TREASURY_KEY_FILE"] = str(NO_KEY_FILE)


def export_tx(db: str) -> list:
    """Rows a node would send to peers (same query as sync_engine / tracker upload)."""
    conn = sqlite3.connect(db)
    rows = [list(r) for r in select_rows_since(conn, "transactions", "", 500)]
    conn.close()
    return rows


def signed_transfer(priv_hex: str, sender: str, recipient: str, amount_cents: int, **overrides) -> dict:
    tx = {
        "id": str(uuid.uuid4()), "sender": sender, "recipient": recipient,
        "amount": amount_cents / 100.0, "amount_cents": amount_cents, "reason": "test",
        "timestamp": datetime.now(timezone.utc).isoformat(), "tx_type": blockchain.TX_TYPE_TRANSFER,
    }
    tx.update(overrides)
    tx["tx_hash"] = blockchain.compute_tx_hash(tx)
    tx["signer"] = signing.public_key_of(priv_hex)
    tx["signature"] = signing.sign_tx_hash(priv_hex, tx["tx_hash"])
    return tx


def as_row(tx: dict) -> list:
    return [tx.get(c, "") for c in TX_COLUMNS]


def ingest(db: str, *txs: dict) -> dict:
    return ingest_rows("transactions", TX_COLUMNS, [as_row(t) for t in txs], db_path=db)


def tx_count(db: str) -> int:
    conn = sqlite3.connect(db)
    n = conn.execute("SELECT COUNT(*) FROM transactions").fetchone()[0]
    conn.close()
    return n


class RestTransferTests(unittest.TestCase):
    """The REST API on a normal (non-treasury) node keeps working."""

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(main.app)

    def register(self, username):
        r = self.client.post("/auth/register", data={"username": username, "password": "pw-" + username})
        self.assertEqual(r.status_code, 200, r.text)
        token = r.json()["token"]
        w = self.client.post("/wallets/create", data={"name": "main", "api_token": token})
        self.assertEqual(w.status_code, 200, w.text)
        return token, w.json()

    def balance(self, wallet_id):
        return self.client.get(f"/wallets/{wallet_id}").json()["balance_cents"]

    def test_wallet_is_public_key_and_transfer_is_signed(self):
        alice_token, alice = self.register("alice")
        _, bob = self.register("bob")
        self.assertTrue(signing.is_public_key(alice["id"]))
        self.assertEqual(alice["gfc_balance"], 100.0)

        r = self.client.post("/transactions/create", json={
            "sender": alice["id"], "recipient": bob["id"], "amount": 25.0,
            "reason": "tip", "api_token": alice_token})
        self.assertEqual(r.status_code, 200, r.text)
        tx = r.json()
        self.assertTrue(tx["signed"])
        self.assertEqual(self.balance(alice["id"]), 7_500)
        self.assertEqual(self.balance(bob["id"]), 12_500)

        conn = sqlite3.connect(main.DB_PATH)
        sig, signer = conn.execute("SELECT signature, signer FROM transactions WHERE id = ?",
                                   (tx["id"],)).fetchone()
        keys = conn.execute("SELECT COUNT(*) FROM wallet_keys").fetchone()[0]
        conn.close()
        self.assertEqual(signer, alice["id"])
        self.assertTrue(signing.verify_tx_signature(alice["id"], tx["tx_hash"], sig))
        self.assertGreaterEqual(keys, 2)
        self.assertTrue(blockchain.validate_chain(main.DB_PATH)[0])

    def test_transfer_rejections(self):
        carol_token, carol = self.register("carol")
        dan_token, dan = self.register("dan")
        too_much = self.client.post("/transactions/create", json={
            "sender": carol["id"], "recipient": dan["id"], "amount": 1000.0,
            "reason": "", "api_token": carol_token})
        self.assertEqual(too_much.status_code, 400)
        not_owner = self.client.post("/transactions/create", json={
            "sender": carol["id"], "recipient": dan["id"], "amount": 1.0,
            "reason": "", "api_token": dan_token})
        self.assertEqual(not_owner.status_code, 403)
        self.assertEqual(self.balance(carol["id"]), 10_000)

    def upload(self, token, **form):
        files = {"file": ("model.glb", b"x" * 200_000, "model/gltf-binary")}  # earns 1 cent per play
        return self.client.post("/seeds/upload", data={"api_token": token, **form}, files=files)

    def test_seed_upload_signed_and_play_pays_signer(self):
        fay_token, fay = self.register("fay")
        gus_token, gus = self.register("gus")
        r = self.upload(fay_token, title="ship")
        self.assertEqual(r.status_code, 200, r.text)
        seed = r.json()
        self.assertTrue(seed["rewards_enabled"])
        self.assertEqual(seed["reward_wallet"], fay["id"])

        # Can't route rewards to someone else's wallet
        self.assertEqual(self.upload(fay_token, reward_wallet=gus["id"]).status_code, 400)
        # Anonymous uploads are shared but earn nothing
        self.assertFalse(self.upload("").json()["rewards_enabled"])

        before = self.balance(fay["id"])
        self_play = self.client.post(f"/seeds/{seed['id']}/played", data={"api_token": fay_token}).json()
        self.assertFalse(self_play["credited"])
        play = self.client.post(f"/seeds/{seed['id']}/played", data={"api_token": gus_token}).json()
        self.assertTrue(play["credited"], play)
        self.assertEqual(self.balance(fay["id"]), before + round(play["amount"] * 100))
        conn = sqlite3.connect(main.DB_PATH)
        paid = conn.execute("SELECT recipient FROM transactions WHERE tx_type = 'REWARD' "
                            "ORDER BY timestamp DESC LIMIT 1").fetchone()[0]
        conn.close()
        self.assertEqual(paid, fay["id"])

    def test_local_only_grant_is_not_shared(self):
        # This node has no treasury key, so its grants are unsigned and never sent to peers
        _, erin = self.register("erin")
        exported = {r[TX_COLUMNS.index("recipient")] for r in export_tx(main.DB_PATH)}
        self.assertNotIn(erin["id"], exported)


class SyncValidationTests(unittest.TestCase):
    """Rows from peers are only accepted if signed, consistent and funded."""

    def setUp(self):
        tag = uuid.uuid4().hex[:8]
        # Treasury node: holds the treasury key, so its grants are network-valid
        self.t = new_node(f"treasury_{tag}")
        self.b = new_node(f"peer_{tag}")
        self.alice = new_wallet(self.t, "alice")
        with as_treasury_node():
            self.grant = blockchain.process_user_grant(self.t, "alice", self.alice)
        self.alice_priv = signing.get_wallet_private_key(self.t, self.alice)
        self.bob = new_wallet(self.b, "bob")
        self.bob_priv = signing.get_wallet_private_key(self.b, self.bob)

    def test_valid_grant_and_transfer_sync(self):
        blockchain.process_transfer(self.t, self.alice, self.bob, 3_000, "thanks")
        result = ingest_rows("transactions", TX_COLUMNS, export_tx(self.t), db_path=self.b)
        self.assertEqual(result["inserted"], 2, result)
        self.assertEqual(result["rejected"], 0, result)
        self.assertEqual(blockchain.get_balance_cents(self.b, self.alice), 7_000)
        self.assertEqual(blockchain.get_balance_cents(self.b, self.bob), 3_000)
        self.assertTrue(blockchain.validate_chain(self.b)[0])

        # Bob (on node B) can now spend what he received, and node T accepts it back
        blockchain.process_transfer(self.b, self.bob, self.alice, 1_000)
        back = ingest_rows("transactions", TX_COLUMNS, export_tx(self.b), db_path=self.t)
        self.assertEqual(back["inserted"], 1, back)
        self.assertEqual(blockchain.get_balance_cents(self.t, self.alice), 8_000)

        # Re-delivery is harmless
        again = ingest_rows("transactions", TX_COLUMNS, export_tx(self.t), db_path=self.b)
        self.assertEqual(again["inserted"], 0)
        self.assertEqual(blockchain.get_balance_cents(self.b, self.bob), 2_000)

    def test_out_of_order_transfer_waits_until_funded(self):
        transfer = blockchain.process_transfer(self.t, self.alice, self.bob, 2_500)
        rows = {r[0]: r for r in export_tx(self.t)}
        first = ingest_rows("transactions", TX_COLUMNS, [rows[transfer["id"]]], db_path=self.b)
        self.assertEqual(first["pending"], 1, first)
        self.assertEqual(blockchain.get_balance_cents(self.b, self.bob), 0)
        second = ingest_rows("transactions", TX_COLUMNS, [rows[self.grant["id"]]], db_path=self.b)
        self.assertEqual(second["inserted"], 2, second)  # grant + the queued transfer
        self.assertEqual(blockchain.get_balance_cents(self.b, self.bob), 2_500)

    def test_overspend_never_accepted(self):
        ingest_rows("transactions", TX_COLUMNS, export_tx(self.t), db_path=self.b)
        tx = signed_transfer(self.alice_priv, self.alice, self.bob, 50_000)
        self.assertEqual(ingest(self.b, tx)["pending"], 1)
        self.assertEqual(blockchain.get_balance_cents(self.b, self.bob), 0)
        self.assertEqual(blockchain.get_balance_cents(self.b, self.alice), 10_000)

    def test_forged_rows_rejected(self):
        before = tx_count(self.b)
        attacker = Ed25519PrivateKey.generate()
        attacker_priv = attacker.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex()
        attacker_wallet = signing.public_key_of(attacker_priv)
        now = datetime.now(timezone.utc).isoformat()

        def mint(tx_type, amount, priv, recipient=attacker_wallet, **extra):
            tx = {"id": str(uuid.uuid4()), "sender": blockchain.TREASURY_WALLET_ID, "recipient": recipient,
                  "amount": amount / 100, "amount_cents": amount, "reason": "", "timestamp": now,
                  "tx_type": tx_type}
            tx.update(extra)
            tx["tx_hash"] = blockchain.compute_tx_hash(tx)
            tx["signer"] = signing.public_key_of(priv)
            tx["signature"] = signing.sign_tx_hash(priv, tx["tx_hash"])
            return tx

        # Spend the victim's wallet with the attacker's key
        steal = signed_transfer(attacker_priv, self.alice, attacker_wallet, 5_000)
        steal_claiming_sender = dict(steal, signer=self.alice)
        # Mints not signed by the pinned treasury key
        fake_grant = mint(blockchain.TX_TYPE_GRANT, blockchain.NEW_USER_GRANT_CENTS, attacker_priv)
        fake_reward = mint(blockchain.TX_TYPE_REWARD, 50_000, attacker_priv)
        # Real treasury signature, but outside the mint rules
        big_grant = mint(blockchain.TX_TYPE_GRANT, 10 ** 9, TREASURY_PRIV)
        huge_reward = mint(blockchain.TX_TYPE_REWARD, blockchain.MAX_REWARD_CENTS + 1, TREASURY_PRIV)
        premine = mint(blockchain.TX_TYPE_PREMINE, 10 ** 12, TREASURY_PRIV)
        # Contents changed after signing (hash mismatch), and re-hashed (signature mismatch)
        valid = signed_transfer(self.alice_priv, self.alice, self.bob, 1_000)
        tampered = dict(valid, amount_cents=900_000)
        rehashed = dict(tampered)
        rehashed["tx_hash"] = blockchain.compute_tx_hash(rehashed)
        # Unsigned rows (old peers, or a local-only mint) and a far-future timestamp
        unsigned = dict(fake_grant, signature="", signer="")
        future = signed_transfer(attacker_priv, attacker_wallet, self.bob, 1,
                                 timestamp=(datetime.now(timezone.utc) + timedelta(days=30)).isoformat())
        # Sender that is not a public key
        legacy = signed_transfer(attacker_priv, "not-a-key", self.bob, 1)

        forged = [steal, steal_claiming_sender, fake_grant, fake_reward, big_grant, huge_reward,
                  premine, tampered, rehashed, unsigned, future, legacy]
        for tx in forged:
            status, reason = blockchain.check_synced_transaction(self.b, tx)
            self.assertEqual(status, blockchain.REJECTED, f"{tx['tx_type']} {reason}")
        result = ingest(self.b, *forged)
        self.assertEqual(result["rejected"], len(forged), result)
        self.assertEqual(tx_count(self.b), before)
        self.assertEqual(blockchain.get_balance_cents(self.b, attacker_wallet), 0)

    def test_replay_and_double_grant_rejected(self):
        ingest_rows("transactions", TX_COLUMNS, export_tx(self.t), db_path=self.b)
        tx = signed_transfer(self.alice_priv, self.alice, self.bob, 1_000)
        self.assertEqual(ingest(self.b, tx)["inserted"], 1)
        replay = dict(tx, id=str(uuid.uuid4()))
        self.assertEqual(ingest(self.b, replay)["rejected"], 1)
        self.assertEqual(blockchain.get_balance_cents(self.b, self.bob), 1_000)

        # A second treasury-signed grant to the same wallet
        second = dict(self.grant, id=str(uuid.uuid4()), timestamp=datetime.now(timezone.utc).isoformat())
        second["tx_hash"] = blockchain.compute_tx_hash(second)
        second["signature"] = signing.sign_tx_hash(TREASURY_PRIV, second["tx_hash"])
        self.assertEqual(blockchain.check_synced_transaction(self.b, second)[0], blockchain.REJECTED)

    def test_balance_never_comes_from_wallet_rows(self):
        conn = sqlite3.connect(self.t)
        conn.execute("UPDATE wallets SET gfc_balance = 1e12, gfc_balance_cents = 10000000000000 WHERE id = ?",
                     (self.alice,))
        conn.commit()
        conn.close()
        forged_wallets = ["id", "name", "owner", "gfc_balance", "created_at", "gfc_balance_cents", "is_treasury"]
        rows = [[self.alice, "rich", "alice", 1e12, "2026-01-01T00:00:00", 10 ** 13, 1],
                [blockchain.TREASURY_WALLET_ID, "fake treasury", "x", 0, "2026-01-01T00:00:00", 0, 1]]
        result = ingest_rows("wallets", forged_wallets, rows, db_path=self.b)
        self.assertEqual(result["inserted"], 1, result)
        conn = sqlite3.connect(self.b)
        cached = conn.execute("SELECT gfc_balance_cents, is_treasury FROM wallets WHERE id = ?",
                              (self.alice,)).fetchone()
        conn.close()
        self.assertEqual(cached, (0, 0))
        self.assertEqual(blockchain.get_balance_cents(self.b, self.alice), 0)

    def test_derived_tables_not_accepted(self):
        for table, cols, row in [
            ("blocks", ["block_index", "prev_hash", "merkle_root", "timestamp", "tx_count"],
             [999, "0" * 64, "x", "2026-01-01", 1]),
            ("user_grants", ["username", "wallet_id", "granted_at"], ["bob", "x", "2026-01-01"]),
            ("podt_proofs", ["proof_id", "seeder_wallet", "receiver_wallet", "file_hash", "file_size_bytes",
                             "reward_cents", "tx_id", "created_at", "seed_id"],
             ["p", "x", "y", "h", 1, 1, "t", "2026-01-01", "s"]),
        ]:
            self.assertEqual(ingest_rows(table, cols, [row], db_path=self.b)["inserted"], 0, table)
        conn = sqlite3.connect(self.b)
        self.assertIsNone(conn.execute("SELECT 1 FROM blocks WHERE block_index = 999").fetchone())
        self.assertIsNone(conn.execute("SELECT 1 FROM user_grants WHERE username = 'bob'").fetchone())
        conn.close()

    def test_private_keys_never_exported(self):
        conn = sqlite3.connect(self.t)
        for table in ("users", "seeds", "transactions", "likes", "comments", "bookmarks", "wallets"):
            payload = json.dumps([list(r) for r in select_rows_since(conn, table, "", 500)])
            self.assertNotIn(self.alice_priv, payload, table)
        conn.close()


def make_seed(priv_hex, wallet, owner="alice", **overrides) -> dict:
    """A seed row as a peer would send it, signed by `priv_hex` (None = unsigned)."""
    filename = f"{uuid.uuid4().hex[:12]}_model.glb"
    seed = {c: "" for c in SEED_COLUMNS}
    seed.update(id=signing.seed_id_for(wallet, filename), owner=owner, title="t", filename=filename,
                content_type="3d", file_size=4096, gfc_earned=0, likes=0, comments=0, views=0,
                created_at=datetime.now(timezone.utc).isoformat(), reward_wallet=wallet)
    seed.update(overrides)
    seed["signature"] = signing.sign_seed(priv_hex, seed) if priv_hex else ""
    return seed


def seed_rows(*seeds) -> list:
    return [[s[c] for c in SEED_COLUMNS] for s in seeds]


class SeedRewardTests(unittest.TestCase):
    """Rewards go only to the wallet that signed the seed."""

    def setUp(self):
        tag = uuid.uuid4().hex[:8]
        self.home = new_node(f"seedhome_{tag}")
        self.peer = new_node(f"seedpeer_{tag}")
        self.alice = new_wallet(self.home, "alice")
        self.alice_priv = signing.get_wallet_private_key(self.home, self.alice)
        attacker = Ed25519PrivateKey.generate()
        self.attacker_priv = attacker.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex()
        self.attacker = signing.public_key_of(self.attacker_priv)

    def reward_wallet(self, db, seed_id):
        conn = sqlite3.connect(db)
        try:
            return signing.seed_reward_wallet(conn, seed_id)
        finally:
            conn.close()

    def test_signed_seed_syncs_and_pays_its_signer(self):
        seed = make_seed(self.alice_priv, self.alice)
        result = ingest_rows("seeds", SEED_COLUMNS, seed_rows(seed), db_path=self.peer)
        self.assertEqual(result["inserted"], 1, result)
        self.assertEqual(self.reward_wallet(self.peer, seed["id"]), self.alice)

    def test_forged_seeds_rejected(self):
        real = make_seed(self.alice_priv, self.alice)
        # Same ID, re-signed with the attacker's wallet as reward wallet
        resigned = dict(real, reward_wallet=self.attacker)
        resigned["signature"] = signing.sign_seed(self.attacker_priv, resigned)
        # Reward wallet swapped without re-signing
        swapped = dict(real, reward_wallet=self.attacker)
        # Signed by the attacker but claiming Alice's wallet
        claimed = make_seed(self.attacker_priv, self.alice)
        result = ingest_rows("seeds", SEED_COLUMNS, seed_rows(resigned, swapped, claimed), db_path=self.peer)
        self.assertEqual(result["rejected"], 3, result)
        self.assertEqual(result["inserted"], 0, result)
        # The real seed still arrives afterwards and pays Alice
        ingest_rows("seeds", SEED_COLUMNS, seed_rows(real), db_path=self.peer)
        self.assertEqual(self.reward_wallet(self.peer, real["id"]), self.alice)

    def test_unsigned_seed_and_owner_label_pay_nobody(self):
        # A peer claims Alice's name for its own wallet, and sends an unsigned seed for "alice"
        ingest_rows("wallets", ["id", "name", "owner", "created_at"],
                    [[self.attacker, "x", "alice", "2026-01-01T00:00:00"]], db_path=self.peer)
        legacy = make_seed(None, self.attacker, id=uuid.uuid4().hex[:12])
        result = ingest_rows("seeds", SEED_COLUMNS, seed_rows(legacy), db_path=self.peer)
        self.assertEqual(result["inserted"], 1, result)
        conn = sqlite3.connect(self.peer)
        stored = conn.execute("SELECT reward_wallet FROM seeds WHERE id = ?", (legacy["id"],)).fetchone()[0]
        conn.close()
        self.assertEqual(stored, "")
        self.assertIsNone(self.reward_wallet(self.peer, legacy["id"]))


class KeystoreTests(unittest.TestCase):
    """Wallet keys are encrypted at rest and can be backed up and restored."""

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(main.app)

    def register(self, username, password=None):
        password = password or "pw-" + username
        r = self.client.post("/auth/register", data={"username": username, "password": password})
        self.assertEqual(r.status_code, 200, r.text)
        token = r.json()["token"]
        w = self.client.post("/wallets/create", data={"name": "main", "api_token": token}).json()
        return token, w["id"], password

    def stored_key(self, wallet_id, db=None):
        conn = sqlite3.connect(db or main.DB_PATH)
        row = conn.execute("SELECT private_key FROM wallet_keys WHERE wallet_id = ?", (wallet_id,)).fetchone()
        conn.close()
        return row[0] if row else None

    def test_keys_encrypted_at_rest_and_unlocked_by_session(self):
        token, wallet, password = self.register("hana")
        stored = self.stored_key(wallet)
        self.assertTrue(keystore.is_encrypted(stored))
        # The database alone can't produce the key; the live token can
        self.assertIsNone(signing.get_wallet_private_key(main.DB_PATH, wallet))
        self.assertIsNone(keystore.data_key_for_token("not-a-token"))
        priv = signing.get_wallet_private_key(main.DB_PATH, wallet, keystore.data_key_for_token(token))
        self.assertEqual(signing.public_key_of(priv), wallet)
        self.assertNotIn(priv, stored)
        # Signing without the data key fails loudly instead of sending an unsigned transfer
        _, other, _ = self.register("ivan")
        with self.assertRaises(ValueError):
            blockchain.process_transfer(main.DB_PATH, wallet, other, 100)
        # A fresh login unlocks the same keys
        login = self.client.post("/auth/login", data={"username": "hana", "password": password}).json()
        r = self.client.post("/transactions/create", json={
            "sender": wallet, "recipient": other, "amount": 1.0, "reason": "", "api_token": login["token"]})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertTrue(r.json()["signed"])

    def test_plaintext_keys_encrypted_on_login(self):
        token, _, password = self.register("jo")
        conn = sqlite3.connect(main.DB_PATH)
        old_wallet = signing.create_wallet_key(conn)  # plaintext, as before this change
        conn.execute("INSERT INTO wallets (id, name, owner, created_at) VALUES (?, 'old', 'jo', '')", (old_wallet,))
        conn.commit()
        conn.close()
        self.assertFalse(keystore.is_encrypted(self.stored_key(old_wallet)))
        self.client.post("/auth/login", data={"username": "jo", "password": password})
        self.assertTrue(keystore.is_encrypted(self.stored_key(old_wallet)))

    def test_export_and_import(self):
        token, wallet, password = self.register("kim")
        passphrase = "correct horse battery"
        bad_pw = self.client.post("/wallets/export", data={
            "api_token": token, "password": "wrong", "backup_passphrase": passphrase})
        self.assertEqual(bad_pw.status_code, 401)
        short = self.client.post("/wallets/export", data={
            "api_token": token, "password": password, "backup_passphrase": "short"})
        self.assertEqual(short.status_code, 400)
        r = self.client.post("/wallets/export", data={
            "api_token": token, "password": password, "backup_passphrase": passphrase})
        self.assertEqual(r.status_code, 200, r.text)
        backup = r.json()
        priv = signing.get_wallet_private_key(main.DB_PATH, wallet, keystore.data_key_for_token(token))
        self.assertNotIn(priv, json.dumps(backup))

        # Wrong passphrase and tampered parameters are refused
        lee_token, _, _ = self.register("lee")
        wrong = self.client.post("/wallets/import", data={
            "api_token": lee_token, "backup_passphrase": "not the passphrase", "backup": json.dumps(backup)})
        self.assertEqual(wrong.status_code, 400)
        huge = dict(backup, n=2 ** 30)
        self.assertEqual(self.client.post("/wallets/import", data={
            "api_token": lee_token, "backup_passphrase": passphrase, "backup": json.dumps(huge)}).status_code, 400)

        # Restore onto a brand-new node (e.g. after losing the data folder)
        node = new_node(f"restore_{uuid.uuid4().hex[:8]}")
        conn = sqlite3.connect(node)
        conn.execute("INSERT INTO users (id, username, password, created_at) VALUES ('u', 'kim', ?, '')",
                     (main.hash_password("new-password"),))
        conn.commit()
        conn.close()
        data_key = keystore.unlock_user_keys("kim", "new-password", db_path=node)
        self.assertEqual(keystore.import_wallets("kim", data_key, passphrase, backup, db_path=node), [wallet])
        self.assertTrue(keystore.is_encrypted(self.stored_key(wallet, node)))
        self.assertEqual(signing.get_wallet_private_key(node, wallet, data_key), priv)

    def test_backup_with_mismatched_key_rejected(self):
        priv_other = signing.generate_keypair()[0]  # a key that doesn't match the wallet
        _, wallet, _ = self.register("max")
        forged = keystore.seal_backup("correct horse battery", {"wallets": [
            {"wallet_id": wallet, "private_key": priv_other, "name": "x"}]}, "wallets")
        with self.assertRaises(keystore.KeystoreError):
            keystore.import_wallets("max", b"k" * 32, "correct horse battery", forged)

    def test_treasury_backup_restore_and_encrypt(self):
        work = Path(tempfile.mkdtemp(prefix="gfc_treasury_cli_", dir=_TMP))
        key_file, backup_file = work / "treasury_key.hex", work / "treasury.backup"
        key_file.write_text(TREASURY_PRIV)
        os.environ["GFC_TREASURY_KEY_FILE"] = str(key_file)
        os.environ["GFC_BACKUP_PASSPHRASE"] = "treasury passphrase 1"
        try:
            self.assertEqual(signing._cli(["backup", str(backup_file)]), 0)
            self.assertNotIn(TREASURY_PRIV, backup_file.read_text())
            key_file.unlink()
            self.assertEqual(signing._cli(["restore", str(backup_file)]), 0)
            self.assertEqual(key_file.read_text().strip(), TREASURY_PRIV)

            self.assertEqual(signing._cli(["encrypt"]), 0)
            self.assertNotIn(TREASURY_PRIV, key_file.read_text())
            os.environ.pop("GFC_TREASURY_PASSPHRASE", None)
            self.assertIsNone(signing.load_treasury_private_key())  # locked without the passphrase
            os.environ["GFC_TREASURY_PASSPHRASE"] = "treasury passphrase 1"
            self.assertEqual(signing.load_treasury_private_key(), TREASURY_PRIV)
        finally:
            os.environ["GFC_TREASURY_KEY_FILE"] = str(NO_KEY_FILE)
            os.environ.pop("GFC_BACKUP_PASSPHRASE", None)
            os.environ.pop("GFC_TREASURY_PASSPHRASE", None)


if __name__ == "__main__":
    unittest.main(verbosity=2)
