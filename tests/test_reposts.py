"""
Tests for the anti-repost framework: reposts are allowed, but labelled and linked
to the original, and every earning goes to the original creator.

Run from the repository root:
    python -m unittest discover -s tests -v
"""

import base64
import types
import io
import json
import os
import random
import sqlite3
import struct
import unittest
import uuid
from datetime import datetime, timedelta, timezone

# Sets up the isolated data dir and test treasury key before any GFC module loads config
import test_signed_ledger  # noqa: F401
from test_signed_ledger import TREASURY_PRIV, as_treasury_node, backdate_user, unique_phone, verify_phone

from fastapi.testclient import TestClient  # noqa: E402
from PIL import Image, ImageDraw  # noqa: E402

import blockchain  # noqa: E402
import fingerprint  # noqa: E402
import main  # noqa: E402
import reposts  # noqa: E402
import signing  # noqa: E402
import sync_engine  # noqa: E402
from config import SEEDS_ORIG_DIR  # noqa: E402
from sync_ingest import TABLE_COLUMNS, ingest_rows  # noqa: E402

RECEIPT_COLUMNS = [c.strip() for c in TABLE_COLUMNS["originality_receipts"].split(",")]


# ---------- test content ----------

def artwork(seed: int, size=(640, 480)) -> Image.Image:
    """A distinct, detailed image for each seed."""
    rnd = random.Random(seed)
    img = Image.new("RGB", size, tuple(rnd.randrange(256) for _ in range(3)))
    draw = ImageDraw.Draw(img)
    for _ in range(40):
        x, y = rnd.randrange(size[0]), rnd.randrange(size[1])
        draw.rectangle([x, y, x + rnd.randrange(30, 200), y + rnd.randrange(30, 200)],
                       fill=tuple(rnd.randrange(256) for _ in range(3)))
    for _ in range(15):
        x, y = rnd.randrange(size[0]), rnd.randrange(size[1])
        draw.ellipse([x, y, x + rnd.randrange(20, 150), y + rnd.randrange(20, 150)],
                     fill=tuple(rnd.randrange(256) for _ in range(3)))
    return img


def encode(img: Image.Image, fmt: str, **kw) -> bytes:
    buf = io.BytesIO()
    img.save(buf, fmt, **kw)
    return buf.getvalue()


def mesh_points(seed: int, n: int = 30) -> list:
    """A bumpy n x n height-field surface (n^2 distinct vertices), different for each seed."""
    rnd = random.Random(seed)
    bumps = [(rnd.uniform(0, 1), rnd.uniform(0, 1), rnd.uniform(-0.3, 0.3)) for _ in range(6)]
    pts = []
    for i in range(n):
        for j in range(n):
            u, v = i / (n - 1), j / (n - 1)
            h = sum(a / (1 + 20 * ((u - bx) ** 2 + (v - by) ** 2)) for bx, by, a in bumps)
            pts.append((u * 2 - 1, h, v * 1.5 - 0.75))
    return pts


def build_glb(points: list, interleave_normals=False, name="mesh", extra_json=None) -> bytes:
    """A minimal glTF 2.0 binary with one primitive holding `points` as POSITION."""
    stride = 24 if interleave_normals else 12
    blob = bytearray()
    for p in points:
        blob += struct.pack("<3f", *p)
        if interleave_normals:
            blob += struct.pack("<3f", 0.0, 1.0, 0.0)
    gltf = {
        "asset": {"version": "2.0", "generator": name},
        "buffers": [{"byteLength": len(blob)}],
        "bufferViews": [{"buffer": 0, "byteOffset": 0, "byteLength": len(blob), "byteStride": stride}],
        "accessors": [{"bufferView": 0, "componentType": 5126, "count": len(points), "type": "VEC3",
                       "min": [min(p[i] for p in points) for i in range(3)],
                       "max": [max(p[i] for p in points) for i in range(3)]}],
        "meshes": [{"name": name, "primitives": [{"attributes": {"POSITION": 0}, "mode": 0}]}],
        "nodes": [{"mesh": 0, "name": name}],
        "scenes": [{"nodes": [0]}],
    }
    gltf.update(extra_json or {})
    js = json.dumps(gltf).encode()
    js += b" " * (-len(js) % 4)
    blob += b"\0" * (-len(blob) % 4)
    total = 12 + 8 + len(js) + 8 + len(blob)
    return (b"glTF" + struct.pack("<II", 2, total) + struct.pack("<I", len(js)) + b"JSON" + js
            + struct.pack("<I", len(blob)) + b"BIN\0" + bytes(blob))


def reexport(points: list, rnd_seed=7) -> bytes:
    """The same geometry as another exporter might write it: shuffled, split seams, moved and scaled."""
    rnd = random.Random(rnd_seed)
    pts = list(points) + rnd.sample(points, len(points) // 5)  # vertices duplicated along UV seams
    rnd.shuffle(pts)
    pts = [(x * 2.5 + 10, y * 2.5 - 3, z * 2.5 + 1) for x, y, z in pts]  # translated, uniformly scaled
    return build_glb(pts, interleave_normals=True, name="Exported_from_other_tool",
                     extra_json={"materials": [{"name": "red"}]})


# ---------- fingerprint unit tests ----------

class FingerprintTests(unittest.TestCase):
    def test_image_near_duplicates_match_and_different_images_dont(self):
        original = fingerprint.image_hash(encode(artwork(1), "PNG"))
        resized_jpeg = fingerprint.image_hash(encode(artwork(1).resize((320, 240)), "JPEG", quality=60))
        upscaled_webp = fingerprint.image_hash(encode(artwork(1).resize((1280, 960)), "WEBP", quality=50))
        self.assertLessEqual(fingerprint.image_distance(original, resized_jpeg), fingerprint.IMAGE_MAX_DISTANCE)
        self.assertLessEqual(fingerprint.image_distance(original, upscaled_webp), fingerprint.IMAGE_MAX_DISTANCE)
        for other in range(2, 12):
            other_hash = fingerprint.image_hash(encode(artwork(other), "PNG"))
            self.assertGreater(fingerprint.image_distance(original, other_hash), 3 * fingerprint.IMAGE_MAX_DISTANCE)

    def test_generic_images_are_not_claimable(self):
        self.assertIsNone(fingerprint.image_hash(encode(Image.new("RGB", (400, 400), (20, 30, 40)), "PNG")))
        self.assertIsNone(fingerprint.image_hash(encode(artwork(1, size=(24, 24)), "PNG")))

    def test_glb_reexport_matches_and_other_geometry_doesnt(self):
        points = mesh_points(1)
        a = fingerprint.geometry_print(build_glb(points), ".glb")
        b = fingerprint.geometry_print(reexport(points), ".glb")
        self.assertIsNotNone(a)
        self.assertTrue(fingerprint.geometry_similar(a, b))
        for other in range(2, 8):
            c = fingerprint.geometry_print(build_glb(mesh_points(other)), ".glb")
            self.assertFalse(fingerprint.geometry_similar(a, c))

    def test_simple_geometry_is_not_claimable(self):
        cube = [(x, y, z) for x in (0, 1) for y in (0, 1) for z in (0, 1)]
        self.assertIsNone(fingerprint.geometry_print(build_glb(cube), ".glb"))
        self.assertIsNone(fingerprint.geometry_print(b"not a model", ".glb"))


# ---------- end to end ----------

class RepostTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(main.app)

    def register(self, verified=True, name=None):
        name = name or "u" + uuid.uuid4().hex[:10]
        r = self.client.post("/auth/register", data={"username": name, "password": "pw-" + name})
        self.assertEqual(r.status_code, 200, r.text)
        token = r.json()["token"]
        if verified:
            with as_treasury_node():
                verify_phone(self.client, token, unique_phone())
        wallet = self.client.post("/wallets/create", data={"name": "main", "api_token": token}).json()["id"]
        return name, token, wallet

    def upload(self, token, filename, data, notary=True):
        files = {"file": (filename, data, "application/octet-stream")}
        if notary:
            with as_treasury_node():
                r = self.client.post("/seeds/upload", data={"api_token": token}, files=files)
        else:
            r = self.client.post("/seeds/upload", data={"api_token": token}, files=files)
        self.assertEqual(r.status_code, 200, r.text)
        return r.json()

    def balance(self, wallet):
        return blockchain.get_balance_cents(main.DB_PATH, wallet)

    def txs(self, tx_type, recipient):
        conn = sqlite3.connect(main.DB_PATH)
        rows = conn.execute("SELECT amount_cents, signature FROM transactions WHERE tx_type = ? AND recipient = ?",
                            (tx_type, recipient)).fetchall()
        conn.close()
        return rows

    # --- detection ---

    def test_exact_duplicate_is_a_repost_linked_to_the_original(self):
        alice, alice_token, _ = self.register()
        _, bob_token, _ = self.register()
        video = os.urandom(300_000)
        original = self.upload(alice_token, "clip.mp4", video)
        self.assertIsNone(original["repost_of"])
        copy = self.upload(bob_token, "my_clip.mp4", video)
        self.assertEqual(copy["repost_of"]["seed_id"], original["id"])
        self.assertEqual(copy["repost_of"]["owner"], alice)
        self.assertEqual(copy["repost_of"]["label"], f"Repost of @{alice}")
        self.assertEqual(copy["repost_of"]["matched_by"], "sha256")
        self.assertTrue(copy["repost_of"]["url"].endswith(f"/p/{original['id']}"))

        # Feed, seed and share JSON all carry the label
        self.assertEqual(self.client.get(f"/seeds/{copy['id']}").json()["repost_of"]["seed_id"], original["id"])
        feed = {s["id"]: s for s in self.client.get("/seeds").json()["items"]}
        self.assertEqual(feed[copy["id"]]["repost_of"]["owner"], alice)
        self.assertIsNone(feed[original["id"]]["repost_of"])
        share = self.client.get(f"/p/{copy['id']}/share").json()
        self.assertEqual(share["repost_of"]["seed_id"], original["id"])
        self.assertIn(f"by {alice} on GFC", share["text"])

        # Video gets exact matching only: one different byte is not a repost
        other = self.upload(bob_token, "clip2.mp4", video[:-1] + bytes([video[-1] ^ 1]))
        self.assertIsNone(other["repost_of"])

    def test_image_resized_and_reencoded_is_a_repost_but_a_different_image_isnt(self):
        alice, alice_token, _ = self.register()
        _, bob_token, _ = self.register()
        original = self.upload(alice_token, "art.png", encode(artwork(101), "PNG"))
        copy = self.upload(bob_token, "art_small.jpg", encode(artwork(101).resize((300, 225)), "JPEG", quality=70))
        self.assertEqual(copy["repost_of"]["seed_id"], original["id"])
        self.assertEqual(copy["repost_of"]["matched_by"], "img")
        different = self.upload(bob_token, "mine.png", encode(artwork(102), "PNG"))
        self.assertIsNone(different["repost_of"])

    def test_glb_reexport_is_a_repost(self):
        alice, alice_token, _ = self.register()
        _, bob_token, _ = self.register()
        points = mesh_points(201)
        original = self.upload(alice_token, "statue.glb", build_glb(points))
        copy = self.upload(bob_token, "statue_v2.glb", reexport(points))
        self.assertEqual(copy["repost_of"]["seed_id"], original["id"])
        self.assertEqual(copy["repost_of"]["matched_by"], "geo")
        different = self.upload(bob_token, "other.glb", build_glb(mesh_points(202)))
        self.assertIsNone(different["repost_of"])

    def test_nodes_without_the_treasury_key_issue_no_receipts(self):
        _, alice_token, _ = self.register()
        _, bob_token, _ = self.register()
        data = os.urandom(50_000)
        first = self.upload(alice_token, "a.mp3", data, notary=False)
        conn = sqlite3.connect(main.DB_PATH)
        receipts = conn.execute("SELECT COUNT(*) FROM originality_receipts WHERE seed_id = ?",
                                (first["id"],)).fetchone()[0]
        conn.close()
        self.assertEqual(receipts, 0)
        # Nothing notarised yet, so nothing to match against
        self.assertIsNone(self.upload(bob_token, "b.mp3", data, notary=False)["repost_of"])

    # --- earnings ---

    def test_view_reward_of_a_repost_goes_to_the_original(self):
        alice, alice_token, alice_wallet = self.register()
        _, bob_token, bob_wallet = self.register()
        viewer, viewer_token, _ = self.register()
        backdate_user(main.DB_PATH, viewer)
        data = os.urandom(300_000)
        self.upload(alice_token, "song.mp3", data)
        copy = self.upload(bob_token, "song.mp3", data)
        bob_before, alice_before = self.balance(bob_wallet), self.balance(alice_wallet)
        with as_treasury_node():
            play = self.client.post(f"/seeds/{copy['id']}/played", data={"api_token": viewer_token}).json()
        self.assertTrue(play["credited"], play)
        self.assertEqual(self.balance(alice_wallet) - alice_before, round(play["amount"] * 100))
        self.assertEqual(self.balance(bob_wallet), bob_before)
        # The original creator watching the repost is a self-play
        backdate_user(main.DB_PATH, alice)
        self_play = self.client.post(f"/seeds/{copy['id']}/played", data={"api_token": alice_token}).json()
        self.assertEqual(self_play["reason"], "self-play")

    def test_podt_credit_for_a_synced_repost_goes_to_the_original(self):
        _, alice_token, alice_wallet = self.register()
        data = os.urandom(300_000)  # earns PoDT credit
        original = self.upload(alice_token, "film.mp4", data)

        # A signed seed from another node whose file is a copy; it arrives by sync, then its file
        priv, wallet = signing.generate_keypair()
        filename = uuid.uuid4().hex[:12] + "_film_copy.mp4"
        seed = {"id": signing.seed_id_for(wallet, filename), "owner": "mallory", "filename": filename,
                "file_size": len(data), "created_at": "2020-01-01T00:00:00", "reward_wallet": wallet}
        seed["signature"] = signing.sign_seed(priv, seed)
        columns = list(seed)
        self.assertEqual(ingest_rows("seeds", columns, [[seed[c] for c in columns]])["inserted"], 1)
        alice_before = self.balance(alice_wallet)
        engine = sync_engine.SyncEngine.__new__(sync_engine.SyncEngine)  # no networking needed
        engine._pending_file_chunks = {}
        peer = types.SimpleNamespace(peer_address="peer")
        with as_treasury_node():
            engine._on_seed_file_response(peer, {"seed_id": seed["id"], "file_type": "original", "found": True,
                                                 "filename": filename, "file_size": len(data)})
            engine._on_seed_file_chunk(peer, {"seed_id": seed["id"], "file_type": "original", "chunk_idx": 0,
                                              "data": base64.b64encode(data).decode(), "is_last": True})
        conn = sqlite3.connect(main.DB_PATH)
        self.assertEqual(reposts.repost_of(conn, seed["id"])["original_seed_id"], original["id"])
        conn.close()
        self.assertGreater(self.balance(alice_wallet), alice_before)
        self.assertEqual(self.balance(wallet), 0)
        self.assertEqual(self.txs(blockchain.TX_TYPE_REWARD, wallet), [])

    def test_repost_credit_once_per_verified_reposter_and_original(self):
        alice, alice_token, alice_wallet = self.register()
        _, bob_token, _ = self.register()
        _, carol_token, _ = self.register(verified=False)
        img = artwork(301)
        self.upload(alice_token, "art.png", encode(img, "PNG"))
        start = self.balance(alice_wallet)

        first = self.upload(bob_token, "a.png", encode(img, "PNG"))
        self.assertEqual(first["repost_credit_gfc"], 15.0)
        self.assertEqual(self.balance(alice_wallet) - start, blockchain.REPOST_CREDIT_CENTS)
        [(amount, signature)] = self.txs(blockchain.TX_TYPE_REPOST, alice_wallet)
        self.assertEqual(amount, 1_500)
        self.assertTrue(signature)  # treasury-signed, so peers accept it

        # Same reposter, same original again (even as a near-duplicate): no more credit
        again = self.upload(bob_token, "b.jpg", encode(img.resize((320, 240)), "JPEG", quality=80))
        self.assertIsNotNone(again["repost_of"])
        self.assertEqual(again["repost_credit_gfc"], 0.0)
        # Unverified reposter: labelled, but no credit
        unverified = self.upload(carol_token, "c.png", encode(img, "PNG"))
        self.assertIsNotNone(unverified["repost_of"])
        self.assertEqual(unverified["repost_credit_gfc"], 0.0)
        # The original creator reposting their own work: nothing extra
        own = self.upload(alice_token, "again.png", encode(img, "PNG"))
        self.assertEqual(own["repost_of"]["owner"], alice)
        self.assertEqual(own["repost_credit_gfc"], 0.0)
        self.assertEqual(self.balance(alice_wallet) - start, blockchain.REPOST_CREDIT_CENTS)

        # Circulation stats count REPOST mints: everything the treasury paid out is in circulation
        stats = blockchain.get_blockchain_stats(main.DB_PATH)
        self.assertEqual(stats["gfc_in_circulation_cents"] + stats["treasury_balance_cents"],
                         blockchain.PREMINE_CENTS)

    # --- network rules ---

    def receipt(self, prints, seed_id, first_seen_at, key=TREASURY_PRIV, owner="alice", wallet=None):
        return reposts.sign_receipt(key, prints, seed_id, owner, wallet or signing.generate_keypair()[1],
                                    first_seen_at)

    def test_peers_accept_only_treasury_signed_receipts(self):
        db = test_signed_ledger.new_node("receipts_" + uuid.uuid4().hex[:6])
        now = datetime.now(timezone.utc).isoformat()
        good = self.receipt(["sha256:" + "ab" * 32], "seedgood", now)
        forged = self.receipt(["sha256:" + "cd" * 32], "seedforged", now, key=signing.generate_keypair()[0])
        tampered = dict(self.receipt(["sha256:" + "ef" * 32], "seedtampered", now))
        tampered["reward_wallet"] = signing.generate_keypair()[1]  # redirect the original's earnings
        future = self.receipt(["sha256:" + "12" * 32], "seedfuture",
                              (datetime.now(timezone.utc) + timedelta(days=2)).isoformat())
        rows = [[r[c] for c in RECEIPT_COLUMNS] for r in (good, forged, tampered, future)]
        result = ingest_rows("originality_receipts", RECEIPT_COLUMNS, rows, db_path=db)
        self.assertEqual((result["inserted"], result["rejected"]), (1, 3))
        conn = sqlite3.connect(db)
        self.assertEqual([r[0] for r in conn.execute("SELECT seed_id FROM originality_receipts")], ["seedgood"])
        conn.close()

    def test_peers_accept_only_exact_treasury_signed_repost_credits(self):
        wallet = signing.generate_keypair()[1]
        db = test_signed_ledger.new_node("repost_peer_" + uuid.uuid4().hex[:6])

        def mint(amount, priv=TREASURY_PRIV):
            tx = {"id": str(uuid.uuid4()), "sender": blockchain.TREASURY_WALLET_ID, "recipient": wallet,
                  "amount": amount / 100, "amount_cents": amount, "reason": "Repost credit",
                  "timestamp": datetime.now(timezone.utc).isoformat(), "tx_type": blockchain.TX_TYPE_REPOST}
            tx["tx_hash"] = blockchain.compute_tx_hash(tx)
            tx["signer"] = signing.public_key_of(priv)
            tx["signature"] = signing.sign_tx_hash(priv, tx["tx_hash"])
            return tx

        self.assertEqual(blockchain.check_synced_transaction(db, mint(1_500))[0], blockchain.ACCEPTED)
        self.assertEqual(blockchain.check_synced_transaction(db, mint(1_600)),
                         (blockchain.REJECTED, "wrong repost credit amount"))
        self.assertEqual(blockchain.check_synced_transaction(db, mint(1_500, signing.generate_keypair()[0]))[0],
                         blockchain.REJECTED)

    def test_earliest_receipt_wins(self):
        db = test_signed_ledger.new_node("earliest_" + uuid.uuid4().hex[:6])
        data = os.urandom(20_000)
        seeds = []
        for name in ("first", "second"):
            filename = f"{uuid.uuid4().hex[:12]}_{name}.wav"
            (SEEDS_ORIG_DIR / filename).write_bytes(data)
            seed_id = name + uuid.uuid4().hex[:8]
            conn = sqlite3.connect(db)
            conn.execute("INSERT INTO seeds (id, owner, filename, created_at) VALUES (?, ?, ?, ?)",
                         (seed_id, name, filename, "2026-01-01T00:00:00"))
            conn.commit()
            conn.close()
            self.assertIsNone(reposts.process_seed(db, seed_id))  # no receipts on this node yet
            seeds.append(seed_id)
        first, second = seeds
        prints = ["sha256:" + fingerprint.sha256_file(SEEDS_ORIG_DIR / filename)]
        now = datetime.now(timezone.utc)

        def ingest(receipt):
            ingest_rows("originality_receipts", RECEIPT_COLUMNS, [[receipt[c] for c in RECEIPT_COLUMNS]], db_path=db)

        def original_of(seed_id):
            conn = sqlite3.connect(db)
            row = reposts.repost_of(conn, seed_id)
            conn.close()
            return row and row["original_seed_id"]

        # The receipt for "second" arrives first: "first" looks like its repost for now
        ingest(self.receipt(prints, second, (now - timedelta(hours=1)).isoformat(), owner="second"))
        self.assertEqual(original_of(first), second)
        self.assertIsNone(original_of(second))
        # Then the older receipt for "first" arrives: the earliest wins
        ingest(self.receipt(prints, first, (now - timedelta(hours=2)).isoformat(), owner="first"))
        self.assertIsNone(original_of(first))
        self.assertEqual(original_of(second), first)

    # --- share page ---

    def test_share_page_labels_repost_and_escapes(self):
        evil = '<b>x</b>"&' + uuid.uuid4().hex[:6]
        _, evil_token, _ = self.register(name=evil)
        _, bob_token, _ = self.register()
        data = os.urandom(10_000)
        original = self.upload(evil_token, "o.mp4", data)
        copy = self.upload(bob_token, "c.mp4", data)
        page = self.client.get(f"/p/{copy['id']}").text
        self.assertIn(f'Repost of <a href="/p/{original["id"]}">@', page)
        self.assertNotIn("<b>x</b>", page)
        self.assertIn("&lt;b&gt;x&lt;/b&gt;&quot;&amp;", page)
        self.assertNotIn("Rewards verified", page)  # the reposter's wallet isn't the one paid
        original_page = self.client.get(f"/p/{original['id']}").text
        top = original_page[original_page.index('<section class="featured"'):original_page.index('</section>')]
        self.assertNotIn("Repost of", top)  # the copy may appear in the feed below, labelled


if __name__ == "__main__":
    unittest.main(verbosity=2)
