"""
Tests for GFC Ads (ads.py, app_ads.py): buying an ad, the uniform-price market, ads in the
feed, instant creator pay per view, refunds, and the things that must not count.

Run from the repository root:
    python -m unittest discover -s tests -v
"""

import os
import sqlite3
import sys
import unittest
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_signed_ledger  # noqa: F401  (sets up the isolated data dir and a test treasury first)
from test_signed_ledger import as_treasury_node, mark_verified

from fastapi.testclient import TestClient  # noqa: E402

import ads  # noqa: E402
import blockchain  # noqa: E402
import config  # noqa: E402
import main  # noqa: E402

GFC = 100  # cents


class AdsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(main.app)
        cls.db = main.DB_PATH

    def setUp(self):
        self.saved = config.REQUIRE_PHONE_TO_POST
        config.REQUIRE_PHONE_TO_POST = True  # the real network's rules
        conn = sqlite3.connect(self.db)
        ads.init_tables(conn)
        conn.execute("UPDATE ad_campaigns SET status = 'ended' WHERE status = 'active'")  # each test starts clean
        conn.execute("DELETE FROM ad_slots")
        conn.commit()
        conn.close()
        ads.invalidate_market()

    def tearDown(self):
        config.REQUIRE_PHONE_TO_POST = self.saved

    # ---------- helpers ----------

    def account(self, gfc=0):
        name = "ad" + uuid.uuid4().hex[:9]
        token = self.client.post("/auth/register", data={"username": name, "password": "pw-" + name}).json()["token"]
        h = {"Authorization": f"Bearer {token}"}
        mark_verified(self.db, name)
        wallet = self.client.post("/wallets/create", data={"name": "main"}, headers=h).json()["id"]
        if gfc:
            with as_treasury_node():
                blockchain.process_operator_mint(self.db, wallet, gfc * GFC, "Operator grant (other): ads test")
        return name, h, wallet

    def post(self, h, title="post"):
        r = self.client.post("/seeds/upload", data={"title": title}, headers=h,
                             files={"file": ("note.txt", f"{title} {uuid.uuid4().hex}".encode(), "text/plain")})
        self.assertEqual(r.status_code, 200, r.text)
        return r.json()["id"]

    def buy(self, h, wallet, seed, budget=1000, cpm=100, days=7):
        return self.client.post("/ads/campaigns", headers=h, data={
            "seed_id": seed, "wallet_id": wallet, "budget": budget, "max_cpm": cpm, "days": days})

    def balance(self, wallet):
        return blockchain.get_balance_cents(self.db, wallet)

    def feed(self, h):
        ads.invalidate_market()
        return self.client.get("/feed", headers=h).json()["items"]

    def fill_feed(self, n=16):
        _, h, _ = self.account()
        return [self.post(h, f"filler {i}") for i in range(n)]

    # ---------- buying ----------

    def test_buying_an_ad_moves_the_budget_to_the_ads_wallet(self):
        _, h, wallet = self.account(gfc=2000)
        seed = self.post(h)
        start = self.balance(wallet)  # 2,000 plus any sign-up and first post bonuses
        r = self.buy(h, wallet, seed, budget=1000, cpm=150)
        self.assertEqual(r.status_code, 200, r.text)
        c = r.json()
        self.assertEqual((c["status"], c["budget"], c["max_cpm"], c["views"]), ("active", 1000, 150, 0))
        self.assertEqual(self.balance(wallet), start - 1000 * GFC)
        self.assertGreaterEqual(self.balance(ads.ads_wallet(self.db)), 1000 * GFC)
        mine = self.client.get("/ads/campaigns", headers=h).json()
        self.assertEqual(mine["campaigns"][0]["id"], c["id"])
        self.assertEqual(mine["market"]["floor_per_1000_views"], 100)

    def test_buying_rules(self):
        _, h, wallet = self.account(gfc=50)
        seed = self.post(h)
        self.assertIn("lowest price", self.buy(h, wallet, seed, cpm=50).json()["detail"])
        self.assertIn("1 to 30 days", self.buy(h, wallet, seed, days=31).json()["detail"])
        self.assertIn("Insufficient balance", self.buy(h, wallet, seed, budget=10_000_000).json()["detail"])
        _, other_h, _ = self.account()
        theirs = self.post(other_h)
        self.assertIn("your own posts", self.buy(h, wallet, theirs, budget=20).json()["detail"])
        name, unverified_h, w2 = self.account(gfc=100)
        unverified_post = self.post(unverified_h)  # posted while verified; then the verification is gone
        conn = sqlite3.connect(self.db)
        conn.execute("DELETE FROM phone_verifications WHERE username = ?", (name,))
        conn.commit()
        conn.close()
        self.assertIn("Verify your phone", self.buy(unverified_h, w2, unverified_post, budget=20).json()["detail"])

    # ---------- the market ----------

    def test_uniform_price_auction(self):
        conn = sqlite3.connect(self.db)
        conn.execute("INSERT INTO ad_slots (hour, slots) VALUES (?, ?)", (ads._hour(ads._now()), 80))  # 20 per period
        conn.commit()
        conn.close()
        bids = []
        for cpm in (300, 200, 120):
            _, h, wallet = self.account(gfc=5000)
            # Budgets big enough that each wants more than the whole supply
            bids.append(self.buy(h, wallet, self.post(h), budget=4000, cpm=cpm, days=1).json()["id"])
        m = ads.compute_market(self.db)
        self.assertEqual(m["supply"], ads.MIN_SUPPLY_PER_PERIOD)
        self.assertEqual([w["id"] for w in m["winners"]], [bids[0]])  # the top bid takes the slots
        self.assertEqual(m["clearing_cpm_cents"], 200 * GFC)            # and pays the second bid, not its own
        # With plenty of supply everyone wins and the price falls to the floor
        conn = sqlite3.connect(self.db)
        conn.execute("UPDATE ad_slots SET slots = 10000000")
        conn.commit()
        conn.close()
        m = ads.compute_market(self.db)
        self.assertEqual(len(m["winners"]), 3)
        self.assertEqual(m["clearing_cpm_cents"], ads.FLOOR_CPM_CENTS)
        self.assertEqual(self.client.get("/ads/market").json()["price_per_1000_views"], 100)

    # ---------- the feed, views and pay ----------

    def test_ads_in_the_feed_and_instant_pay_for_the_creator_above(self):
        advertiser, ah, awallet = self.account(gfc=500)
        ad_seed = self.post(ah, "Buy my album")
        cid = self.buy(ah, awallet, ad_seed, budget=200, cpm=100).json()["id"]
        _, ch, cwallet = self.account()  # a creator with posts in the feed
        for i in range(ads.AD_EVERY * 2):
            self.post(ch, f"creator post {i}")
        viewer, vh, _ = self.account()

        items = self.feed(vh)
        ad_positions = [i for i, it in enumerate(items) if it.get("ad")]
        self.assertTrue(ad_positions)
        self.assertEqual(ad_positions[0], ads.AD_EVERY)  # after the 8th post
        first = items[ad_positions[0]]
        self.assertEqual((first["id"], first["ad"]["campaign"], first["ad"]["label"]), (ad_seed, cid, "Sponsored"))
        above = items[ad_positions[0] - 1]
        self.assertEqual(above["owner"], ch and above["owner"])  # whoever is above gets paid

        # Logged out: no ads at all
        self.assertFalse([it for it in self.client.get("/feed").json()["items"] if it.get("ad")])
        # The advertiser doesn't see their own ad
        self.assertFalse([it for it in self.feed(ah) if it.get("ad")])

        creator_wallet_above = self._reward_wallet(above["id"])
        before = self.balance(creator_wallet_above)
        r = self.client.post("/ads/view", headers=vh, data={"token": first["ad"]["token"]})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertTrue(r.json()["counted"])
        self.assertEqual(r.json()["creator_paid"], 0.07)        # 70% of 100 GFC / 1,000 views
        self.assertEqual(self.balance(creator_wallet_above), before + 7)  # paid at once, on the ledger
        c = self.client.get("/ads/campaigns", headers=ah).json()["campaigns"][0]
        self.assertEqual((c["views"], c["spent"], c["paid_to_creators"]), (1, 0.1, 0.07))

        # Once per viewer per ad per day
        again = self.client.post("/ads/view", headers=vh, data={"token": first["ad"]["token"]}).json()
        self.assertFalse(again["counted"])
        # A token served to someone else, or tampered with, doesn't count
        _, other_h, _ = self.account()
        self.assertEqual(self.client.post("/ads/view", headers=other_h, data={"token": first["ad"]["token"]}).status_code, 400)
        forged = first["ad"]["token"].replace("|10000|", "|1|")
        self.assertEqual(self.client.post("/ads/view", headers=vh, data={"token": forged}).status_code, 400)

    def _reward_wallet(self, seed_id):
        conn = sqlite3.connect(self.db)
        try:
            return conn.execute("SELECT reward_wallet FROM seeds WHERE id = ?", (seed_id,)).fetchone()[0]
        finally:
            conn.close()

    def test_views_that_pay_no_creator(self):
        advertiser, ah, awallet = self.account(gfc=500)
        ad_seed = self.post(ah)
        cid = self.buy(ah, awallet, ad_seed, budget=100, cpm=100).json()["id"]
        viewer, vh, vwallet = self.account()
        # The post above is the advertiser's own: the view costs, but pays no creator
        exp = int(ads.time.time()) + 600
        token = ads._token(cid, viewer, ad_seed, 10000, exp)
        r = self.client.post("/ads/view", headers=vh, data={"token": token}).json()
        self.assertTrue(r["counted"])
        self.assertEqual(r["creator_paid"], 0)
        # Above the viewer's own post: the viewer can't pay themselves
        own = self.post(vh)
        viewer2_token = ads._token(cid, viewer, own, 10000, exp)
        conn = sqlite3.connect(self.db)
        conn.execute("DELETE FROM ad_views WHERE viewer = ?", (viewer.lower(),))
        conn.commit()
        conn.close()
        before = self.balance(vwallet)
        self.assertEqual(self.client.post("/ads/view", headers=vh, data={"token": viewer2_token}).json()["creator_paid"], 0)
        self.assertEqual(self.balance(vwallet), before)
        # The advertiser's own views never count
        self.assertFalse(self.client.post("/ads/view", headers=ah, data={
            "token": ads._token(cid, advertiser, own, 10000, exp)}).json()["counted"])

    # ---------- ending and refunds ----------

    def test_cancel_refunds_what_is_left(self):
        _, h, wallet = self.account(gfc=300)
        seed = self.post(h)
        start = self.balance(wallet)
        cid = self.buy(h, wallet, seed, budget=200, cpm=100).json()["id"]
        self.assertEqual(self.balance(wallet), start - 200 * GFC)
        c = self.client.post(f"/ads/campaigns/{cid}/cancel", headers=h).json()
        self.assertEqual((c["status"], c["refund"]), ("cancelled", 200))
        self.assertEqual(self.balance(wallet), start)
        # Twice is harmless; someone else can't cancel it
        self.assertEqual(self.client.post(f"/ads/campaigns/{cid}/cancel", headers=h).json()["refund"], 200)
        self.assertEqual(self.balance(wallet), start)
        _, other_h, _ = self.account()
        self.assertEqual(self.client.post(f"/ads/campaigns/{cid}/cancel", headers=other_h).status_code, 404)

    def test_an_ad_ends_when_its_budget_or_time_runs_out(self):
        _, h, wallet = self.account(gfc=100)
        cid = self.buy(h, wallet, self.post(h), budget=10, cpm=100).json()["id"]  # 100 views' worth
        conn = sqlite3.connect(self.db)
        conn.execute("UPDATE ad_campaigns SET spent_mc = ? WHERE id = ?", (10 * GFC * 1000 - 10000, cid))  # one view left
        conn.commit()
        conn.close()
        viewer, vh, _ = self.account()
        r = self.client.post("/ads/view", headers=vh, data={
            "token": ads._token(cid, viewer, "none", 10000, int(ads.time.time()) + 600)}).json()
        self.assertTrue(r["counted"])
        self.assertEqual(ads.campaign(cid, self.db)["status"], "ended")  # spent: ended, nothing to refund
        # Time up: the sweep ends it and refunds
        cid2 = self.buy(h, wallet, self.post(h), budget=50, cpm=100).json()["id"]
        conn = sqlite3.connect(self.db)
        conn.execute("UPDATE ad_campaigns SET ends_at = '2000-01-01T00:00:00+00:00' WHERE id = ?", (cid2,))
        conn.commit()
        conn.close()
        before = self.balance(wallet)
        self.assertGreaterEqual(ads.sweep(self.db), 1)
        self.assertEqual(ads.campaign(cid2, self.db)["status"], "ended")
        self.assertEqual(self.balance(wallet), before + 50 * GFC)

    def test_the_ads_wallet_never_pays_out_more_than_it_took_in(self):
        _, h, wallet = self.account(gfc=1000)
        escrow = ads.ads_wallet(self.db)
        start = self.balance(escrow)
        cid = self.buy(h, wallet, self.post(h), budget=100, cpm=100).json()["id"]
        _, ch, _ = self.account()
        above = self.post(ch)
        for _ in range(5):
            viewer, vh, _ = self.account()
            self.client.post("/ads/view", headers=vh, data={
                "token": ads._token(cid, viewer, above, 10000, int(ads.time.time()) + 600)})
        self.client.post(f"/ads/campaigns/{cid}/cancel", headers=h)
        c = ads.campaign(cid, self.db)
        # In: 100 GFC. Out: 5 x 0.07 to the creator + the refund. Kept: the network's 30%
        self.assertEqual(c["paid_to_creators"], 0.35)
        self.assertEqual(c["refund"], 99.5)
        self.assertEqual(self.balance(escrow) - start, 15)  # 0.15 GFC network share


if __name__ == "__main__":
    unittest.main(verbosity=2)
