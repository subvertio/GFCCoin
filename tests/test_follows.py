"""
Tests for follows (app_follows.py): follow and unfollow creators, the Following feed, and the
follow state on feed items and profiles.

Run from the repository root:
    python -m unittest discover -s tests -v
"""

import os
import sys
import unittest
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_signed_ledger  # noqa: F401  (sets up the isolated data dir and a test treasury first)

from fastapi.testclient import TestClient  # noqa: E402

import config  # noqa: E402
import main  # noqa: E402


class FollowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(main.app)

    def setUp(self):
        self.saved = config.REQUIRE_PHONE_TO_POST
        config.REQUIRE_PHONE_TO_POST = False

    def tearDown(self):
        config.REQUIRE_PHONE_TO_POST = self.saved

    def account(self):
        name = "f" + uuid.uuid4().hex[:10]
        token = self.client.post("/auth/register", data={"username": name, "password": "pw-" + name}).json()["token"]
        self.client.post("/wallets/create", data={"name": "main", "api_token": token})
        return name, {"Authorization": f"Bearer {token}"}

    def post(self, headers, title):
        r = self.client.post("/seeds/upload", data={"title": title}, headers=headers,
                             files={"file": ("pic.png", os.urandom(2048), "image/png")})
        self.assertEqual(r.status_code, 200, r.text)
        return r.json()["id"]

    def test_follow_shows_up_in_feeds_and_profile_and_unfollow_undoes_it(self):
        creator, creator_h = self.account()
        other, other_h = self.account()
        fan, fan_h = self.account()
        mine = self.post(creator_h, "Creator post")
        theirs = self.post(other_h, "Someone else")

        self.assertEqual(self.client.get("/feed/following", headers=fan_h).json()["items"], [])
        r = self.client.post(f"/users/{creator.upper()}/follow", headers=fan_h)  # any case works
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual((r.json()["username"], r.json()["followed_by_me"], r.json()["followers"]), (creator, True, 1))
        self.assertEqual(self.client.post(f"/users/{creator}/follow", headers=fan_h).json()["followers"], 1)  # twice is fine

        ids = [i["id"] for i in self.client.get("/feed/following", headers=fan_h).json()["items"]]
        self.assertIn(mine, ids)
        self.assertNotIn(theirs, ids)
        feed = {i["id"]: i for i in self.client.get("/feed", headers=fan_h).json()["items"]}
        self.assertTrue(feed[mine]["following"])
        self.assertFalse(feed[theirs]["following"])
        self.assertEqual([u["username"] for u in self.client.get("/following", headers=fan_h).json()["users"]], [creator])

        profile = self.client.get(f"/users/{creator}", headers=fan_h).json()
        self.assertEqual((profile["followers"], profile["following"], profile["followed_by_me"]), (1, 0, True))
        self.assertFalse(self.client.get(f"/users/{creator}").json()["followed_by_me"])  # logged out
        self.assertEqual(self.client.get(f"/users/{fan}").json()["following"], 1)

        # Bookmarks say it too
        self.client.post(f"/seeds/{mine}/bookmark", headers=fan_h)
        self.assertTrue(self.client.get("/bookmarks", headers=fan_h).json()["items"][0]["following"])

        r = self.client.delete(f"/users/{creator}/follow", headers=fan_h)
        self.assertEqual((r.json()["followed_by_me"], r.json()["followers"]), (False, 0))
        self.assertEqual(self.client.get("/feed/following", headers=fan_h).json()["items"], [])
        self.assertFalse(self.client.get(f"/users/{creator}", headers=fan_h).json()["followed_by_me"])

    def test_follow_needs_login_a_real_account_and_someone_else(self):
        me, h = self.account()
        other, _ = self.account()
        self.assertEqual(self.client.post(f"/users/{other}/follow").status_code, 401)
        self.assertEqual(self.client.post("/users/nobody-here-xyz/follow", headers=h).status_code, 404)
        r = self.client.post(f"/users/{me}/follow", headers=h)
        self.assertEqual(r.status_code, 400)
        self.assertIn("yourself", r.json()["detail"])
        self.assertEqual(self.client.get("/feed/following").json()["items"], [])  # logged out
        self.assertEqual(self.client.get("/following").json()["users"], [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
