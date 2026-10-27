"""
Tests for reports and blocks (moderation.py, app_moderation.py).

Run from the repository root:
    python -m unittest discover -s tests -v
"""

import os
import sqlite3
import unittest
import uuid

# Sets up the isolated data dir and test treasury key before any GFC module loads config
import test_signed_ledger  # noqa: F401
from test_signed_ledger import as_treasury_node

from fastapi.testclient import TestClient  # noqa: E402

import main  # noqa: E402
import moderation  # noqa: E402


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


class ModerationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(main.app)

    def tearDown(self):
        os.environ.pop("GFC_REPORT_HIDE_THRESHOLD", None)

    def register(self):
        name = "m" + uuid.uuid4().hex[:10]
        r = self.client.post("/auth/register", data={"username": name, "password": "pw-" + name})
        self.assertEqual(r.status_code, 200, r.text)
        return name, r.json()["token"]

    def upload(self, token, title="post"):
        files = {"file": ("clip.mp4", os.urandom(20_000), "application/octet-stream")}
        with as_treasury_node():
            r = self.client.post("/seeds/upload", data={"title": title}, files=files, headers=bearer(token))
        self.assertEqual(r.status_code, 200, r.text)
        return r.json()["id"]

    def feed_ids(self, token=None):
        r = self.client.get("/feed", headers=bearer(token) if token else {})
        self.assertEqual(r.status_code, 200, r.text)
        return {item["id"] for item in r.json()["items"]}

    def report(self, token, seed, reason="spam"):
        return self.client.post(f"/seeds/{seed}/report", data={"reason": reason}, headers=bearer(token))

    # ---------- reports ----------

    def test_report_needs_login_and_a_known_reason(self):
        _, owner = self.register()
        seed = self.upload(owner)
        self.assertEqual(self.client.post(f"/seeds/{seed}/report", data={"reason": "spam"}).status_code, 401)
        _, other = self.register()
        self.assertEqual(self.report(other, seed, "boring").status_code, 400)
        self.assertEqual(self.report(other, "nope", "spam").status_code, 404)

    def test_cant_report_own_post(self):
        _, owner = self.register()
        seed = self.upload(owner)
        self.assertEqual(self.report(owner, seed).status_code, 400)

    def test_threshold_hides_everywhere_but_for_the_creator(self):
        os.environ["GFC_REPORT_HIDE_THRESHOLD"] = "2"
        owner_name, owner = self.register()
        seed = self.upload(owner, "reported")
        _, a = self.register()
        _, b = self.register()
        r = self.report(a, seed)
        self.assertEqual(r.json(), {"reported": True, "hidden": False})
        r = self.report(a, seed, "scam")  # the same account again doesn't count twice
        self.assertFalse(r.json()["hidden"])
        self.assertIn(seed, self.feed_ids())
        self.assertTrue(self.report(b, seed).json()["hidden"])

        self.assertNotIn(seed, self.feed_ids())
        self.assertNotIn(seed, self.feed_ids(a))
        self.assertIn(seed, self.feed_ids(owner))  # the creator still sees it
        self.assertEqual(self.client.get(f"/seeds/{seed}").status_code, 410)
        self.assertEqual(self.client.get(f"/p/{seed}").status_code, 410)
        self.assertNotIn(seed, {s["id"] for s in self.client.get("/seeds").json()["items"]})
        self.assertNotIn(seed, {s["id"] for s in self.client.get("/search", params={"q": "reported"}).json()["seeds"]})

        conn = sqlite3.connect(main.DB_PATH)
        try:
            listed = {r["seed_id"]: r for r in moderation.open_reports(conn)}
            self.assertEqual(listed[seed]["reports"], 2)
            self.assertEqual(listed[seed]["status"], "hidden")
            self.assertEqual(listed[seed]["owner"], owner_name)

            # Operator restores it: visible again, and the old reports no longer count
            moderation.set_decision(conn, seed, "restore")
            self.assertIn(seed, self.feed_ids())
            self.assertNotIn(seed, {r["seed_id"] for r in moderation.open_reports(conn)})
        finally:
            conn.close()
        _, c = self.register()
        self.assertFalse(self.report(c, seed).json()["hidden"])  # 1 new report, threshold 2

    def test_operator_remove_and_hide(self):
        _, owner = self.register()
        seed = self.upload(owner)
        conn = sqlite3.connect(main.DB_PATH)
        try:
            moderation.set_decision(conn, seed, "remove")
            self.assertNotIn(seed, self.feed_ids())
            with self.assertRaises(moderation.ModerationError):
                moderation.set_decision(conn, "missing-seed", "remove")
            with self.assertRaises(moderation.ModerationError):
                moderation.set_decision(conn, seed, "delete")
        finally:
            conn.close()

    # ---------- blocks ----------

    def test_block_hides_that_account_only_for_the_blocker(self):
        spammer_name, spammer = self.register()
        seed = self.upload(spammer)
        me_name, me = self.register()
        _, someone = self.register()

        r = self.client.post(f"/users/{spammer_name.upper()}/block", headers=bearer(me))
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["blocked"], spammer_name)
        self.assertNotIn(seed, self.feed_ids(me))
        self.assertIn(seed, self.feed_ids(someone))
        self.assertIn(seed, self.feed_ids())
        self.assertEqual(self.client.get("/users/me/blocks", headers=bearer(me)).json()["blocked"], [spammer_name])

        self.assertEqual(self.client.delete(f"/users/{spammer_name}/block", headers=bearer(me)).status_code, 200)
        self.assertIn(seed, self.feed_ids(me))
        self.assertEqual(self.client.get("/users/me/blocks", headers=bearer(me)).json()["blocked"], [])

    def test_block_rules(self):
        me_name, me = self.register()
        self.assertEqual(self.client.post(f"/users/{me_name}/block", headers=bearer(me)).status_code, 400)
        self.assertEqual(self.client.post("/users/nobody-here-xyz/block", headers=bearer(me)).status_code, 404)
        self.assertEqual(self.client.post(f"/users/{me_name}/block").status_code, 401)


if __name__ == "__main__":
    unittest.main()
