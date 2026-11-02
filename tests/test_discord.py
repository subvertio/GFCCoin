"""
Tests for Discord verification (app_discord.py): codes from the GFC app, the signed /verify
interaction, the one-to-one link, role grants that fail and get retried, unlinking, and losing
phone verification. Discord itself is faked; the requests are signed like Discord signs them.

Run from the repository root:
    python -m unittest discover -s tests -v
"""

import datetime
import json
import os
import sqlite3
import sys
import threading
import time
import unittest
import uuid
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_signed_ledger  # noqa: F401  (sets up the isolated data dir and a test treasury first)
from test_signed_ledger import mark_verified

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

import app_discord  # noqa: E402
import main  # noqa: E402

GUILD, ROLE, VERIFY_CH, OTHER_CH = "1566799981438959616", "1700000000000000001", "1700000000000000002", "1700000000000000003"
KEY = Ed25519PrivateKey.generate()
PUB = KEY.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
ENV = {"GFC_DISCORD_PUBLIC_KEY": PUB, "GFC_DISCORD_APP_ID": "1700000000000000000", "GFC_DISCORD_BOT_TOKEN": "test-bot-token",
       "GFC_DISCORD_GUILD_ID": GUILD, "GFC_DISCORD_ROLE_ID": ROLE, "GFC_DISCORD_VERIFY_CHANNEL_ID": VERIFY_CH}


class FakeDiscord:
    """Records role changes; `fail` makes the next calls raise like an outage; `members` limits who's on the server."""
    def __init__(self):
        self.roles, self.calls, self.logs, self.fail, self.members = set(), [], [], False, None

    def set_role(self, discord_user_id, on, reason):
        self.calls.append((discord_user_id, on))
        if self.fail:
            raise app_discord.DiscordError("role grant failed: HTTP 503")
        if self.members is not None and discord_user_id not in self.members:
            return app_discord.LEFT
        (self.roles.add if on else self.roles.discard)(discord_user_id)
        return app_discord.GRANTED if on else app_discord.REMOVED

    def log(self, text):
        self.logs.append(text)


class DiscordTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(main.app)

    def setUp(self):
        self.env = mock.patch.dict(os.environ, ENV)
        self.env.start()
        self.fake = FakeDiscord()
        # Every client the module makes is the fake: only set_role and log reach "Discord"
        self.patches = [mock.patch.object(app_discord.DiscordClient, "set_role", lambda _s, *a: self.fake.set_role(*a)),
                        mock.patch.object(app_discord.DiscordClient, "log", lambda _s, t: self.fake.log(t))]
        for p in self.patches:
            p.start()
        app_discord._failed.clear()
        app_discord._commands.clear()
        conn = sqlite3.connect(main.DB_PATH)  # each test starts with no links: reconcile() sees only its own
        app_discord.init_tables(conn)
        conn.execute("DELETE FROM discord_links")
        conn.commit()
        conn.close()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        self.env.stop()

    # ------------------------------------------------------------ helpers

    def account(self, verified=True):
        name = "Dc" + uuid.uuid4().hex[:9]
        token = self.client.post("/auth/register", data={"username": name, "password": "pw-" + name}).json()["token"]
        if verified:
            mark_verified(main.DB_PATH, name)
        return name, {"Authorization": f"Bearer {token}"}

    def code(self, h):
        return self.client.post("/discord/code", headers=h)

    def signed(self, payload, key=KEY, ts=None):
        body = json.dumps(payload).encode()
        ts = str(int(time.time()) if ts is None else ts)
        sig = key.sign(ts.encode() + body).hex()
        return self.client.post("/discord/interactions", content=body,
                                headers={"X-Signature-Ed25519": sig, "X-Signature-Timestamp": ts,
                                         "Content-Type": "application/json"})

    def verify(self, code, discord_id=None, guild=GUILD, channel=VERIFY_CH):
        discord_id = discord_id or str(10**17 + uuid.uuid4().int % 10**17)
        r = self.signed({"type": 2, "guild_id": guild, "channel_id": channel,
                         "member": {"user": {"id": discord_id, "username": "tester"}},
                         "data": {"name": "verify", "options": [{"name": "code", "value": code}]}})
        self.assertEqual(r.status_code, 200)
        data = r.json()["data"]
        self.assertEqual(data["flags"], app_discord.EPHEMERAL)  # never visible to the channel
        return discord_id, data["content"]

    def links(self, username):
        conn = sqlite3.connect(main.DB_PATH)
        try:
            return conn.execute("SELECT discord_user_id, role_state, ended_at FROM discord_links WHERE username = ? "
                                "ORDER BY id", (username,)).fetchall()
        finally:
            conn.close()

    # ------------------------------------------------------------ issuing codes

    def test_codes_need_a_full_login_and_a_verified_phone(self):
        self.assertEqual(self.client.post("/discord/code").status_code, 401)
        _, unverified = self.account(verified=False)
        self.assertEqual(self.code(unverified).status_code, 403)
        name, h = self.account()
        limited = self.client.post("/auth/tokens", headers=h, data={"password": "pw-" + name, "scopes": "read"}).json()["token"]
        self.assertEqual(self.code({"Authorization": f"Bearer {limited}"}).status_code, 403)
        r = self.code(h).json()
        self.assertRegex(r["code"], r"^GFC-[2-9A-Z]{4}-[2-9A-Z]{4}$")
        self.assertEqual(r["expiresIn"], 600)

    def test_codes_are_stored_hashed_and_a_new_one_replaces_the_old(self):
        name, h = self.account()
        first, second = self.code(h).json()["code"], self.code(h).json()["code"]
        conn = sqlite3.connect(main.DB_PATH)
        stored = [r[0] for r in conn.execute("SELECT code_hash FROM discord_codes WHERE username = ?", (name,))]
        conn.close()
        self.assertNotIn(first, stored)
        self.assertNotIn(second, stored)
        self.assertIn("isn't valid", self.verify(first)[1])
        self.assertIn("verified as GFC member", self.verify(second)[1])

    def test_switched_off_until_configured(self):
        name, h = self.account()
        with mock.patch.dict(os.environ, {"GFC_DISCORD_BOT_TOKEN": ""}):
            self.assertEqual(self.code(h).status_code, 503)
            self.assertFalse(self.client.get("/discord/status", headers=h).json()["available"])

    # ------------------------------------------------------------ the signed interaction

    def test_requests_not_signed_by_discord_are_refused(self):
        self.assertEqual(self.signed({"type": 1}, key=Ed25519PrivateKey.generate()).status_code, 401)
        self.assertEqual(self.signed({"type": 1}, ts=int(time.time()) - 3600).status_code, 401)  # replayed later
        self.assertEqual(self.client.post("/discord/interactions", json={"type": 1}).status_code, 401)
        self.assertEqual(self.signed({"type": 1}).json(), {"type": 1})  # Discord's endpoint check

    def test_verify_links_the_account_and_grants_only_the_role(self):
        name, h = self.account()
        did, text = self.verify(self.code(h).json()["code"])
        self.assertIn(name, text)
        self.assertEqual(self.fake.roles, {did})
        self.assertEqual(self.links(name), [(did, app_discord.GRANTED, None)])
        st = self.client.get("/discord/status", headers=h).json()
        self.assertTrue(st["linked"])
        self.assertEqual(st["role"], app_discord.GRANTED)
        self.assertFalse(any("GFC-" in m for m in self.fake.logs))  # codes never reach the log channel

    def test_a_code_works_once_and_expires(self):
        name, h = self.account()
        code = self.code(h).json()["code"]
        self.verify(code)
        _, again = self.verify(code)
        self.assertIn("isn't valid", again)
        other, h2 = self.account()
        late = self.code(h2).json()["code"]
        future = datetime.datetime.now(datetime.timezone.utc) + app_discord.CODE_TTL + datetime.timedelta(seconds=5)
        with mock.patch.object(app_discord, "_now", return_value=future):
            _, text = self.verify(late)
        self.assertIn("isn't valid", text)
        self.assertEqual(self.links(other), [])

    def test_concurrent_redemptions_link_once(self):
        name, h = self.account()
        code = app_discord.app_connect.normalize(self.code(h).json()["code"])
        results = []

        def go(did):
            results.append(app_discord.redeem(code, did, "racer", GUILD)[0])

        threads = [threading.Thread(target=go, args=(str(10**17 + i),)) for i in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(sorted(results).count("linked"), 1)
        self.assertEqual(len(self.links(name)), 1)

    def test_one_account_per_discord_user_and_one_discord_user_per_account(self):
        a, ha = self.account()
        b, hb = self.account()
        did, _ = self.verify(self.code(ha).json()["code"])
        _, text = self.verify(self.code(hb).json()["code"], discord_id=did)  # same Discord user, second account
        self.assertIn("already linked to a GFC account", text)
        self.assertEqual(self.links(b), [])
        self.assertEqual(self.code(ha).status_code, 409)  # A can't get a code while linked

    def test_wrong_server_or_channel_does_nothing(self):
        name, h = self.account()
        code = self.code(h).json()["code"]
        self.assertIn("only works in the GFC Discord", self.verify(code, guild="999")[1])
        self.assertIn(f"<#{VERIFY_CH}>", self.verify(code, channel=OTHER_CH)[1])
        self.assertEqual(self.links(name), [])
        self.assertIn("verified as GFC member", self.verify(code)[1])  # the code still works where it should

    def test_too_many_wrong_codes_lock_the_discord_user_out(self):
        did = str(10**17 + 42)
        for _ in range(app_discord.FAILED_TRIES_PER_DISCORD_USER):
            self.verify("GFC-AAAA-AAAA", discord_id=did)
        name, h = self.account()
        _, text = self.verify(self.code(h).json()["code"], discord_id=did)
        self.assertIn("Too many wrong codes", text)
        self.assertEqual(self.links(name), [])

    def test_a_phone_check_lost_before_redeeming_grants_nothing(self):
        name, h = self.account()
        code = self.code(h).json()["code"]
        conn = sqlite3.connect(main.DB_PATH)
        conn.execute("DELETE FROM phone_verifications WHERE username = ?", (name,))
        conn.commit()
        conn.close()
        self.assertIn("doesn't have a verified phone", self.verify(code)[1])
        self.assertEqual(self.fake.roles, set())

    # ------------------------------------------------------------ failures, unlinking, revocation

    def test_a_failed_role_grant_is_retried_by_the_next_pass(self):
        name, h = self.account()
        self.fake.fail = True
        did, text = self.verify(self.code(h).json()["code"])
        self.assertIn("within a few minutes", text)
        self.assertEqual(self.links(name)[0][1], app_discord.PENDING)
        app_discord.reconcile()  # still down: nothing changes, nothing lost
        self.assertEqual(self.links(name)[0][1], app_discord.PENDING)
        self.fake.fail = False
        app_discord.reconcile()
        self.assertEqual(self.links(name)[0][1], app_discord.GRANTED)
        self.assertEqual(self.fake.roles, {did})

    def test_a_member_who_left_is_granted_again_on_return(self):
        name, h = self.account()
        self.fake.members = set()
        did, _ = self.verify(self.code(h).json()["code"])
        self.assertEqual(self.links(name)[0][1], app_discord.LEFT)
        self.fake.members = {did}
        app_discord.reconcile()
        self.assertEqual(self.fake.roles, {did})

    def test_unlink_removes_the_role_and_allows_a_new_link(self):
        name, h = self.account()
        did, _ = self.verify(self.code(h).json()["code"])
        self.assertTrue(self.client.post("/discord/unlink", headers=h).json()["unlinked"])
        self.assertEqual(self.fake.roles, set())
        self.assertEqual(self.links(name)[0][1:], (app_discord.REMOVED, self.links(name)[0][2]))
        self.assertIsNotNone(self.links(name)[0][2])
        new_did, _ = self.verify(self.code(h).json()["code"])
        self.assertEqual(self.fake.roles, {new_did})

    def test_a_failed_removal_is_retried(self):
        name, h = self.account()
        did, _ = self.verify(self.code(h).json()["code"])
        self.fake.fail = True
        self.client.post("/discord/unlink", headers=h)
        self.assertEqual(self.links(name)[0][1], app_discord.REMOVING)
        self.fake.fail = False
        app_discord.reconcile()
        self.assertEqual(self.links(name)[0][1], app_discord.REMOVED)
        self.assertEqual(self.fake.roles, set())

    def test_losing_phone_verification_ends_the_link(self):
        name, h = self.account()
        did, _ = self.verify(self.code(h).json()["code"])
        conn = sqlite3.connect(main.DB_PATH)
        conn.execute("DELETE FROM phone_verifications WHERE username = ?", (name,))
        conn.commit()
        conn.close()
        app_discord.reconcile()
        self.assertEqual(self.fake.roles, set())
        self.assertIsNotNone(self.links(name)[0][2])

    def test_relinking_the_same_discord_user_keeps_the_role(self):
        name, h = self.account()
        did, _ = self.verify(self.code(h).json()["code"])
        self.fake.fail = True
        self.client.post("/discord/unlink", headers=h)  # removal fails: left for the next pass
        self.fake.fail = False
        self.verify(self.code(h).json()["code"], discord_id=did)  # linked again first
        app_discord.reconcile()  # the old removal must not take the new link's role away
        self.assertEqual(self.fake.roles, {did})


if __name__ == "__main__":
    unittest.main(verbosity=2)
