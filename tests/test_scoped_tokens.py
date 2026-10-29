"""
Tests for front-end auth: Bearer tokens alongside the legacy api_token field,
scoped tokens minted with /auth/tokens (read / post / spend, daily spend limit,
expiry, revocation), and CORS for configured origins only.

Run from the repository root:
    python -m unittest discover -s tests -v
"""

import os
import sqlite3
import unittest
import uuid
from datetime import datetime, timedelta

# Shares the isolated data dir, treasury env and fake provider set up by the ledger tests
from test_signed_ledger import unique_phone, verify_phone

from fastapi.testclient import TestClient  # noqa: E402
import main  # noqa: E402


def name(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:8]}"


def bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


class TokenTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(main.app)

    def register(self, funded=False):
        username = name("user")
        password = "pw-" + username
        r = self.client.post("/auth/register", data={"username": username, "password": password})
        self.assertEqual(r.status_code, 200, r.text)
        token = r.json()["token"]
        wallet = None
        if funded:
            self.assertIn("You're verified", verify_phone(self.client, token, unique_phone()).text)
            w = self.client.post("/wallets/create", headers=bearer(token), data={"name": "main"})
            self.assertEqual(w.status_code, 200, w.text)
            wallet = w.json()["id"]
        return {"user": username, "password": password, "token": token, "wallet": wallet}

    def mint(self, acct, scopes, **form):
        r = self.client.post("/auth/tokens", headers=bearer(acct["token"]),
                             data={"password": acct["password"], "scopes": scopes, **form})
        self.assertEqual(r.status_code, 200, r.text)
        return r.json()

    def transfer(self, token, sender, recipient, amount):
        return self.client.post("/transactions/create", headers=bearer(token), json={
            "sender": sender, "recipient": recipient, "amount": amount, "reason": "test"})

    def upload(self, token):
        files = {"file": ("model.glb", os.urandom(1000), "model/gltf-binary")}
        return self.client.post("/seeds/upload", headers=bearer(token), data={"title": "t"}, files=files)


class BearerAuthTests(TokenTestCase):

    def test_bearer_and_legacy_both_work(self):
        acct = self.register()
        by_header = self.client.get("/users/me", headers=bearer(acct["token"]))
        self.assertEqual(by_header.status_code, 200, by_header.text)
        self.assertEqual(by_header.json()["username"], acct["user"])
        by_query = self.client.get("/users/me", params={"api_token": acct["token"]})
        self.assertEqual(by_query.json()["username"], acct["user"])
        by_form = self.client.post("/users/me", data={"api_token": acct["token"], "bio": "hi"})
        self.assertEqual(by_form.json()["bio"], "hi")
        self.assertEqual(self.client.get("/users/me").status_code, 401)

    def test_header_wins_over_legacy_field(self):
        alice, bob = self.register(), self.register()
        r = self.client.get("/users/me", headers=bearer(alice["token"]), params={"api_token": bob["token"]})
        self.assertEqual(r.json()["username"], alice["user"])
        r = self.client.post("/users/me", headers=bearer(alice["token"]),
                             data={"api_token": bob["token"], "bio": "alice here"})
        self.assertEqual(r.json()["username"], alice["user"])
        # A bad header is not rescued by a good legacy token
        r = self.client.get("/users/me", headers=bearer("not-a-token"), params={"api_token": bob["token"]})
        self.assertEqual(r.status_code, 401)

    def test_header_works_for_json_transfer(self):
        a, b = self.register(funded=True), self.register(funded=True)
        r = self.transfer(a["token"], a["wallet"], b["wallet"], 1.0)
        self.assertEqual(r.status_code, 200, r.text)
        self.assertTrue(r.json()["signed"])
        # Header beats a legacy body token belonging to the recipient
        r = self.client.post("/transactions/create", headers=bearer(b["token"]), json={
            "sender": a["wallet"], "recipient": b["wallet"], "amount": 1.0, "reason": "",
            "api_token": a["token"]})
        self.assertEqual(r.status_code, 403)

    def test_openapi_advertises_bearer(self):
        schemes = self.client.get("/openapi.json").json()["components"]["securitySchemes"]
        self.assertIn("HTTPBearer", schemes)


class ScopedTokenTests(TokenTestCase):

    def test_mint_needs_full_token_and_password(self):
        acct = self.register()
        r = self.client.post("/auth/tokens", headers=bearer(acct["token"]),
                             data={"password": "wrong", "scopes": "read"})
        self.assertEqual(r.status_code, 401)
        limited = self.mint(acct, "read post")["token"]
        r = self.client.post("/auth/tokens", headers=bearer(limited),
                             data={"password": acct["password"], "scopes": "read"})
        self.assertEqual(r.status_code, 403)
        r = self.client.post("/auth/tokens", headers=bearer(acct["token"]),
                             data={"password": acct["password"], "scopes": "read admin"})
        self.assertEqual(r.status_code, 400)

    def test_read_only_token_cannot_post_spend_or_export(self):
        acct = self.register(funded=True)
        other = self.register(funded=True)
        minted = self.mint(acct, "read", label="viewer")
        self.assertEqual(minted["scopes"], ["read"])
        token = minted["token"]

        self.assertEqual(self.client.get("/users/me", headers=bearer(token)).status_code, 200)
        self.assertEqual(self.client.get("/feed", headers=bearer(token)).status_code, 200)
        self.assertEqual(self.client.get("/bookmarks", headers=bearer(token)).status_code, 200)

        self.assertEqual(self.upload(token).status_code, 403)
        self.assertEqual(self.client.post("/users/me", headers=bearer(token), data={"bio": "x"}).status_code, 403)
        self.assertEqual(self.client.post("/seeds/abc/like", headers=bearer(token)).status_code, 403)
        self.assertEqual(self.client.post("/seeds/abc/comments", headers=bearer(token),
                                          data={"text": "hi"}).status_code, 403)
        self.assertEqual(self.client.post("/wallets/create", headers=bearer(token)).status_code, 403)
        self.assertEqual(self.transfer(token, acct["wallet"], other["wallet"], 1.0).status_code, 403)
        r = self.client.post("/wallets/export", headers=bearer(token), data={
            "password": acct["password"], "backup_passphrase": "a long backup passphrase"})
        self.assertEqual(r.status_code, 403)
        # Read-only tokens never get a wrap of the data key
        conn = sqlite3.connect(main.DB_PATH)
        wrap = conn.execute("SELECT dk_wrap FROM sessions WHERE substr(token_hash, 1, 16) = ?",
                            (minted["id"],)).fetchone()[0]
        conn.close()
        self.assertFalse(wrap)

    def test_post_token_signs_seeds_but_cannot_transfer(self):
        acct = self.register(funded=True)
        other = self.register(funded=True)
        token = self.mint(acct, "read,post")["token"]
        r = self.upload(token)
        self.assertEqual(r.status_code, 200, r.text)
        self.assertTrue(r.json()["rewards_enabled"])  # signed with the wallet key
        self.assertEqual(self.client.post(f"/seeds/{r.json()['id']}/like", headers=bearer(token))
                         .status_code, 200)
        self.assertEqual(self.transfer(token, acct["wallet"], other["wallet"], 1.0).status_code, 403)
        r = self.client.post("/wallets/export", headers=bearer(token), data={
            "password": acct["password"], "backup_passphrase": "a long backup passphrase"})
        self.assertEqual(r.status_code, 403)

    def test_spend_token_signs_transfers_within_daily_limit(self):
        acct = self.register(funded=True)
        other = self.register(funded=True)
        token = self.mint(acct, "spend", spend_limit_cents=500)["token"]
        self.assertEqual(self.transfer(token, acct["wallet"], other["wallet"], 3.0).status_code, 200)
        over = self.transfer(token, acct["wallet"], other["wallet"], 2.5)
        self.assertEqual(over.status_code, 403)
        self.assertIn("limit", over.json()["detail"])
        self.assertEqual(self.transfer(token, acct["wallet"], other["wallet"], 2.0).status_code, 200)
        self.assertEqual(self.transfer(token, acct["wallet"], other["wallet"], 0.01).status_code, 403)
        # The full-scope token has no limit
        self.assertEqual(self.transfer(acct["token"], acct["wallet"], other["wallet"], 10.0).status_code, 200)

        listed = self.client.get("/auth/tokens", headers=bearer(acct["token"])).json()["tokens"]
        limited = [t for t in listed if t["spend_limit_cents"] == 500]
        self.assertEqual(limited[0]["spent_today_cents"], 500)

    def test_failed_transfer_does_not_use_up_limit(self):
        acct = self.register(funded=True)
        other = self.register(funded=True)
        minted = self.mint(acct, "spend", spend_limit_cents=50_000)
        too_much = self.transfer(minted["token"], acct["wallet"], other["wallet"], 200.0)  # balance is 100
        self.assertEqual(too_much.status_code, 400)
        listed = self.client.get("/auth/tokens", headers=bearer(acct["token"])).json()["tokens"]
        self.assertEqual(next(t for t in listed if t["id"] == minted["id"])["spent_today_cents"], 0)

    def test_list_and_revoke(self):
        acct = self.register()
        minted = self.mint(acct, "read", label="my web app")
        listed = self.client.get("/auth/tokens", headers=bearer(acct["token"])).json()["tokens"]
        self.assertEqual({t["id"] for t in listed} >= {minted["id"]}, True)
        self.assertTrue(any(t["current"] for t in listed))
        self.assertNotIn(minted["token"], str(listed))
        # Limited tokens can't list or revoke others
        self.assertEqual(self.client.get("/auth/tokens", headers=bearer(minted["token"])).status_code, 403)

        r = self.client.delete(f"/auth/tokens/{minted['id']}", headers=bearer(acct["token"]))
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(self.client.get("/users/me", headers=bearer(minted["token"])).status_code, 401)
        self.assertEqual(self.client.delete(f"/auth/tokens/{minted['id']}",
                                            headers=bearer(acct["token"])).status_code, 404)

    def test_token_can_revoke_itself_but_not_others_tokens(self):
        alice, bob = self.register(), self.register()
        a_limited = self.mint(alice, "read")
        b_limited = self.mint(bob, "read")
        self.assertEqual(self.client.delete(f"/auth/tokens/{b_limited['id']}",
                                            headers=bearer(alice["token"])).status_code, 404)
        r = self.client.delete(f"/auth/tokens/{a_limited['id']}", headers=bearer(a_limited["token"]))
        self.assertEqual(r.status_code, 200)
        self.assertEqual(self.client.get("/users/me", headers=bearer(a_limited["token"])).status_code, 401)
        self.assertEqual(self.client.get("/users/me", headers=bearer(b_limited["token"])).status_code, 200)

    def test_expired_token_rejected(self):
        acct = self.register()
        minted = self.mint(acct, "read", expires_in_days=1)
        self.assertEqual(self.client.get("/users/me", headers=bearer(minted["token"])).status_code, 200)
        conn = sqlite3.connect(main.DB_PATH)
        conn.execute("UPDATE sessions SET expires_at = ? WHERE substr(token_hash, 1, 16) = ?",
                     ((datetime.utcnow() - timedelta(seconds=1)).isoformat(), minted["id"]))
        conn.commit()
        conn.close()
        self.assertEqual(self.client.get("/users/me", headers=bearer(minted["token"])).status_code, 401)
        bad = self.client.post("/auth/tokens", headers=bearer(acct["token"]),
                               data={"password": acct["password"], "scopes": "read", "expires_in_days": 1000})
        self.assertEqual(bad.status_code, 400)


class CorsTests(unittest.TestCase):
    ALLOWED = "https://my-frontend.example"

    def client_with(self, origins):
        """Rebuild the app's middleware stack so NodeCORSMiddleware rereads GFC_CORS_ORIGINS."""
        saved = os.environ.get("GFC_CORS_ORIGINS")

        def restore():
            if saved is None:
                os.environ.pop("GFC_CORS_ORIGINS", None)
            else:
                os.environ["GFC_CORS_ORIGINS"] = saved
            main.app.middleware_stack = None
        self.addCleanup(restore)
        if origins is None:
            os.environ.pop("GFC_CORS_ORIGINS", None)
        else:
            os.environ["GFC_CORS_ORIGINS"] = origins
        main.app.middleware_stack = None
        return TestClient(main.app)

    def preflight(self, client, origin):
        return client.options("/feed", headers={"Origin": origin, "Access-Control-Request-Method": "GET",
                                                "Access-Control-Request-Headers": "authorization"})

    def test_no_cors_by_default(self):
        client = self.client_with(None)
        r = client.get("/health", headers={"Origin": self.ALLOWED})
        self.assertNotIn("access-control-allow-origin", r.headers)
        self.assertNotIn("access-control-allow-origin", self.preflight(client, self.ALLOWED).headers)

    def test_only_configured_origins(self):
        client = self.client_with(f"{self.ALLOWED}/, https://other.example")
        r = client.get("/health", headers={"Origin": self.ALLOWED})
        self.assertEqual(r.headers.get("access-control-allow-origin"), self.ALLOWED)
        pre = self.preflight(client, self.ALLOWED)
        self.assertEqual(pre.status_code, 200)
        self.assertIn("authorization", pre.headers.get("access-control-allow-headers", "").lower())
        self.assertNotIn("access-control-allow-credentials", r.headers)

        evil = client.get("/health", headers={"Origin": "https://evil.example"})
        self.assertNotIn("access-control-allow-origin", evil.headers)
        self.assertNotIn("access-control-allow-origin", self.preflight(client, "https://evil.example").headers)


if __name__ == "__main__":
    unittest.main()
