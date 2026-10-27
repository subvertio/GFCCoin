"""
Tests for phone verification and the reward rules that depend on it: grants
only after verification, play rewards only from verified, aged viewers, and a
daily cap per creator. Uses the fake SMS provider; Twilio is never called.

Run from the repository root:
    python -m unittest discover -s tests -v
"""

import hashlib
import os
import sqlite3
import unittest
import uuid
from datetime import datetime, timedelta, timezone

import httpx

# Shares the isolated data dir, treasury env and fake provider set up by the ledger tests
from test_signed_ledger import FAKE_SMS, backdate_user, unique_phone

from fastapi.testclient import TestClient  # noqa: E402
import blockchain  # noqa: E402
import main  # noqa: E402
import phone_verify  # noqa: E402
from sync_ingest import SYNCABLE_TABLES, select_rows_since  # noqa: E402


def name(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:8]}"


class PhoneVerifyTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(main.app)
        phone_verify.set_verifier(FAKE_SMS)

    def register(self, username=None):
        username = username or name("user")
        r = self.client.post("/auth/register", data={"username": username, "password": "pw-" + username})
        self.assertEqual(r.status_code, 200, r.text)
        return username, r.json()["token"]

    def start(self, token, phone):
        return self.client.post("/verify/phone/start", data={"api_token": token, "phone": phone})

    def check(self, token, phone, code):
        return self.client.post("/verify/phone/check", data={"api_token": token, "phone": phone, "code": code})

    def verify(self, token, phone=None):
        phone = phone or unique_phone()
        self.assertEqual(self.start(token, phone).status_code, 200)
        r = self.check(token, phone, FAKE_SMS.sent[phone])
        self.assertTrue(r.json()["verified"], r.text)
        return r.json()

    def wallet(self, token):
        r = self.client.post("/wallets/create", data={"name": "main", "api_token": token})
        self.assertEqual(r.status_code, 200, r.text)
        return r.json()

    def balance(self, wallet_id):
        return blockchain.get_balance_cents(main.DB_PATH, wallet_id)

    def is_verified(self, username):
        conn = sqlite3.connect(main.DB_PATH)
        try:
            return phone_verify.is_verified(conn, username)
        finally:
            conn.close()


class VerificationFlowTests(PhoneVerifyTestCase):

    def test_right_and_wrong_code(self):
        user, token = self.register()
        phone = unique_phone()
        self.assertEqual(self.start(token, phone).status_code, 200)
        code = FAKE_SMS.sent[phone]
        wrong = "000000" if code != "000000" else "111111"
        r = self.check(token, phone, wrong)
        self.assertEqual(r.status_code, 200)
        self.assertFalse(r.json()["verified"])
        self.assertFalse(self.is_verified(user))
        self.assertTrue(self.check(token, phone, code).json()["verified"])
        self.assertTrue(self.is_verified(user))

    def test_check_without_start_or_for_other_number(self):
        _, token = self.register()
        phone = unique_phone()
        self.assertEqual(self.check(token, phone, "123456").status_code, 400)
        self.start(token, phone)
        self.assertEqual(self.check(token, unique_phone(), FAKE_SMS.sent[phone]).status_code, 400)

    def test_too_many_wrong_codes_needs_new_start(self):
        _, token = self.register()
        phone = unique_phone()
        self.start(token, phone)
        code = FAKE_SMS.sent[phone]
        for _ in range(phone_verify.MAX_CHECKS_PER_START):
            self.assertFalse(self.check(token, phone, "x").json()["verified"])
        self.assertEqual(self.check(token, phone, code).status_code, 400)

    def test_requires_login(self):
        self.assertEqual(self.start("bogus-token", unique_phone()).status_code, 401)
        self.assertEqual(self.check("bogus-token", unique_phone(), "1").status_code, 401)

    def test_bad_number_and_voip_refused(self):
        _, token = self.register()
        self.assertEqual(self.start(token, "555-0123").status_code, 400)  # too short (10 digits are taken as +1)
        voip = unique_phone()
        FAKE_SMS.voip_numbers.add(voip)
        self.assertEqual(self.start(token, voip).status_code, 400)
        self.assertNotIn(voip, FAKE_SMS.sent)

    def test_normalize_phone(self):
        self.assertEqual(phone_verify.normalize_phone("+1 (415) 555-0123"), "+14155550123")
        self.assertEqual(phone_verify.normalize_phone("0044 20 7946 0958"), "+442079460958")
        # No + means US/Canada
        self.assertEqual(phone_verify.normalize_phone("415-555-0123"), "+14155550123")
        self.assertEqual(phone_verify.normalize_phone("(415) 555 0123"), "+14155550123")
        self.assertEqual(phone_verify.normalize_phone("1 415 555 0123"), "+14155550123")
        for bad in ("", "+0123456789", "+1", "+1415555012x", "555-0123", "4155550123x", "2415550123456"):
            with self.assertRaises(phone_verify.VerifyError, msg=bad):
                phone_verify.normalize_phone(bad)
        self.assertEqual(phone_verify.phone_hash("+1 415 555 0123"), phone_verify.phone_hash("+14155550123"))


class PhoneUniquenessTests(PhoneVerifyTestCase):

    def test_phone_reused_across_accounts_rejected(self):
        _, token_a = self.register()
        user_b, token_b = self.register()
        phone = "+1555" + str(uuid.uuid4().int)[:7]
        self.verify(token_a, phone)
        # Same number, different formatting
        spaced = phone[:2] + " " + phone[2:5] + "-" + phone[5:]
        r = self.start(token_b, spaced)
        self.assertEqual(r.status_code, 409, r.text)
        self.assertFalse(self.is_verified(user_b))

    def test_reuse_rejected_when_both_started_before_either_finished(self):
        _, token_a = self.register()
        user_b, token_b = self.register()
        phone = unique_phone()
        self.start(token_a, phone)
        code_a = FAKE_SMS.sent[phone]
        self.start(token_b, phone)
        code_b = FAKE_SMS.sent[phone]
        self.assertNotEqual(code_a, code_b)  # second send replaced the first code
        self.assertTrue(self.check(token_b, phone, code_b).json()["verified"])
        self.assertEqual(self.start(token_a, phone).status_code, 409)
        FAKE_SMS.sent[phone] = "424242"  # even with a valid provider code, A can't take the number
        self.assertEqual(self.check(token_a, phone, "424242").status_code, 409)
        self.assertTrue(self.is_verified(user_b))

    def test_one_phone_per_account(self):
        _, token = self.register()
        self.verify(token)
        self.assertEqual(self.start(token, unique_phone()).status_code, 409)

    def test_raw_number_never_stored_or_synced(self):
        user, token = self.register()
        phone = unique_phone()
        self.verify(token, phone)
        digits = phone.lstrip("+")
        with open(main.DB_PATH, "rb") as f:
            raw = f.read()
        self.assertNotIn(digits.encode(), raw)
        self.assertNotIn(digits.encode("utf-16-le"), raw)

        conn = sqlite3.connect(main.DB_PATH)
        stored = conn.execute("SELECT phone_hash FROM phone_verifications WHERE username = ?", (user,)).fetchone()[0]
        self.assertEqual(stored, phone_verify.phone_hash(phone))
        self.assertNotEqual(stored, hashlib.sha256(phone.encode()).hexdigest())  # keyed, not plain
        for table in SYNCABLE_TABLES:
            self.assertFalse(table.startswith("phone_"), table)
            payload = repr([list(r) for r in select_rows_since(conn, table, "", 5000)])
            self.assertNotIn(stored, payload, table)
            self.assertNotIn(digits, payload, table)
        conn.close()

    def test_start_rate_limited_per_user_and_per_phone(self):
        _, token = self.register()
        for _ in range(phone_verify.MAX_STARTS_PER_USER):
            self.assertEqual(self.start(token, unique_phone()).status_code, 200)
        self.assertEqual(self.start(token, unique_phone()).status_code, 429)

        phone = unique_phone()
        for _ in range(phone_verify.MAX_STARTS_PER_PHONE):
            _, t = self.register()
            self.assertEqual(self.start(t, phone).status_code, 200)
        _, t = self.register()
        self.assertEqual(self.start(t, phone).status_code, 429)


class GrantTests(PhoneVerifyTestCase):

    def test_grant_only_after_verification(self):
        user, token = self.register()
        w = self.wallet(token)
        self.assertEqual(w["gfc_balance"], 0.0)
        self.assertEqual(self.balance(w["id"]), 0)
        self.assertIsNone(blockchain.process_user_grant(main.DB_PATH, user, w["id"]))

        result = self.verify(token)
        self.assertEqual(result["grant"], 100.0)
        self.assertEqual(self.balance(w["id"]), blockchain.NEW_USER_GRANT_CENTS)
        # Checking again, or a second wallet, doesn't grant again
        self.assertEqual(self.check(token, unique_phone(), "1").json()["grant"], 0.0)
        self.assertEqual(self.wallet(token)["gfc_balance"], 0.0)
        self.assertEqual(self.balance(w["id"]), blockchain.NEW_USER_GRANT_CENTS)

    def test_verified_before_wallet_gets_grant_at_creation(self):
        _, token = self.register()
        self.assertEqual(self.verify(token)["grant"], 0.0)  # no wallet yet
        self.assertEqual(self.wallet(token)["gfc_balance"], 100.0)


class PlayRewardTests(PhoneVerifyTestCase):

    def creator(self):
        user, token = self.register()
        self.verify(token)
        return user, token, self.wallet(token)

    def viewer(self, verified=True, aged=True):
        user, token = self.register()
        if verified:
            self.verify(token)
        if aged:
            backdate_user(main.DB_PATH, user)
        return user, token

    def upload(self, token):
        files = {"file": ("model.glb", os.urandom(200_000), "model/gltf-binary")}
        r = self.client.post("/seeds/upload", data={"api_token": token, "title": "t"}, files=files)
        self.assertEqual(r.status_code, 200, r.text)
        return r.json()["id"]

    def play(self, token, seed_id):
        return self.client.post(f"/seeds/{seed_id}/played", data={"api_token": token}).json()

    def test_unverified_viewer_play_pays_nothing(self):
        _, ctoken, cwallet = self.creator()
        seed = self.upload(ctoken)
        before = self.balance(cwallet["id"])
        _, unverified = self.viewer(verified=False)
        r = self.play(unverified, seed)
        self.assertFalse(r["credited"])
        self.assertEqual(r["reason"], "viewer phone not verified")
        self.assertEqual(self.balance(cwallet["id"]), before)

    def test_new_account_play_pays_nothing(self):
        _, ctoken, cwallet = self.creator()
        seed = self.upload(ctoken)
        before = self.balance(cwallet["id"])
        user, fresh = self.viewer(aged=False)
        r = self.play(fresh, seed)
        self.assertEqual(r["reason"], "viewer account too new")
        backdate_user(main.DB_PATH, user, hours=23)
        self.assertEqual(self.play(fresh, seed)["reason"], "viewer account too new")
        self.assertEqual(self.balance(cwallet["id"]), before)
        backdate_user(main.DB_PATH, user, hours=25)
        self.assertTrue(self.play(fresh, seed)["credited"])

    def test_daily_cap_per_creator(self):
        _, ctoken, cwallet = self.creator()
        seed1, seed2 = self.upload(ctoken), self.upload(ctoken)
        _, other_token, other_wallet = self.creator()
        other_seed = self.upload(other_token)
        viewer, vtoken = self.viewer()

        before = self.balance(cwallet["id"])
        self.assertTrue(self.play(vtoken, seed1)["credited"])
        paid = self.balance(cwallet["id"]) - before
        self.assertGreater(paid, 0)
        # Same creator, another seed, same day: capped
        r = self.play(vtoken, seed2)
        self.assertFalse(r["credited"])
        self.assertEqual(r["reason"], "daily limit for this creator reached")
        # A different creator is still paid
        self.assertTrue(self.play(vtoken, other_seed)["credited"])
        # Replaying the paid seed doesn't use up or reset anything
        self.assertEqual(self.play(vtoken, seed1)["reason"], "already credited")
        self.assertEqual(self.balance(cwallet["id"]) - before, paid)

        # Next day: seed2 pays; seed1 still never pays twice
        yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).date().isoformat()
        conn = sqlite3.connect(main.DB_PATH)
        conn.execute("UPDATE play_reward_slots SET day = ? WHERE viewer = ?", (yesterday, viewer))
        conn.commit()
        conn.close()
        self.assertEqual(self.play(vtoken, seed1)["reason"], "already credited")
        self.assertTrue(self.play(vtoken, seed2)["credited"])
        self.assertEqual(self.balance(cwallet["id"]) - before, 2 * paid)


# Cloudflare's documented Turnstile test secrets
TURNSTILE_PASS_SECRET = "1x0000000000000000000000000000000AA"
TURNSTILE_FAIL_SECRET = "2x0000000000000000000000000000000AA"


class TurnstileTests(PhoneVerifyTestCase):
    """Turnstile in front of /verify/phone/start, against a mocked siteverify (no network)."""

    def setUp(self):
        self.calls = []

        def siteverify(request):
            form = dict(httpx.QueryParams(request.content.decode()))
            self.calls.append((str(request.url), form))
            # Mirrors Cloudflare: the "1x" test secret always passes, the "2x" one always fails
            ok = form.get("secret") == TURNSTILE_PASS_SECRET and bool(form.get("response"))
            return httpx.Response(200, json={"success": ok, "error-codes": [] if ok else ["invalid-input-response"]})

        phone_verify.set_turnstile_client(httpx.Client(transport=httpx.MockTransport(siteverify)))
        self.addCleanup(phone_verify.set_turnstile_client, httpx.Client(timeout=5.0))
        self.addCleanup(os.environ.pop, "GFC_TURNSTILE_SECRET", None)

    def start_with(self, token, phone, turnstile_token=None):
        data = {"api_token": token, "phone": phone}
        if turnstile_token is not None:
            data["turnstile_token"] = turnstile_token
        return self.client.post("/verify/phone/start", data=data)

    def starts_logged(self, user):
        conn = sqlite3.connect(main.DB_PATH)
        try:
            return conn.execute("SELECT COUNT(*) FROM phone_verify_starts WHERE username = ?", (user,)).fetchone()[0]
        finally:
            conn.close()

    def test_pass(self):
        os.environ["GFC_TURNSTILE_SECRET"] = TURNSTILE_PASS_SECRET
        _, token = self.register()
        phone = unique_phone()
        r = self.start_with(token, phone, "XXXX.DUMMY.TOKEN.XXXX")
        self.assertEqual(r.status_code, 200, r.text)
        self.assertIn(phone, FAKE_SMS.sent)
        url, form = self.calls[0]
        self.assertEqual(url, phone_verify.TURNSTILE_VERIFY_URL)
        self.assertEqual(form["response"], "XXXX.DUMMY.TOKEN.XXXX")
        self.assertIn("remoteip", form)

    def test_fail_sends_nothing_and_uses_no_rate_limit(self):
        os.environ["GFC_TURNSTILE_SECRET"] = TURNSTILE_FAIL_SECRET
        user, token = self.register()
        phone = unique_phone()
        r = self.start_with(token, phone, "XXXX.DUMMY.TOKEN.XXXX")
        self.assertEqual(r.status_code, 403, r.text)
        self.assertNotIn(phone, FAKE_SMS.sent)
        self.assertEqual(self.starts_logged(user), 0)

    def test_missing_token(self):
        os.environ["GFC_TURNSTILE_SECRET"] = TURNSTILE_PASS_SECRET
        user, token = self.register()
        phone = unique_phone()
        self.assertEqual(self.start_with(token, phone).status_code, 403)
        self.assertEqual(self.start_with(token, phone, "").status_code, 403)
        self.assertEqual(self.calls, [])  # rejected without calling Cloudflare
        self.assertNotIn(phone, FAKE_SMS.sent)
        self.assertEqual(self.starts_logged(user), 0)

    def test_cloudflare_unreachable_fails_closed(self):
        os.environ["GFC_TURNSTILE_SECRET"] = TURNSTILE_PASS_SECRET

        def down(request):
            raise httpx.ConnectTimeout("timed out", request=request)

        phone_verify.set_turnstile_client(httpx.Client(transport=httpx.MockTransport(down)))
        _, token = self.register()
        phone = unique_phone()
        self.assertEqual(self.start_with(token, phone, "XXXX.DUMMY.TOKEN.XXXX").status_code, 403)
        self.assertNotIn(phone, FAKE_SMS.sent)

    def test_refusals_say_why_and_log_cloudflares_codes(self):
        os.environ["GFC_TURNSTILE_SECRET"] = TURNSTILE_PASS_SECRET
        cases = [
            (200, {"success": False, "error-codes": ["timeout-or-duplicate"]}, phone_verify.TURNSTILE_EXPIRED),
            (200, {"success": False, "error-codes": ["invalid-input-response"]}, phone_verify.TURNSTILE_REJECTED),
            (200, {"success": False, "error-codes": ["invalid-input-secret"]}, phone_verify.TURNSTILE_MISCONFIGURED),
            (200, {"success": False, "error-codes": ["internal-error"]}, phone_verify.TURNSTILE_UNAVAILABLE),
            (500, {}, phone_verify.TURNSTILE_UNAVAILABLE),
        ]
        for status, body, reason in cases:
            phone_verify.set_turnstile_client(httpx.Client(transport=httpx.MockTransport(
                lambda request, s=status, b=body: httpx.Response(s, json=b))))
            with self.subTest(reason=reason, codes=body.get("error-codes")):
                with self.assertLogs("gfc.phone") as logs:
                    with self.assertRaises(phone_verify.FlowError) as ctx:
                        phone_verify.check_turnstile("XXXX.DUMMY.TOKEN.XXXX", "203.0.113.5")
                self.assertEqual(ctx.exception.status, 403)
                self.assertEqual(ctx.exception.reason, reason)
                for code in body.get("error-codes", []):
                    self.assertIn(code, "\n".join(logs.output))
                self.assertNotIn(TURNSTILE_PASS_SECRET, "\n".join(logs.output))
        with self.assertRaises(phone_verify.FlowError) as ctx:
            phone_verify.check_turnstile("")
        self.assertEqual(ctx.exception.reason, phone_verify.TURNSTILE_MISSING)

    def test_secret_unset_skips_check(self):
        os.environ.pop("GFC_TURNSTILE_SECRET", None)
        _, token = self.register()
        phone = unique_phone()
        self.assertEqual(self.start_with(token, phone).status_code, 200)
        self.assertEqual(self.calls, [])
        self.assertIn(phone, FAKE_SMS.sent)


class TwilioAdapterTests(unittest.TestCase):
    """The Twilio adapter against a mocked transport (no network)."""

    def make(self, handler, lookup=False):
        v = phone_verify.TwilioVerifier("AC_test", "token_test", "VA_test", lookup_line_type=lookup)
        v.client = httpx.Client(auth=("AC_test", "token_test"), transport=httpx.MockTransport(handler))
        return v

    def test_start_and_check(self):
        seen = []

        def handler(request):
            seen.append((request.method, request.url.host, request.url.path, request.content.decode()))
            if request.url.path.endswith("/VerificationCheck"):
                ok = "Code=123456" in request.content.decode()
                return httpx.Response(200, json={"status": "approved" if ok else "pending"})
            return httpx.Response(201, json={"status": "pending"})

        v = self.make(handler)
        v.start("+14155550123")
        self.assertTrue(v.check("+14155550123", "123456"))
        self.assertFalse(v.check("+14155550123", "999999"))
        self.assertEqual(seen[0][1], "verify.twilio.com")
        self.assertEqual(seen[0][2], "/v2/Services/VA_test/Verifications")
        self.assertIn("Channel=sms", seen[0][3])

    def test_lookup_refuses_voip(self):
        def handler(request):
            if request.url.host == "lookups.twilio.com":
                kind = "nonFixedVoip" if request.url.path.endswith("0199") else "mobile"
                return httpx.Response(200, json={"line_type_intelligence": {"type": kind}})
            return httpx.Response(201, json={"status": "pending"})

        v = self.make(handler, lookup=True)
        v.start("+14155550123")
        with self.assertRaises(phone_verify.VerifyError):
            v.start("+14155550199")

    def test_provider_errors_raise(self):
        v = self.make(lambda request: httpx.Response(500))
        with self.assertRaises(phone_verify.VerifyError):
            v.start("+14155550123")

    def test_refusal_logs_twilios_code_and_message(self):
        body = {"code": 60410, "message": "Verification delivery attempt blocked for +14155550123",
                "more_info": "https://www.twilio.com/docs/errors/60410", "status": 403}
        v = self.make(lambda request: httpx.Response(403, json=body))
        with self.assertLogs("gfc.phone", level="WARNING") as logs:
            with self.assertRaises(phone_verify.VerifyError) as ctx:
                v.start("+14155550123")
        self.assertEqual(ctx.exception.provider_code, 60410)
        self.assertIn("Twilio 60410", str(ctx.exception))
        written = "\n".join(logs.output)
        self.assertIn("60410", written)
        self.assertIn("delivery attempt blocked", written)

    def test_refusal_without_a_json_body(self):
        v = self.make(lambda request: httpx.Response(403, text="<html>no</html>"))
        with self.assertRaises(phone_verify.VerifyError) as ctx:
            v.start("+14155550123")
        self.assertIsNone(ctx.exception.provider_code)
        self.assertEqual(str(ctx.exception), "verification provider error (403)")

    def test_lookup_refusal_has_twilios_code(self):
        def handler(request):
            if request.url.host == "lookups.twilio.com":
                return httpx.Response(401, json={"code": 20003, "message": "Authenticate"})
            return httpx.Response(201, json={"status": "pending"})

        with self.assertRaises(phone_verify.VerifyError) as ctx:
            self.make(handler, lookup=True).start("+14155550123")
        self.assertEqual(ctx.exception.provider_code, 20003)


if __name__ == "__main__":
    unittest.main(verbosity=2)


class TwilioCredentialTests(unittest.TestCase):
    """A restricted API key is preferred over the account auth token."""

    VARS = ("TWILIO_ACCOUNT_SID", "TWILIO_AUTH_TOKEN", "TWILIO_API_KEY_SID",
            "TWILIO_API_KEY_SECRET", "TWILIO_VERIFY_SERVICE_SID")

    def setUp(self):
        self.saved = {v: os.environ.pop(v, None) for v in self.VARS}
        self.saved_verifier = phone_verify._verifier

    def tearDown(self):
        for v, val in self.saved.items():
            os.environ.pop(v, None)
            if val is not None:
                os.environ[v] = val
        phone_verify._verifier = self.saved_verifier

    def build(self, **env):
        os.environ.update(env)
        phone_verify._verifier = None
        return phone_verify.get_verifier()

    def test_api_key_preferred(self):
        v = self.build(TWILIO_ACCOUNT_SID="AC1", TWILIO_AUTH_TOKEN="tok", TWILIO_API_KEY_SID="SK1",
                       TWILIO_API_KEY_SECRET="sec", TWILIO_VERIFY_SERVICE_SID="VA1")
        self.assertIsInstance(v, phone_verify.TwilioVerifier)
        self.assertEqual(v.auth_user, "SK1")

    def test_api_key_without_auth_token(self):
        v = self.build(TWILIO_ACCOUNT_SID="AC1", TWILIO_API_KEY_SID="SK1",
                       TWILIO_API_KEY_SECRET="sec", TWILIO_VERIFY_SERVICE_SID="VA1")
        self.assertEqual(v.auth_user, "SK1")

    def test_auth_token_fallback(self):
        v = self.build(TWILIO_ACCOUNT_SID="AC1", TWILIO_AUTH_TOKEN="tok", TWILIO_VERIFY_SERVICE_SID="VA1")
        self.assertEqual(v.auth_user, "AC1")

    def test_incomplete_key_or_missing_service_uses_fake(self):
        self.assertIsInstance(self.build(TWILIO_API_KEY_SID="SK1", TWILIO_VERIFY_SERVICE_SID="VA1"),
                              phone_verify.FakeVerifier)
        os.environ.pop("TWILIO_VERIFY_SERVICE_SID")
        self.assertIsInstance(self.build(TWILIO_API_KEY_SID="SK1", TWILIO_API_KEY_SECRET="sec"),
                              phone_verify.FakeVerifier)
