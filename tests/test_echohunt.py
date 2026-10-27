"""
Tests for Echo Hunt (the 3D-audio anti-bot game), Play Integrity verdict checks,
and the optional Echo Hunt gate on rewarded plays. Uses the fake integrity
verifier; Google is never called.

Run from the repository root:
    python -m unittest discover -s tests -v
"""

import base64
import json
import os
import random
import sqlite3
import unittest
from datetime import datetime, timedelta, timezone

import httpx

# Shares the isolated data dir, treasury env and fake SMS provider set up by the ledger tests
import test_signed_ledger  # noqa: F401
import test_phone_verify

from fastapi.testclient import TestClient  # noqa: E402
import echohunt  # noqa: E402
import main  # noqa: E402
import play_integrity  # noqa: E402
from sync_ingest import SYNCABLE_TABLES  # noqa: E402


# ============================================================================
# TRACE GENERATORS
# ============================================================================

def human_trace(target_az, target_el, tap_ms=1500, seed=1, aim_error=0.0):
    """
    A hand turning a phone: a reaction pause, then a minimum-jerk turn to the
    target (shortest way round), with sensor noise and uneven sample intervals.
    """
    rng = random.Random(seed)
    turn = ((target_az + aim_error + 180) % 360) - 180  # signed shortest yaw turn
    pause, move_end = 280.0, tap_ms - 120.0
    samples, t = [], rng.uniform(5, 15)
    while t < tap_ms - 5:
        if t < pause:
            x = 0.0
        else:
            tau = min(1.0, (t - pause) / (move_end - pause))
            x = 10 * tau ** 3 - 15 * tau ** 4 + 6 * tau ** 5
        az = (turn * x + rng.gauss(0, 0.3)) % 360
        el = target_el * x + rng.gauss(0, 0.3)
        samples.append([round(t, 1), round(az, 2), round(el, 2)])
        t += rng.uniform(14, 24)
    last = samples[-1]
    return {"tap_ms": tap_ms, "facing": {"azimuth": last[1], "elevation": last[2]}, "samples": samples}


def straight_trace(target_az, target_el, tap_ms=1500, noise=0.0, seed=1):
    """A synthetic sweep: progress exactly proportional to time, evenly sampled."""
    rng = random.Random(seed)
    turn = ((target_az + 180) % 360) - 180
    samples = []
    for i in range(int(tap_ms // 16)):
        t = 10 + i * 16
        x = (t - 10) / (tap_ms - 20)
        samples.append([t, (turn * x + rng.gauss(0, noise)) % 360, target_el * x + rng.gauss(0, noise)])
    last = samples[-1]
    return {"tap_ms": tap_ms, "facing": {"azimuth": last[1], "elevation": last[2]}, "samples": samples}


def human_rounds(challenge_rounds, **kw):
    return [human_trace(r["azimuth"], r["elevation"], seed=i, **kw) for i, r in enumerate(challenge_rounds)]


TARGET = {"azimuth": 210, "elevation": 10, "sound": "owl", "start_delay_ms": 1000}


# ============================================================================
# PURE SCORING
# ============================================================================

class ScoringTests(unittest.TestCase):

    def test_human_trace_passes(self):
        for seed in range(20):
            rng = random.Random(seed)
            target = dict(TARGET, azimuth=rng.randint(45, 315), elevation=rng.randint(-10, 20))
            sub = echohunt.parse_round(human_trace(target["azimuth"], target["elevation"],
                                                   tap_ms=rng.randint(900, 4000), seed=seed))
            self.assertIsNone(echohunt.score_round(target, sub), f"seed {seed}")

    def test_wrong_direction_fails(self):
        sub = echohunt.parse_round(human_trace(TARGET["azimuth"], TARGET["elevation"], aim_error=40))
        self.assertEqual(echohunt.score_round(TARGET, sub), "wrong direction")
        # Within tolerance still passes
        sub = echohunt.parse_round(human_trace(TARGET["azimuth"], TARGET["elevation"], aim_error=15))
        self.assertIsNone(echohunt.score_round(TARGET, sub))

    def test_instant_tap_fails(self):
        sub = echohunt.parse_round(human_trace(TARGET["azimuth"], TARGET["elevation"]))
        sub["tap_ms"] = 120
        self.assertEqual(echohunt.score_round(TARGET, sub), "tap too fast")

    def test_slow_tap_fails(self):
        sub = echohunt.parse_round(human_trace(TARGET["azimuth"], TARGET["elevation"], tap_ms=9000))
        self.assertEqual(echohunt.score_round(TARGET, sub), "tap too slow")

    def test_straight_line_trace_fails(self):
        for noise in (0.0, 0.3):
            sub = echohunt.parse_round(straight_trace(TARGET["azimuth"], TARGET["elevation"], noise=noise))
            self.assertIn(echohunt.score_round(TARGET, sub),
                          ("constant-speed trace (synthetic)", "straight-line trace (synthetic)"), f"noise {noise}")

    def test_teleport_fails(self):
        raw = human_trace(TARGET["azimuth"], TARGET["elevation"])
        # Stay forward, then jump straight to the target
        for s in raw["samples"][:-3]:
            s[1], s[2] = 0.1, 0.0
        for s in raw["samples"][-3:]:
            s[1], s[2] = raw["facing"]["azimuth"], raw["facing"]["elevation"]
        self.assertEqual(echohunt.score_round(TARGET, echohunt.parse_round(raw)), "orientation jumped (teleport)")

    def test_trace_that_does_not_move_fails(self):
        raw = human_trace(TARGET["azimuth"], TARGET["elevation"])
        for s in raw["samples"]:
            s[1], s[2] = 0.0, 0.0
        raw["facing"] = {"azimuth": TARGET["azimuth"], "elevation": TARGET["elevation"]}
        self.assertEqual(echohunt.score_round(TARGET, echohunt.parse_round(raw)),
                         "trace does not move towards the target")

    def test_non_monotonic_and_bad_rate_fail(self):
        raw = human_trace(TARGET["azimuth"], TARGET["elevation"])
        raw["samples"][5][0] = raw["samples"][4][0]
        self.assertEqual(echohunt.score_round(TARGET, echohunt.parse_round(raw)), "sample times not increasing")

        raw = human_trace(TARGET["azimuth"], TARGET["elevation"])
        raw["samples"] = raw["samples"][::8]  # ~6 Hz
        raw["samples"][-1][0] = raw["tap_ms"] - 5
        self.assertIn(echohunt.score_round(TARGET, echohunt.parse_round(raw)),
                      ("implausible sample rate", "too few orientation samples"))

    def test_two_of_three_rounds(self):
        rounds = [dict(TARGET, azimuth=a) for a in (100, 200, 300)]
        challenge = {"rounds": rounds}
        subs = [human_trace(r["azimuth"], r["elevation"], seed=i) for i, r in enumerate(rounds)]
        subs[2] = human_trace(300, 10, aim_error=60)
        result = echohunt.score_challenge(challenge, subs)
        self.assertTrue(result["passed"])
        self.assertEqual(result["rounds_passed"], 2)
        subs[1] = human_trace(200, 10, aim_error=60)
        self.assertFalse(echohunt.score_challenge(challenge, subs)["passed"])

    def test_submitted_faster_than_rounds_take(self):
        rounds = [dict(TARGET, azimuth=a) for a in (100, 200, 300)]
        subs = [human_trace(r["azimuth"], r["elevation"], seed=i) for i, r in enumerate(rounds)]
        self.assertFalse(echohunt.score_challenge({"rounds": rounds}, subs, elapsed_ms=500)["passed"])
        self.assertTrue(echohunt.score_challenge({"rounds": rounds}, subs, elapsed_ms=8000)["passed"])

    def test_malformed_submission(self):
        with self.assertRaises(echohunt.SubmissionError):
            echohunt.score_challenge({"rounds": [TARGET] * 3}, [{}])
        with self.assertRaises(echohunt.SubmissionError):
            echohunt.parse_round({"tap_ms": "fast", "facing": {"azimuth": 1}, "samples": []})

    def test_challenge_shape(self):
        challenge = echohunt.new_challenge()
        self.assertEqual(len(challenge["rounds"]), echohunt.ROUNDS)
        for r in challenge["rounds"]:
            self.assertTrue(45 <= r["azimuth"] <= 315)
            self.assertIn(r["sound"], echohunt.SOUNDS)
        view = echohunt.client_view(challenge)
        self.assertEqual(view["challenge_id"], challenge["id"])

    def test_tables_never_synced(self):
        for table in ("echohunt_challenges", "echohunt_passes"):
            self.assertNotIn(table, SYNCABLE_TABLES)


class VerdictTests(unittest.TestCase):
    PKG = "tech.galacticfederation.gfc"

    def payload(self, **over):
        fake = play_integrity.FakeIntegrityVerifier(self.PKG)
        return fake.decode(fake.issue("challenge-1", **over))

    def test_good_verdict(self):
        self.assertIsNone(play_integrity.check_verdict(self.payload(), self.PKG, "challenge-1"))

    def test_bad_verdicts(self):
        cases = [
            (self.payload(), "other-challenge", "request hash does not match the challenge"),
            (self.payload(app_verdict="UNRECOGNIZED_VERSION"), "challenge-1", "app not recognized by Play"),
            (self.payload(device_verdicts=("MEETS_BASIC_INTEGRITY",)), "challenge-1", "device integrity not met"),
            (self.payload(package_name="com.evil.clone"), "challenge-1", "wrong package"),
        ]
        for payload, expected_hash, reason in cases:
            self.assertEqual(play_integrity.check_verdict(payload, self.PKG, expected_hash), reason)

    def test_classic_nonce_accepted(self):
        payload = self.payload()
        payload["requestDetails"]["nonce"] = payload["requestDetails"].pop("requestHash")
        self.assertIsNone(play_integrity.check_verdict(payload, self.PKG, "challenge-1"))

    def test_google_adapter(self):
        """Signs an RS256 OAuth assertion, caches the access token, and calls decodeIntegrityToken."""
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding, rsa

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption()).decode()
        sa_file = os.path.join(test_signed_ledger._TMP, "play_sa.json")
        with open(sa_file, "w") as f:
            json.dump({"client_email": "gfc@example.iam.gserviceaccount.com", "private_key": pem,
                       "token_uri": "https://oauth2.googleapis.com/token"}, f)
        payload = self.payload()
        calls = []

        def handler(request):
            calls.append(request)
            if request.url.host == "oauth2.googleapis.com":
                assertion = dict(x.split("=", 1) for x in request.content.decode().split("&"))["assertion"]
                head, claims, sig = assertion.split(".")
                pad = lambda s: base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))  # noqa: E731
                key.public_key().verify(pad(sig), f"{head}.{claims}".encode(), padding.PKCS1v15(), hashes.SHA256())
                self.assertEqual(json.loads(pad(claims))["scope"], play_integrity.SCOPE)
                return httpx.Response(200, json={"access_token": "at-1", "expires_in": 3600})
            self.assertEqual(request.url.path, f"/v1/{self.PKG}:decodeIntegrityToken")
            self.assertEqual(request.headers["authorization"], "Bearer at-1")
            self.assertEqual(json.loads(request.content), {"integrity_token": "tok"})
            return httpx.Response(200, json={"tokenPayloadExternal": payload})

        verifier = play_integrity.GoogleIntegrityVerifier(sa_file, self.PKG)
        verifier.client = httpx.Client(transport=httpx.MockTransport(handler))
        self.assertEqual(verifier.decode("tok"), payload)
        self.assertEqual(verifier.decode("tok"), payload)
        self.assertEqual(len(calls), 3)  # one OAuth exchange, two decodes

    def test_token_older_than_challenge(self):
        payload = self.payload(timestamp_ms=1_000_000)
        self.assertEqual(play_integrity.check_verdict(payload, self.PKG, "challenge-1", not_before_ms=2_000_000),
                         "token requested before the challenge")


# ============================================================================
# API
# ============================================================================

class EchoHuntApiTestCase(test_phone_verify.PhoneVerifyTestCase):

    def setUp(self):
        play_integrity.set_verifier(None)  # unconfigured: integrity skipped

    def tearDown(self):
        play_integrity.set_verifier(None)

    def eh_start(self, token):
        return self.client.post("/echohunt/start", data={"api_token": token})

    def age_challenge(self, challenge_id, seconds=20):
        """Pretend the rounds were played: move the issue time back."""
        conn = sqlite3.connect(main.DB_PATH)
        created = (datetime.now(timezone.utc) - timedelta(seconds=seconds)).isoformat()
        conn.execute("UPDATE echohunt_challenges SET created_at = ? WHERE id = ?", (created, challenge_id))
        conn.commit()
        conn.close()

    def submit(self, token, challenge_id, rounds, integrity_token=""):
        return self.client.post("/echohunt/submit", data={
            "api_token": token, "challenge_id": challenge_id,
            "rounds": json.dumps(rounds), "integrity_token": integrity_token})

    def play_challenge(self, token, aim_error=0.0, integrity_token=None):
        r = self.eh_start(token)
        self.assertEqual(r.status_code, 200, r.text)
        challenge = r.json()
        self.age_challenge(challenge["challenge_id"])
        if callable(integrity_token):
            integrity_token = integrity_token(challenge["challenge_id"])
        return challenge, self.submit(token, challenge["challenge_id"],
                                      human_rounds(challenge["rounds"], aim_error=aim_error),
                                      integrity_token or "")

    def has_pass(self, username):
        conn = sqlite3.connect(main.DB_PATH)
        try:
            return echohunt.has_recent_pass(conn, username)
        finally:
            conn.close()


class EchoHuntApiTests(EchoHuntApiTestCase):

    def test_requires_login(self):
        self.assertEqual(self.eh_start("bogus").status_code, 401)

    def test_start_returns_render_data_only(self):
        _, token = self.register()
        body = self.eh_start(token).json()
        self.assertEqual(len(body["rounds"]), 3)
        for r in body["rounds"]:
            self.assertEqual(set(r), {"index", "azimuth", "elevation", "sound", "start_delay_ms"})

    def test_human_play_passes(self):
        user, token = self.register()
        self.assertFalse(self.has_pass(user))
        _, r = self.play_challenge(token)
        self.assertEqual(r.status_code, 200, r.text)
        self.assertTrue(r.json()["passed"])
        self.assertEqual(r.json()["rounds_passed"], 3)
        self.assertNotIn("reasons", r.json())
        self.assertTrue(self.has_pass(user))

    def test_wrong_direction_fails(self):
        user, token = self.register()
        _, r = self.play_challenge(token, aim_error=90)
        self.assertEqual(r.status_code, 200, r.text)
        self.assertFalse(r.json()["passed"])
        self.assertFalse(self.has_pass(user))

    def test_instant_taps_fail(self):
        user, token = self.register()
        challenge = self.eh_start(token).json()
        self.age_challenge(challenge["challenge_id"])
        rounds = human_rounds(challenge["rounds"])
        for r in rounds:
            r["tap_ms"] = 100
        r = self.submit(token, challenge["challenge_id"], rounds)
        self.assertFalse(r.json()["passed"])
        self.assertFalse(self.has_pass(user))

    def test_straight_line_trace_fails(self):
        _, token = self.register()
        challenge = self.eh_start(token).json()
        self.age_challenge(challenge["challenge_id"])
        rounds = [straight_trace(r["azimuth"], r["elevation"]) for r in challenge["rounds"]]
        self.assertFalse(self.submit(token, challenge["challenge_id"], rounds).json()["passed"])

    def test_submitted_too_fast_fails(self):
        _, token = self.register()
        challenge = self.eh_start(token).json()
        r = self.submit(token, challenge["challenge_id"], human_rounds(challenge["rounds"]))
        self.assertFalse(r.json()["passed"])

    def test_reused_challenge_rejected(self):
        _, token = self.register()
        challenge, r = self.play_challenge(token)
        self.assertTrue(r.json()["passed"])
        again = self.submit(token, challenge["challenge_id"], human_rounds(challenge["rounds"]))
        self.assertEqual(again.status_code, 410)

    def test_expired_challenge_rejected(self):
        _, token = self.register()
        challenge = self.eh_start(token).json()
        conn = sqlite3.connect(main.DB_PATH)
        conn.execute("UPDATE echohunt_challenges SET expires_at = ? WHERE id = ?",
                     ((datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat(), challenge["challenge_id"]))
        conn.commit()
        conn.close()
        r = self.submit(token, challenge["challenge_id"], human_rounds(challenge["rounds"]))
        self.assertEqual(r.status_code, 410)

    def test_other_users_challenge_rejected(self):
        _, token = self.register()
        _, other = self.register()
        challenge = self.eh_start(token).json()
        self.age_challenge(challenge["challenge_id"])
        r = self.submit(other, challenge["challenge_id"], human_rounds(challenge["rounds"]))
        self.assertEqual(r.status_code, 410)

    def test_rate_limit(self):
        _, token = self.register()
        for _ in range(echohunt.MAX_ATTEMPTS_PER_WINDOW):
            self.assertEqual(self.eh_start(token).status_code, 200)
        self.assertEqual(self.eh_start(token).status_code, 429)

    def test_rate_limit_window_expires(self):
        user, token = self.register()
        for _ in range(echohunt.MAX_ATTEMPTS_PER_WINDOW):
            self.eh_start(token)
        conn = sqlite3.connect(main.DB_PATH)
        old = (datetime.now(timezone.utc) - echohunt.ATTEMPT_WINDOW - timedelta(seconds=1)).isoformat()
        conn.execute("UPDATE echohunt_challenges SET created_at = ? WHERE username = ?", (old, user))
        conn.commit()
        conn.close()
        self.assertEqual(self.eh_start(token).status_code, 200)

    def test_malformed_rounds(self):
        _, token = self.register()
        challenge = self.eh_start(token).json()
        r = self.client.post("/echohunt/submit", data={"api_token": token, "challenge_id": challenge["challenge_id"],
                                                       "rounds": "not json"})
        self.assertEqual(r.status_code, 400)


class EchoHuntAuthTests(EchoHuntApiTestCase):
    """Bearer header and legacy api_token both work; the token needs the 'post' scope."""

    def mint(self, username, token, scopes):
        r = self.client.post("/auth/tokens", headers={"Authorization": f"Bearer {token}"},
                             data={"password": "pw-" + username, "scopes": scopes})
        self.assertEqual(r.status_code, 200, r.text)
        return r.json()["token"]

    def test_bearer_token(self):
        user, token = self.register()
        headers = {"Authorization": f"Bearer {self.mint(user, token, 'read post')}"}
        r = self.client.post("/echohunt/start", headers=headers)
        self.assertEqual(r.status_code, 200, r.text)
        challenge = r.json()
        self.age_challenge(challenge["challenge_id"])
        r = self.client.post("/echohunt/submit", headers=headers, data={
            "challenge_id": challenge["challenge_id"], "rounds": json.dumps(human_rounds(challenge["rounds"]))})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertTrue(r.json()["passed"])
        self.assertTrue(self.has_pass(user))

    def test_legacy_api_token(self):
        user, token = self.register()
        _, r = self.play_challenge(token)  # api_token form field
        self.assertTrue(r.json()["passed"])
        self.assertTrue(self.has_pass(user))

    def test_token_without_post_scope_forbidden(self):
        user, token = self.register()
        read_only = self.mint(user, token, "read")
        headers = {"Authorization": f"Bearer {read_only}"}
        r = self.client.post("/echohunt/start", headers=headers)
        self.assertEqual(r.status_code, 403)
        self.assertIn("'post' scope", r.json()["detail"])
        self.assertEqual(self.eh_start(read_only).status_code, 403)  # same via api_token

        # A challenge started with a full token can't be submitted with the read-only one
        challenge = self.eh_start(token).json()
        self.age_challenge(challenge["challenge_id"])
        r = self.client.post("/echohunt/submit", headers=headers, data={
            "challenge_id": challenge["challenge_id"], "rounds": json.dumps(human_rounds(challenge["rounds"]))})
        self.assertEqual(r.status_code, 403)
        self.assertFalse(self.has_pass(user))


class PlayIntegrityApiTests(EchoHuntApiTestCase):

    def setUp(self):
        self.fake = play_integrity.FakeIntegrityVerifier(enforced=True)
        play_integrity.set_verifier(self.fake)

    def test_token_required_when_configured(self):
        user, token = self.register()
        _, r = self.play_challenge(token)
        self.assertEqual(r.status_code, 403)
        self.assertIn("play integrity token required", r.json()["detail"])
        self.assertFalse(self.has_pass(user))

    def test_valid_token_passes(self):
        user, token = self.register()
        _, r = self.play_challenge(token, integrity_token=self.fake.issue)
        self.assertEqual(r.status_code, 200, r.text)
        self.assertTrue(r.json()["passed"])
        self.assertTrue(self.has_pass(user))

    def test_token_for_another_challenge_rejected(self):
        user, token = self.register()
        # A genuine token, but bound to an earlier challenge (replay)
        stale = self.fake.issue(echohunt.new_challenge()["id"])
        _, r = self.play_challenge(token, integrity_token=stale)
        self.assertEqual(r.status_code, 403)
        self.assertIn("request hash does not match", r.json()["detail"])
        self.assertFalse(self.has_pass(user))

    def test_bad_device_rejected(self):
        _, token = self.register()
        _, r = self.play_challenge(token, integrity_token=lambda cid: self.fake.issue(cid, device_verdicts=()))
        self.assertEqual(r.status_code, 403)


# ============================================================================
# REWARD GATING
# ============================================================================

class RewardGatingTests(EchoHuntApiTestCase):

    def setUp(self):
        super().setUp()
        self._saved = os.environ.get("GFC_REQUIRE_ECHOHUNT")

    def tearDown(self):
        super().tearDown()
        if self._saved is None:
            os.environ.pop("GFC_REQUIRE_ECHOHUNT", None)
        else:
            os.environ["GFC_REQUIRE_ECHOHUNT"] = self._saved

    def setup_play(self):
        _, ctoken = self.register()
        self.verify(ctoken)
        self.wallet(ctoken)
        files = {"file": ("model.glb", os.urandom(200_000), "model/gltf-binary")}
        r = self.client.post("/seeds/upload", data={"api_token": ctoken, "title": "t"}, files=files)
        self.assertEqual(r.status_code, 200, r.text)
        viewer, vtoken = self.register()
        self.verify(vtoken)
        test_signed_ledger.backdate_user(main.DB_PATH, viewer)
        return r.json()["id"], viewer, vtoken

    def play(self, token, seed_id):
        return self.client.post(f"/seeds/{seed_id}/played", data={"api_token": token}).json()

    def test_off_by_default(self):
        os.environ.pop("GFC_REQUIRE_ECHOHUNT", None)
        seed, _, vtoken = self.setup_play()
        self.assertTrue(self.play(vtoken, seed)["credited"])

    def test_required_blocks_without_pass_and_allows_with_one(self):
        os.environ["GFC_REQUIRE_ECHOHUNT"] = "1"
        seed, viewer, vtoken = self.setup_play()
        r = self.play(vtoken, seed)
        self.assertFalse(r["credited"])
        self.assertEqual(r["reason"], "echo hunt not passed in the last 24h")

        _, sub = self.play_challenge(vtoken)
        self.assertTrue(sub.json()["passed"])
        self.assertTrue(self.play(vtoken, seed)["credited"])

    def test_pass_older_than_24h_does_not_count(self):
        os.environ["GFC_REQUIRE_ECHOHUNT"] = "1"
        seed, viewer, vtoken = self.setup_play()
        self.assertTrue(self.play_challenge(vtoken)[1].json()["passed"])
        conn = sqlite3.connect(main.DB_PATH)
        conn.execute("UPDATE echohunt_passes SET echohunt_passed_at = ? WHERE username = ?",
                     ((datetime.now(timezone.utc) - timedelta(hours=25)).isoformat(), viewer))
        conn.commit()
        conn.close()
        self.assertEqual(self.play(vtoken, seed)["reason"], "echo hunt not passed in the last 24h")


if __name__ == "__main__":
    unittest.main()
