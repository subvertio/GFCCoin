"""
Tests for requiring a verified phone number to post on the real network.

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
from test_signed_ledger import mark_verified

from fastapi.testclient import TestClient  # noqa: E402

import app_seeds  # noqa: E402
import config  # noqa: E402
import main  # noqa: E402


class PhoneToPostTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(main.app)

    def setUp(self):
        self._saved = config.REQUIRE_PHONE_TO_POST

    def tearDown(self):
        config.REQUIRE_PHONE_TO_POST = self._saved

    def register(self):
        name = "p" + uuid.uuid4().hex[:10]
        r = self.client.post("/auth/register", data={"username": name, "password": "pw-" + name})
        self.assertEqual(r.status_code, 200, r.text)
        token = r.json()["token"]
        self.client.post("/wallets/create", data={"name": "main", "api_token": token})
        return name, token

    def upload(self, token=None):
        data = {"api_token": token} if token else {}
        files = {"file": ("note.txt", os.urandom(2048), "text/plain")}
        return self.client.post("/seeds/upload", data=data, files=files)

    def test_custom_treasury_keys_make_a_test_network(self):
        # The suite runs with its own treasury key (GFC_TREASURY_PUBKEYS)
        self.assertTrue(config.IS_TESTNET)
        self.assertEqual(config.NETWORK, "testnet")
        self.assertFalse(config.REQUIRE_PHONE_TO_POST)

    def test_test_network_lets_anyone_post(self):
        config.REQUIRE_PHONE_TO_POST = False
        _, token = self.register()
        self.assertEqual(self.upload(token).status_code, 200)
        self.assertEqual(self.upload().status_code, 200)  # even logged out

    def test_real_network_needs_a_verified_phone(self):
        config.REQUIRE_PHONE_TO_POST = True
        name, token = self.register()

        r = self.upload()
        self.assertEqual(r.status_code, 401)

        r = self.upload(token)
        self.assertEqual(r.status_code, 403)
        self.assertEqual(r.json()["detail"], app_seeds.PHONE_REQUIRED_DETAIL)

        mark_verified(main.DB_PATH, name)
        r = self.upload(token)
        self.assertEqual(r.status_code, 200, r.text)

    def test_health_tells_apps_the_rule(self):
        config.REQUIRE_PHONE_TO_POST = True
        body = self.client.get("/health").json()
        self.assertTrue(body["phone_required_to_post"])
        self.assertEqual(body["network"], config.NETWORK)


if __name__ == "__main__":
    unittest.main(verbosity=2)
