"""
Tests for the website price ticker (app_ticker.py): GeckoTerminal first, the chain when it fails,
the last answer (stale) when both fail, the one-minute cache, and the widget's headers.
The price sources are faked; nothing here calls the internet.

Run from the repository root:
    python -m unittest discover -s tests -v
"""

import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_signed_ledger  # noqa: F401  (sets up the isolated data dir first)

from fastapi.testclient import TestClient  # noqa: E402

import app_ticker  # noqa: E402
import main  # noqa: E402

GECKO = {"priceUsd": 0.1013, "change24hPct": 1.5, "volume24hUsd": 12.0, "liquidityUsd": 603.0,
         "fdvUsd": 405.0, "source": "geckoterminal"}
CHAIN = {"priceUsd": 0.1004, "change24hPct": None, "volume24hUsd": None, "liquidityUsd": None,
         "fdvUsd": None, "source": "onchain"}


def fail():
    raise RuntimeError("down")


class TickerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(main.app)

    def setUp(self):
        app_ticker._cache.update(at=0.0, data=None)

    def sources(self, gecko, chain):
        return mock.patch.multiple(app_ticker, from_gecko=gecko, from_chain=chain)

    def test_geckoterminal_first_with_links_and_open_cors(self):
        with self.sources(lambda: dict(GECKO), fail):
            r = self.client.get("/ticker.json")
        self.assertEqual(r.status_code, 200)
        t = r.json()
        self.assertEqual((t["priceUsd"], t["source"], t["stale"], t["symbol"]), (0.1013, "geckoterminal", False, "GFC"))
        self.assertIn(app_ticker.TOKEN, t["tradeUrl"])
        self.assertEqual(r.headers["access-control-allow-origin"], "*")

    def test_the_chain_when_geckoterminal_fails(self):
        with self.sources(fail, lambda: dict(CHAIN)):
            t = self.client.get("/ticker.json").json()
        self.assertEqual((t["priceUsd"], t["source"], t["change24hPct"]), (0.1004, "onchain", None))

    def test_cached_for_a_minute(self):
        calls = []

        def gecko():
            calls.append(1)
            return dict(GECKO)
        with self.sources(gecko, fail):
            app_ticker.ticker(now=1000.0)
            app_ticker.ticker(now=1030.0)
            self.assertEqual(len(calls), 1)
            app_ticker.ticker(now=1000.0 + app_ticker.CACHE_SECONDS + 1)
            self.assertEqual(len(calls), 2)

    def test_stale_then_unavailable_when_everything_fails(self):
        with self.sources(lambda: dict(GECKO), fail):
            app_ticker.ticker(now=1000.0)
        with self.sources(fail, fail):
            t = app_ticker.ticker(now=1000.0 + 120)
            self.assertTrue(t["stale"])
            self.assertEqual(t["priceUsd"], 0.1013)
            self.assertIsNone(app_ticker.ticker(now=1000.0 + app_ticker.STALE_SECONDS + 1))
            app_ticker._cache.update(at=0.0, data=None)
            self.assertEqual(self.client.get("/ticker.json").status_code, 503)

    def test_the_widget_can_be_framed_but_runs_only_its_own_script(self):
        r = self.client.get("/ticker")
        self.assertEqual(r.status_code, 200)
        csp = r.headers["content-security-policy"]
        self.assertIn("frame-ancestors *", csp)
        self.assertIn("connect-src 'self'", csp)
        self.assertNotIn("unsafe", csp)
        self.assertIn("/ticker.json", r.text)
        self.assertIn("Trade on Uniswap", r.text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
