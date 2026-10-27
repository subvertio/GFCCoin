"""
Tests that phone numbers and verify link codes never reach the node's logs (logredact.py).

Run from the repository root:
    python -m unittest discover -s tests -v
"""

import io
import logging
import unittest

import logredact


class RedactTests(unittest.TestCase):
    def test_phone_numbers_keep_only_the_last_two_digits(self):
        line = 'HTTP Request: GET https://lookups.twilio.com/v2/PhoneNumbers/+14155550198?Fields=line_type_intelligence "HTTP/1.1 200 OK"'
        out = logredact.redact(line)
        self.assertNotIn("4155550198", out)
        self.assertIn("/PhoneNumbers/+...98?Fields", out)
        self.assertEqual(logredact.redact("to %2B442079460958 now"), "to +...58 now")

    def test_verify_link_codes_hidden(self):
        out = logredact.redact('"GET /verify?c=50maEC9p0ai3vKlIHbyvksh00sjJ4M88 HTTP/1.1" 200')
        self.assertEqual(out, '"GET /verify?c=<hidden> HTTP/1.1" 200')

    def test_ordinary_lines_untouched(self):
        for line in ("Grant: 100.00 GFC -> 98583d379702c2843ccd2ea1d3cc2a24f5bff0e6726169ac9592730c920ccad4",
                     "2026-10-27 17:13:05,782 [gfc.discovery] INFO: Tracker sync: uploaded 9 rows across tables",
                     "GET /sync_download?exclude_peer=165.245.192.180%3A6881",
                     "timestamp 2026-10-27T17:45:02+00:00, +100 GFC"):
            self.assertEqual(logredact.redact(line), line)

    def test_filter_rewrites_records_from_any_logger(self):
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        root = logging.getLogger()
        root.addHandler(handler)
        try:
            logredact.install()
            logredact.install()  # twice is fine
            self.assertEqual(handler.filters.count(logredact._FILTER), 1)
            # httpx logs URLs through %-style args: the formatted message is what gets redacted
            logging.getLogger("httpx").warning("HTTP Request: %s %s", "GET", "https://lookups.twilio.com/v2/PhoneNumbers/+14155550100")
        finally:
            root.removeHandler(handler)
        written = stream.getvalue()
        self.assertNotIn("4155550100", written)
        self.assertIn("+...00", written)


if __name__ == "__main__":
    unittest.main()
