"""
Fuzz tests (Hypothesis): throw random and malformed input at the code that handles
input from strangers, and check it never crashes and never accepts what it shouldn't.

Targets:
- rows synced from peers and the tracker (security.sanitize_incoming_rows, sync_ingest.ingest_rows)
- signature checks on transactions and seeds (signing.py)
- the zip checks on downloads (filescan.check_zip)
- upload file names (app_seeds.safe_name, detect_content_type)

Skipped if Hypothesis isn't installed (it's a test-only dependency: requirements-dev.txt).
More examples per test for a deeper run:
    $env:GFC_FUZZ_EXAMPLES = '2000'; python -m unittest tests.test_fuzz -v

Run from the repository root:
    python -m unittest discover -s tests -v
"""

import io
import json
import os
import sqlite3
import sys
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_signed_ledger  # noqa: F401  (sets up the isolated data dir and a test treasury first)

try:
    from hypothesis import HealthCheck, assume, given, settings, strategies as st
    HAVE_HYPOTHESIS = True
except ImportError:  # pragma: no cover
    HAVE_HYPOTHESIS = False

import blockchain  # noqa: E402
import filescan  # noqa: E402
import main  # noqa: E402
import signing  # noqa: E402
import sync_ingest  # noqa: E402
from app_seeds import SAFE_RE, detect_content_type, safe_name  # noqa: E402
from security import sanitize_incoming_rows  # noqa: E402

EXAMPLES = int(os.environ.get("GFC_FUZZ_EXAMPLES", "200"))


def _settings(n=EXAMPLES):
    return settings(max_examples=n, deadline=None, derandomize=not os.environ.get("GFC_FUZZ_EXAMPLES"),
                    suppress_health_check=[HealthCheck.too_slow, HealthCheck.filter_too_much,
                                           HealthCheck.data_too_large])


if HAVE_HYPOTHESIS:
    # What a peer can send: anything JSON can carry
    json_scalar = st.one_of(st.none(), st.booleans(), st.integers(min_value=-2**70, max_value=2**70),
                            st.floats(allow_nan=True, allow_infinity=True), st.text(max_size=80))
    json_value = st.recursive(json_scalar, lambda inner: st.one_of(
        st.lists(inner, max_size=4), st.dictionaries(st.text(max_size=8), inner, max_size=4)), max_leaves=8)
    hexish = st.one_of(st.text(alphabet="0123456789abcdefABCDEF", max_size=140), st.text(max_size=140))

    def column_names(table):
        allowed = [c.strip() for c in sync_ingest.TABLE_COLUMNS[table].split(",")]
        # Mostly real column names (so rows get past the whitelist), plus junk and SQL-looking names
        return st.lists(st.one_of(st.sampled_from(allowed), st.text(max_size=20),
                                  st.sampled_from(["password", "gfc_balance", "is_treasury", "id; DROP TABLE seeds",
                                                   "owner) VALUES (1); --", "balance_cents"])),
                        min_size=1, max_size=len(allowed) + 3)
else:  # pragma: no cover
    def given(*a, **k):
        return lambda f: f

    def _settings(n=0):  # noqa: F811
        return lambda f: f

    def column_names(table):
        return None

    st = json_value = hexish = None


def make_zip(files) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return buf.getvalue()


@unittest.skipUnless(HAVE_HYPOTHESIS, "needs hypothesis (pip install -r requirements-dev.txt)")
class FuzzTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        main.app  # the app's startup created the tables
        cls.db = main.DB_PATH
        cls.priv, cls.pub = signing.generate_keypair()
        cls.tmp = Path(test_signed_ledger._TMP) / "fuzz"
        cls.tmp.mkdir(exist_ok=True)

    # ---------- rows from peers ----------

    @_settings()
    @given(table=st.sampled_from(sync_ingest.SYNCABLE_TABLES), data=st.data())
    def test_sanitize_keeps_only_whitelisted_columns(self, table, data):
        columns = data.draw(st.lists(st.one_of(st.text(max_size=20), json_value), max_size=12))
        rows = data.draw(st.lists(st.one_of(st.lists(json_value, max_size=12), json_value), max_size=6))
        safe_cols, safe_rows = sanitize_incoming_rows(table, columns, rows, sync_ingest.TABLE_COLUMNS)
        allowed = {c.strip() for c in sync_ingest.TABLE_COLUMNS[table].split(",")} | {"password"}
        self.assertTrue(set(safe_cols) <= allowed, safe_cols)
        self.assertTrue(all(len(r) == len(safe_cols) for r in safe_rows))
        if table == "users" and safe_cols:
            self.assertEqual(safe_cols[-1], "password")  # always replaced, never taken from a peer

    @_settings(max(EXAMPLES // 2, 25))
    @given(data=st.data(), table=st.sampled_from(sync_ingest.SYNCABLE_TABLES))
    def test_peer_rows_never_crash_ingest_or_touch_balances(self, data, table):
        columns = data.draw(column_names(table))
        rows = data.draw(st.lists(st.lists(json_value, min_size=len(columns), max_size=len(columns)),
                                  min_size=1, max_size=4))
        before = self._ledger_state()
        result = sync_ingest.ingest_rows(table, columns, rows, db_path=self.db)
        self.assertEqual(result["received"], len(rows))
        # Junk can't be a signed, funded transaction: the ledger and every balance stay as they were
        self.assertEqual(self._ledger_state(), before)

    def _ledger_state(self):
        conn = sqlite3.connect(self.db)
        try:
            return (conn.execute("SELECT COUNT(*) FROM transactions").fetchone()[0],
                    conn.execute("SELECT COALESCE(SUM(gfc_balance_cents), 0) FROM wallets").fetchone()[0],
                    blockchain.get_balance_cents(self.db, blockchain.TREASURY_WALLET_ID))
        finally:
            conn.close()

    @_settings(max(EXAMPLES // 2, 25))
    @given(field=st.sampled_from(["sender", "recipient", "amount", "amount_cents", "tx_hash", "signature",
                                  "signer", "reason", "tx_type", "timestamp"]),
           value=json_value)
    def test_tampered_signed_transaction_is_never_accepted(self, field, value):
        """A real signed transfer with one field changed by a peer must not be accepted."""
        tx = self._signed_transfer()
        assume(tx[field] != value)
        tampered = dict(tx, **{field: value})
        columns = list(tampered)
        before = self._ledger_state()
        sync_ingest.ingest_rows("transactions", columns, [[tampered[c] for c in columns]], db_path=self.db)
        self.assertEqual(self._ledger_state(), before)

    def _signed_transfer(self):
        """A transaction a real wallet signed (unfunded, so even untouched it only waits)."""
        tx = {"id": "fz" + os.urandom(6).hex(), "sender": self.pub, "recipient": "ab" * 32, "amount": 1.0,
              "amount_cents": 100, "reason": "fuzz", "timestamp": "2026-10-30T00:00:00", "tx_type": "TRANSFER",
              "signer": self.pub}
        tx["tx_hash"] = blockchain.compute_tx_hash(tx) if hasattr(blockchain, "compute_tx_hash") else "00" * 32
        tx["signature"] = signing.sign_tx_hash(self.priv, tx["tx_hash"])
        return tx

    # ---------- signatures ----------

    @_settings()
    @given(pub=st.one_of(hexish, json_value), tx_hash=st.one_of(st.text(max_size=80), json_value),
           sig=st.one_of(hexish, json_value))
    def test_signature_check_never_crashes_on_junk(self, pub, tx_hash, sig):
        try:
            result = signing.verify_tx_signature(pub, tx_hash, sig)
        except AttributeError:
            # tx_hash.encode(): only str hashes reach here from the ledger code
            self.assertNotIsInstance(tx_hash, str)
            return
        self.assertIs(result, False)
        self.assertIsInstance(signing.is_public_key(pub), bool)

    @_settings()
    @given(tx_hash=st.text(min_size=1, max_size=64), flip=st.integers(min_value=0, max_value=511))
    def test_one_flipped_bit_breaks_a_signature(self, tx_hash, flip):
        sig = bytearray(bytes.fromhex(signing.sign_tx_hash(self.priv, tx_hash)))
        self.assertTrue(signing.verify_tx_signature(self.pub, tx_hash, sig.hex()))
        sig[flip // 8] ^= 1 << (flip % 8)
        self.assertFalse(signing.verify_tx_signature(self.pub, tx_hash, sig.hex()))

    @_settings()
    @given(seed=st.dictionaries(st.sampled_from(["id", "owner", "filename", "file_size", "created_at",
                                                 "reward_wallet", "signature", "title"]), json_value))
    def test_seed_check_never_crashes_on_junk(self, seed):
        self.assertIs(signing.verify_seed(seed), False)

    @_settings()
    @given(field=st.sampled_from(signing.SEED_SIGNED_FIELDS), value=json_value)
    def test_changing_a_signed_seed_field_breaks_its_signature(self, field, value):
        seed = {"owner": "alice", "filename": "clip.mp4", "file_size": 1234, "created_at": "2026-10-30T00:00:00",
                "reward_wallet": self.pub}
        seed["id"] = signing.seed_id_for(self.pub, seed["filename"])
        seed["signature"] = signing.sign_seed(self.priv, seed)
        self.assertTrue(signing.verify_seed(seed))
        # JSON can't tell 1234 from 1234.0: that isn't a different seed
        assume(json.dumps(seed[field]) != json.dumps(value) and seed[field] != value)
        self.assertFalse(signing.verify_seed(dict(seed, **{field: value})))

    # ---------- downloads ----------

    @_settings()
    @given(data=st.binary(max_size=4096))
    def test_zip_check_never_crashes_on_random_bytes(self, data):
        self._check_zip_bytes(data)

    @_settings()
    @given(files=st.dictionaries(st.text(min_size=1, max_size=30).filter(lambda n: "\x00" not in n),
                                 st.binary(max_size=300), min_size=1, max_size=5),
           cuts=st.lists(st.tuples(st.integers(min_value=0), st.integers(min_value=0, max_value=255)),
                         max_size=8),
           truncate=st.one_of(st.none(), st.integers(min_value=0)))
    def test_zip_check_never_crashes_on_damaged_zips(self, files, cuts, truncate):
        """Real zips with random bytes overwritten or cut short: the classic crafted-archive attack."""
        data = bytearray(make_zip(files))
        for pos, byte in cuts:
            data[pos % len(data)] = byte
        if truncate is not None:
            data = data[:truncate % (len(data) + 1)]
        self._check_zip_bytes(bytes(data))

    def _check_zip_bytes(self, data: bytes):
        p = self.tmp / "fuzz.zip"
        p.write_bytes(data)
        ok, reason, summary = filescan.check_zip(p)
        self.assertIsInstance(ok, bool)
        self.assertIsInstance(summary, dict)
        if not ok:
            self.assertTrue(reason)

    # ---------- upload names ----------

    @_settings()
    @given(name=st.text(max_size=200))
    def test_uploaded_names_stay_in_the_upload_folder(self, name):
        safe = safe_name(name)
        self.assertTrue(safe)
        self.assertNotIn("/", safe)
        self.assertNotIn("\\", safe)
        self.assertNotIn("\x00", safe)
        self.assertFalse(SAFE_RE.search(safe.replace(".", "")), safe)  # only safe characters remain
        stored = (self.tmp / f"abc123_{safe}").resolve()
        self.assertEqual(stored.parent, self.tmp.resolve())
        self.assertIn(detect_content_type(name), {"audio", "video", "image", "model", "text", "other"}
                      | set(getattr(sys.modules["app_seeds"], "CONTENT_TYPE_MAP", {})))


if __name__ == "__main__":
    unittest.main(verbosity=2)
