"""
Bridge service tests: a throwaway ledger DB (with a test treasury key) and a
local anvil chain running the evm/ contracts. Nothing touches a real network.

Needs Foundry (anvil, forge) and bridge/requirements.txt; skipped otherwise.
Run from the repository root:
    python -m unittest tests.test_bridge -v
"""

import os
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_TMP = tempfile.mkdtemp(prefix="gfc_bridge_")
_FOUNDRY_BIN = Path.home() / ".foundry" / "bin"


def _tool(name: str):
    return shutil.which(name) or (str(_FOUNDRY_BIN / f"{name}.exe") if (_FOUNDRY_BIN / f"{name}.exe").exists()
                                  else shutil.which(name, path=str(_FOUNDRY_BIN)))


ANVIL, FORGE = _tool("anvil"), _tool("forge")
try:
    import eth_account  # noqa: F401
    HAVE_ETH = True
except ImportError:
    HAVE_ETH = False

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat  # noqa: E402

_treasury = Ed25519PrivateKey.generate()
TREASURY_PRIV = _treasury.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex()
TREASURY_PUB = _treasury.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
os.environ["GFC_DATA_DIR"] = _TMP
os.environ["GFC_TREASURY_PUBKEYS"] = TREASURY_PUB
os.environ["GFC_TREASURY_KEY_FILE"] = str(Path(_TMP) / "no_treasury_key.hex")
os.environ.pop("GFC_FIREBASE_CONFIG", None)
sys.path.insert(0, str(ROOT))

import blockchain  # noqa: E402
import main  # noqa: E402
import signing  # noqa: E402

if HAVE_ETH:
    from eth_abi import encode  # noqa: E402
    from eth_account import Account  # noqa: E402
    from eth_utils import keccak  # noqa: E402

    from bridge import deposits, eip712, relayer, releases  # noqa: E402
    from bridge.attester import Attester  # noqa: E402
    from bridge.chain import BridgeContract, Chain, calldata, token_total_supply  # noqa: E402
    from bridge.config import BridgeConfig  # noqa: E402
    from bridge.reconcile import reconcile  # noqa: E402
    from bridge.store import HELD, MINTED, PAID, REFUND, WAITING, Store  # noqa: E402

CHAIN_ID = 31337
CENT = 10 ** 16
LIMITS = (10_000_00, 50_000_00, 86_400, 10_00)  # maxMint, windowLimit, window, minOut (cents / seconds)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def new_ledger(name: str) -> str:
    path = str(Path(_TMP) / f"{name}-{uuid.uuid4().hex[:8]}.db")
    saved = main.DB_PATH
    main.DB_PATH = path
    try:
        main.init_db()
    finally:
        main.DB_PATH = saved
    return path


def _signed(tx: dict, priv: str, signer: str) -> dict:
    tx["amount"] = tx["amount_cents"] / 100.0
    tx["tx_hash"] = blockchain.compute_tx_hash(tx)
    tx["signer"] = signer
    tx["signature"] = signing.sign_tx_hash(priv, tx["tx_hash"])
    return tx


def treasury_mint(db: str, wallet: str, cents: int, tx_type: str = blockchain.TX_TYPE_OPERATOR,
                  when: datetime = None) -> dict:
    when = when or datetime.now(timezone.utc) - timedelta(days=60)
    reason = "Operator grant (other): bridge test funds" if tx_type == blockchain.TX_TYPE_OPERATOR else "test"
    tx = _signed({"id": str(uuid.uuid4()), "sender": blockchain.TREASURY_WALLET_ID, "recipient": wallet,
                  "amount_cents": cents, "reason": reason, "timestamp": when.isoformat(), "tx_type": tx_type},
                 TREASURY_PRIV, TREASURY_PUB)
    status, why = blockchain.accept_synced_transaction(db, tx)
    assert status == blockchain.ACCEPTED, why
    return tx


def transfer(db: str, priv: str, pub: str, recipient: str, cents: int, reason: str,
             when: datetime = None) -> dict:
    when = when or datetime.now(timezone.utc) - timedelta(hours=2)
    tx = _signed({"id": str(uuid.uuid4()), "sender": pub, "recipient": recipient, "amount_cents": cents,
                  "reason": reason, "timestamp": when.isoformat(), "tx_type": blockchain.TX_TYPE_TRANSFER},
                 priv, pub)
    status, why = blockchain.accept_synced_transaction(db, tx)
    assert status == blockchain.ACCEPTED, why
    return tx


@unittest.skipUnless(ANVIL and FORGE and HAVE_ETH, "needs Foundry (anvil, forge) and bridge/requirements.txt")
class BridgeServiceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Under `unittest discover` another module may have loaded config with its own test
        # treasury key first; accept ours too while this class runs.
        cls._saved_pubkeys = signing.TREASURY_PUBKEYS
        signing.TREASURY_PUBKEYS = tuple(signing.TREASURY_PUBKEYS) + (TREASURY_PUB,)
        subprocess.run([FORGE, "build", "--root", str(ROOT / "evm")], check=True, capture_output=True)
        cls.artifacts = {}
        import json
        for name in ("GFCToken", "GFCBridge"):
            art = json.loads((ROOT / "evm" / "out" / f"{name}.sol" / f"{name}.json").read_text())
            cls.artifacts[name] = art["bytecode"]["object"]
        cls.port = _free_port()
        cls.anvil = subprocess.Popen([ANVIL, "--port", str(cls.port), "--chain-id", str(CHAIN_ID), "--silent"],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cls.chain = Chain(f"http://127.0.0.1:{cls.port}")
        for _ in range(100):
            try:
                cls.chain.chain_id()
                break
            except Exception:
                time.sleep(0.1)
        else:
            raise RuntimeError("anvil did not start")

    @classmethod
    def tearDownClass(cls):
        signing.TREASURY_PUBKEYS = cls._saved_pubkeys
        cls.chain.close()
        cls.anvil.terminate()
        cls.anvil.wait(10)

    # ------------------------------------------------------------------ fixtures

    def _account(self):
        acct = Account.create()
        self.chain.rpc("anvil_setBalance", [acct.address, hex(10 ** 20)])
        return acct

    def _deploy(self, name: str, types, args) -> str:
        data = self.artifacts[name] + encode(types, args).hex()
        return self.chain.send(self.admin.key.hex(), None, data)["contractAddress"]

    def setUp(self):
        self.admin = self._account()
        self.relayer_acct = self._account()
        self.pauser = self._account()
        self.user_evm = self._account()
        self.attester_accts = [Account.create() for _ in range(3)]

        self.token_addr = self._deploy("GFCToken", ["address", "uint48", "uint256"],
                                       [self.admin.address, 0, 1_000_000 * 10 ** 18])
        self.bridge_addr = self._deploy("GFCBridge",
                                        ["address", "address", "uint48", "uint256", "(uint256,uint256,uint256,uint256)"],
                                        [self.token_addr, self.admin.address, 0, 2, LIMITS])
        admin_key = self.admin.key.hex()
        grant = "grantRole(bytes32,address)"
        for role in ("MINTER_ROLE", "BURNER_ROLE"):  # the bridge mints and is the only burner
            self.chain.send(admin_key, self.token_addr,
                            calldata(grant, ["bytes32", "address"], [keccak(text=role), self.bridge_addr]))
        self.chain.send(admin_key, self.bridge_addr,
                        calldata(grant, ["bytes32", "address"], [keccak(text="PAUSER_ROLE"), self.pauser.address]))
        for a in self.attester_accts:
            self.chain.send(admin_key, self.bridge_addr,
                            calldata(grant, ["bytes32", "address"], [keccak(text="ATTESTER_ROLE"), a.address]))
        self.bridge = BridgeContract(self.chain, self.bridge_addr)

        self.ledger = new_ledger("bridge-node")
        self.escrow_priv, self.escrow_pub = signing.generate_keypair()
        self.user_priv, self.user_pub = signing.generate_keypair()
        treasury_mint(self.ledger, self.user_pub, 10_000_00)

        self.cfg = BridgeConfig(
            rpc_url=f"http://127.0.0.1:{self.port}", chain_id=CHAIN_ID, bridge_address=self.bridge_addr,
            escrow_wallet=self.escrow_pub, ledger_db=self.ledger,
            state_db=str(Path(_TMP) / f"state-{uuid.uuid4().hex[:8]}.db"),
            finality_seconds=60, chain_finality="0", min_deposit_cents=10_00, relay_fee_cents=1_00,
            faucet_hold_days=14, manual_review_cents=5_000_00,
        )
        self.store = Store(self.cfg.state_db)

    def attesters(self, *dbs):
        dbs = dbs or (self.ledger,) * 3
        return [Attester(self.cfg, ledger_db=db, key=a.key.hex()) for db, a in zip(dbs, self.attester_accts)]

    def deposit(self, cents: int, evm_to: str = None, chain_id: int = CHAIN_ID, **kw) -> dict:
        evm_to = evm_to or self.user_evm.address
        return transfer(self.ledger, self.user_priv, self.user_pub, self.escrow_pub, cents,
                        f"bridge:v1:{chain_id}:{evm_to}", **kw)

    def relay(self, attesters=None):
        relayer.scan_deposits(self.cfg, self.store)
        return relayer.relay(self.cfg, self.store, self.bridge, attesters or self.attesters(),
                             self.relayer_acct.key.hex())

    def balance(self, addr: str) -> int:
        return self.chain.call(self.token_addr, "balanceOf(address)", ["address"], [addr])

    def bridge_out(self, cents: int, ledger_wallet: str):
        key = self.user_evm.key.hex()
        self.chain.send(key, self.token_addr,
                        calldata("approve(address,uint256)", ["address", "uint256"], [self.bridge_addr, cents * CENT]))
        self.chain.send(key, self.bridge_addr, calldata("bridgeOut(uint256,bytes32)", ["uint256", "bytes32"],
                                                        [cents * CENT, bytes.fromhex(ledger_wallet)]))

    # ------------------------------------------------------------------ ledger -> chain

    def test_eip712_digest_matches_contract(self):
        req = eip712.mint_request("ab" * 32, self.user_evm.address, 123_45, 2_000_000_000)
        msg = eip712._message(CHAIN_ID, self.bridge_addr, req)
        local = keccak(b"\x19" + msg.version + msg.header + msg.body)
        self.assertEqual(local, self.bridge.mint_digest(req))

    def test_deposit_mints_once_minus_fee(self):
        dep = self.deposit(500_00)
        counts = self.relay()
        self.assertEqual(counts[MINTED], 1)
        self.assertEqual(self.balance(self.user_evm.address), (500_00 - 1_00) * CENT)
        self.assertEqual(self.store.deposit(dep["tx_hash"])["status"], MINTED)
        self.assertTrue(self.bridge.processed(bytes.fromhex(dep["tx_hash"])))

        self.relay()  # nothing left to do
        self.assertEqual(self.balance(self.user_evm.address), (500_00 - 1_00) * CENT)
        self.assertTrue(reconcile(self.cfg, self.store, self.bridge).ok)

    def test_not_final_deposit_waits(self):
        self.deposit(500_00, when=datetime.now(timezone.utc) - timedelta(seconds=5))
        self.relay()
        self.assertEqual(self.store.deposits(), [])
        self.assertEqual(self.balance(self.user_evm.address), 0)

    def test_forged_row_written_into_db_is_ignored(self):
        # A row that never passed the node's checks: signed by someone else's key
        other_priv, _ = signing.generate_keypair()
        forged = {"id": str(uuid.uuid4()), "sender": self.user_pub, "recipient": self.escrow_pub,
                  "amount_cents": 9_000_00, "reason": f"bridge:v1:{CHAIN_ID}:{self.user_evm.address}",
                  "timestamp": (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat(),
                  "tx_type": blockchain.TX_TYPE_TRANSFER}
        forged = _signed(forged, other_priv, self.user_pub)
        conn = sqlite3.connect(self.ledger)
        blockchain._insert_tx(conn, forged)
        conn.execute("UPDATE transactions SET block_index = 999 WHERE id = ?", (forged["id"],))
        conn.commit()
        conn.close()

        counts = relayer.scan_deposits(self.cfg, self.store)
        self.assertEqual(counts[deposits.INVALID], 1)
        self.assertEqual(self.store.deposits(), [])

    def test_attesters_check_their_own_ledger(self):
        dep = self.deposit(500_00)
        empty = new_ledger("attester-without-deposit")
        # One attester's node hasn't seen the deposit: 2 of 3 still mint
        self.assertEqual(self.relay(self.attesters(self.ledger, self.ledger, empty))[MINTED], 1)

        dep2 = self.deposit(400_00)
        counts = self.relay(self.attesters(self.ledger, empty, empty))
        self.assertEqual(counts[WAITING], 1)
        self.assertIn("1/2 attestations", self.store.deposit(dep2["tx_hash"])["detail"])
        self.assertEqual(self.store.deposit(dep["tx_hash"])["status"], MINTED)

    def test_attester_refuses_a_request_that_differs_from_the_ledger(self):
        dep = self.deposit(500_00)
        deadline = int(time.time()) + 600
        a = self.attesters()[0]
        self.assertIsNotNone(a.attest(dep["tx_hash"], self.user_evm.address, 499_00, deadline).signature)
        self.assertIsNone(a.attest(dep["tx_hash"], self.user_evm.address, 500_00, deadline).signature)
        self.assertIsNone(a.attest(dep["tx_hash"], self.relayer_acct.address, 499_00, deadline).signature)

    def test_small_bad_and_foreign_deposits(self):
        small = self.deposit(5_00)
        bad = transfer(self.ledger, self.user_priv, self.user_pub, self.escrow_pub, 100_00, "for the bridge")
        self.deposit(100_00, chain_id=8453)  # another chain's bridge: not ours
        self.relay()
        self.assertEqual(self.store.deposit(small["tx_hash"])["status"], REFUND)
        self.assertEqual(self.store.deposit(bad["tx_hash"])["status"], REFUND)
        self.assertEqual(len(self.store.deposits()), 2)
        self.assertEqual(self.balance(self.user_evm.address), 0)

    def test_fresh_faucet_credit_is_held(self):
        farmer_priv, farmer_pub = signing.generate_keypair()
        treasury_mint(self.ledger, farmer_pub, blockchain.NEW_USER_GRANT_CENTS, blockchain.TX_TYPE_GRANT,
                      when=datetime.now(timezone.utc) - timedelta(days=1))
        dep = transfer(self.ledger, farmer_priv, farmer_pub, self.escrow_pub, 100_00,
                       f"bridge:v1:{CHAIN_ID}:{self.user_evm.address}")
        self.assertEqual(self.relay()[WAITING], 1)
        self.assertIn("faucet credit on hold", self.store.deposit(dep["tx_hash"])["detail"])

        self.cfg = replace(self.cfg, faucet_hold_days=0.5)
        self.assertEqual(self.relay(self.attesters())[MINTED], 1)

    def test_faucet_credit_passed_to_another_wallet_is_held(self):
        farmer_priv, farmer_pub = signing.generate_keypair()
        mule_priv, mule_pub = signing.generate_keypair()
        treasury_mint(self.ledger, farmer_pub, blockchain.NEW_USER_GRANT_CENTS, blockchain.TX_TYPE_GRANT,
                      when=datetime.now(timezone.utc) - timedelta(days=1))
        transfer(self.ledger, farmer_priv, farmer_pub, mule_pub, 100_00, "gift",
                 when=datetime.now(timezone.utc) - timedelta(hours=3))
        dep = transfer(self.ledger, mule_priv, mule_pub, self.escrow_pub, 100_00,
                       f"bridge:v1:{CHAIN_ID}:{self.user_evm.address}")
        self.assertEqual(self.relay()[WAITING], 1)
        self.assertIn("faucet credit on hold", self.store.deposit(dep["tx_hash"])["detail"])

    def test_sender_daily_limit_and_gas_budget(self):
        self.cfg = replace(self.cfg, max_mints_per_sender_per_day=1)
        self.deposit(100_00)
        second = self.deposit(200_00)
        counts = self.relay()
        self.assertEqual((counts[MINTED], counts[WAITING]), (1, 1))
        self.assertIn("daily mint limit", self.store.deposit(second["tx_hash"])["detail"])

        self.cfg = replace(self.cfg, max_mints_per_sender_per_day=10, relayer_daily_gas_limit=1)
        self.assertEqual(self.relay()[WAITING], 1)
        self.assertIn("gas budget", self.store.deposit(second["tx_hash"])["detail"])

    def test_large_deposit_needs_manual_approval(self):
        dep = self.deposit(6_000_00)
        self.assertEqual(self.relay()[WAITING], 1)
        approvals = Path(_TMP) / f"approvals-{uuid.uuid4().hex[:8]}.txt"
        approvals.write_text(dep["tx_hash"] + "\n")
        self.cfg = replace(self.cfg, approvals_file=str(approvals))
        self.assertEqual(self.relay(self.attesters())[MINTED], 1)

    def test_deposit_above_contract_cap_is_held(self):
        treasury_mint(self.ledger, self.user_pub, 10_000_00)
        dep = self.deposit(15_000_00)
        self.assertEqual(self.relay()[HELD], 1)
        self.assertIn("per-mint cap", self.store.deposit(dep["tx_hash"])["detail"])

    # ------------------------------------------------------------------ chain -> ledger

    def test_bridge_out_is_paid_exactly_once(self):
        self.deposit(500_00)
        self.relay()
        wallet_priv, wallet_pub = signing.generate_keypair()
        self.bridge_out(200_00, wallet_pub)

        self.assertEqual(releases.scan_bridged_out(self.cfg, self.store, self.bridge), 1)
        self.assertEqual(releases.pay_releases(self.cfg, self.store, self.escrow_priv)[PAID], 1)
        self.assertEqual(blockchain.get_balance_cents(self.ledger, wallet_pub), 200_00)

        # Rescanning, re-paying, and a lost state row all leave one payout
        self.assertEqual(releases.scan_bridged_out(self.cfg, self.store, self.bridge), 0)
        releases.pay_releases(self.cfg, self.store, self.escrow_priv)
        self.store.set_release(1, "seen")
        self.assertEqual(releases.pay_releases(self.cfg, self.store, self.escrow_priv)[PAID], 1)
        self.assertEqual(blockchain.get_balance_cents(self.ledger, wallet_pub), 200_00)
        self.assertEqual(blockchain.get_balance_cents(self.ledger, self.escrow_pub), 500_00 - 200_00)
        self.assertTrue(reconcile(self.cfg, self.store, self.bridge).ok)

    def test_release_waits_for_chain_finality(self):
        self.deposit(500_00)
        self.relay()
        self.cfg = replace(self.cfg, chain_finality="5")
        _, wallet_pub = signing.generate_keypair()
        self.bridge_out(50_00, wallet_pub)
        self.assertEqual(releases.scan_bridged_out(self.cfg, self.store, self.bridge), 0)
        self.chain.rpc("anvil_mine", [hex(5)])
        self.assertEqual(releases.scan_bridged_out(self.cfg, self.store, self.bridge), 1)

    def test_release_limits_and_bad_wallet(self):
        self.deposit(5_000_00)  # at the manual-review threshold, not above it
        self.assertEqual(self.relay()[MINTED], 1)
        self.cfg = replace(self.cfg, max_release_cents=1_000_00)
        _, wallet_pub = signing.generate_keypair()
        self.bridge_out(2_000_00, wallet_pub)   # nonce 1: over the per-release limit
        self.bridge_out(50_00, self.escrow_pub)  # nonce 2: back to escrow itself
        releases.scan_bridged_out(self.cfg, self.store, self.bridge)
        counts = releases.pay_releases(self.cfg, self.store, self.escrow_priv)
        self.assertEqual(counts[HELD], 2)
        self.assertEqual(blockchain.get_balance_cents(self.ledger, wallet_pub), 0)

        self.assertTrue(self.store.approve_release(1))
        self.assertEqual(releases.pay_releases(self.cfg, self.store, self.escrow_priv)[PAID], 1)
        self.assertEqual(blockchain.get_balance_cents(self.ledger, wallet_pub), 2_000_00)

    def test_wrong_escrow_key_is_refused(self):
        other_priv, _ = signing.generate_keypair()
        with self.assertRaises(ValueError):
            releases.pay_releases(self.cfg, self.store, other_priv)

    # ------------------------------------------------------------------ reconcile

    def test_reconcile_pauses_when_a_watched_wallet_is_taken_over(self):
        self.deposit(500_00)
        self.relay()
        owner = self._account()  # a Safe owner, say
        cfg = replace(self.cfg, watch_addresses=[owner.address])
        attester = self.attester_accts[0]
        self.assertTrue(reconcile(cfg, self.store, self.bridge, self.pauser.key.hex(),
                                  own_keys=[attester.key.hex()]).ok)

        # The attester's key signed an EIP-7702 authorization: its account now runs someone's contract
        sweeper = "0x" + "5e" * 20
        self.chain.rpc("anvil_setCode", [attester.address, "0xef0100" + sweeper[2:]])
        report = reconcile(cfg, self.store, self.bridge, self.pauser.key.hex(), own_keys=[attester.key.hex()])
        self.assertFalse(report.ok)
        self.assertTrue(report.paused)
        self.assertTrue(self.bridge.paused())
        self.assertTrue(any(attester.address in p and "EIP-7702" in p and sweeper[2:] in p
                            for p in report.problems), report.problems)

        # A configured owner with any code is flagged too
        self.chain.rpc("anvil_setCode", [owner.address, "0x6000"])
        report = reconcile(cfg, self.store, self.bridge)
        self.assertTrue(any(owner.address in p and "contract code" in p for p in report.problems))

    def test_reconcile_pauses_on_unbacked_mint(self):
        self.deposit(500_00)
        self.relay()
        self.assertTrue(reconcile(self.cfg, self.store, self.bridge, self.pauser.key.hex()).ok)

        # Two attester keys leak: they sign a mint with no ledger deposit behind it
        req = eip712.mint_request("cd" * 32, self.user_evm.address, 1_000_00, int(time.time()) + 600)
        sigs = sorted((eip712.sign_mint(a.key.hex(), CHAIN_ID, self.bridge_addr, req)
                       for a in self.attester_accts[:2]), key=lambda s: int(s[0], 16))
        self.bridge.mint_from_ledger(self.relayer_acct.key.hex(), req, [s for _, s in sigs])

        report = reconcile(self.cfg, self.store, self.bridge, self.pauser.key.hex())
        self.assertFalse(report.ok)
        self.assertTrue(report.paused)
        self.assertTrue(self.bridge.paused())
        self.assertTrue(any("no ledger deposit" in p for p in report.problems))
        self.assertTrue(any("escrow" in p for p in report.problems))

        # A paused bridge relays nothing
        self.deposit(100_00)
        self.assertEqual(self.relay(), {MINTED: 0, WAITING: 0, HELD: 0})
        self.assertEqual(token_total_supply(self.chain, self.token_addr), (499_00 + 1_000_00) * CENT)


if __name__ == "__main__":
    unittest.main()
