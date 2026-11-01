"""
Tests for bridge/roles.py (audit F15): the role inventory rebuilt from RoleGranted/RoleRevoked
events, and the problems it reports. A fake chain stands in for the RPC.

Run from the repository root:
    python -m unittest discover -s tests -v
"""

import unittest

from eth_utils import keccak

from bridge import roles

TOKEN = "0x" + "11" * 20
BRIDGE = "0x" + "22" * 20
SAFE = "0x" + "33" * 20
DEPLOYER = "0x" + "44" * 20
PAUSER = "0x" + "55" * 20
ATTESTERS = ["0x" + f"{i:02x}" * 20 for i in (0xa1, 0xa2, 0xa3)]
ZERO = "0x" + "00" * 20


def role(name):
    return "0x" + ("00" * 32 if name == "DEFAULT_ADMIN" else keccak(text=name + "_ROLE").hex())


class FakeChain:
    def __init__(self):
        self.events = {TOKEN: [], BRIDGE: []}
        self.contracts = {SAFE, TOKEN, BRIDGE}
        self.pending = {TOKEN: ZERO, BRIDGE: ZERO}

    def grant(self, contract, name, account, granted=True):
        self.events[contract].append({
            "topics": [roles.TOPIC_GRANTED if granted else roles.TOPIC_REVOKED, role(name),
                       "0x" + "00" * 12 + account[2:], "0x" + "00" * 32],
            "blockNumber": hex(100 + len(self.events[contract])), "logIndex": "0x0"})

    def block_number(self):
        return 1000

    def logs(self, address, topic, from_block, to_block, chunk):
        return [e for e in self.events[address.lower() if address.lower() in self.events else address]
                if e["topics"][0] == topic]

    def code(self, address):
        return b"\x60" if address.lower() in self.contracts else b""

    def call(self, to, signature, types=(), args=(), returns=("uint256",)):
        assert signature == "pendingDefaultAdmin()"
        return self.pending[to.lower()], 0


class FakeBridge:
    def __init__(self, threshold=2):
        self.address = BRIDGE
        self._threshold = threshold

    def threshold(self):
        return self._threshold


def healthy_chain():
    c = FakeChain()
    # What Deploy.s.sol does, then the Safe accepting admin
    c.grant(TOKEN, "DEFAULT_ADMIN", DEPLOYER)
    c.grant(BRIDGE, "DEFAULT_ADMIN", DEPLOYER)
    c.grant(TOKEN, "MINTER", BRIDGE)
    c.grant(TOKEN, "BURNER", BRIDGE)
    c.grant(TOKEN, "PAUSER", PAUSER)
    c.grant(BRIDGE, "PAUSER", PAUSER)
    for a in ATTESTERS:
        c.grant(BRIDGE, "ATTESTER", a)
    for contract in (TOKEN, BRIDGE):
        c.grant(contract, "DEFAULT_ADMIN", DEPLOYER, granted=False)
        c.grant(contract, "DEFAULT_ADMIN", SAFE)
    return c


class RoleInventoryTests(unittest.TestCase):
    def inv(self, chain, threshold=2):
        return roles.inventory(chain, FakeBridge(threshold), TOKEN, 0)

    def test_a_correct_deploy_is_clean(self):
        inv = self.inv(healthy_chain())
        self.assertEqual(inv["problems"], [])
        self.assertEqual(len(inv["roles"]["bridge"]["ATTESTER"]), 3)

    def test_a_role_the_deployer_kept_is_reported(self):
        # The audit's case: the deployer grants itself MINTER before handing admin over
        c = healthy_chain()
        c.grant(TOKEN, "MINTER", DEPLOYER)
        problems = self.inv(c)["problems"]
        self.assertTrue(any("MINTER held by" in p for p in problems), problems)

    def test_admin_handover_and_threshold_problems(self):
        c = healthy_chain()
        c.contracts.discard(SAFE)  # the admin is a plain wallet
        c.pending[BRIDGE] = "0x" + "66" * 20
        problems = " | ".join(self.inv(c, threshold=1)["problems"])
        self.assertIn("plain wallet, not a Safe", problems)
        self.assertIn("handover", problems)
        self.assertIn("one attester key can mint", problems)

    def test_overlapping_jobs_and_missing_burner(self):
        c = healthy_chain()
        c.grant(BRIDGE, "ATTESTER", PAUSER)
        c.grant(TOKEN, "BURNER", BRIDGE, granted=False)
        problems = " | ".join(self.inv(c)["problems"])
        self.assertIn("several jobs", problems)
        self.assertIn("the bridge lacks BURNER", problems)

    def test_revoked_roles_are_gone(self):
        c = healthy_chain()
        c.grant(BRIDGE, "ATTESTER", ATTESTERS[0], granted=False)
        c.grant(BRIDGE, "ATTESTER", ATTESTERS[1], granted=False)
        inv = self.inv(c)
        self.assertEqual(len(inv["roles"]["bridge"]["ATTESTER"]), 1)
        self.assertTrue(any("1 attesters for a threshold of 2" in p for p in inv["problems"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
