"""
Who holds every role on the token and the bridge, rebuilt from their RoleGranted / RoleRevoked
events since the deploy block (audit F15). The contracts don't enumerate role members, and a
deployer could grant itself a role before handing admin to the Safe, so the events are the
complete record.

`python -m bridge roles` prints the inventory and what's wrong with it:
- the admin isn't a contract (a Safe), or there's more than one, or a handover is pending;
- anyone but the bridge can mint or burn the token;
- an address holds two jobs (admin, pauser, attester, minter);
- fewer attesters than the bridge's threshold, or a threshold below 2.
Read-only: it sends nothing.
"""

from typing import Dict, List, Set

from eth_utils import keccak, to_checksum_address

TOPIC_GRANTED = "0x" + keccak(text="RoleGranted(bytes32,address,address)").hex()
TOPIC_REVOKED = "0x" + keccak(text="RoleRevoked(bytes32,address,address)").hex()

ROLE_NAMES = {
    "0x" + "00" * 32: "DEFAULT_ADMIN",
    **{"0x" + keccak(text=name).hex(): name[:-5] for name in
       ("MINTER_ROLE", "BURNER_ROLE", "PAUSER_ROLE", "ATTESTER_ROLE")},
}


def members(chain, address: str, from_block: int, to_block: int, chunk: int) -> Dict[str, Set[str]]:
    """{role name: current holders} from the contract's role events, in order."""
    events = []
    for topic, granted in ((TOPIC_GRANTED, True), (TOPIC_REVOKED, False)):
        for log in chain.logs(address, topic, from_block, to_block, chunk):
            events.append((int(log["blockNumber"], 16), int(log.get("logIndex", "0x0"), 16), granted, log))
    held: Dict[str, Set[str]] = {}
    for _, _, granted, log in sorted(events, key=lambda e: (e[0], e[1])):
        role = ROLE_NAMES.get(log["topics"][1].lower(), log["topics"][1])
        account = to_checksum_address("0x" + log["topics"][2][-40:])
        (held.setdefault(role, set()).add if granted else held.setdefault(role, set()).discard)(account)
    return held


def inventory(chain, bridge, token_address: str, from_block: int, chunk: int = 5_000) -> dict:
    """Role holders on both contracts and the problems with them."""
    head = chain.block_number()
    roles = {"token": members(chain, token_address, from_block, head, chunk),
             "bridge": members(chain, bridge.address, from_block, head, chunk)}
    bridge_addr = to_checksum_address(bridge.address)
    problems: List[str] = []

    for name, held in roles.items():
        admins = held.get("DEFAULT_ADMIN", set())
        if len(admins) != 1:
            problems.append(f"{name}: {len(admins)} admins")
        for a in admins:
            if not chain.code(a):
                problems.append(f"{name}: admin {a} is a plain wallet, not a Safe")
        pending, _ = chain.call(token_address if name == "token" else bridge.address,
                                "pendingDefaultAdmin()", returns=("address", "uint48"))
        if int(pending, 16):
            problems.append(f"{name}: an admin handover to {to_checksum_address(pending)} is pending")
    for role in ("MINTER", "BURNER"):
        others = roles["token"].get(role, set()) - {bridge_addr}
        if others:
            problems.append(f"token: {role} held by {', '.join(sorted(others))} (only the bridge may)")
        if bridge_addr not in roles["token"].get(role, set()):
            problems.append(f"token: the bridge lacks {role}")

    jobs: Dict[str, List[str]] = {}
    for name, held in roles.items():
        for role, holders in held.items():
            for h in holders:
                jobs.setdefault(h, []).append(f"{name} {role}")
    for holder, js in jobs.items():
        kinds = {j.split()[1] for j in js}
        if holder != bridge_addr and len(kinds) > 1:
            problems.append(f"{holder} holds several jobs: {', '.join(sorted(js))}")

    threshold = bridge.threshold()
    attesters = roles["bridge"].get("ATTESTER", set())
    if threshold < 2:
        problems.append(f"bridge: threshold {threshold}: one attester key can mint")
    if len(attesters) < threshold:
        problems.append(f"bridge: {len(attesters)} attesters for a threshold of {threshold}")
    return {"roles": roles, "threshold": threshold, "problems": problems}
