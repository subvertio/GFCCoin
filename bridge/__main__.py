"""
python -m bridge <command>

  status                 deposit and release counts by status, and the last reconcile
  relay                  scan escrow deposits and mint the ones attesters sign
  release                pay finalized BridgedOut events from escrow
  reconcile              check backing; pauses the bridge if a pauser key is set
  approve-release NONCE  let a held release past the per-release / daily limits
  refund TX_HASH         send a deposit marked refund/held back to its sender
  new-escrow-key FILE    create an encrypted escrow key file; prints only its public key
  new-evm-key FILE       create an encrypted EVM keystore file; prints only its address
  clear-incident ADDR    forget a latched watched-wallet alarm once its key is rotated
  attest-serve           run this machine's attester as a signing endpoint (bridge/attester_http.py)
  new-attester-secret FILE  create the secret an attester endpoint and the relayer share
  run [--interval S]     relay, release and reconcile in a loop; errors are logged and retried
  roles                  who holds every role on the token and bridge, and what's wrong (read-only)

Configuration is GFC_BRIDGE_* environment variables (bridge/config.py). In this
version the relayer calls attesters in-process: GFC_BRIDGE_ATTESTER_KEY_FILE,
plus GFC_BRIDGE_EXTRA_ATTESTER_KEY_FILES (comma-separated) for a single-operator
testnet. On mainnet the service refuses to hold more than one attester key (that
would put the whole quorum on one machine, audit F14): the other attesters run
`attest-serve` on their own machines, and the relayer reaches them through
GFC_BRIDGE_REMOTE_ATTESTER_URLS and GFC_BRIDGE_REMOTE_ATTESTER_SECRET_FILES; see
docs/remote-attesters.md.
"""

import argparse
import logging
import os
import sys
import time
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # node modules (blockchain, signing)

# status, refund, approve-release and new-escrow-key work without the EVM dependencies;
# relay, release, reconcile and run need bridge/requirements.txt.
from bridge import releases  # noqa: E402
from bridge.config import BridgeConfig, read_escrow_key, read_evm_key  # noqa: E402
from bridge.store import Store  # noqa: E402


logger = logging.getLogger("gfc.bridge")


def _remote_attesters(cfg: BridgeConfig) -> list:
    from bridge.attester_http import RemoteAttester, read_secret
    if len(cfg.remote_attester_urls) != len(cfg.remote_attester_secret_files):
        raise SystemExit("GFC_BRIDGE_REMOTE_ATTESTER_URLS and GFC_BRIDGE_REMOTE_ATTESTER_SECRET_FILES "
                         "need one entry each per attester")
    return [RemoteAttester(cfg, url, read_secret(f), label=f"remote attester #{i + 1}")
            for i, (url, f) in enumerate(zip(cfg.remote_attester_urls, cfg.remote_attester_secret_files))]


def _serve_attester(cfg: BridgeConfig, host: str, port: int) -> int:
    """attest-serve: this machine's attester, its own ledger node and key, as a signing endpoint."""
    from bridge import attester_http, keyfiles
    from bridge.attester import Attester
    secret_file = os.environ.get("GFC_ATTESTER_SECRET_FILE")
    if not cfg.attester_key_file or not secret_file:
        raise SystemExit("set GFC_BRIDGE_ATTESTER_KEY_FILE and GFC_ATTESTER_SECRET_FILE")
    problems = key_problems(cfg, {"attester": cfg.attester_key_file})
    why = keyfiles.access_problem(secret_file)
    if why:
        problems.append(f"the attester secret file is {why}")
    for p in problems:
        if cfg.is_testnet:
            logger.warning(f"Testnet only: {p}")
        else:
            print(f"Refusing to sign on mainnet: {p}", file=sys.stderr)
    if problems and not cfg.is_testnet:
        return 2
    attester = Attester(cfg, key=read_evm_key(cfg.attester_key_file))
    server = attester_http.make_server(attester, attester_http.read_secret(secret_file), host, port)
    logger.info(f"Attester {attester.address} signing for chain {cfg.chain_id} bridge {cfg.bridge_address} "
                f"from ledger {cfg.ledger_db}, on {host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0

MAX_BACKOFF_SECONDS = 600


def _attester_files(cfg: BridgeConfig) -> list:
    files = [cfg.attester_key_file] if cfg.attester_key_file else []
    return files + [f for f in os.environ.get("GFC_BRIDGE_EXTRA_ATTESTER_KEY_FILES", "").split(",") if f]


def key_problems(cfg: BridgeConfig, files: dict) -> list:
    """
    What's wrong with the key files ({role: path}), for mainnet: plain-text keys, files
    other accounts can read, and a quorum of attester keys in this one process (audit F14).
    """
    from bridge import keyfiles
    problems = []
    attesters = [r for r in files if r.startswith("attester")]
    if len(attesters) > 1:
        problems.append(f"{len(attesters)} attester keys in one service: one compromised machine could mint. "
                        "Run each attester on its own machine")
    for role, path in files.items():
        if not keyfiles.is_keystore(path):
            problems.append(f"the {role} key file is plain text: use an encrypted one "
                            f"(python -m bridge new-{'escrow' if role == 'escrow' else 'evm'}-key)")
        why = keyfiles.access_problem(path)
        if why:
            problems.append(f"the {role} key file is {why}")
    return problems


def _distinct(keys: dict) -> list:
    """Two roles on one EVM key defeat the point of separate roles."""
    from eth_account import Account
    seen, problems = {}, []
    for role, key in keys.items():
        addr = Account.from_key(key).address
        if addr in seen:
            problems.append(f"the {role} and {seen[addr]} keys are the same wallet {addr}")
        seen.setdefault(addr, role)
    return problems


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="python -m bridge")
    sub = parser.add_subparsers(dest="cmd", required=True)
    for name in ("status", "relay", "release", "reconcile", "roles"):
        sub.add_parser(name)
    ap = sub.add_parser("approve-release")
    ap.add_argument("nonce", type=int)
    fp = sub.add_parser("refund")
    fp.add_argument("tx_hash")
    kp = sub.add_parser("new-escrow-key")
    kp.add_argument("file")
    ek = sub.add_parser("new-evm-key")
    ek.add_argument("file")
    ci = sub.add_parser("clear-incident")
    ci.add_argument("address")
    sv = sub.add_parser("attest-serve")
    sv.add_argument("--host", default="127.0.0.1")
    sv.add_argument("--port", type=int, default=8300)
    ns = sub.add_parser("new-attester-secret")
    ns.add_argument("file")
    rp = sub.add_parser("run")
    rp.add_argument("--interval", type=float, default=30.0)
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    if args.cmd == "new-escrow-key":
        import json
        import keystore
        import signing
        path = Path(args.file)
        if path.exists():
            print(f"{path} already exists; not overwriting it", file=sys.stderr)
            return 1
        priv, pub = signing.generate_keypair()  # never written to disk in plaintext
        passphrase = os.environ.get("GFC_BRIDGE_ESCROW_PASSPHRASE") or \
            signing._passphrase("Passphrase for the escrow key file (12+ chars): ", True)
        sealed = keystore.seal_backup(passphrase, {"private_key": priv, "public_key": pub}, "treasury")
        signing._write_secret(path, json.dumps(sealed, indent=2))
        print(f"Encrypted escrow key written to {path}. Run the bridge with GFC_BRIDGE_ESCROW_PASSPHRASE set.")
        print(f"Pin this public key in config.PINNED_BRIDGE_ESCROWS for its chain:\n  {pub}")
        return 0
    if args.cmd == "new-evm-key":
        import getpass
        from bridge import keyfiles
        path = Path(args.file)
        if path.exists():
            print(f"{path} already exists; not overwriting it", file=sys.stderr)
            return 1
        passphrase = getpass.getpass("Passphrase for the new key file (12+ chars): ")
        if len(passphrase) < 12 or passphrase != getpass.getpass("Again: "):
            print("passphrases differ or are shorter than 12 characters", file=sys.stderr)
            return 1
        print(f"Encrypted key written to {path}. Its address:\n  {keyfiles.write_evm_keystore(str(path), passphrase)}")
        return 0
    if args.cmd == "new-attester-secret":
        import signing
        from bridge import attester_http, keyfiles
        path = Path(args.file)
        if path.exists():
            print(f"{path} already exists; not overwriting it", file=sys.stderr)
            return 1
        signing._write_secret(path, attester_http.new_secret())
        keyfiles.restrict_to_owner(str(path))
        print(f"Secret written to {path}. Copy it to the relayer machine (never by chat or email) and set it as "
              "GFC_ATTESTER_SECRET_FILE here and in GFC_BRIDGE_REMOTE_ATTESTER_SECRET_FILES there.")
        return 0
    cfg = BridgeConfig.from_env()
    if args.cmd == "attest-serve":
        return _serve_attester(cfg, args.host, args.port)
    store = Store(cfg.state_db)
    store.pin_bridge(cfg.bridge_address)  # one state file per bridge contract

    if args.cmd == "status":
        for table, rows in (("deposits", store.deposits()), ("releases", store.releases())):
            counts = {}
            for r in rows:
                counts[r["status"]] = counts.get(r["status"], 0) + 1
            print(f"{table}: {counts or 'none'}")
        for addr, text in store.meta_like("incident:").items():
            print(f"INCIDENT {addr}: {text}")
        if store.get_meta("last_error"):
            print(f"last error: {store.get_meta('last_error')}")
        return 0
    if args.cmd == "clear-incident":
        from bridge.reconcile import clear_incident
        ok = clear_incident(store, args.address)
        print("cleared; a new nonce baseline is taken on the next reconcile" if ok else "no incident for that address")
        return 0 if ok else 1
    if args.cmd == "refund":
        if not cfg.escrow_key_file:
            raise SystemExit("GFC_BRIDGE_ESCROW_KEY_FILE is not set")
        bridge_for_refund = None
        if cfg.rpc_url:  # a refund checks the chain first: a minted deposit is never refunded
            from bridge.chain import BridgeContract, Chain
            bridge_for_refund = BridgeContract(Chain(cfg.rpc_url), cfg.bridge_address)
        ledger_tx = releases.refund_deposit(cfg, store, read_escrow_key(cfg.escrow_key_file), args.tx_hash,
                                            bridge=bridge_for_refund)
        print(f"refunded: ledger tx {ledger_tx}")
        return 0
    if args.cmd == "approve-release":
        ok = store.approve_release(args.nonce)
        print("approved" if ok else "no held release with that nonce")
        return 0 if ok else 1

    from bridge import relayer
    from bridge.attester import Attester
    from bridge.chain import BridgeContract, Chain
    from bridge.reconcile import reconcile

    chain = Chain(cfg.rpc_url, label="main rpc")
    verifiers = [Chain(url, label=f"verify rpc #{i + 1}") for i, url in enumerate(cfg.verify_rpc_urls)]
    for c in [chain, *verifiers]:
        if c.chain_id() != cfg.chain_id:
            print(f"{c.label} is chain {c.chain_id()}, config says {cfg.chain_id}", file=sys.stderr)
            return 2
    bridge = BridgeContract(chain, cfg.bridge_address)
    if args.cmd == "roles":
        from bridge.roles import inventory
        inv = inventory(chain, bridge, bridge.token(), cfg.start_block, cfg.log_chunk_blocks)
        for name, held in inv["roles"].items():
            for role, holders in sorted(held.items()):
                print(f"{name} {role}: {', '.join(sorted(holders)) or '(nobody)'}")
        print(f"bridge threshold: {inv['threshold']}")
        print("roles: ok" if not inv["problems"] else "roles: PROBLEMS")
        for p in inv["problems"]:
            print("  -", p)
        return 0 if not inv["problems"] else 1

    files = {role: path for role, path in (("relayer", cfg.relayer_key_file), ("pauser", cfg.pauser_key_file),
                                           ("escrow", cfg.escrow_key_file)) if path}
    files.update({f"attester {i + 1}": f for i, f in enumerate(_attester_files(cfg))})
    problems = cfg.mainnet_problems() + key_problems(cfg, files)
    from bridge.keyfiles import access_problem
    problems += [f"remote attester secret {Path(f).name} is {why}" for f in cfg.remote_attester_secret_files
                 if (why := access_problem(f))]
    if problems and cfg.is_testnet:
        for p in problems:
            logger.warning(f"Testnet only: {p}")
    elif problems and args.cmd in ("relay", "release", "run"):
        print("Refusing to move funds on mainnet:", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        return 2

    # Every key is read once, here: an encrypted one asks for its passphrase once
    relayer_key = read_evm_key(cfg.relayer_key_file) if cfg.relayer_key_file else None
    escrow_key = read_escrow_key(cfg.escrow_key_file) if cfg.escrow_key_file else None
    pauser_key = read_evm_key(cfg.pauser_key_file) if cfg.pauser_key_file else None
    attester_keys = [read_evm_key(f) for f in _attester_files(cfg)]
    attesters = [Attester(cfg, key=k) for k in attester_keys] + _remote_attesters(cfg)
    shared = _distinct({**({"relayer": relayer_key} if relayer_key else {}),
                        **({"pauser": pauser_key} if pauser_key else {}),
                        **{f"attester {i + 1}": k for i, k in enumerate(attester_keys)}})
    addresses = [a.address for a in attesters]
    if len(set(addresses)) != len(addresses):
        shared.append("two attesters (local or remote) are the same wallet")
    if shared:
        for p in shared:
            print(p, file=sys.stderr)
        return 2
    # Remote attesters' wallets never send transactions either: watch them like the local ones
    remote = [a.address for a in attesters[len(attester_keys):]]
    cfg = replace(cfg, watch_addresses=cfg.watch_addresses + remote, quiet_addresses=cfg.quiet_addresses + remote)

    def do_relay():
        if not relayer_key:
            raise SystemExit("GFC_BRIDGE_RELAYER_KEY_FILE is not set")
        print("scan:", relayer.scan_deposits(cfg, store))
        print("relay:", relayer.relay(cfg, store, bridge, attesters, relayer_key))

    def do_release():
        if not escrow_key:
            raise SystemExit("GFC_BRIDGE_ESCROW_KEY_FILE is not set")
        print("new BridgedOut events:", releases.scan_bridged_out(cfg, store, bridge, verifiers))
        print("release:", releases.pay_releases(cfg, store, escrow_key))

    def do_reconcile() -> bool:
        report = reconcile(cfg, store, bridge, pauser_key, own_keys=[relayer_key, *attester_keys],
                           quiet_keys=attester_keys, verifiers=verifiers)
        print(f"reconcile: {'ok' if report.ok else 'PROBLEMS'} outstanding={report.outstanding_cents} "
              f"escrow={report.escrow_cents} unpaid={report.unpaid_release_cents}"
              + (" (bridge paused)" if report.paused else ""))
        for p in report.problems:
            print("  -", p)
        return report.ok

    if args.cmd == "relay":
        do_relay()
    elif args.cmd == "release":
        do_release()
    elif args.cmd == "reconcile":
        return 0 if do_reconcile() else 1
    elif args.cmd == "run":
        failures = 0
        while True:
            try:
                if do_reconcile():  # never move funds while the books don't balance
                    if relayer_key:
                        do_relay()
                    if escrow_key:
                        do_release()
                failures = 0
            except Exception as e:  # a flaky RPC, a locked DB: log it, wait longer, try again (audit F12)
                failures += 1
                detail = f"{type(e).__name__}: {e}"
                for url in [cfg.rpc_url, *cfg.verify_rpc_urls]:
                    detail = detail.replace(url, "<rpc>")  # never log an RPC URL: it may hold an API key
                store.set_meta("last_error", f"{time.strftime('%Y-%m-%d %H:%M:%S')} ({failures} in a row) {detail}")
                (logger.critical if failures >= 5 else logger.error)(f"Pass failed ({failures} in a row): {detail}")
            time.sleep(min(args.interval * 2 ** min(failures, 10), max(args.interval, MAX_BACKOFF_SECONDS)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
