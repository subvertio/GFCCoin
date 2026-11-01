"""
python -m bridge <command>

  status                 deposit and release counts by status, and the last reconcile
  relay                  scan escrow deposits and mint the ones attesters sign
  release                pay finalized BridgedOut events from escrow
  reconcile              check backing; pauses the bridge if a pauser key is set
  approve-release NONCE  let a held release past the per-release / daily limits
  refund TX_HASH         send a deposit marked refund/held back to its sender
  new-escrow-key FILE    create an encrypted escrow key file; prints only its public key
  run [--interval S]     relay, release and reconcile in a loop
  roles                  who holds every role on the token and bridge, and what's wrong (read-only)

Configuration is GFC_BRIDGE_* environment variables (bridge/config.py). In this
version the relayer calls attesters in-process: GFC_BRIDGE_ATTESTER_KEY_FILE,
plus GFC_BRIDGE_EXTRA_ATTESTER_KEY_FILES (comma-separated) for a single-operator
testnet. Production attesters run on separate machines; see docs/bridge-service.md.
"""

import argparse
import logging
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # node modules (blockchain, signing)

# status, refund, approve-release and new-escrow-key work without the EVM dependencies;
# relay, release, reconcile and run need bridge/requirements.txt.
from bridge import releases  # noqa: E402
from bridge.config import BridgeConfig, read_escrow_key, read_evm_key  # noqa: E402
from bridge.store import Store  # noqa: E402


def _attesters(cfg: BridgeConfig) -> list:
    from bridge.attester import Attester
    files = [cfg.attester_key_file] if cfg.attester_key_file else []
    files += [f for f in os.environ.get("GFC_BRIDGE_EXTRA_ATTESTER_KEY_FILES", "").split(",") if f]
    return [Attester(cfg, key=read_evm_key(f)) for f in files]


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
    cfg = BridgeConfig.from_env()
    store = Store(cfg.state_db)
    store.pin_bridge(cfg.bridge_address)  # one state file per bridge contract

    if args.cmd == "status":
        for table, rows in (("deposits", store.deposits()), ("releases", store.releases())):
            counts = {}
            for r in rows:
                counts[r["status"]] = counts.get(r["status"], 0) + 1
            print(f"{table}: {counts or 'none'}")
        return 0
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
    from bridge.chain import BridgeContract, Chain
    from bridge.reconcile import reconcile

    chain = Chain(cfg.rpc_url)
    if chain.chain_id() != cfg.chain_id:
        print(f"RPC is chain {chain.chain_id()}, config says {cfg.chain_id}", file=sys.stderr)
        return 2
    bridge = BridgeContract(chain, cfg.bridge_address)
    relayer_key = read_evm_key(cfg.relayer_key_file) if cfg.relayer_key_file else None
    escrow_key = read_escrow_key(cfg.escrow_key_file) if cfg.escrow_key_file else None
    pauser_key = read_evm_key(cfg.pauser_key_file) if cfg.pauser_key_file else None

    def do_relay():
        if not relayer_key:
            raise SystemExit("GFC_BRIDGE_RELAYER_KEY_FILE is not set")
        print("scan:", relayer.scan_deposits(cfg, store))
        print("relay:", relayer.relay(cfg, store, bridge, _attesters(cfg), relayer_key))

    def do_release():
        if not escrow_key:
            raise SystemExit("GFC_BRIDGE_ESCROW_KEY_FILE is not set")
        print("new BridgedOut events:", releases.scan_bridged_out(cfg, store, bridge))
        print("release:", releases.pay_releases(cfg, store, escrow_key))

    def do_reconcile() -> bool:
        report = reconcile(cfg, store, bridge, pauser_key,
                           own_keys=[relayer_key] + [a._key for a in _attesters(cfg)])
        print(f"reconcile: {'ok' if report.ok else 'PROBLEMS'} outstanding={report.outstanding_cents} "
              f"escrow={report.escrow_cents} unpaid={report.unpaid_release_cents}"
              + (" (bridge paused)" if report.paused else ""))
        for p in report.problems:
            print("  -", p)
        return report.ok

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
    if args.cmd == "relay":
        do_relay()
    elif args.cmd == "release":
        do_release()
    elif args.cmd == "reconcile":
        return 0 if do_reconcile() else 1
    elif args.cmd == "run":
        while True:
            if do_reconcile():  # never move funds while the books don't balance
                if relayer_key:
                    do_relay()
                if escrow_key:
                    do_release()
            time.sleep(args.interval)
    return 0


if __name__ == "__main__":
    sys.exit(main())
