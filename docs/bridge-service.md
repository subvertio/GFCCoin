# Bridge service (`bridge/`)

This is the off-chain half of the wrapped-GFC bridge. The contracts are in `evm/` and the
overall plan is in [dex-plan.md](dex-plan.md). **Nothing has been deployed.** The tests
run against a throwaway ledger and a local `anvil` chain.

## Flow

**Ledger → chain**

1. The user signs a ledger TRANSFER to the escrow wallet. The `reason` field must be
   exactly `bridge:v1:<chainId>:<0xEVMaddress>`. It is covered by the user's signature,
   because it's part of `tx_hash`.
2. `relayer.scan_deposits()` reads **this node's** ledger DB and re-checks every escrow
   row:
   - the hash is recomputed and must match;
   - the Ed25519 signature must verify;
   - the row must be in a block and older than `finality_seconds`.

   It doesn't matter how a row got into the DB. A row written straight into SQLite, or
   a forged peer row, fails the same checks.
3. Each attester (`attester.py`) re-runs those checks against **its own** ledger DB.
   It also checks that the request matches the ledger exactly (destination, and the
   amount minus the fee), then applies policy. If everything passes, it signs the
   EIP-712 MintRequest. The digest is tested against the contract's `mintDigest()`.
4. The relayer sorts `threshold` signatures by signer address and calls
   `mintFromLedger`. The relayer holds only a gas wallet.

**Chain → ledger**

1. `releases.scan_bridged_out()` reads `BridgedOut` events, but only up to the
   finalized block (`chain_finality`: `finalized`, `safe`, or a number of
   confirmations).
2. `pay_releases()` signs an escrow TRANSFER and adds it through
   `blockchain.accept_synced_transaction()`, the same checks a peer row gets. The
   node's sync then shares it like any other signed transfer.
3. Each nonce is paid at most once:
   - the ledger tx id is derived from (chain id, nonce), so a second insert is a
     duplicate;
   - before signing, the service looks on the ledger for an existing
     `bridge-out:v1:<chainId>:<nonce>:` row.

**Reconcile**

`reconcile.py` runs four checks:
- token supply = (minted − bridged out) × 10¹⁶;
- escrow ≥ wrapped supply + burned-but-unpaid releases;
- every peer DB also sees enough escrow;
- every `MintedFromLedger` event matches a valid deposit.

If any check fails, it pauses the bridge with the pauser key. In `run` mode the service
moves no funds while reconcile is failing.

## Protecting the relayer's gas and the pool

Anyone can relay a mint, but if *our* relayer submits it, *we* pay the gas (about
110–200k gas per mint). Swaps and `bridgeOut` are always paid by the user. These
limits stop people from farming free GFC to spend our gas, or to dump it into the pool:

| Setting | Default | What it does |
|---|---|---|
| `GFC_BRIDGE_MIN_DEPOSIT_CENTS` | 100 GFC | Smaller deposits are never minted. They are marked `refund` |
| `GFC_BRIDGE_RELAY_FEE_CENTS` | 0 | Taken out of the minted amount and kept in escrow. It pays for gas |
| `GFC_BRIDGE_FAUCET_HOLD_DAYS` | 14 | A wallet whose newest GRANT, REFERRAL, FIRST_POST or REPOST credit is younger than this waits |
| `GFC_BRIDGE_MAX_MINTS_PER_SENDER_PER_DAY` | 3 | Per ledger wallet |
| `GFC_BRIDGE_RELAYER_DAILY_GAS` | 5,000,000 | When the budget is used up, mints wait until the next UTC day |
| `GFC_BRIDGE_MANUAL_REVIEW_CENTS` | 10,000 GFC | Larger deposits need their `tx_hash` in the approvals file |
| `GFC_BRIDGE_MAX_RELEASE_CENTS` / `_DAILY_RELEASE_CENTS` | 10,000 / 50,000 GFC | Releases over these are held until `approve-release` |

The contract has its own caps on top of these: a per-mint cap, a per-window cap, and the
token's supply cap.

## Configuration

All configuration comes from `GFC_BRIDGE_*` environment variables (see `bridge/config.py`):

- **Required:**
  - `RPC_URL`, `CHAIN_ID`, `ADDRESS` (the bridge contract), and `ESCROW_WALLET` (the
    escrow's Ed25519 public key);
  - `LEDGER_DB`, which defaults to the node's DB;
  - `STATE_DB`, a separate SQLite file.
- **Key files:** `RELAYER_KEY_FILE`, `ATTESTER_KEY_FILE`, `PAUSER_KEY_FILE` and
  `ESCROW_KEY_FILE`.
  - The escrow key file uses the treasury key format, so it can be encrypted with
    `python signing.py encrypt`. `GFC_BRIDGE_ESCROW_PASSPHRASE` unlocks it.
  - Keys are only ever read from files and are never logged.
  - httpx request logging is turned off, because RPC URLs often carry an API key.
- **Optional:** `DENYLIST_FILE`, `APPROVALS_FILE`, `PEER_LEDGER_DBS`,
  `FINALITY_SECONDS`, `CHAIN_FINALITY`, `START_BLOCK`.

## Commands

From the repository root, in PowerShell:

```powershell
python -m pip install -r requirements.txt -r bridge/requirements.txt
python -m bridge status
python -m bridge relay
python -m bridge release
python -m bridge reconcile
python -m bridge approve-release 12
python -m bridge run --interval 30
```

## Tests

`tests/test_bridge.py` needs Foundry (`anvil`, `forge`) and `bridge/requirements.txt`. If
they're missing, it skips. It covers:

- **Mint path:**
  - the EIP-712 digest matches the contract;
  - a deposit mints exactly once, minus the fee;
  - a deposit inside the finality window waits;
  - a forged row written straight into the DB is ignored;
  - 2 of 3 attesters mint, and 1 of 3 waits;
  - an attester refuses a request that differs from its ledger.
- **Deposits that must not mint:**
  - small deposits, deposits with a bad reason, and deposits for another chain;
  - fresh faucet credit is held;
  - the per-sender daily limit and the gas budget apply;
  - large deposits wait for manual approval;
  - deposits above the contract's per-mint cap are held.
- **Release path:**
  - a release is paid exactly once, including after its state row is lost;
  - releases wait for chain finality;
  - the release limits apply;
  - a release back to the escrow wallet is held;
  - the wrong escrow key is refused.
- **Reconcile:** it pauses the bridge after a mint made with leaked attester keys that
  has no deposit behind it.

```powershell
python -m unittest tests.test_bridge -v
```

## Known gaps (before any public deployment)

- **The faucet hold only looks at the depositing wallet.** A farmer can move fresh grant
  GFC to a second wallet and deposit from there. Following funds through wallets, or
  holding back any deposit funded by recent faucet credit, is the next step. Phone
  verification (one account per number) is still the main Sybil gate.
- **Attesters run in-process.** The relayer calls `Attester` objects directly, so one
  operator holds every key, which is only acceptable on a testnet. Production attesters
  need a small signing endpoint each, on separate machines and operators.
- **Ledger finality is time-based.** It still relies on this node's ordering (see the
  double-spend note in `dex-plan.md`). Treasury-signed checkpoints should replace it.
- **Refunds are manual.** Deposits in `refund`, and held releases with a bad wallet, need
  a person to fix them.
- **The escrow key is hot.** It signs releases on the bridge host. Keep the release limits
  low, and move the key to an HSM or KMS with Ed25519 support if one is available.
- **The service writes to the live node's SQLite DB.** Payouts go into the same file the
  node uses. It works with SQLite locking, but load-test it alongside a running node on
  testnet.
