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
   - the row must really be in its block (the block exists, holds only that deposit, and its
     Merkle root is the deposit's hash), and **admitted** to this ledger more than
     `finality_seconds` ago. The timestamp the depositor signed doesn't count: anyone can
     backdate it (audit F08). See [ledger-checkpoints.md](ledger-checkpoints.md) for what's
     still trusted.

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
3. Each burn is paid exactly once (audit F04–F06):
   - the payout's reason, `bridge-out:v2:<chain>:<bridge address>:<nonce>:<evm tx>`, is in
     the signed hash, and **every node accepts only one payout per (chain, bridge, nonce)**.
     A retry, a replayed old signature or a payout under another id is rejected;
   - the payout is signed once and saved in the state (`releases.intent`) before it's
     submitted. Every retry resends exactly those bytes;
   - a release is `paid` only when the ledger holds a confirmed row with that payout's
     tx_hash, recipient and amount. A matching id proves nothing, since ids aren't signed;
   - every pass re-checks paid releases. If a payout's row is gone (a ledger restored from an
     older backup), the same saved payout is sent again. Without a saved payout, the release
     is held for a person.
4. Mints (F10) go `seen → submitted → minted`. A mint counts only once `processed` is set in
   a finalized block. One that disappears (a reorg or a revert) goes back to `seen` and is
   tried again, and the contract's `processed` still prevents a double mint.
5. The state file is pinned to one bridge contract (`meta.bridge_address`), because a
   replacement contract restarts its nonces. Use a new `GFC_BRIDGE_STATE_DB` for a new bridge.

**Reconcile**

`reconcile.py` runs five checks:
- token supply = (minted − bridged out) × 10¹⁶;
- escrow ≥ wrapped supply + burned-but-unpaid releases;
- every peer DB also sees enough escrow;
- every `MintedFromLedger` event matches a valid deposit;
- no watched wallet has code. The watched wallets are the EVM keys this service holds,
  plus `GFC_BRIDGE_WATCH_ADDRESSES`, which should list the attesters, the pauser and the Safe
  owners. Under EIP-7702, a plain wallet that signs an authorization runs another contract's
  code (`0xef0100` + its address). This is how Binance's hot wallet was swept in October 2026.
  Code there means that key's signing was abused, so the key must be rotated.

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
| `GFC_BRIDGE_FAUCET_HOLD_DAYS` | 14 | GRANT, REFERRAL, FIRST_POST and REPOST credit younger than this can't be bridged, even after it's passed through other wallets (see below) |
| `GFC_BRIDGE_MAX_MINTS_PER_SENDER_PER_DAY` | 3 | Per ledger wallet |
| `GFC_BRIDGE_RELAYER_DAILY_GAS` | 5,000,000 | When the budget is used up, mints wait until the next UTC day |
| `GFC_BRIDGE_MANUAL_REVIEW_CENTS` | 10,000 GFC | Larger deposits need their `tx_hash` in the approvals file |
| `GFC_BRIDGE_MAX_RELEASE_CENTS` / `_DAILY_RELEASE_CENTS` | 10,000 / 50,000 GFC | Releases over these are held until `approve-release` |

The contract has its own caps on top of these: a per-mint cap, a per-window cap, and the
token's supply cap.

## Ledger side: pinned escrows and the rules every node enforces

`config.BRIDGE_ESCROWS` maps each EVM chain ID to its escrow wallet. Tests and testnets
set it with `GFC_BRIDGE_ESCROWS="84532:<pubkey>"`. It is empty until an escrow key exists.
For any pinned escrow, `blockchain.bridge_rule_violation()` applies to REST transfers
(`process_transfer`) and to synced rows (`check_synced_transaction`) alike:

| Rule | Why |
|---|---|
| A transfer *to* an escrow needs the reason `bridge:v1:<that escrow's chain>:<0x address>`, and the address can't be zero | A typo or a wrong chain can't strand GFC in escrow waiting for a manual refund |
| A transfer *from* an escrow needs the reason `bridge-out:v2:<chain>:<bridge address>:<nonce>:<evm tx>` (`v1` without the address, still accepted) or `bridge-refund:v1:<deposit tx_hash>` | Every escrow outflow can be traced to a burn on chain or to a refund |
| One payout per (chain, bridge, nonce), and one refund per deposit, returning the whole deposit to the wallet that made it | A retry, a replayed signature or a restored database can't pay one burn twice, or refund a deposit twice (audit F04–F07) |
| No mints to an escrow, and no escrow-to-escrow transfers | Escrow only changes through deposits, payouts and refunds |

**This is a consensus change.** Nodes on an older release still accept rows that newer
nodes reject (for example a deposit with a bad reason), so pin an escrow only in a
release every node has taken. With no escrow pinned, nothing changes.

Create an escrow key with `python -m bridge new-escrow-key FILE`. It writes an encrypted
key file and prints only the public key, which is what you pin. The passphrase comes from
`GFC_BRIDGE_ESCROW_PASSPHRASE`, or a prompt.

### Free credit passed through other wallets

The hold on fresh free credit follows funds backwards (`deposits.fresh_faucet_cents`):

- Ages are **admission times**: when the ledger accepted the row (its block's timestamp),
  never the timestamp its signer chose. A transfer backdated to look older than the hold
  is still inside it (audit F02).
- Any GRANT, REFERRAL, FIRST_POST or REPOST credit a wallet received within the hold
  period is fresh.
- Each incoming transfer within the hold period is fresh up to the amount of fresh
  credit its sender held when it was sent. This is followed up to 3 hops back, and every
  incoming transfer inside the hold is looked at: a pile of small transfers can't push a
  fresh one out of view (F02).
- Past 3 hops, or once a 500-lookup budget runs out, incoming transfers count as fresh.
  That way a long chain of wallets, or a huge history, can't be used to get around the
  check.
- Payouts from an escrow are clean.

A deposit can only use the part of the balance that isn't fresh. Fresh credit is assumed
to be spent last.

Attesters judge the balance as it was just before the deposit's block. The node's
`/bridge/deposit` endpoint makes the same check up front and refuses a deposit it
couldn't mint, with the message "only X GFC can be bridged now".

## Bridge to Base: the API front ends use

| Endpoint | What it does |
|---|---|
| `GET /bridge/info` | Pinned chains (name, escrow, and the token address once `GFC_BRIDGE_TOKENS` is set), the minimum deposit, the fee, the hold, and a not-an-investment notice |
| `GET /bridge/quote?wallet_id=W` | `balance_cents`, `bridgeable_cents` and `held_cents` |
| `POST /bridge/deposit` (Bearer, `spend` scope) | Body `{wallet_id, chain_id, evm_address, amount}`. The node signs the escrow deposit with the exact reason. Returns `tx_hash` and `mint_cents` |

The deposit endpoint uses the same per-token spend limit as `/transactions/create`. The
node's minimum, fee and hold settings (`GFC_BRIDGE_MIN_DEPOSIT_CENTS`,
`GFC_BRIDGE_RELAY_FEE_CENTS`, `GFC_BRIDGE_FAUCET_HOLD_DAYS`) should match the bridge
service's.

## Refunds

A deposit marked `refund` (under the minimum) or `held` (above the contract's per-mint
cap) goes back to its sender with `python -m bridge refund TX_HASH`. That sends a
`bridge-refund:v1:<tx_hash>` transfer. Every node accepts one refund per deposit, and only
the whole deposit back to the wallet that made it.

A deposit must never be both refunded and minted (audit F07):
- attesters refuse a deposit the ledger shows as refunded, and a rebuilt state marks it
  `refunded`;
- `refund` checks the chain first, when `GFC_BRIDGE_RPC_URL` is set: a deposit that's
  `processed` is never refunded;
- while an attestation issued for the deposit is still usable (its deadline), it waits;
- if the state file is newer than the deposit, it waits one mint TTL, because a lost or
  restored state can't remember attestations from before it.

**Remaining gap:** a state restored from an *old backup* may not remember an attestation
issued after that backup. After restoring the state, wait one mint TTL before running any
refund.

## Trusting the chain: which RPC answers count

The service only knows the chain through RPC providers, and a provider can lie (audit F09).
- **A burn is paid only once every configured provider confirms it.** The main RPC and each
  `GFC_BRIDGE_VERIFY_RPC_URLS` provider must return the burn's receipt, successful, in the
  recorded block, with exactly that `BridgedOut` log at that index, in a block it treats as
  final. Until then the release waits, and nothing is signed for it.
- **Disagreement stops releases, it doesn't lose them.** A provider that contradicts the
  others is logged as an error and verification stops for that pass; the release stays
  recorded and is checked again.
- **Logs are checked field by field.** Wrong contract, wrong event, wrong sizes, a removed
  (reorged) log or one outside the asked block range stops the scan without moving its cursor.
  Two different events for one nonce hold that release for a person.
- **Reconcile cross-checks too.** Each verifier must agree on the bridge's totals and the
  token supply at a block both treat as final.
- **What this still trusts.** One provider can only be checked for consistency: a consistent
  liar has to be outvoted. Mainnet therefore needs at least one independently run provider
  (not the same company behind another URL), and `CHAIN_FINALITY=finalized`. Verifying Base's
  own finality proofs would remove the providers from the trust; it isn't built.

## Keys: one machine must not be enough (audit F14)

- **On mainnet the service refuses to move funds** when:
  - it holds more than one attester key, since one compromised machine would then hold the
    quorum (run each attester elsewhere);
  - a key file is plain text (EVM keys must be encrypted keystores from
    `python -m bridge new-evm-key`, and the escrow key a file from `new-escrow-key`);
  - another account on the machine can read a key file (on Windows, any Everyone, Users or
    Authenticated Users entry in its ACL; `new-evm-key` writes an owner-only ACL);
  - two roles share one wallet.
- **On testnets** the same problems are logged as warnings, so the single-operator test setup
  keeps working.
- **Passphrases are typed at startup.** Each encrypted EVM key asks once when the service starts
  (or reads `GFC_BRIDGE_KEY_PASSPHRASE`); keys are read once and kept in memory, never written
  back decrypted. Encryption protects files at rest, not a running service: a compromised
  service account can still read keys out of memory.

## Watching for abused keys (audit F13)

`reconcile` checks two things about the wallets behind the bridge, and **latches** what it
finds: an alarm stays a problem, and keeps the bridge paused, until a person rotates the key
and runs `python -m bridge clear-incident ADDRESS`.
- **Code on a plain wallet** (`WATCH_ADDRESSES`, plus the keys the service holds): an
  EIP-7702 delegation or any other code.
- **A new nonce on a quiet wallet** (the attesters and the pauser, plus `QUIET_ADDRESSES`):
  these never send transactions. An EIP-7702 authorization raises its signer's nonce, so a
  delegation set, used and cleared between two checks still shows. The service's own pause
  transaction doesn't count.

This only notices after the fact. It can't stop a key that's already abused, only stop the
bridge acting on it. The defence is the wallet rules in the testnet checklist (A2b): these keys
never sign authorizations, and Safe owners are hardware wallets.

## Pausing: the bridge, not the token (audit F16)

- **Automatic pauses stop the bridge only.** `reconcile` calls `GFCBridge.pause()`: mints and
  bridge-outs stop, but GFC keeps moving on Base, so the Uniswap pool keeps trading and
  liquidity providers can still withdraw.
- **The token pause is a person's decision.** `GFCToken.pause()` stops every GFC transfer:
  swaps, adding liquidity and collecting GFC from a position all fail (WETH-only actions may
  still work). Use it only if the token itself is being abused (a stolen minter, say), and say
  publicly why.
- **Unpausing is the Safe's.** A pauser can pause again after the Safe unpauses, until the
  Safe revokes its role: revoke a pauser whose key may be compromised before unpausing.

## Running it unattended (audit F12)

- `python -m bridge run` survives errors: a failed pass (a flaky RPC, a locked database) is
  logged and retried with backoff up to 10 minutes. After 5 failures in a row it logs at
  CRITICAL. `status` shows the last error. Error messages never include an RPC URL.
- `reconcile` reads the chain at one pinned block, and the escrow balance and unpaid releases in
  one snapshot, so a mint or payout landing mid-check doesn't cause a false pause.
- Each mint is capped at `MAX_GAS_PER_MINT` gas (400,000) and `MAX_FEE_GWEI` per gas (1 gwei).
  Over a cap, nothing is sent. A reverted mint's gas counts against the daily budget, and a mint
  sent without a receipt yet is left alone while its attestations are valid, rather than resent.
- Each mint must be exactly the amount recorded for its deposit (the deposit less the relay fee
  at the time); `reconcile` flags any other amount.

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
  `FINALITY_SECONDS`, `CHAIN_FINALITY`, `START_BLOCK`, and `WATCH_ADDRESSES`
  (comma-separated plain wallets that must never get code; never the Safe itself).
- **Trust and limits:** `VERIFY_RPC_URLS` (independent providers, comma-separated; mainnet
  needs one), `QUIET_ADDRESSES` (wallets that never send transactions), `MAX_GAS_PER_MINT`
  and `MAX_FEE_GWEI`.

## Commands

From the repository root, in PowerShell:

```powershell
python -m pip install -r requirements.txt -r bridge/requirements.txt
python -m bridge status
python -m bridge relay
python -m bridge release
python -m bridge reconcile
python -m bridge roles            # who holds every role (from the events), and anything wrong
python -m bridge approve-release 12
python -m bridge refund <deposit tx_hash>
python -m bridge new-escrow-key D:\keys\escrow-84532.json
python -m bridge new-evm-key D:\keys\relayer.json      # encrypted; prints only the address
python -m bridge clear-incident 0x...                    # after rotating a flagged key
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
- **Reconcile:**
  - it pauses the bridge after a mint made with leaked attester keys that has no deposit
    behind it;
  - it pauses the bridge when an attester's account is delegated under EIP-7702, and flags
    a watched Safe owner that has code;
  - a quiet key that sent anything, or a delegation that was cleared again, stays an alarm
    until `clear-incident`;
  - a mint for any amount other than its deposit's is flagged;
  - the gas and fee caps stop a send.

`tests/test_bridge_rpc_trust.py` needs no chain (fake RPC providers): a forged log with no
receipt is never paid, a consistent liar is outvoted, a provider that's behind makes a release
wait, malformed logs stop the scan, mainnet refuses a single provider or a quorum of keys in one
process, and RPC errors never include the URL.

```powershell
python -m unittest tests.test_bridge -v
python -m unittest discover -s tests -p "test_bridge*.py"
```

## Known gaps (before any public deployment)

- **The free-credit hold can be diluted.** It follows funds 3 hops back, but someone who
  mixes fresh credit with enough clean GFC in the same wallet can bridge the clean part
  first, and fresh credit becomes bridgeable once it ages. Phone verification (one
  account per number) is still the main defence against fake accounts.
- **Attesters need their own machines.** On a testnet the relayer may hold every attester key;
  mainnet refuses more than one. The others run `python -m bridge attest-serve` next to their
  own ledger node, and the relayer reaches them over HMAC-authenticated HTTP
  ([remote-attesters.md](remote-attesters.md)). Separate operators, not just separate machines,
  is what makes 2 of 3 mean something.
- **Ledger finality is time-based.** It still relies on this node's ordering (see the
  double-spend note in `dex-plan.md`). Treasury-signed checkpoints should replace it.
- **Refunds are run by hand.** `python -m bridge refund` handles deposits. A held release
  to a bad wallet still needs a person: those tokens are already burned.
- **The escrow key is hot.** It signs releases on the bridge host. Keep the release limits
  low, and move the key to an HSM or KMS with Ed25519 support if one is available.
- **The EVM keys are hot too.** The relayer, pauser and attester keys are on the bridge host
  (encrypted on mainnet, decrypted in memory while it runs). Whoever can make one sign can
  also sign an EIP-7702 authorization and take that account over. Keep them on separate
  machines (attesters apart from the relayer), give each only what its role needs, and keep
  `WATCH_ADDRESSES` complete. The takeover checks notice after the fact; they don't prevent
  anything.
- **RPC providers are trusted, as a group.** Releases need every configured provider to agree,
  so a lie needs all of them. Proof-based verification of Base finality isn't built.
- **Safe owners must be hardware wallets.** A delegated owner's contract can approve any Safe
  transaction in that owner's name. The testnet checklist (A2b) has the wallet rules.
- **The service writes to the live node's SQLite DB.** Payouts go into the same file the
  node uses. It works with SQLite locking, but load-test it alongside a running node on
  testnet.
