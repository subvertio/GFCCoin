# GFC on a DEX: plan

Status: **plan and scaffold only.** Nothing here has been deployed, no gas has been spent, and
the running node and public server are unchanged. The contracts in `evm/` compile and pass
their local tests. They have **not** been audited.

Not legal or tax advice. Section 5 lists the questions to take to a US crypto lawyer before
anything goes on chain.

---

## 1. Architecture decision

### What the ledger guarantees today (and what it doesn't)

What the code does, since the bridge has to fit around it:

- **Amounts are integer cents.** `blockchain.py` keeps `amount_cents`, where 100 = 1.00 GFC.
- **A transaction is identified by `tx_hash`.** `compute_tx_hash()` is SHA-256 over
  canonical JSON of `sender, recipient, amount_cents, timestamp, tx_type, reason`. A
  `TRANSFER` is signed by its sender's Ed25519 key (`signing.sign_tx_hash`, domain
  `GFC-TX-SIG-v1:`), and a wallet ID *is* its public key. The `reason` is inside the hash,
  so whatever the user writes there is covered by their signature.
- **Supply only comes from the treasury, and only within per-type rules.**
  `check_synced_transaction()` accepts a mint only when it comes from
  `TREASURY_WALLET_ID`, is signed by a pinned key (`config.TREASURY_PUBKEYS`), and
  stays inside its type's cap:

  | Type | Rule |
  |---|---|
  | GRANT | exactly 100 GFC, once per wallet |
  | REWARD (PoDT) | at most 1,000 GFC |
  | REFERRAL | 1,000 GFC to the inviter, or a 100 GFC bonus to the invitee |
  | REPOST | 15 GFC |
  | FIRST_POST | at most 1,000 GFC, once per wallet |
  | OPERATOR | at most 10,000 GFC, with a memo; node-host grants exactly 10,000, once |

  (The task brief said "100 GFC per referral". The code pays 1,000 to the inviter and 100
  to the invitee.)
- **The treasury can't make transfers.** `process_transfer()` refuses the treasury as
  sender or recipient, and synced rows sent *to* the treasury are rejected. The 100-trillion
  GFC premine can only leave the treasury through the mint types above.
- **Balances are recomputed locally from validated rows, and the ledger has no global
  ordering.** Each node accepts rows in timestamp order and puts them in its *own* local
  blocks (`create_block`). A wallet can sign two conflicting transfers and send them to
  different peers. Each peer accepts whichever one it sees first and parks the other as
  `PENDING`. Nothing makes the network agree on which one won. That's acceptable for app
  credits, but it is **the main thing a bridge has to defend against**.
- **PoDT rewards come from the sync engine,** not from user claims. `/podt/report_transfer`
  is off unless `GFC_ENABLE_PODT_REPORT=1`, because the claim is self-reported. Rewards are
  capped per transaction, per viewer per creator per day, and by account age.
- **Phone verification is the main Sybil gate.** It runs on Firebase, allows one account
  per number, and pays the 100 GFC grant. Once GFC has a market price, every faucet
  (grant, referral, first post, PoDT) turns into cash that can be extracted, and the
  reward for farming them goes up with it.

### Options

| | A. Wrap the existing ledger (lock and mint) | B. New ERC-20, custodial mint and burn by the treasury | **C. Hybrid (recommended)** |
|---|---|---|---|
| Backing | Every token is matched by GFC locked in a ledger escrow wallet | Treasury mints on chain and debits the user on the ledger off-chain | Same 1:1 escrow as A |
| Who can create on-chain supply | The bridge relayer key | The treasury operator | A k-of-n set of independent attesters, inside on-chain rate limits and caps |
| What one leaked key does | The relayer key mints without limit → the pool is drained | Unlimited minting, and the ledger treasury key is now also exposed to a hot service | One attester key alone mints **nothing**. A full quorum is still held to `maxMintCents` per mint and `windowLimitCents` per window, until the pauser stops it |
| Ledger treasury key | Not involved | Online, signing on-chain-related actions | Not involved. It stays offline as it is today |
| Ledger changes | One pinned escrow wallet | New debit/burn semantics on the ledger | One pinned escrow wallet, plus (later) treasury-signed checkpoints |
| Audit surface | Small | Large: two systems with mixed trust | Small contracts, plus an off-chain attester spec |

**Decision: C, a hybrid lock-and-mint bridge with threshold attestation.**

- The ERC-20 is a *wrapped* representation. The only minter is `GFCBridge`, and it mints
  only against a ledger deposit into the escrow wallet that `threshold` attesters have
  signed for (EIP-712). Each deposit can mint once (`processed[ledgerTxHash]`).
- Burning goes through `bridgeOut`, which destroys the tokens and emits `BridgedOut(nonce, …)`.
  The release service then pays the user from the ledger escrow with an ordinary signed
  `TRANSFER`. The treasury doesn't mint anything new.
- The ledger treasury key is never used by the bridge. The EVM admin is a separate
  multisig, and the attesters hold their own secp256k1 keys.

### Security tradeoffs of the decision

1. **Finality is borrowed from one node.** Because the ledger has no global ordering, the
   bridge treats one *canonical* view as final: a bridge node that syncs from the treasury
   node. A deposit counts only when that node has accepted it into a block and it is older
   than a finality window. A user who double-spends could leave other nodes disagreeing
   about the escrow's balance. **Before mainnet**, the treasury node should publish
   signed checkpoints (block height plus a rolling hash of accepted `tx_hash`es) that
   attesters require, so "final" means something every node can check.
2. **Attesters are a trust assumption.** Mitigations: k-of-n with k ≥ 2, keys on different
   operators and machines, each attester running its own ledger node and its own RPC
   endpoint, and on-chain caps that bound the loss if all of them are compromised.
3. **The pause buttons are centralization, and users should be told so.** The token-level
   `pause()` also freezes DEX trading. Keep it while the bridge is young. Plan to renounce
   the token's `PAUSER_ROLE` later and keep only the bridge-level pause.
4. **The admin can add minters.** The admin (`DEFAULT_ADMIN_ROLE`) can grant `MINTER_ROLE`
   to anyone. Put the admin behind a `TimelockController` owned by the multisig, so a role
   change is public for days before it takes effect. The admin handover is already
   two-step with a delay (`AccessControlDefaultAdminRules`).
5. **Decimals: 18 on chain, 2 on the ledger.** `CENT = 1e16`. `bridgeOut` only accepts
   whole cents, so nothing is lost to rounding. Any dust below a cent stays with the user
   on chain.
6. **The supply ceiling is the premine.** `MAX_SUPPLY` equals `PREMINE_CENTS × 1e16`
   (100 trillion GFC), and the working `supplyCap` is set far lower and raised only on
   purpose.
7. **Initial liquidity is a ledger-rule question, not a contract question.** Today the
   treasury can't move premine into the escrow (no treasury `TRANSFER`, and OPERATOR mints
   are capped at 10,000). Seeding a pool from the treasury would need a new, explicitly
   capped ledger rule that every node enforces, and section 5 flags it as the riskiest
   legal step. The alternative is to have no team seeding at all: users bridge GFC they
   earned, and the pool grows from that.

### File and folder plan

The EVM code goes in this repo rather than a new one. The bridge service has to reuse
`blockchain.py` and `signing.py`, and the deposit `reason` format and EIP-712 type should be
versioned in the same commits as the ledger code that produces them. `evm/` can move to its
own repo later if auditors want a clean scope. It has no imports from the Python side.

```
evm/                          # Foundry project (this branch)
  foundry.toml  foundry.lock  remappings.txt
  lib/forge-std  lib/openzeppelin-contracts      # git submodules, pinned v1.17.0 / v5.7.0
  src/GFCToken.sol            # ERC-20 + Permit + Burnable + Pausable + delayed-admin roles, supply cap
  src/GFCBridge.sol           # EIP-712 k-of-n mint, rate limits, bridgeOut burn, pause
  src/interfaces/IGFCToken.sol, IGFCBridge.sol
  script/Deploy.s.sol         # deploy + wire roles + begin admin handover (not run on any network)
  test/GFCToken.t.sol  GFCBridge.t.sol  GFCBridgeInvariant.t.sol  Deploy.t.sol
bridge/                       # off-chain service (section 4); see docs/bridge-service.md
  config.py  chain.py  eip712.py  store.py  deposits.py  attester.py  relayer.py  releases.py  reconcile.py  __main__.py
tests/test_bridge.py          # Python tests: ledger test DB + anvil
docs/dex-plan.md              # this file
```

Ledger changes for a separate PR. **These affect consensus, so every node has to upgrade
before they take effect:**

- `config.BRIDGE_ESCROW_WALLETS`: pinned escrow public key(s), the same pattern as
  `TREASURY_PUBKEYS`.
- A deposit `reason` grammar: `bridge:v1:<chainId>:<0xEVMaddress>`. Nodes don't need to
  enforce it, but the wallet UI should generate it and attesters parse it strictly.
- Treasury-signed checkpoints (tradeoff 1).
- Only if counsel approves pool seeding: a capped, one-time treasury-to-escrow allocation
  type.

---

## 2. Chain and DEX

**Recommendation: Base**, with Arbitrum One as the fallback. Ethereum mainnet is not
recommended for launch.

| | Base | Ethereum L1 | Arbitrum One | Solana |
|---|---|---|---|---|
| Fits this code | Yes (EVM) | Yes | Yes | No. It would need an SPL token and a new program |
| Per-action cost | Low (L2) | High for 60–200k-gas user actions | Low (L2) | Low |
| Audience fit | Farcaster and Coinbase onramp users | Broadest | DeFi users | Separate ecosystem |
| Main risk | One sequencer (it can delay or censor); L2 reorgs before L1 finality | Cost | Same as Base | Different stack, tools and audit |

On an L2, the release service must wait until a `BridgedOut` block is **finalized on L1**
(or at least "safe") before paying out ledger GFC. On mints, `deadline` keeps an attestation
from being used long after a sequencer outage.

### Costs: formulas and measured gas

Gas units below come from `forge test --gas-report` and a local `forge script` simulation,
not from any network. Prices are unknowns: fill them in from a block explorer on the day.

| Action | Gas (measured locally) |
|---|---|
| Deploy token + bridge + role wiring + admin handover (`Deploy.s.sol`, simulated) | 4,412,750 |
| `mintFromLedger`, 2 of 3 signatures | median ~110,850, max ~199,460 (first mint in a window: cold storage) |
| `bridgeOut` | median ~62,448, max ~96,660 |
| `approve` / `transfer` | ~46,453 / ~36,645 median |
| Uniswap pool create + initialize + first position | **unknown**: measure on Base Sepolia |
| Multisig accepting admin on 2 contracts | **unknown**: depends on the multisig |

- **L2 (Base or Arbitrum):** `cost_ETH = gas × (l2_base_fee + priority_fee) + l1_data_fee`.
  `l1_data_fee` scales with the transaction's calldata and blob prices. It is large for
  the deployment (about 19.3 KB of runtime bytecode, plus initcode) and small for user
  actions.
- **L1:** `cost_ETH = gas × (base_fee + priority_fee)`.
- **USD:** `cost_USD = cost_ETH × ETH_USD`. ETH_USD, base fees and blob prices are
  **unknown here**, so no number is given.
- **Who pays:** anyone can relay `mintFromLedger`, so the user or a sponsor can pay mint
  gas. `bridgeOut` is always paid by the user.
- **Not gas:** pool liquidity (the ETH or USDC side is real money and a business
  decision), the audit (get quotes), RPC providers, multisig hardware. All of these are
  **unknown**.

### DEX options

- **Uniswap v3, GFC/WETH, 1% fee tier** (the usual tier for a new, volatile token). This
  is the default pick: aggregators and token lists support it everywhere, and the tooling
  is mature.
- **Uniswap v4, GFC/ETH, no hook.** Pool creation is cheaper (one singleton contract) and
  it pairs with native ETH. Indexer and aggregator support is close to v3's. Don't add a
  custom hook, because that's another contract to audit.
- **Aerodrome** (Base-native ve(3,3)) is the biggest venue on Base. Liquidity there tends
  to need emissions or bribes, which looks like paying for volume. Skip it for the MVP.

Take every router, factory and position-manager address from the DEX's own documentation
on deployment day. None are listed here on purpose.

---

## 3. Contracts (scaffold on this branch)

Built with **Foundry**, not Hardhat. Tests are written in Solidity next to the code, fuzz
and invariant testing are built in, `forge script` simulates locally without an RPC, and
nothing in `evm/` needs a Node toolchain. Hardhat's advantage, its TypeScript plugin
ecosystem, isn't needed here.

- **`GFCToken`**: `ERC20`, `ERC20Permit`, `ERC20Burnable`, `ERC20Pausable` and
  `AccessControlDefaultAdminRules`.
  - Roles: `DEFAULT_ADMIN_ROLE` (the treasury multisig), `MINTER_ROLE` (the bridge only)
    and `PAUSER_ROLE` (a guardian that can pause but not unpause).
  - Supply: `supplyCap ≤ MAX_SUPPLY`. Nothing is minted on chain at deployment.
- **`GFCBridge`**: `mintFromLedger(MintRequest, signatures)`.
  - Signatures are EIP-712 over `(ledgerTxHash, to, amountCents, deadline)`, bound to the
    chain ID and the bridge address. Signers must be strictly increasing, which also rules
    out duplicates.
  - Limits: a per-mint cap, a per-window cap, and a deadline.
  - `processed` is set only on success, so a mint that fails at the token's cap doesn't
    consume the deposit.
  - `bridgeOut(amount, ledgerWallet)` burns through the allowance (or a permit) and emits
    a nonce.
  - `totalMintedCents` and `totalBridgedOutCents` are kept for reconciliation.
- **Tests: 32 passing.** They cover roles, the cap, pause (pauser can't unpause), permit,
  the delayed admin handover, 2-of-3 mints, replay, the same deposit sent to another
  address, too few signatures, duplicate or unsorted signers, a non-attester signer, a
  tampered amount, a signature made for another bridge, expiry, the per-mint and per-window
  caps with reset, pause in both directions, bridge-out burn and event, bridge-out input
  errors, and deploy wiring. One fuzz test and three invariants (8,192 random calls) check
  that `totalSupply == (minted − bridgedOut) × CENT`, that supply stays within the cap, and
  that the window is never overspent.

Run (PowerShell, from `evm\`): `forge test`, `forge test --gas-report`, `forge coverage`.

---

## 4. Off-chain bridge service

Built in `bridge/`, with its runbook, settings and known gaps in
[bridge-service.md](bridge-service.md). The outline it implements:

**The trust rule:** rows synced from peers are untrusted. The service never takes a
balance, a block or a deposit from a peer's word. It acts only on rows that its own node
accepted through `blockchain.check_synced_transaction()`. That function requires a valid
Ed25519 signature, a `tx_hash` that matches the row, funding, and, for any mint, a pinned
treasury signature within its type's cap. A peer can't forge a deposit without the
depositor's key, and it can't fund one with invented GFC without the treasury key.

```
user wallet --TRANSFER(reason=bridge:v1:8453:0xabc…)--> ESCROW (ledger)
      bridge node (syncs from treasury node; finality window; later: checkpoints)
         ├─ attester 1 ─┐  each runs its own node + RPC, checks independently,
         ├─ attester 2 ─┼─ signs EIP-712 MintRequest
         └─ attester 3 ─┘
                 relayer (no special key) → GFCBridge.mintFromLedger → GFCToken.mint
user → GFCBridge.bridgeOut → BridgedOut(nonce) → [L1-finalized] → releases.py signs
       ESCROW → user TRANSFER (reason=bridge-out:v1:8453:<nonce>) → ledger
reconcile.py: escrow_balance ≥ (totalMinted − totalBridgedOut) − releases in flight, else PAUSE
```

- **`deposits.py`** reads the bridge node's DB, not the network. It finds deposits that:
  - have recipient `ESCROW`, type `TRANSFER`, and `block_index IS NOT NULL`;
  - are older than the finality window, and later fall under a treasury checkpoint;
  - have a `reason` that matches `^bridge:v1:<chainId>:0x[0-9a-fA-F]{40}$` exactly, and
    whose `chainId` is this chain;
  - are not yet in `processed` on chain.

  Any deposit that fails parsing is queued for a manual refund, never minted.
- **`attester.py`**:
  - Re-runs the same checks against its *own* node.
  - Applies policy:
    - delays deposits from wallets whose grant, referral or first-post credits are
      younger than N days, so a farmer can't take fresh faucet GFC straight to market;
    - holds amounts above a manual-review threshold;
    - screens the destination address against sanctions lists.
  - Signs `Mint(ledgerTxHash = bytes32(tx_hash), to, amountCents, deadline)`.
  - Keys belong in a hardware wallet or KMS, one per operator. Never on the treasury
    node.
- **`relayer.py`** collects k signatures, sorts them by signer address, and submits. It
  holds only a gas wallet.
- **`releases.py`** handles bridge-out:
  - Waits for L1-final `BridgedOut` events.
  - Is idempotent on `nonce`: before signing it checks the ledger for an existing
    `bridge-out:v1:<chainId>:<nonce>` reason.
  - Signs the escrow `TRANSFER` with the escrow Ed25519 key. Store that key encrypted
    like the treasury key (`signing.py encrypt`), or in an HSM/KMS that supports Ed25519
    if one is available. Apply per-release and per-day limits.
- **`reconcile.py`** runs every block or minute and checks:
  - **(a)** `token.totalSupply() == (totalMintedCents − totalBridgedOutCents) × CENT`;
  - **(b)** canonical escrow balance ≥ outstanding wrapped supply;
  - **(c)** the escrow balance agrees across ≥ 2 independent nodes;
  - **(d)** every on-chain mint has a matching deposit.

  If any check fails, it calls `pause()` with the guardian key and pages a human.
- **`store.py`** is a SQLite file with deposits, attestations, submitted mints, releases
  and a cursor. It's separate from the node DB.
- **Tests** run against a ledger test DB with `GFC_TREASURY_PUBKEYS` set to a test key
  (as `tests/test_signed_ledger.py` already does) plus `anvil`. They cover forged
  deposits, unfunded deposits, double-spend races, a reorged `BridgedOut`, release
  idempotency, and auto-pause.

---

## 5. US legal and compliance gotchas

Take these to counsel before mainnet. Each one can block launch.

1. **Never an ICO, never an investment.**
   - No presale and no "token sale".
   - Don't use phrases like "get in early", "price", "returns", "moon", "staking yield" or
     "listing".
   - The team doesn't sell GFC to fund development. If the team ever sells treasury GFC
     into the pool, counsel has to approve it first, because that is the classic
     securities-offering fact pattern.
2. **Howey exposure comes from the facts, not from labels.**
   - The treasury holds a 100-trillion premine and the team controls minting rules. Both
     must be disclosed.
   - Keep GFC framed and *designed* as consumptive network credit, earned by doing things
     (seeding, posting, inviting), not bought in expectation of the team's efforts
     raising its value.
   - Ask counsel about the current SEC posture and the status of federal market-structure
     legislation. Both have been changing, and this plan doesn't assume either.
3. **Money transmission (FinCEN/MSB and state licenses).** Once ledger GFC can be swapped
   for ETH, it may count as convertible virtual currency. Whoever runs the escrow (issuing
   and redeeming wrapped GFC) could then be an "administrator" or "exchanger" under FinCEN's
   CVC guidance, with state money-transmitter or NY BitLicense questions on top. Get this
   answered *before* running the bridge for the public.
4. **Sanctions (OFAC).** Screen bridge-in destinations and bridge-out callers. Block
   sanctioned addresses and comprehensively sanctioned jurisdictions. This applies even
   without KYC.
5. **Disclosures** go on the site, in the app, and in the token's metadata link:
   - "GFC is an in-app credit for the GFC network. It is not an investment, not a
     security, not a deposit, and carries no promise of value or profit. Wrapped GFC on
     Base is redeemable only for ledger GFC, not for dollars. The team may pause the
     bridge and token in an emergency, and controls the treasury. Smart contracts and
     bridges can fail and funds can be lost."
   - "Rewards may be taxable income once they have a market value. Ask a tax
     professional."
   - Publish the contract addresses, the roles and who holds them, the caps, and the
     audit status. Say "unaudited" until an audit exists.
6. **Terms of Service and privacy.**
   - The ToS should say that credits can change, that the operator has no obligation to
     redeem them, and which jurisdictions are excluded.
   - Phone numbers (Firebase) are personal data. The privacy policy has to cover them,
     and they must never be linked to on-chain addresses in public.
7. **App stores.** Check Google Play's blockchain-content policy, and Apple's rules on
   currency earned through in-app tasks if an iOS client ever ships, before the Android
   client links rewards to a tradable token. Shipping the bridge as web-only is a
   possible way around this.
8. **Marketing law.** Follow the FTC endorsement rules for any paid or gifted promotion.
   Don't run "engage to earn" campaigns (likes or recasts for GFC). They are karma
   farming, invite Sybils, and look like paying for hype.
9. **Tax and reporting.** Ask counsel whether rewards with a market value create reporting
   duties (Forms 1099) for the operator, and whether anything in the bridge counts as a
   broker under the newer digital-asset reporting rules.

---

## 6. MVP, step by step

Every step that deploys a contract or spends gas **waits for the owner's explicit go-ahead.**

0. **Prerequisites**
   - Counsel review of section 5.
   - Choose the escrow key custody.
   - Ledger PR: pinned `BRIDGE_ESCROW_WALLETS` plus the deposit reason grammar.
   - Decide on the finality window, and the checkpoints design.
   - Decide how liquidity is sourced: user-bridged only, or a capped and counsel-approved
     treasury allocation.
1. **Contracts** (scaffold done on this branch)
   - Add a `TimelockController` admin.
   - Raise branch coverage to 100% (`forge coverage`). Today: 100% of lines and functions,
    96% of statements, 81% of branches in `src/`.
   - Run static analysis (Slither and/or Aderyn) and triage the findings.
   - Freeze the EIP-712 type and the reason grammar as v1.
2. **Bridge service** (`bridge/`): build section 4 with end-to-end tests using anvil and a
   test ledger. Use a test treasury key through `GFC_TREASURY_PUBKEYS`, never the public
   node.
3. **Testnet (Base Sepolia).**
   - Set up a test multisig, three attesters on three machines, and a test ledger network.
   - Drills:
     - pause and unpause;
     - attester key rotation;
     - one attester offline;
     - a double-spend attempt;
     - an L2 reorg or delay;
     - forged peer rows;
     - hitting the rate limits;
     - recovery after the reconciler pauses.
   - Run for at least two weeks.
4. **Audit checklist**, before mainnet:
   - **Code freeze and scope:**
     - code frozen at a tagged commit;
     - scope covers `evm/src` *and* the attester spec (deposit validation is where the
       real risk is);
     - an independent firm or contest with a published report;
     - every finding fixed or accepted, with written reasons.
   - **Contract checks:**
     - invariants hold under fuzzing at higher run counts;
     - roles, initial holders and caps documented;
     - an emergency runbook exists.
   - **Key custody:**
     - multisig signers on separate hardware wallets;
     - the deployer key keeps no roles, which `Deploy.t.sol` asserts;
     - the treasury ledger key is not on any bridge host.
   - **Operations:**
     - monitoring and alerting on the reconcile checks;
     - a bug bounty terms page.
5. **Mainnet (Base)**, after the go-ahead.
   - Run `Deploy.s.sol` with low caps, for example a supply cap of a few × the expected
     first-month bridged volume. That number is a business decision and isn't given here.
   - Verify the source on the explorer.
   - The multisig accepts admin after the delay.
   - Publish the addresses only after verification.
6. **Uniswap pool**, after the go-ahead.
   - Create a v3 GFC/WETH 1% pool, or a v4 GFC/ETH pool with no hook.
   - Set the initial price with the first position.
   - Disclose who provided liquidity and whether the LP position is locked.
   - Submit the token to token lists only with accurate metadata and the disclosures link.
7. **Announcement** (copy below): post after the pool exists and the addresses are
   verified. Pin the disclosures.

### Announcement copy (Nostr / Farcaster)

Plain text, under 300 characters per post, no price talk, no engagement bait. Fill in the
placeholders. Don't post until the addresses are verified on the explorer.

> GFC credits can now move between the GFC network and Base.
> Earn GFC by seeding, posting and inviting friends, then bridge it as an ERC-20 if you want to hold or swap it on chain.
> Token: <TOKEN_ADDRESS> · Bridge: <BRIDGE_ADDRESS> · How it works: <DOCS_URL>

> What it is: wrapped GFC, 1:1 backed by GFC locked in a public ledger escrow. Minting needs 2 of 3 independent attesters, under daily limits.
> What it isn't: an investment, a sale, or a promise of value. There's no presale and the team isn't selling.
> Audit: <AUDIT_STATUS>

> Things to know before you bridge: it's new code, bridges can fail, and the team can pause it in an emergency. Start small. Rewards may be taxable once they have a market value.
> Questions and bug reports: <ISSUES_URL>

The posts don't say "like/recast/zap to win", "airdrop", "early", or anything about price.
