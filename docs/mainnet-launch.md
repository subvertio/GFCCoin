# Mainnet launch: GFC on Uniswap (Base)

The steps from today's state to a GFC/WETH pool on Uniswap v3 on Base, in order. Each has
an owner: **you** means Steve does it, by typing every passphrase and signing in his own
wallets. **Claude** means the step is prepared and checked with you before anything is sent.
Nothing here spends real money without an explicit yes at that step.

Status, 2026-11-01:
- Every GPT audit finding has a fix.
- The live node signs ledger checkpoints.
- Attester #2 (ODESSIUS) is prepared.
- The testnet rehearsal on the final code comes first (step 0).

## Decisions (yours, before step 3)

| | Decision | Suggestion |
|---|---|---|
| D1 | Safe owners on Base | 3 hardware wallets, or 2 hardware and 1 phone, held by different people; threshold 2 |
| D2 | Attester #3: machine and operator | someone other than you, on their own machine |
| D3 | Second RPC provider | a paid provider (Alchemy or QuickNode) as main, plus `https://mainnet.base.org` as the verifier, or the other way round |
| D4 | Limits | per mint 10,000 GFC, 50,000 GFC per day, supply cap 1,000,000 GFC (the deploy defaults): small at first, raised by the Safe later |
| D5 | Relay fee | 1 GFC (100 cents), the same on every attester |
| D6 | Starting price and liquidity | how much GFC you bridge out, and how much ETH you pair with it. The ratio is the starting price |

## Steps

**0. Testnet rehearsal on the final code** (you, Claude watching)
1. Restart the test node and bridge windows: both scripts now run master, with checkpoints.
2. Bridge 100+ GFC to Base, then 50 back.
3. Check: the mint lands, the release pays, `reconcile` is ok, and `status` shows the
   checkpoints as ok.
4. Rebuild the test pool on the v2 token, and swap once.

**1. Mainnet escrow key** (you)
- Run `python -m bridge new-escrow-key D:\gfc-mainnet\keys\escrow-8453.json` on the relayer
  machine. You type the passphrase; the command prints only the public key.
- Claude pins it in `config.PINNED_BRIDGE_ESCROWS` (`8453: <pubkey>`) in a node release.
- Run `gfc update` on the live node.
- This is consensus config: every node enforces the escrow rules from that release on.

**2. Wallets** (you)
- Create the Safe on Base with the D1 owners, threshold 2.
- Create the deployer (a fresh keystore with a little ETH on Base: deploying costs well under
  $1 at Base fees).
- Create the relayer key (a little ETH for gas).
- Create the pauser and attester #1 keys with `new-evm-key` (never funded).
- Attester #2 is `0x3c587C3AD0Bb7D8cF00167443111d57a17433035`. Attester #3 comes from D2.

**3. Deploy** (Claude prepares, you run and sign)
1. Simulate first: `forge script ... --rpc-url base` without `--broadcast`.
2. Deploy with `GFC_MULTISIG`, `GFC_PAUSER`, `GFC_ATTESTERS` (all 3), `GFC_THRESHOLD=2`, and
   the D4 limits.
3. Verify the contracts on Basescan.
4. Wait the admin delay, then the Safe accepts admin of both contracts (Transaction Builder,
   as on testnet).
5. `python -m bridge roles` must say `roles: ok`.

**4. Bridge service and attesters** (you start them; Claude checks)
- **Relayer machine:**
  - main RPC and `GFC_BRIDGE_VERIFY_RPC_URLS` (D3);
  - `GFC_BRIDGE_CHECKPOINT_URL=https://node.galacticfederation.tech`;
  - attester #1 local;
  - `GFC_BRIDGE_REMOTE_ATTESTER_URLS=http://100.75.98.77:8300,<attester 3>`, with their
    secret files.
- **ODESSIUS and attester #3:** fill in the bridge address and escrow wallet in their start
  scripts, then start `attest-serve`.
- **Check:** every mainnet check passes at startup (it refuses to run otherwise), and
  `reconcile` is ok.
- **Set the cutoff:** `GFC_BRIDGE_DEPOSITS_FROM` = the deploy block's time, on the relayer and
  every attester. A deposit names its chain, not its bridge contract, so after a redeploy a new
  contract would otherwise mint the old contract's deposits again. Mainnet refuses to start
  without it.
- **Pin the token in a release:** `GFC_BRIDGE_TOKENS` / `config` `8453: <token>`, so the app
  shows the Bridge to Base button.

**5. First real round trip, small** (you)
- Bridge 100 GFC to Base and back.
- Check the release and `reconcile`.

**6. Liquidity** (you, D6)
1. Bridge the GFC for the pool to the wallet that will own the position.
2. Create the GFC/WETH pool on Uniswap v3 at the D6 price, with the 1% fee tier (thin early
   liquidity).
3. Add a full-range position.
4. Swap a tiny amount once to confirm.
5. Post the pool link.

**7. After launch**
- Watch `reconcile` and `status` daily.
- Raise the limits from the Safe only once the bridge has run cleanly for a while.
- Revoke and rotate any key the monitors flag before unpausing.
