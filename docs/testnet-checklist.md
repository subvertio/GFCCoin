# Base Sepolia testnet checklist

This is the plan for a first public-testnet run of the bridge: the contracts in `evm/`, the
service in `bridge/`, and a **separate test ledger network** (its own test treasury key). It
never touches the public node (`gfc-node`) or real GFC.

- **Part A** is what you set up. Keys you create stay on your machines. Nobody pastes a private
  key into a chat, a ticket or a command line.
- **Part B** lists the exact commands Claude will run, but **only after you approve each
  numbered step**. Nothing here has been run.

Base Sepolia is chain ID **84532**. Its ETH is free test ETH with no value. Where this
checklist says "from the official docs", take the URL from Base's or Safe's own documentation
on the day. No URLs or addresses are hard-coded here on purpose, except Base's public RPC,
which you should confirm in Base's docs too.

---

## Part A: what you set up

### A1. Folders (outside every repo)

```powershell
New-Item -ItemType Directory -Force D:\gfc-testnet\keys, D:\gfc-testnet\node-data, D:\gfc-testnet\bridge | Out-Null
```

Key files go in `D:\gfc-testnet\keys`. Never put them in `D:\projects\...`, so they can't be
committed by accident.

### A2. Wallets (EVM, Base Sepolia)

| Role | What it is | How to create it | Needs test ETH |
|---|---|---|---|
| **Deployer** | Deploys the contracts and wires roles, then hands admin to the Safe and keeps nothing | `cast wallet import gfc-testnet-deployer --interactive` (Foundry's encrypted keystore: paste a fresh key from a new MetaMask account, or use `cast wallet new` in your own terminal) | Yes, about 0.05 (deploying is about 4.4M gas) |
| **Safe (admin)** | 2-of-3 multisig: the treasury/admin role on both contracts. It can unpause, change limits and grant roles | In the Safe web app (from Safe's official site), pick the **Base Sepolia** network and create a Safe with 3 owner addresses you control and threshold 2. On the testnet, 3 fresh MetaMask accounts are fine; for mainnet the owners must be hardware wallets (see A2b) | The owners need a little for signing transactions |
| **Pauser** | Fast emergency stop on the token and the bridge. It can pause, never unpause | A separate MetaMask account. For the bridge service's auto-pause, also save its key as a file (A3) | Yes, a little |
| **Attesters ×3** | Each signs mints after checking the deposit on its own ledger | Key files (A3). On this testnet all three run in one bridge process; production puts them on 3 machines | No (they only sign) |
| **Relayer** | Submits mints and pays their gas | Key file (A3) | Yes, about 0.05 |
| **Your test user** | Receives wrapped GFC; you'll swap or bridge it back from here | Any MetaMask account on Base Sepolia | A little, to bridge back |

**Test ETH:** use a Base Sepolia faucet from **Base's official docs** ("Network faucets"). Some
faucets need a Coinbase or Alchemy login. Fund the deployer, the relayer, the pauser and your
test user.

### A2b. Key safety: EIP-7702 and hot keys

Binance's hot wallets were drained in October 2026 after its signing system was made to sign
an **EIP-7702 authorization**. With EIP-7702 (live on Ethereum and Base), a plain wallet that
signs one hands its whole account to a contract. The attacker never needs the private key: a
single signature on the wrong prompt is enough. The bridge's rules:

- **Never approve an EIP-7702 request** on any bridge wallet: the Safe owners, the pauser, the
  attesters, the relayer or the deployer. In MetaMask and other wallets it shows up as
  "Switch to smart account", "Upgrade your account", "Smart account" or "Set code" /
  "Authorization". Decline it, even if a site you trust asks. These wallets only ever sign
  ordinary transactions, and the attesters only sign mint requests.
- **Safe owners:** on the testnet, 3 fresh MetaMask accounts used for nothing else. For
  mainnet, **3 hardware wallets** (each in its own place, with its own recovery phrase), never
  browser-extension accounts. Under EIP-7702 a delegated owner's contract can approve any Safe
  transaction in that owner's name. Two owners taken over is the whole admin role.
- **Hot key files** (relayer, pauser, attesters, escrow) live only in `D:\gfc-testnet\keys`, are
  read only by the bridge service, and hold only what their role needs: the relayer holds a
  little gas, the attesters and the pauser hold none. On mainnet:
  - each attester runs on its **own machine**, with its own node and its own operator;
  - the escrow key moves to an **HSM or KMS** with Ed25519 support, and the release limits stay low;
  - the relayer and pauser are on a different machine from the attesters.
- **The bridge watches for takeovers.** Every `reconcile` reads the code of each watched
  wallet: the keys the service holds, plus `GFC_BRIDGE_WATCH_ADDRESSES` (B6). Any code there,
  such as `0xef0100…`, which is an EIP-7702 delegation, makes it report the takeover and pause
  the bridge. Then rotate that key: revoke its role from the Safe, grant a new address, and
  replace the owner in the Safe.

### A3. Key files for the bridge service

Each command writes the key to a file and prints only the address. Run them yourself, in the
bridge venv:

```powershell
cd D:\projects\GFC
$py = '.\.venv\Scripts\python.exe'   # a venv with requirements.txt + bridge\requirements.txt
foreach ($name in 'attester0','attester1','attester2','relayer','pauser') {
  & $py -c "import sys,pathlib; from eth_account import Account; a=Account.create(); p=pathlib.Path(sys.argv[1]); p.write_text(a.key.hex()); print(sys.argv[2], a.address)" "D:\gfc-testnet\keys\$name.key" $name
}
```

That covers every bridge-service key. If you'd rather use your MetaMask pauser, skip `pauser`
here, and the bridge will run without auto-pause.

Then fund the **relayer** and the **pauser** addresses with test ETH.

### A4. Test ledger keys (Ed25519, never the real treasury)

```powershell
cd D:\projects\GFC
# A test treasury for the test ledger network: encrypted file, prints only the public key
python signing.py generate-encrypted D:\gfc-testnet\keys\test-treasury.json
# The bridge escrow: encrypted file, prints only the public key to pin
$env:GFC_BRIDGE_ESCROW_PASSPHRASE = Read-Host -AsSecureString "Escrow passphrase (12+ chars)" | ConvertFrom-SecureString -AsPlainText
.\.venv\Scripts\python.exe -m bridge new-escrow-key D:\gfc-testnet\keys\escrow-84532.json
```

`ConvertFrom-SecureString -AsPlainText` needs PowerShell 7. In Windows PowerShell 5.1, leave
the variable unset and `new-escrow-key` will prompt you instead.

### A5. Send these to Claude

**Public values only:**

- the Safe address;
- the 3 Safe owner addresses (to watch for takeovers);
- the pauser address;
- the 3 attester addresses (from A3);
- the deployer keystore name (`gfc-testnet-deployer`);
- the test treasury public key (A4);
- the escrow public key (A4).

Optionally, a Basescan (Etherscan v2) API key for source verification. Keep it in an env var:
`$env:ETHERSCAN_API_KEY`.

Never send:

- private keys or key files;
- the deployer keystore password;
- the escrow or test-treasury passphrases.

You type those into the prompts yourself.

---

## Part B: the commands Claude will run, one approved step at a time

All from `D:\projects\GFC` (after PRs #38–#40 are merged), in PowerShell. Deploy-time values
are lower than the defaults on purpose:

| Setting | Testnet value |
|---|---|
| Supply cap | 100,000 GFC |
| Per mint | 1,000 GFC |
| Per day | 5,000 GFC |
| Admin delay | 300 seconds |

### B0. Preflight (read-only, no gas)

```powershell
$env:Path = "$HOME\.foundry\bin;$env:Path"
$env:BASE_SEPOLIA_RPC = 'https://sepolia.base.org'   # confirm in Base's docs; a provider URL with a key works too
cast chain-id --rpc-url $env:BASE_SEPOLIA_RPC        # must print 84532
cast balance (cast wallet address --account gfc-testnet-deployer) --rpc-url $env:BASE_SEPOLIA_RPC --ether
cd evm; forge test; cd ..
```

### B1. Simulate the deploy against Base Sepolia (no broadcast, no gas)

```powershell
cd evm
$env:GFC_MULTISIG = '<Safe address>'
$env:GFC_PAUSER = '<pauser address>'
$env:GFC_ATTESTERS = '<attester0>,<attester1>,<attester2>'
$env:GFC_THRESHOLD = '2'
$env:GFC_ADMIN_DELAY = '300'
$env:GFC_SUPPLY_CAP_GFC = '100000'
$env:GFC_MAX_MINT_GFC = '1000'
$env:GFC_WINDOW_LIMIT_GFC = '5000'
forge script script/Deploy.s.sol --rpc-url $env:BASE_SEPOLIA_RPC --account gfc-testnet-deployer
```

This prints the gas estimate and the addresses the contracts would get. **It's the last stop
before spending test ETH.**

### B2. Deploy (spends test ETH, after your approval)

```powershell
forge script script/Deploy.s.sol --rpc-url $env:BASE_SEPOLIA_RPC --account gfc-testnet-deployer --broadcast --verify
cd ..
```

You type the keystore password at the prompt. Drop `--verify` if there's no `ETHERSCAN_API_KEY`.
The token and bridge addresses come from `evm\broadcast\Deploy.s.sol\84532\run-latest.json`.
Claude reads them from there and doesn't type them by hand. Record the deploy block for
`GFC_BRIDGE_START_BLOCK`.

### B3. Your step: the Safe accepts admin (after 300 seconds)

In the Safe app's transaction builder, call `acceptDefaultAdminTransfer()` on the **token**
and then on the **bridge**, and sign with 2 of 3 owners. Claude checks the result (read-only):

```powershell
cast call <token> "defaultAdmin()(address)" --rpc-url $env:BASE_SEPOLIA_RPC    # = the Safe
cast call <bridge> "defaultAdmin()(address)" --rpc-url $env:BASE_SEPOLIA_RPC   # = the Safe
cast call <token> "hasRole(bytes32,address)(bool)" (cast keccak "MINTER_ROLE") <bridge> --rpc-url $env:BASE_SEPOLIA_RPC
cast call <token> "hasRole(bytes32,address)(bool)" 0x0000000000000000000000000000000000000000000000000000000000000000 (cast wallet address --account gfc-testnet-deployer) --rpc-url $env:BASE_SEPOLIA_RPC   # false
```

### B4. Start the test ledger node (local, P2P off)

```powershell
$env:GFC_TREASURY_PUBKEYS = '<test treasury public key>'
$env:GFC_TREASURY_KEY_FILE = 'D:\gfc-testnet\keys\test-treasury.json'
$env:GFC_TREASURY_PASSPHRASE = '<you type it in this terminal>'
$env:GFC_BRIDGE_ESCROWS = '84532:<escrow public key>'
$env:GFC_BRIDGE_TOKENS = '84532:<token>'
$env:GFC_BRIDGE_RELAY_FEE_CENTS = '100'
D:\projects\GFC-Client\Scripts\RunLocalNode.ps1 -BackendDir D:\projects\GFC -DataDir D:\gfc-testnet\node-data -Port 8200
```

`RunLocalNode.ps1` switches P2P off, so test accounts and test GFC never reach the real
network. Check it: `Invoke-RestMethod http://127.0.0.1:8200/bridge/info` should show
`enabled: true`, Base Sepolia, and the token.

### B5. Fund a test account (test treasury, local ledger only)

Register in the client (or `POST /auth/register`) and create a wallet. Then, in a second
terminal with the same `GFC_TREASURY_*` variables as B4, pay it a test operator grant. Operator
grants aren't free credit, so all of it can be bridged:

```powershell
$env:GFC_DATA_DIR = 'D:\gfc-testnet\node-data'
python treasury_grants.py grant <wallet id> 1000 other "testnet bridge funds"
```

### B6. Start the bridge service

```powershell
$env:GFC_BRIDGE_RPC_URL = $env:BASE_SEPOLIA_RPC
$env:GFC_BRIDGE_CHAIN_ID = '84532'
$env:GFC_BRIDGE_ADDRESS = '<bridge>'
$env:GFC_BRIDGE_ESCROW_WALLET = '<escrow public key>'
$env:GFC_BRIDGE_LEDGER_DB = 'D:\gfc-testnet\node-data\gfc_ledger.db'
$env:GFC_BRIDGE_STATE_DB = 'D:\gfc-testnet\bridge\state.db'
$env:GFC_BRIDGE_START_BLOCK = '<deploy block>'
$env:GFC_BRIDGE_CHAIN_FINALITY = 'finalized'
$env:GFC_BRIDGE_FINALITY_SECONDS = '120'           # short for the testnet; production is longer
$env:GFC_BRIDGE_RELAY_FEE_CENTS = '100'
$env:GFC_BRIDGE_RELAYER_KEY_FILE = 'D:\gfc-testnet\keys\relayer.key'
$env:GFC_BRIDGE_PAUSER_KEY_FILE = 'D:\gfc-testnet\keys\pauser.key'
$env:GFC_BRIDGE_ATTESTER_KEY_FILE = 'D:\gfc-testnet\keys\attester0.key'
$env:GFC_BRIDGE_EXTRA_ATTESTER_KEY_FILES = 'D:\gfc-testnet\keys\attester1.key,D:\gfc-testnet\keys\attester2.key'
$env:GFC_BRIDGE_ESCROW_KEY_FILE = 'D:\gfc-testnet\keys\escrow-84532.json'
$env:GFC_BRIDGE_ESCROW_PASSPHRASE = '<you type it in this terminal>'
# Plain wallets that must never get code (A2b): the 3 Safe owners, plus the pauser and the
# attesters (the keys above are watched anyway; listing them as well does no harm). Never the Safe itself.
$env:GFC_BRIDGE_WATCH_ADDRESSES = '<owner1>,<owner2>,<owner3>,<pauser>,<attester0>,<attester1>,<attester2>'
.\.venv\Scripts\python.exe -m bridge reconcile    # must say ok before anything moves
.\.venv\Scripts\python.exe -m bridge run --interval 30
```

### B7. The happy path (you, in the client; Claude watches)

1. In the client, connected to `http://127.0.0.1:8200`, go to **Wallet → Bridge to Base** and
   bridge 150 GFC to your test user's address.
2. About 2 minutes later, the bridge log shows `Minted 149.00 GFC`. Check the balance:
   `cast call <token> "balanceOf(address)(uint256)" <your address> --rpc-url $env:BASE_SEPOLIA_RPC`.
   Expect `149000000000000000000`.
3. Bridge back. In MetaMask (or with Claude's `cast send` from **your** test user, if you import
   that account as a Foundry keystore), approve the bridge for 50 GFC and call `bridgeOut`
   with your ledger wallet ID as `bytes32`. Once the block is finalized, the ledger wallet
   gets +50.
4. `python -m bridge status` and `python -m bridge reconcile` should both be clean.

### B8. Drills (each one a separate approval)

| Drill | How | Expect |
|---|---|---|
| Pause | `cast send <bridge> "pause()" --account gfc-testnet-pauser --rpc-url $env:BASE_SEPOLIA_RPC` | Mints and bridge-outs stop. The pauser can't unpause; the Safe can (`unpause()` in the transaction builder) |
| One attester down | Remove one file from `GFC_BRIDGE_EXTRA_ATTESTER_KEY_FILES` and restart | Still mints (2 of 3). With two down, deposits wait |
| Fresh free credit | Verify a new account's phone (welcome grant) and try to bridge it, directly and after sending it to a second wallet | The client says only X can be bridged, and the node refuses |
| Small deposit | Deposit 50 GFC through `POST /bridge/deposit` | The node refuses it (minimum 100) |
| Daily limit | Bridge 1,000 GFC six times in a day | The 6th waits for the window to reset |
| Release limit | Bridge out more than `GFC_BRIDGE_MAX_RELEASE_CENTS` | Held until `python -m bridge approve-release <nonce>` |
| Refund | A deposit marked `held` | `python -m bridge refund <tx_hash>` returns it once |
| Unbacked supply | Stop the bridge, then have 2 attester keys sign a mint with no deposit (a one-off script, testnet only) | `reconcile` reports it and auto-pauses the bridge |
| EIP-7702 takeover | With a throwaway account added to `GFC_BRIDGE_WATCH_ADDRESSES`, sign and send an EIP-7702 authorization for it (`cast send --auth <any contract> ...` from that account, testnet only) | `reconcile` reports "delegated to … (EIP-7702)" and auto-pauses the bridge. Remove the account from the list and unpause from the Safe |
| Restart safety | Kill the service in the middle of a release and start it again | Paid once, never twice |

### B9. Cleanup or keep running

Stop the node and the bridge with Ctrl+C. The testnet contracts can stay deployed, because
they hold nothing of value. Keep `D:\gfc-testnet\keys` until the run is written up, then
delete the key files.

---

## Pass criteria before talking about mainnet

- [ ] B7 works end to end at least 10 times, including twice across a service restart.
- [ ] Every drill in B8 behaves as expected.
- [ ] `reconcile` is clean the whole time.
- [ ] The release path has never paid twice.
- [ ] The run has lasted at least two weeks, with the service running continuously.
- [ ] Before mainnet, the attesters move to 3 separate machines and operators. The in-process
  mode is testnet-only.
- [ ] Before mainnet, the Safe owners are 3 hardware wallets, the escrow key is in an HSM or
  KMS, and `GFC_BRIDGE_WATCH_ADDRESSES` lists every owner, attester and the pauser (A2b).
- [ ] No bridge wallet has ever approved an EIP-7702 authorization: `reconcile`'s takeover
  check has stayed clean the whole run.
- [ ] The audit (see `docs/dex-plan.md` section 6) is booked, with this testnet's addresses in
  scope for reproduction.
