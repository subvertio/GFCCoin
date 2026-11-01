# Attesters on their own machines

A mint needs 2 of the 3 attesters' signatures. That protects anything only if no single
machine holds two attester keys. On mainnet, the bridge service refuses to hold more than
one attester key (audit F14), so the others run as signing endpoints on separate machines,
ideally with separate operators.

## How it works

- Each attester machine runs its own **ledger node** (synced from the network like any
  other node) and `python -m bridge attest-serve` with **its own key**.
- The relayer asks every attester to sign each deposit's MintRequest. Each attester checks
  the deposit against **its own ledger** and signs only what that ledger shows: right
  amount, right address, final, not refunded, not fresh free credit. A relayer that's been
  broken into can only get signatures for real deposits.
- The relayer checks every signature it gets back really is that attester's, over exactly
  that request.
- Requests carry an HMAC made with a secret that the attester and relayer share. The secret
  itself never goes over the wire, and requests older than 60 seconds are refused.
- The relayer records each request's deadline before asking. A deposit is never refunded
  while a signature that someone might hold could still mint it. Attesters refuse deadlines
  further out than the mint TTL (1 hour by default).

Code: `bridge/attester_http.py`. Tests: `tests/test_bridge_remote_attesters.py`, plus a 2-of-3
mint over HTTP in `tests/test_bridge.py`.

## Setting up one attester machine

On the attester machine, with the GFC node code checked out and
`python -m pip install -r requirements.txt -r bridge/requirements.txt` done:

1. **Run a ledger node** and let it sync. The attester reads that node's database.
2. **Make the attester key**, encrypted and readable by this account only. The command
   prints only the address:
   ```powershell
   python -m bridge new-evm-key D:\gfc-attester\attester.json
   ```
3. **Make the shared secret.** Copy the file to the relayer machine by USB stick or
   `scp`, never by chat or email:
   ```powershell
   python -m bridge new-attester-secret D:\gfc-attester\secret.txt
   ```
4. **Grant the address `ATTESTER_ROLE`** on the bridge, from the Safe (Transaction Builder:
   `grantRole(ATTESTER_ROLE, address)`). Revoke the role from the key it replaces. Then check:
   ```powershell
   python -m bridge roles
   ```
5. **Start it** with the same policy settings as the relayer: hold days, minimum deposit,
   relay fee, mint TTL. The passphrase is typed when it starts.
   ```powershell
   $env:GFC_BRIDGE_CHAIN_ID = '8453'
   $env:GFC_BRIDGE_ADDRESS = '0x...'               # the bridge contract
   $env:GFC_BRIDGE_ESCROW_WALLET = '...'           # the escrow's ledger public key
   $env:GFC_BRIDGE_LEDGER_DB = 'D:\gfc-node\gfc_ledger.db'
   $env:GFC_BRIDGE_ATTESTER_KEY_FILE = 'D:\gfc-attester\attester.json'
   $env:GFC_ATTESTER_SECRET_FILE = 'D:\gfc-attester\secret.txt'
   $env:GFC_BRIDGE_RELAY_FEE_CENTS = '100'
   python -m bridge attest-serve --port 8300
   ```
6. **Make it reachable from the relayer, privately.** It listens on 127.0.0.1 only. Pick
   one way in:
   - a private network, such as Tailscale or WireGuard, with `--host` set to that address;
   - an SSH tunnel from the relayer: `ssh -N -L 8301:127.0.0.1:8300 attester1`;
   - TLS through a reverse proxy, such as Caddy with `reverse_proxy 127.0.0.1:8300`.

   On mainnet the relayer refuses a plain `http://` URL unless it's on its own machine (a
   tunnel's local end).

## On the relayer machine

```powershell
$env:GFC_BRIDGE_ATTESTER_KEY_FILE = 'D:\gfc-bridge\attester0.json'      # at most one local attester
$env:GFC_BRIDGE_REMOTE_ATTESTER_URLS = 'http://127.0.0.1:8301,https://attester2.example'
$env:GFC_BRIDGE_REMOTE_ATTESTER_SECRET_FILES = 'D:\gfc-bridge\attester1-secret.txt,D:\gfc-bridge\attester2-secret.txt'
python -m bridge run --interval 30
```

At startup the relayer:
- asks each attester for `/info`, and refuses one that signs for another chain or bridge;
- refuses two attesters that share one wallet.

From then on it watches the remote attesters' wallets like its own: no code, and no new
nonce.

## What it doesn't do (yet)

- **Each attester trusts its own node's ledger.** Signed checkpoints would let attesters
  agree on one history (`docs/ledger-checkpoints.md`).
- **No rate limit beyond one request at a time.** Someone who has the secret can make an
  attester busy, but can't make it sign anything its ledger doesn't show.
- **The secret is symmetric.** Whoever holds the relayer's copy can send requests: that is,
  ask for signatures on real deposits only.
