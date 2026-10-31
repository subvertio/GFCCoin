# evm/: wrapped GFC (ERC-20) and ledger bridge

This is a Foundry project. The design, threat model and rollout plan are in
[../docs/dex-plan.md](../docs/dex-plan.md). **Nothing here has been deployed or audited.**

- `src/GFCToken.sol` is the ERC-20. It has 18 decimals, Permit, Burnable, Pausable, a
  supply cap, and roles: admin (the treasury multisig, with a delayed handover), minter
  (the bridge only) and pauser.
- `src/GFCBridge.sol` mints against ledger escrow deposits that k-of-n attesters have
  signed (EIP-712). It has per-mint and per-window caps, and `bridgeOut` burns tokens back
  to a ledger wallet.
- `script/Deploy.s.sol` deploys both contracts, wires the roles, and hands admin over to
  the multisig. Only run it with the owner's go-ahead.

## Setup (Windows, PowerShell)

Foundry v1.8.5 is installed in `$HOME\.foundry\bin`. The dependencies are git submodules
pinned in `foundry.lock`.

```powershell
$env:Path = "$HOME\.foundry\bin;$env:Path"
git submodule update --init --recursive
cd evm
forge test
forge test --gas-report
forge coverage
```

To simulate the deploy locally with placeholder addresses (no RPC, nothing is broadcast):

```powershell
$env:GFC_MULTISIG = "0x000000000000000000000000000000000000A11C"
$env:GFC_PAUSER = "0x000000000000000000000000000000000000B0B0"
$env:GFC_ATTESTERS = "0x0000000000000000000000000000000000000A01,0x0000000000000000000000000000000000000A02,0x0000000000000000000000000000000000000A03"
$env:GFC_THRESHOLD = "2"
forge script script/Deploy.s.sol
```
