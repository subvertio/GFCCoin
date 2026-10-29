"""
GFC Bridge Service - moves GFC between the ledger and the wrapped ERC-20 (evm/)

Ledger -> chain: users sign a ledger TRANSFER to the escrow wallet with
reason `bridge:v1:<chainId>:<0xaddress>`. deposits.py finds final deposits on
this node's own ledger DB, attester.py re-checks them and signs an EIP-712
MintRequest, relayer.py collects `threshold` signatures and calls
GFCBridge.mintFromLedger.

Chain -> ledger: releases.py reads finalized BridgedOut events and pays the
ledger wallet from escrow with a signed TRANSFER, at most once per nonce.

reconcile.py checks that wrapped supply is always backed by escrow and pauses
the bridge if not. See docs/bridge-service.md.

Nothing here trusts a peer: deposits are re-verified from their Ed25519
signature and tx_hash, and supply only changes through the bridge contract.
"""
