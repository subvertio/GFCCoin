# Signed ledger: design note

Before this change, P2P sync (`sync_engine.py`) and the tracker relay
(`peer_discovery.py`) copied `transactions`, `wallets`, `blocks`, `user_grants`
and `podt_proofs` rows from any peer using `INSERT OR IGNORE`. A modified node
could make up balances, or spend anyone's wallet, and every other node would
accept the result. This note covers what changed and why.

## Wallet keys and signed transfers

- **A wallet's ID is its Ed25519 public key** (64 hex characters, the same
  length as the old random IDs). Any node can check a transfer against the
  `sender` field alone. There is no separate key directory for a peer to forge.
- **The private key stays on the wallet's home node**, in the `wallet_keys`
  table. That table isn't in `SYNCABLE_TABLES`, so it's never sent anywhere.
  The REST API is unchanged: `POST /transactions/create` still authenticates
  with the session token plus wallet ownership (`security.require_user`). The
  node then signs the transfer with the wallet's key.
- **What gets signed:** `SIGNATURE_DOMAIN + tx_hash`. `tx_hash` is the existing
  `compute_tx_hash()` over sender, recipient, amount_cents, timestamp, tx_type
  and reason, so the signature covers every field that affects balances. New
  columns `signature` and `signer` are added to `transactions`.

## Validating synced transactions

Both sync paths now call `sync_ingest.ingest_rows()`. For `transactions`, that
calls `blockchain.ingest_synced_transactions()`, which applies these rules to
each row:

| Check | Result if it fails |
|---|---|
| `tx_hash == compute_tx_hash(row)` | rejected |
| `tx_hash` not already in the ledger under another id (replay) | rejected |
| Signature present and valid for the signer | rejected |
| TRANSFER: `sender` is a public key and is the signer; not the treasury | rejected |
| GRANT/REWARD: from the treasury wallet, signed by a pinned treasury key | rejected |
| GRANT: exactly 100 GFC, and the wallet's first grant | rejected |
| REWARD: at most `MAX_REWARD_CENTS` (1,000 GFC) | rejected |
| PREMINE | always rejected |
| Timestamp parses and is less than 1 hour in the future | rejected |
| Sender's balance on this node covers the amount | **pending** |

A *pending* transfer has a valid signature, but its funding hasn't reached this
node yet (sync runs table by table and peer by peer, so the order varies). It
goes into the local `pending_sync_tx` table and is checked again after every
batch. It expires after 7 days, and the queue is capped at 5,000 rows.

Accepted rows go into a **new local block**. The peer's `block_index` is
ignored, because block numbers are only meaningful on the node that made them.
`blocks`, `user_grants` and `podt_proofs` are no longer synced. Each node
derives them from the transactions it issued or accepted.

## Balances

A balance is the sum of confirmed rows in the node's own `transactions` table.
Every row there was either created on this node or passed the checks above.
Synced `wallets` rows are a directory only: `id, name, owner, created_at`.
Their balance cache columns are set to 0, and a `wallets` row can't claim the
treasury ID. `gfc_balance` / `gfc_balance_cents` from a peer are never read.

## The mint rule: a treasury signature (and why)

GRANT and REWARD rows create credit, so they need an authority that every node
can check. Options considered:

1. **Recompute mints locally.** A node can't independently check that a remote
   user is new, or that some other node really received N bytes. Recomputing
   just moves the trust back to whoever reported the event.
2. **Mints signed by the node that issued them, with local caps.** This is
   free to abuse: a modified node creates a thousand usernames (or a thousand
   node keys) and mints 100 GFC for each. That's forging balances with extra
   steps.
3. **Mints signed by a treasury key that every node pins** (chosen). Every node
   can verify the signature, and the issuer is accountable. Hard caps (fixed
   grant amount, one grant per wallet, a maximum reward size) limit the damage
   if the key leaks. This matches how the project already works: the treasury
   and premine are centrally issued.

How it works in practice:

- Pin the treasury public key(s) in `config.TREASURY_PUBKEYS`, or set
  `GFC_TREASURY_PUBKEYS` for test networks. `python signing.py` generates a
  keypair and writes the private key to `DATA_DIR/treasury_key.hex` (override
  with `GFC_TREASURY_KEY_FILE`).
- A node that holds the treasury key signs the grants and rewards it issues,
  and those spread through the whole network.
- A node without the key still issues grants and rewards so the app keeps
  working, but they're **local-only**: unsigned, never sent, and rejected by
  peers. Transfers funded from local-only credit are signed and sent, but stay
  *pending* on other nodes until signed funding for them arrives there.
- `PREMINE` is never synced. Every node creates the same genesis rule locally.

**Until a treasury key is pinned, no mint is accepted from peers.** That's the
safe default, but it means only credit minted by a treasury node moves
between nodes.

## Upgrading an existing node

- Wallets created before this change have no key. They can still transfer on
  their home node (`"signed": false` in the response), but peers reject those
  transfers. Create a new wallet to get a network-valid one.
- Ledger rows already in the database from before the upgrade are kept and
  still count on this node. Some of them may have been forged by a peer before
  validation existed. Only signed rows are sent to peers, so these rows don't
  spread. If you're unsure about a node's history, start it with a fresh data
  directory.

## What this doesn't solve

- **No consensus on order.** Two validly signed transfers that together
  overspend a wallet are resolved first come, first served on each node, so
  nodes can disagree about which one went through. Fixing that needs a
  consensus protocol, or a sequencer (for example a treasury-signed block
  order).
- **Sybil-resistant rewards.** The treasury node decides which grants and
  rewards to sign, and it can still be farmed with fake accounts and fake
  plays. A real fix needs identity or proof-of-personhood, rate limits and
  reward rules that hold up against collusion.
- **Issuance is centralized.** Network-wide credit depends on the treasury key
  holder(s). A claims service, where non-treasury nodes submit mint requests
  for the treasury to sign, would be the next step.
- **Private keys are stored unencrypted** in the node's SQLite file, protected
  only by the user's OS account. Key export/backup and encryption at rest are
  still to do.
- **Other synced rows aren't authenticated.** Seeds, likes, comments and the
  wallet `owner` label are still taken at face value. This matters because
  reward routing picks a wallet by `owner` or `reward_wallet`, so a forged
  row could redirect rewards to the attacker's wallet. That's a follow-up.
