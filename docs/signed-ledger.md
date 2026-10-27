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
  with the session token (which needs the `spend` scope) plus wallet ownership. The
  node then signs the transfer with the wallet's key.
- **What gets signed:** `SIGNATURE_DOMAIN + tx_hash`. `tx_hash` is the existing
  `compute_tx_hash()` over sender, recipient, amount_cents, timestamp, tx_type
  and reason, so the signature covers every field that affects balances. New
  columns `signature` and `signer` are added to `transactions`.

## Keeping keys safe (keystore.py)

- **Encrypted at rest.** Each user has a random data key that encrypts their
  wallet keys (AES-256-GCM, bound to the wallet ID). The data key is stored
  only wrapped: under the user's password (scrypt), and under each live
  session's API token (HKDF). Only the token's hash is in the database, so a
  copied database or data folder holds no usable wallet keys. Login unwraps
  the data key with the password, and API calls with a valid token can sign as
  before. Plaintext keys from before this change are encrypted at the owner's
  next login.
- **Forgetting your password loses your keys**, because there's no reset that
  could recover them. That's why export exists:
- **`POST /wallets/export`** (token + password + backup passphrase of at least
  12 characters) returns a passphrase-encrypted backup of all your wallet keys
  on this node (scrypt + AES-GCM).
- **`POST /wallets/import`** restores the backup on any node, under any
  account. Every key is checked against its wallet ID. Holding the key proves
  ownership, so the local wallet is assigned to the importing user. Backup KDF
  parameters are bounded, so a crafted file can't exhaust memory.
- **Treasury key:** `python signing.py backup FILE` writes an encrypted copy.
  `restore FILE` recreates the key file from it. `encrypt` encrypts the key file
  in place, and the treasury node then needs `GFC_TREASURY_PASSPHRASE` to sign
  mints. Without it, the node runs but issues local-only credit.

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
| FIRST_POST: at most `FIRST_POST_BONUS_MAX_CENTS` (1,000 GFC), and the wallet's first one (see [first-post-bonus.md](first-post-bonus.md)) | rejected |
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

**Pinned key.** `config.PINNED_TREASURY_PUBKEYS` contains the operator's
treasury public key. The private key is kept outside the repository, in the
operator's data directory (`data/`, which is gitignored). Only nodes that hold
that file sign mints. To rotate or add a key, run `python signing.py` and add
the new public key to the list.

## Who gets paid for a seed

Before this change, rewards went to the seed's `reward_wallet` if a wallet row
with that ID existed. Otherwise they went to the first wallet whose `owner` label
matched the seed owner. Both the seed row and the wallet row come from peers, so
a forged wallet row named "bob" could take Bob's rewards.

- **Seeds are signed by their reward wallet** (`signing.sign_seed`). The
  signature covers `id, owner, filename, file_size, created_at, reward_wallet`.
  On upload, the wallet must be one of the uploader's wallets with its key on
  this node. The default is their oldest one.
- **The seed ID is derived from the wallet and filename**
  (`signing.seed_id_for`). An attacker who re-signs someone's seed with their
  own wallet ends up with a different seed ID, so the original isn't hijacked.
- **Rewards go only to a verified signer** (`signing.seed_reward_wallet`), for
  both play rewards and PoDT transfer rewards. The owner-name fallback is gone.
- **Synced seeds:** signed seed rows that fail verification are dropped.
  Unsigned (legacy or anonymous) seeds are still shared as content, but their
  `reward_wallet` is cleared, so they earn nothing.

## Phone verification and reward rules

Signing proves who issued a mint, not that a real person earned it. One person
could create many accounts, collect 100 GFC per account and have the accounts
play each other's seeds. Phone verification makes each such account cost a
phone number.

**Flow.** `POST /verify/phone/start` (`api_token`, `phone` in E.164) sends an
SMS code. `POST /verify/phone/check` (`api_token`, `phone`, `code`) marks the
account verified. Both use `security.require_user`. The provider sits behind a
small interface in `phone_verify.py` (`start(phone)`, `check(phone, code)`):

- `TwilioVerifier` is used when `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN` and
  `TWILIO_VERIFY_SERVICE_SID` are set. With `TWILIO_LOOKUP_LINE_TYPE=1` it
  first runs a Twilio Lookup line-type check and refuses VoIP numbers (each
  lookup is billed).
- Otherwise `FakeVerifier` is used. It sends nothing and prints the code to the
  node's console, so it is for development and tests only. A treasury node
  must have Twilio configured, or anyone can verify any number.

**Bot check (Cloudflare Turnstile).** When `GFC_TURNSTILE_SECRET` is set,
`/verify/phone/start` also needs a `turnstile_token` form field. The node
checks it with Cloudflare's `siteverify` (secret, token and client IP, 5 s
timeout) and returns 403 if Cloudflare rejects it or can't be reached (fail
closed). This runs before rate limiting and before the SMS provider, so a
failed challenge never costs a text. This guards against SMS pumping (bots
requesting texts to premium numbers) and scripted signups. If the secret is
unset, the check is skipped with a one-time warning, so local nodes keep
working. Turnstile belongs on the hosted treasury/verification endpoint,
where the secret stays private. An ordinary local node can't keep a secret
from the person running it, so the check means nothing there. The client
(the Unreal web view or a website) needs the matching Turnstile **site key**
to render the widget and get a token.

**Privacy.** The number is normalized to E.164 and only
`HMAC-SHA256(key, number)` is stored, keyed with a per-node secret in
`DATA_DIR/phone_hmac_key.hex` (override with `GFC_PHONE_HMAC_KEY_FILE`). The
raw number is never written to the database. The `phone_*` tables aren't in
`SYNCABLE_TABLES`, so verification status and hashes never leave the node.
(The optional `phone` profile field from `/auth/register` is separate and
unchanged.)

**Limits.** One verified account per phone hash, and one phone per account. At
most 5 code requests per user and 5 per phone hash per 24 hours (counted
before the provider is called, so failed sends count too). A code is valid for
10 minutes and allows 5 wrong guesses.

**Reward rules** (constants in `blockchain.py`):

| Rule | Where |
|---|---|
| New-user GRANT only after phone verification (not at wallet creation) | `process_user_grant`; issued by `/verify/phone/check`, or by `/wallets/create` if already verified |
| Play reward only if the viewer is verified | `play_reward_block_reason` |
| Viewer account at least 24 hours old (`MIN_VIEWER_ACCOUNT_AGE`) | `play_reward_block_reason` |
| At most one paid play per viewer, per creator wallet, per UTC day (`PLAY_REWARDS_PER_CREATOR_PER_DAY`) | `claim_play_slot`, table `play_reward_slots` |
| One payout per (seed, viewer), as before | `podt_proofs.proof_id` |

**Where this is enforced.** Only treasury-signed mints are valid network-wide,
so these rules matter on the treasury node, which decides what to sign.
**Non-treasury nodes enforce them locally only**: their grants and rewards are
local-only anyway, and a modified node can skip the checks for its own local
ledger, but it can't make other nodes accept the result. Verification status
isn't synced, so a peer can't claim that its users are verified.

**Next step: a claims service.** Today, only users registered on the treasury
node can earn network-valid credit. A claims service would let a non-treasury
node forward a verified claim (a grant request, or a play) to the treasury.
The treasury would then re-check it and sign the mint. For the treasury to
trust a claim, it has to verify the phone itself (the user completes the SMS
flow against the treasury, which keeps the phone hash), and it has to apply the
viewer and daily-cap rules to its own records of the claimant. That means user
identities shared between nodes (signed user keys) and a treasury API with
authentication and rate limits. That is too much to add here, so it is left as
the next step.

## Upgrading an existing node

- After the phone-verification change, existing users get no further grants
  or play rewards until they verify a phone. Users who already received their
  grant keep it. `migrate_to_blockchain.py` now skips grants for unverified
  users.

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
- **Sybil-resistant rewards.** Phone verification (below) makes each farmed
  account cost a phone number, but cheap SMS numbers exist, so farming is
  harder, not impossible. A real fix needs proof-of-personhood and reward
  rules that hold up against collusion.
- **Issuance is centralized.** Network-wide credit depends on the treasury key
  holder(s). A claims service is the next step (see *Phone verification*).
- **Keys are only as strong as the password.** Someone holding the data
  folder can try to guess a weak password offline (scrypt slows that down but
  can't stop it). Keys are also decrypted in memory while signing, so malware
  on the node can still steal them.
- **Usernames aren't keys.** A seed's `owner` name, likes, comments and the
  wallet `owner` label are still taken at face value. They no longer decide who
  gets paid, but a peer can still post content under someone else's name (the
  rewards then go to the impersonator's own wallet). Signed user identities
  would fix that.
- **A seed's `file_size` is self-declared** for play rewards, so a creator can
  overstate it, up to the per-reward cap. PoDT transfer rewards use the bytes
  actually received.
