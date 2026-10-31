# Galactic Federation Coin (GFC) White Paper

**Version 0.2, October 29, 2026.** Stephen Donald Favis, The Galactic Federation.
Replaces v0.1 (July 23, 2025). What changed is listed at the end.

> GFC is software in active development. This paper describes how it works today and what is
> planned. Planned items are marked **Planned**; they can change or not happen. Nothing here is
> an offer to sell anything, a promise of future value, or financial advice.

---

## Part 1: GFC in plain words

### What is GFC?

GFC is a social app for creators, with its own coin. You post music, video, photos, 3D models and
text. When other people watch, play or listen to what you post, you earn GFC. There's no
follower minimum and no waiting list: your first viewer can earn you your first coin.

Behind the app is a network of computers ("nodes") that share the posts and keep the record of
who owns which coins. Anyone can run a node, and anyone can build their own app on top of it.

### Why does it exist?

Small creators have a hard time on big platforms:

- **You need an audience to get an audience.** Feeds favour accounts that are already big.
- **Pay starts late.** Most platforms pay nothing until you have thousands of followers.
- **The platform owns everything.** Your posts, followers and earnings live on someone else's
  servers, under rules that can change overnight.

GFC pays from the first view, keeps the record of earnings public and checkable, and lets the
community carry the posts instead of one company.

### How do I earn GFC?

| You... | You get |
|---|---|
| Sign up and verify your phone | **100 GFC** |
| Make your first original post | **1,000 GFC** |
| Invite a friend who signs up and starts watching | **1,000 GFC** (and your friend gets **100 GFC** extra) |
| Have someone play your post | **0.10 GFC per MB** of the post (up to 1,000 GFC per play) |
| Have someone repost your work | the repost's earnings go to **you**, the original creator |

So a new creator who verifies their phone and posts something gets **1,100 GFC** to start.

A few fair-play rules keep this honest:

- **One person, one account.** Payouts need a verified phone number, and each number can verify
  only one account.
- **No paying yourself.** Playing your own posts earns nothing.
- **Real viewers only.** A viewer's account must be at least a day old, and each viewer can earn a
  given creator at most one play reward per day.
- **Credit goes to the original.** GFC recognises reposted copies of images and 3D models (even
  slightly changed ones) and of identical files, and sends the earnings to the original creator.

### What can I do with GFC?

Today you can hold GFC in your wallet and send it to anyone on the network, for example to tip a
creator. **Planned:** a bridge to the Base blockchain and a listing on a decentralised exchange
(see the roadmap at the end).

### Is it safe?

- **Your wallet keys never leave your node.** The node signs payments for you. Keys are stored
  encrypted, and only your password (or your recovery code) can unlock them.
- **Your phone number isn't stored.** Only a scrambled fingerprint of it is kept, to stop one
  number verifying many accounts.
- **Your private details stay private.** Only your username, bio, avatar and join date are shared
  with other nodes. Your password, email and phone never leave the node you signed up on.
- **You can recover your account.** You get a recovery code when you sign up, and you can reset
  your password with your verified phone or email.
- **The record is public.** Every payment the treasury makes is signed and can be checked by
  anyone.

### How do I get it?

- **Android:** download from [node.galacticfederation.tech/app](https://node.galacticfederation.tech/app)
- **Windows:** download from [node.galacticfederation.tech/app](https://node.galacticfederation.tech/app#windows)
- **Web:** browse the feed at [node.galacticfederation.tech](https://node.galacticfederation.tech)

---

## Part 2: How it works

### 2.1 The pieces

- **Nodes.** A node is a Python (FastAPI) server with its own SQLite database. It stores posts and
  their files, keeps the ledger, signs on behalf of its users, and syncs with other nodes.
- **The treasury node.** The public node at `node.galacticfederation.tech` also holds the
  treasury key. It signs new-coin payments ("mints"), runs phone verification, and serves the web
  feed, share pages and app downloads.
- **Apps.** The GFC app (0.2.2) is built with Tauri and three.js for Android and Windows. It's
  small: about 11 MB on Android and 3 MB on Windows. The web feed works in any browser. Anyone can
  build another app on the open API (section 2.8).

### 2.2 Supply

- The ledger counts in hundredths: **1 GFC = 100 units**, so amounts have two decimal places.
- Each node's genesis block holds a fixed **premine of 100,000,000,000,000 GFC (100 trillion)**
  in the treasury wallet.
- **The treasury can't send ordinary payments.** Coins leave it only as *mints*: payments of
  fixed types, each with a hard cap, signed by the treasury key. Every node checks those rules
  before it accepts a mint.
- "Coins in circulation" is the total of all mints so far, published at `/blockchain/stats`.

| Mint | Amount | Rules every node checks |
|---|---|---|
| Sign-up grant | exactly 100 GFC | after phone verification; the wallet's first grant only |
| First post bonus | up to 1,000 GFC (default 1,000) | first original post; once per wallet |
| View reward | 0.10 GFC per MB, at most 1,000 GFC | once per proof; see section 2.5 |
| Invite reward | exactly 1,000 GFC to the inviter, 100 GFC to the friend | only these amounts |
| Repost credit | exactly 15 GFC | once per reposter per original |
| Operator grant | up to 10,000 GFC | public reason, e.g. hackathon prizes; a node-host thank-you is exactly 10,000 GFC, once per wallet |

Operator grants are listed publicly at `/treasury/grants`.

### 2.3 Wallets and signatures

- A **wallet ID is an Ed25519 public key** (64 hex characters).
- **Private keys stay on the user's node.** They're encrypted with AES-256-GCM under a per-user
  data key. That data key is itself stored only in wrapped form: under the user's password
  (scrypt), under each login session, and under the recovery code. No API returns a raw private
  key.
- **Backups:** a user can export an encrypted backup of their keys (protected by a passphrase of
  at least 12 characters) and import it on any node.
- **Every transfer is signed.** A transaction's hash is SHA-256 over its sender, recipient,
  amount, time, type and reason, and the signature covers a domain-separated copy of that hash.
- **Posts are signed too.** A post is signed by the wallet that collects its rewards, and its ID
  is tied to that wallet, so nobody can redirect someone else's earnings.
- **Edits are signed.** Posters can edit a post's title, description and tags (never its media).
  Each edit is signed and synced, every node shows the newest one, and the full edit history is
  public.

### 2.4 The ledger and syncing

- Each node keeps its own hash-chained ledger: every accepted transaction goes into a block with a
  Merkle root, linked to the previous block.
- **Nodes don't trust each other.** Before accepting a transaction from a peer, a node checks:

    - the hash matches its contents;
    - the signature matches the sender;
    - the amount and type are valid, and mints are signed by the pinned treasury key and within their
      caps;
    - the timestamp isn't more than an hour in the future, and the transaction isn't a replay.

  A transfer whose sender can't afford it yet waits in a queue for up to seven days.
- **Balances come only from transactions the node has checked itself.** A balance number sent by
  a peer is never used.
- **What's shared:** public profiles (username, bio, avatar, join date), posts, edits, signed
  transactions, likes, comments, bookmarks, wallet directory entries, originality receipts and
  verification proofs. **What isn't shared:** passwords, email, phone data, private keys,
  sessions, moderation decisions and local reward records.
- **Transport:** nodes sync over TCP port 6881 with length-prefixed JSON messages, and move files
  in 256 KB chunks. They find each other through a tracker, LAN broadcast (UDP 6882) and peer
  exchange.

### 2.5 View rewards

When someone plays a post, the creator's wallet earns **0.10 GFC per MB** of the post's file,
capped at 1,000 GFC per play. A play pays only if all of these hold:

1. the viewer is logged in, has a verified phone, and their account is at least 24 hours old;
2. the viewer isn't the creator (checked by name, by the original of a repost, and by wallet);
3. the post is at least 1 KB and is signed by a reward wallet;
4. it's the first rewarded play of that post by that viewer;
5. it's the viewer's only rewarded play of that creator today (UTC).

Nodes also earn creators a transfer reward when they download a post's file for the first time.
That payment goes to the creator's signed wallet, not to whoever relayed the file.

### 2.6 Keeping it fair

- **Phone verification.** The SMS code is sent and checked by Firebase (Google), and the node
  checks the signed result. Only an HMAC fingerprint of the number is stored. Each number can
  verify one account, and there are daily limits on attempts.
- **Verified to post.** On the real network, posting needs a verified phone. The treasury node
  signs a proof that each verified account's wallets belong to a verified person, and other nodes
  accept posts only when that proof is present. Posts without it are held back until it arrives.
- **Originality.** Each post is fingerprinted: an exact file hash for every type, a perceptual
  hash for images, and a geometry sketch for 3D models. The treasury node signs an *originality
  receipt* for the first post with each fingerprint, and the earliest receipt wins everywhere. A
  later copy is labelled a repost and its earnings go to the original creator.
- **Moderation.** People can report posts for spam, nudity, violence, harassment, hate, scams or
  copyright. Three reports from different people hide a post on that node, and the node operator
  can review it. People can block accounts they don't want to see.
- **Device checks.** **Planned to switch on:** a short audio game (Echo Hunt) and Google Play
  Integrity, to make it harder for bots to collect view rewards.

### 2.7 Test networks

A node that uses its own treasury key instead of the pinned one is a **test network**. It can't
exchange ledger records with the real network, so developers can try everything (including
posting without phone verification) without touching real GFC.

### 2.8 The open API

Anyone can build their own GFC app or website:

- Log in for a token, and send it as a Bearer header.
- Create limited tokens for third-party apps: scopes `read`, `post` and `spend`, an optional daily
  spending limit, and up to a year's lifetime. Each can be revoked.
- Browser apps on other sites can be allowed through a list of approved origins (CORS).
- The full API is documented at `/docs` on any node.

### 2.9 Known limits

Being clear about what isn't solved yet:

- **No network-wide consensus yet.** Each node checks every transaction on its own, but two
  nodes could briefly disagree about which of two competing payments came first.
- **New coins need the treasury node.** Rewards earned on other nodes only count network-wide
  once the treasury node signs them.
- **Fairness checks raise the cost of cheating but don't eliminate it.** For example, someone
  can still buy cheap phone numbers. Repost detection doesn't yet catch altered video or audio,
  and there's no appeals process yet.
- **The supply is controlled centrally.** The whole premine sits in one treasury, and the
  treasury key is held by the operator.
- **Usernames aren't signed.** Another node could show a look-alike name.

---

## Part 3: Roadmap

### Done

- Signed ledger: Ed25519 wallets, signed transfers, rule-checked mints, a pinned treasury key.
- Creator rewards: sign-up grant, first post bonus, view rewards, invites, repost credit.
- Fair play: phone verification, a network-wide proof of verification, originality receipts,
  moderation.
- Apps: Android and Windows (0.2.2, Tauri and three.js), the web feed with share pages for X, a 3D
  model viewer, audio and video streaming, post editing.
- Creator tools: follows and a Following feed, profiles with photos, comments under every post,
  batch video upload, posts up to 5 GB with server-side video optimisation, and GFC Exclusives.
- Ads: creators promote posts with GFC at a market rate set by a uniform-price auction; 70% of every
  view is paid at once to the creator whose post the ad appears under.
- Downloads: zip files (games, apps) checked and virus-scanned by ClamAV before anyone can get them.
- Accounts: encrypted keys, backups, recovery codes, password reset.
- An open API for third-party apps.

### Next

- Switch on the device checks (Echo Hunt and Play Integrity) for view rewards.
- Ask the treasury node to sign rewards earned on other nodes, so they count everywhere.
- Repost appeals, and repost matching for video and audio.
- Code-signed app installers, and the app in the Google Play store.

### Then

- Network-wide agreement on transaction order (consensus).
- More independent nodes, with thank-you grants for people who run them.
- Community governance of the treasury rules.

### Final milestone: DEX listing (Planned)

- **Bridge to Base.** GFC moves 1:1 between the GFC ledger and an ERC-20 token on Base, a low-fee
  Ethereum layer-2 network. Coins are locked in an escrow on the GFC side, and the token contract
  can only mint against signed attestations, with per-mint and per-period caps and a pause switch.
- **Listing.** A GFC/ETH pool on Uniswap, a decentralised exchange, with no sell tax.
- **Before launch:**

    - a public test on test networks;
    - an independent security audit of the contracts and bridge;
    - legal review of the escrow and liquidity details;
    - a clear plan for initial liquidity.

  Nothing about the bridge or the pool has been deployed or audited yet.

---

## What changed since v0.1

- **The app** is built with Tauri and three.js (Android and Windows), not Unity. It replaced an
  earlier Unreal Engine app in October 2026 and updates it in place.
- **Wallets** are Ed25519 key pairs. They are no longer IDs made from hashed UUIDs, and every
  payment is signed.
- **The supply** is a fixed 100-trillion premine with capped, rule-checked mints. It is not an
  uncapped supply.
- **Rewards** go to the creator's signed wallet for plays and transfers, behind phone
  verification and fair-play limits.
- **New since v0.1:** originality receipts, verification proofs, moderation, account recovery,
  post editing and the open API.
- **Moved to later:** the Python smart-contract engine and the fork manager described in v0.1
  aren't part of the current design.

*© 2026 Stephen Donald Favis, The Galactic Federation.
More at [galacticfederation.tech](https://galacticfederation.tech).*
