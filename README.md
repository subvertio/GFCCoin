# Galactic Federation Coin (GFC)

**A peer-to-peer home for small creators: share your work, get discovered, and earn credit when people actually view it, without a platform taking the cut or the algorithm deciding who gets seen.**

> **Status: early prototype.** GFC is a working backend that people can run and test together. It is not production software, and GFC credits are **not money**. They have no cash value and can't be bought or sold. See [Current limitations](#current-limitations) before relying on it for anything important.

---

## Why GFC exists

Small creators (3D artists, musicians, photographers, video makers) run into the same problems on big platforms:

- **You need an audience to get an audience.** Recommendation algorithms favor accounts that are already big.
- **Platforms own the relationship.** Your work, followers and earnings live on someone else's servers, under rules that can change overnight.
- **Payouts start late.** Monetization usually begins only after thousands of followers or hours watched.
- **Hosting costs money.** Serving large files such as 3D models and video is expensive if you do it yourself.

GFC tries a different model. The community hosts the content, and the people who share and view it earn the credit.

## How it helps creators

| What you get | How GFC does it |
|---|---|
| **Credit from your first viewer** | When another verified user plays your work, you earn GFC credit (one payout per viewer per item, at most one per viewer per day for each creator, no self-crediting). There's no follower threshold. |
| **Free distribution** | Your uploads ("seeds") are copied between peers, so the network serves your files instead of a paid host. |
| **Rewards for sharing** | Nodes that pass content along earn *Proof-of-Data-Transfer* (PoDT) credit (0.10 GFC per MB), so people have a reason to help spread your work. |
| **A starting balance** | Every new user's first wallet gets 100 GFC, once they verify a phone number, to tip, try out and support other creators. |
| **Built for 3D and media** | Native support for images, video, audio and 3D formats (`.glb`, `.gltf`, `.fbx`, `.obj`, `.usdz`, `.stl`, `.3ds`). |
| **A creator profile** | Bio, avatar, a feed, search, likes, comments and bookmarks. |
| **A public ledger** | Every grant, transfer and reward is recorded in a hash-linked chain that anyone can check (`/blockchain/validate`). Transfers are signed with your wallet's key, so other nodes can't fake them. |

### A typical flow

1. **Upload** a piece (a 3D model, track, clip or image) as a *seed*.
2. Your node **syncs** it to peers, found on your LAN, through bootstrap trackers, or by peer exchange.
3. Someone on another node **finds it** in their feed or search and plays it.
4. You **earn GFC** for that view, and the nodes that carried the file earn PoDT credit.
5. You **tip or send GFC** to other creators whose work you like.

## How it works (technical overview)

GFC is a Python/FastAPI backend that each participant runs as a local node. The original desktop front end was built in Unreal Engine for browsing 3D content.

| Component | File | Role |
|---|---|---|
| REST API | `main.py` | Auth, wallets, transactions, feed, search, P2P status |
| Seeds | `app_seeds.py` | Upload, thumbnails, content-type detection |
| Engagement | `app_engagement.py` | Likes, comments, bookmarks, play rewards |
| Profiles | `app_profile.py` | Bio and avatar |
| Ledger | `blockchain.py` | Hash-linked blocks with Merkle roots over SQLite; balances in integer cents; validation of synced transactions |
| Signing | `signing.py` | Ed25519 wallet keys (wallet ID = public key), the treasury key and its backup CLI |
| Keystore | `keystore.py` | Wallet keys encrypted at rest; passphrase-encrypted export/import |
| PoDT | `podt_core.py`, `app_podt.py` | Proof-of-Data-Transfer rewards |
| P2P sync | `sync_engine.py`, `sync_ingest.py` | Length-prefixed JSON over TCP (port 6881), append-only sync; one set of accept rules shared with the tracker relay |
| Discovery | `peer_discovery.py` | Bootstrap trackers, LAN broadcast (UDP 6882), peer exchange |
| Security | `security.py` | Password hashing, session tokens, sync privacy filtering |

### Privacy

- Passwords are stored as salted PBKDF2-SHA256 hashes.
- API tokens are random and expire after 30 days. Only their hash is stored.
- **Only public profile fields are shared with peers:** username, bio, avatar and join date. Passwords, email, phone and real names stay on the node where you registered, so you can only log in on your home node.

## Running a node

Requires Python 3.11+.

```bash
pip install -r requirements.txt
uvicorn main:app --host 127.0.0.1 --port 8000
```

Then open `http://127.0.0.1:8000/docs` for the interactive API docs.

Run the tests with:

```bash
python -m unittest discover -s tests -v
```

- Data is stored in `./data` by default. Set `GFC_DATA_DIR` to use another location.
- To sync with peers, TCP port 6881 and UDP port 6882 must be reachable.
- `gfc_backend.spec` builds a single-file Windows executable with PyInstaller.
- Building your own front end (web, mobile, bots)? See [docs/build-your-own-frontend.md](docs/build-your-own-frontend.md): Bearer auth, scoped tokens with spend limits, CORS (`GFC_CORS_ORIGINS`), and how wallets, uploads, sharing and phone verification work.

## Sharing posts (gateway node and share pages)

Home nodes sit behind routers, so X and other sites can't fetch a post from them. A **gateway node** runs on the public domain (galacticfederation.tech) and serves a read-only share page for every seed it has synced:

- `GET /p/{seed_id}`: an HTML page with the title, creator, description and a media preview. 3D seeds show their poster image only. The page has Open Graph and Twitter Card tags (`summary_large_image`), so X, Discord, messaging apps and others show a preview card. A "rewards verified" badge appears only on seeds signed by their reward wallet.
- `GET /p/{seed_id}/share`: JSON with `url`, suggested `text`, `x_intent_url` and `app_link`.
- `GET /.well-known/assetlinks.json`: Android App Links verification, so `https://galacticfederation.tech/p/...` links open straight in the app once it's installed.

Seed fields come from peers and are untrusted. The page escapes every field, runs no script and sends a strict Content-Security-Policy. It shows only public user fields.

Gateway settings (environment variables):

| Variable | Purpose | Default |
| --- | --- | --- |
| `GFC_PUBLIC_BASE_URL` | Absolute base for `og:url`, `og:image` and share links | `https://galacticfederation.tech` |
| `GFC_APP_LINK_BASE` | Prefix of the "Open in GFC" deep link (`{base}/{seed_id}`) | `gfc://seed` |
| `GFC_ANDROID_PACKAGE` | Android package name for `assetlinks.json` | none |
| `GFC_ANDROID_CERT_SHA256` | Comma-separated SHA-256 signing cert fingerprints (`AB:CD:...`) | none |

`assetlinks.json` returns `[]` until both Android settings are set. Run the gateway behind HTTPS. X only fetches cards over HTTPS, and App Links require it.

### Sharing from the Unreal Android app

The share link is always `{GFC_PUBLIC_BASE_URL}/p/{seed_id}`. The seed must have synced to the gateway before the card renders, so sync first and then share. Two ways to share:

1. **Android share sheet (recommended).** Add a small Java method through a UPL (Unreal Plugin Language) `.xml` in your plugin, and call it from C++ via JNI (`FJavaWrapper::CallVoidMethod`):

   ```java
   public void AndroidThunkJava_ShareText(String text, String url) {
       Intent send = new Intent(Intent.ACTION_SEND);
       send.setType("text/plain");
       send.putExtra(Intent.EXTRA_TEXT, text + " " + url);
       startActivity(Intent.createChooser(send, "Share"));
   }
   ```

   The user picks X or any other app.
2. **Direct "Post to X" button.** Open the X web intent with `FPlatformProcess::LaunchURL`. If the X app is installed, it handles the link:

   ```
   https://x.com/intent/post?text=<url-encoded text>&url=<url-encoded share link>
   ```

   `GET /p/{seed_id}/share` returns this URL ready-made in `x_intent_url`.

To open shared links in the app, add an `intent-filter` with `android:autoVerify="true"` for `https://galacticfederation.tech/p/*` (App Links), and/or one for the `gfc://seed/*` scheme used by "Open in GFC".

## Current limitations

These are known gaps, listed so you can make an informed choice:

- **Fixed: peers can no longer forge balances or spend your wallet.** Wallets are Ed25519 key pairs, and the private key never leaves your node. Every node checks a synced transaction's signature, hash and sender balance before accepting it. Grants and rewards from peers must be signed by the treasury key. Balances are computed only from validated transactions, never from a peer's balance column. See [docs/signed-ledger.md](docs/signed-ledger.md).
- **No consensus yet.** If one wallet signs two transfers that together overspend it, each node accepts whichever one arrives first. Nodes can disagree until there's a consensus or ordering protocol.
- **Fixed: forged rows can't redirect your rewards.** Each seed is signed by its reward wallet, and its ID is tied to that wallet. Rewards go only to the wallet that signed the seed, never to a wallet picked by owner name.
- **Network-wide credit needs the treasury key.** Only grants and rewards signed by the pinned treasury key (`config.PINNED_TREASURY_PUBKEYS`) are accepted from peers. Those issued by other nodes work on that node only. Wallets created before this change can't sign, so their transfers stay on their home node. Seeds uploaded before this change earn no rewards.
- **Reward farming is harder, but not solved.** The 100 GFC grant and play rewards now need a verified phone number (one account per number, via Twilio Verify), and a play only pays if the viewer's account is at least 24 hours old, at most once per viewer per creator per day. Cheap and virtual SMS numbers still exist, so someone with many numbers can still farm. PoDT transfer rewards aren't phone-gated yet. Only the phone number's keyed hash is stored, and it is never synced. Code requests can also be protected by a Cloudflare Turnstile bot check (`GFC_TURNSTILE_SECRET`) against SMS pumping. It belongs on the hosted treasury/verification node, where the secret stays private, not on ordinary local nodes, and the client needs the matching site key. These rules are enforced by the node that issues the reward, and only the treasury node's rewards count network-wide. See [docs/signed-ledger.md](docs/signed-ledger.md#phone-verification-and-reward-rules).
- **Huge premine.** The treasury holds the entire supply, so issuance is centrally controlled.
- **No content moderation tools** yet for reporting or removing illegal or infringing uploads.
- **Fixed: wallet keys are encrypted at rest and can be backed up.** They can only be unlocked with your password or a live login session. **Export a backup** (`POST /wallets/export`) and keep it with its passphrase. There's no password reset, so a forgotten password or a lost data folder can only be recovered from that backup. Treasury operators: `python signing.py backup FILE`.
- **Usernames aren't signed yet.** Someone can post content, likes or comments under another person's name. They can't collect that person's rewards, but they can impersonate them.
- **API tokens are passed as form/query parameters.** Run the node on localhost, or behind HTTPS if it's exposed.
- **The Unreal front end isn't in this repository.** Right now you use the node through its API.

## Roadmap ideas

- A consensus/ordering model for the ledger, and a claims service so any node's grants and rewards can be treasury-signed
- Stronger Sybil resistance than phone verification (proof-of-personhood)
- A lightweight web front end with an in-browser 3D viewer (e.g. `<model-viewer>`/three.js), so viewers don't need to install anything
- Reporting and moderation tools
- Optional bridges to established payment rails for creators who want real-money tips

## Contributing

Issues and pull requests are welcome, especially on the limitations above.
