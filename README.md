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
| **Credit from your first viewer** | When another user plays your work, you earn GFC credit (one payout per viewer per item, no self-crediting). There's no follower threshold. |
| **Free distribution** | Your uploads ("seeds") are copied between peers, so the network serves your files instead of a paid host. |
| **Rewards for sharing** | Nodes that pass content along earn *Proof-of-Data-Transfer* (PoDT) credit (0.10 GFC per MB), so people have a reason to help spread your work. |
| **A starting balance** | Every new user's first wallet gets 100 GFC to tip, try out and support other creators. |
| **Built for 3D and media** | Native support for images, video, audio and 3D formats (`.glb`, `.gltf`, `.fbx`, `.obj`, `.usdz`, `.stl`, `.3ds`). |
| **A creator profile** | Bio, avatar, a feed, search, likes, comments and bookmarks. |
| **A public ledger** | Every grant, transfer and reward is recorded in a hash-linked chain that anyone can check (`/blockchain/validate`). |

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
| Ledger | `blockchain.py` | Hash-linked blocks with Merkle roots over SQLite; balances in integer cents |
| PoDT | `podt_core.py`, `app_podt.py` | Proof-of-Data-Transfer rewards |
| P2P sync | `sync_engine.py` | Length-prefixed JSON over TCP (port 6881), append-only sync |
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

- Data is stored in `./data` by default. Set `GFC_DATA_DIR` to use another location.
- To sync with peers, TCP port 6881 and UDP port 6882 must be reachable.
- `gfc_backend.spec` builds a single-file Windows executable with PyInstaller.

## Current limitations

These are known gaps, listed so you can make an informed choice:

- **No consensus or signatures yet.** Peers trust each other's ledger rows. A modified node could insert fake balances or transactions. Wallets need public-key signatures, and the ledger needs real validation, before GFC can carry value between strangers.
- **Rewards can be farmed.** Play and transfer rewards can be gamed with multiple accounts.
- **Huge premine.** The treasury holds the entire supply, so issuance is centrally controlled.
- **No content moderation tools** yet for reporting or removing illegal or infringing uploads.
- **API tokens are passed as form/query parameters.** Run the node on localhost, or behind HTTPS if it's exposed.
- **The Unreal front end isn't in this repository.** Right now you use the node through its API.

## Roadmap ideas

- Signed transactions and a consensus model for the ledger
- Sybil-resistant reward rules
- A lightweight web front end with an in-browser 3D viewer (e.g. `<model-viewer>`/three.js), so viewers don't need to install anything
- Reporting and moderation tools
- Optional bridges to established payment rails for creators who want real-money tips

## Contributing

Issues and pull requests are welcome, especially on the limitations above.
