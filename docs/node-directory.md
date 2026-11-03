# Node directory and official nodes

Anyone can run a GFC node. Nodes find each other through a small **node directory** (a
Cloudflare Worker, `worker/directory`), on top of the existing ways:
`node.galacticfederation.tech:6881`, LAN broadcast and peer-list gossip. A node is
**official** only while it holds a certificate signed by a **federation key** that the
network operator keeps offline.

## How it fits together

| Piece | Where | What it does |
|---|---|---|
| Node key | each node, `DATA_DIR/node_key.hex` (made on first start) | names the node; holds no funds |
| Federation key | operator's PC, encrypted, offline | signs official-node certificates and revocation lists |
| Certificate | the node, `DATA_DIR/node_cert.json` | "node key X is official until date Y", signed by the federation key |
| Directory | Cloudflare Worker + KV | stores each node's latest signed announcement and the address it came from |

Every 5 minutes each node signs an announcement (its node key, port, public API URL,
version, time and certificate if it has one), posts it to `/announce`, and reads `/nodes`.
It adds every node listed there and marks the ones whose certificate checks out as
official. Official nodes come first in the peer lists it shares.

**Nodes don't trust the directory.** They check every announcement signature, every
certificate against the pinned federation keys (`config.PINNED_FEDERATION_PUBKEYS`) and the
revocation list, and drop anything that fails. The Worker runs the same checks to keep junk
out. It also takes the node's address from the connection itself (`CF-Connecting-IP`), so a
node can't list someone else's address. It caps nodes per address at 4 and forgets a node 30
minutes after its last announcement.

A certificate names a node *key*, not an address. Copying it to another node does nothing:
that node can't sign announcements with the certified key, so it's listed as a community node.

Signatures use their own domain (`GFC-NODE-SIG-v1:` + kind + `:` + body), so no
transaction, seed or checkpoint signature can be replayed as one, and the reverse.

## One-time setup

### 1. Make the federation key (your PC)

```powershell
python node_certs.py new-federation-key F:\GFC\gfc-federation.key
```

It asks for a passphrase and prints the public key. Then:

- Pin the public key in `config.PINNED_FEDERATION_PUBKEYS` and in `worker/directory/wrangler.toml`
  (`FEDERATION_PUBKEYS`), in a release every node takes.
- Back up the key file with the treasury backup. Keep it off the nodes.

### 2. Deploy the Worker (Cloudflare)

```powershell
cd worker\directory
npx wrangler login
npx wrangler kv namespace create NODES      # paste the id into wrangler.toml
npx wrangler deploy                          # prints https://gfc-directory.<you>.workers.dev
```

Put that URL in `config.DEFAULT_DIRECTORY_URLS` (or `GFC_DIRECTORY_URLS` on a node). It
should fit in Workers' and KV's free tier at network sizes up to a few hundred nodes.

### 3. Certify a node

On the node:

```powershell
ssh gfc-node gfc node-key
```

On your PC, with the federation key:

```powershell
python node_certs.py certify F:\GFC\gfc-federation.key <NODE_KEY> "GFC DigitalOcean" --days 365 > node_cert.json
```

Copy `node_cert.json` to the node and install it (it is checked first):

```powershell
scp node_cert.json gfc-node:/tmp/node_cert.json
ssh gfc-node gfc install-cert /tmp/node_cert.json
```

A certificate is public information: it's safe to send by email or chat.

### Revoke a node

```powershell
python node_certs.py revoke F:\GFC\gfc-federation.key 1 <NODE_KEY> [<NODE_KEY> ...] > revocations.json
python node_certs.py publish-revocations revocations.json
```

The sequence number must go up each time. Each list replaces the previous one, so include
every key that should stay revoked. Nodes stop treating a revoked key as official at their
next directory read, and the Worker drops it at once.

## Settings

| Setting | Default | Meaning |
|---|---|---|
| `GFC_DIRECTORY_URLS` | `config.DEFAULT_DIRECTORY_URLS` | directories to announce to and read (comma-separated); empty disables |
| `GFC_DIRECTORY_ANNOUNCE` | `1` | `0`: read the directory but don't list this node |
| `GFC_PUBLIC_API_URL` | empty | this node's public HTTPS API, announced for apps |
| `GFC_NODE_KEY_FILE` | `DATA_DIR/node_key.hex` | the node key |
| `GFC_NODE_CERT_FILE` | `DATA_DIR/node_cert.json` | the installed certificate |
| `GFC_FEDERATION_PUBKEYS` | pinned keys | replaces the pinned federation keys (test networks) |

`/p2p/status` shows this node's key, whether it's official, and how many official peers it knows.

## Tests

```powershell
python -m unittest tests.test_node_certs -v
python worker\directory\test\make_fixture.py; node worker\directory\test\worker.test.mjs
```

The second runs the Worker against Python-signed fixtures with an in-memory KV, so the two
implementations are checked against each other.
