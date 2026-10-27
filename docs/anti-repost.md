# Anti-repost: original creators get the credit and the GFC

On X, a reposter who doesn't credit the original poster takes the attention, and
nothing goes back to the person who made the work. GFC handles this differently:

- **Reposting is allowed.** Nothing is blocked or taken down.
- **A repost is labelled and linked.** If an upload matches content that was seen
  earlier, it becomes a *repost*: the API and share pages say "Repost of
  @original" and link to the original's `/p/<id>` page.
- **All of a repost's earnings go to the original creator.**
  - View rewards: `POST /seeds/{repost}/played` pays the original's signed reward wallet.
  - Proof-of-Data-Transfer credit for transfers of the repost's files
    (`sync_engine._award_podt_credits`) pays the original's wallet.
  - **+15 GFC per repost**, minted by the treasury, when the reposter is
    phone-verified. That's at most once per (reposter, original). The original
    creator reposting their own content earns nothing extra.

Code: `fingerprint.py` (what "the same content" means), `reposts.py` (receipts,
matching, who gets paid, the repost credit), `blockchain.py` (`REPOST` mint).
Tests: `tests/test_reposts.py`.

## Detection

Every seed file gets one or more fingerprints, `"<kind>:<value>"`:

| Type | Fingerprint | Catches | Misses |
|---|---|---|---|
| All | `sha256:` exact file bytes | Byte-for-byte copies | Any change at all |
| Images | `img:` 128-bit dHash (row and column gradients of a 9x9 grayscale thumbnail) | Resized, re-encoded (PNG/JPEG/WebP), recompressed, slightly recoloured copies | Crops, rotations, mirroring, overlays and heavy edits |
| 3D (`.glb`, `.gltf` with embedded buffers) | `geo:` sketch of the normalised vertex set | Re-exports of the same geometry: other vertex order, split or merged seams, new index buffers, materials, textures and names, moved or uniformly scaled | Rotations, remeshing and decimation, Draco/meshopt-compressed meshes, non-uniform scaling, `.gltf` files with external `.bin` buffers |
| Video, audio | `sha256:` only | Exact copies | Re-encodes, trims (see the plan below) |

### Images

The image is decoded with Pillow (pinned in `requirements.txt`) after EXIF
rotation is applied and transparency is flattened onto white. It's converted to
grayscale and shrunk to 9x9. That gives 64 bits for "is this pixel brighter
than the one to its right" and 64 bits for "...than the one below it".

- **Match:** at most `IMAGE_MAX_DISTANCE` = **8 of 128 bits** differ. Unrelated
  images differ in about 64 bits on average. Common practice for a 64-bit dHash
  is a cutoff of about 10 bits, so 8 of 128 is strict.
- **Not claimable:** images smaller than 32 px on a side (icons, emoji), and
  near-uniform images (fewer than 16 or more than 112 bits set: flat colours,
  plain gradients). These are too generic for anyone to "own".
- Decompression bombs are refused (60 MP limit), and an unreadable file still
  gets exact matching.

### 3D models

For `.glb` and `.gltf` (with `data:` URI buffers), every float `VEC3` `POSITION`
accessor of every mesh primitive is read. The steps:

1. **Normalise:** subtract the bounding box minimum, then divide by the longest
   bounding box side. Moving the model or scaling it uniformly changes nothing.
2. **Quantise:** snap the points to a 512-step grid and de-duplicate them. A
   re-export that reorders vertices or duplicates them along UV seams gives the
   same set.
3. **Sketch:** hash each point and keep the 64 smallest hashes (a bottom-k
   MinHash). This is enough to estimate how much two point sets overlap without
   storing the whole set.

- **Match:** an estimated Jaccard similarity of at least **0.9**, and unique
  point counts within **5%** of each other.
- **Not claimable:** models with fewer than **200** unique points (cubes,
  planes, low-poly primitives everyone makes). Draco/meshopt-compressed meshes,
  sparse accessors and external buffers aren't decoded. These get exact matching only.
- No new dependencies: glTF is parsed with `struct` and `json`. Parsing stops
  at 5 million vertices.

### Why conservative

A false "repost" label on someone's original work is worse than a missed repost:
it takes their earnings and tells the world they copied. So every threshold
leans toward "not a repost", and generic content can't be claimed at all.

## Who was first: the notary

A seed's `created_at` is self-declared, and any peer can backdate it. So the
gateway node (`node.galacticfederation.tech`, the one holding the treasury key)
acts as a **notary**:

- **Issuing receipts.** The first time the gateway sees content, it signs an
  **originality receipt** with the treasury key, over
  `(fingerprints, seed_id, owner, reward_wallet, first_seen_at)`. Here
  `reward_wallet` is the seed's own signed reward wallet
  (`signing.seed_reward_wallet`), and `first_seen_at` is the gateway's clock.
  Only signed seeds get receipts: an unsigned seed can't be paid, so it can't be
  an original.
- **When it notarises.** Uploads go through the gateway (that's what the mobile
  app uses). Seeds that arrive by sync are fingerprinted, and notarised, once
  their files arrive (`SyncEngine._assemble_seed_file`). On startup, every node
  fingerprints seeds stored before this feature, oldest `created_at` first
  (`reposts.backfill`, in a background thread). On the gateway, that also
  notarises them.
- **Syncing receipts.** Receipts sync to every node in the
  `originality_receipts` table, over both TCP sync and the tracker relay. A node
  stores a receipt only if it's signed by a pinned treasury key (the same
  `config.TREASURY_PUBKEYS` as mints), its ID is the hash of its signed
  contents, its reward wallet is a public key, and it isn't dated in the future.
  A peer can't forge a receipt or redirect an original's earnings.
- **Deciding a repost.** A seed is a repost of the **earliest** receipt
  (by `first_seen_at`, ties broken by receipt ID) that belongs to another seed
  and matches any of its fingerprints, unless the seed's own receipt is earlier.
  If an older receipt arrives later, affected seeds are re-evaluated, so the
  earliest always wins.
- **Nodes without the treasury key** match against the receipts they hold but
  never issue any.

What each node keeps locally (never synced, and derived from its own files and
the receipts it accepted):

- `seed_fingerprints`: what this node computed for each file.
- `reposts`: which seed is a repost of which original, the original's owner and
  wallet (from the receipt), and how it matched.
- `repost_credits`: which (reposter, original) pairs have been credited.

## Ledger: the `REPOST` mint

- `blockchain.TX_TYPE_REPOST = "REPOST"` is a treasury mint, modelled on
  `REFERRAL`.
- **Exact amount only:** `REPOST_CREDIT_CENTS = 1_500` (15 GFC). Every node
  rejects a synced `REPOST` with any other amount, or one not signed by a pinned
  treasury key. A leaked treasury key still can't mint arbitrary amounts this way.
- It's counted in the circulation stats (`get_blockchain_stats`), alongside
  `REWARD` and `REFERRAL`.
- It's paid by the node where the reposter uploads (normally the gateway). Like
  every mint, it's only network-wide if that node holds the treasury key.

## API

- `POST /seeds/upload` returns `repost_of` (`null` for originals) and
  `repost_credit_gfc` (15.0 when this upload paid the original creator, else 0).
- `GET /seeds`, `GET /seeds/mine`, `GET /seeds/{id}` and `GET /p/{id}/share`
  include `repost_of` on every seed:

```json
"repost_of": {
  "seed_id": "3f9c0a...",
  "owner": "alice",
  "label": "Repost of @alice",
  "url": "https://galacticfederation.tech/p/3f9c0a...",
  "matched_by": "img"
}
```

`matched_by` is `sha256`, `img` or `geo`. On a repost, the share text credits the
original creator ("<title> by alice on GFC").

- `GET /p/{id}` (the share page) shows "Repost of @alice", linking to `/p/<original id>`.
  The "Rewards verified" badge is hidden on reposts, because the reposter's
  wallet isn't the one that's paid. Every value is HTML-escaped and every path
  segment is URL-quoted. The page runs no script.

Clients (such as the Unreal mobile app) should show `repost_of.label` and link
it to the original.

## Honest limits

- **Heavily edited content can evade detection.** That includes crops,
  rotations, mirroring, overlays, colour grading, remeshing or decimating a
  model, rotating a model, re-encoding or trimming video and audio, and Draco
  compression. Someone determined to avoid the label can do it with effort.
- **False positives are possible.** Two genuinely different images can have
  close dHashes (memes from the same template, near-identical photos from the
  same spot, renders of the same scene). Two models can share most of their
  geometry (the same base mesh with small sculpt changes). The thresholds are
  strict, and generic content is excluded, but the risk isn't zero.
- **There's no appeals flow yet.** A creator labelled by mistake can't contest
  it. Suggested follow-up: a `POST /seeds/{id}/dispute` endpoint that records
  the claim and freezes the repost credit. Then an operator review on the
  gateway that issues a treasury-signed "override" record (synced like
  receipts), which every node applies when deciding a repost. Also a
  `GET /seeds/{id}/reposts` endpoint so originals can see who reposted them.
- **"First seen by the gateway" isn't "first created".** Something posted
  elsewhere (or on a node that hasn't synced to the gateway) and then uploaded
  to GFC by someone else first is credited to that uploader. If two copies reach
  the gateway in the same sync batch, whichever file finishes transferring
  first is notarised first. Receipts prove who was first *on GFC*, not
  copyright.
- **Detection needs the file.** A node labels a seed only once it has the
  seed's file and a matching receipt. PoDT credit paid for a transfer that
  completed before the receipt arrived stays where it went.
- **Repost credit farming.** A verified user can repost an accomplice's
  originals to pay them 15 GFC each. That's bounded by once per
  (reposter, original), on top of the phone verification rule (one account per
  number). The credit is counted per node, so the same pair could be paid once
  per paying node. Only treasury-node payments count network-wide.
- **Scale.** Near-duplicate matching scans every receipt for each new seed.
  That's fine for thousands of seeds. For more, add an index: LSH buckets on dHash
  bands and on the geometry sketch, with exact fingerprints in an indexed column.

## Plan: near-duplicate video and audio

Neither needs a heavy dependency on ordinary nodes. Both can run only on the
gateway (the notary), with results going into the receipt like the other
fingerprints:

- **Video:** sample keyframes at fixed intervals with `ffmpeg` (already common
  on servers, invoked as a subprocess with time and size limits). Take a dHash
  of each frame, and store the sequence. Two videos match if a long enough run
  of frame hashes aligns within the image threshold. That survives re-encoding,
  resolution changes and trimming the start or end.
- **Audio:** decode to mono 11 kHz PCM with `ffmpeg`, compute a chroma or
  spectral-peak fingerprint (as Chromaprint/AcoustID does; the `fpcalc` binary
  can be used directly), and compare by bit error rate over aligned windows.
  That survives re-encoding, bitrate and small volume changes.
- Same rules as now: conservative thresholds, a minimum length (very short
  clips are too generic to claim), and evaluation against labelled pairs before
  turning it on.
