# Signed ledger checkpoints: design (not built yet)

The remaining part of audit finding F08, and the main thing between the bridge and
independent attesters. Status: **proposal for the owner to decide on.** Nothing here is
implemented.

## What's fixed already, and what isn't

Fixed (audit Phase 4):
- deposits and free credit are aged by **admission time** (the block's timestamp on this
  node), not by the timestamp their signer chose;
- a deposit must really be in its block: the block exists, holds only that deposit, and
  its Merkle root is the deposit's hash.

Not fixed, because it needs every node to cooperate:
- **An attester trusts its own database as a whole.** Anyone who can write to it can add
  blocks and rows that look consistent. Signatures prove who intended a transfer, not that
  the network accepted it.
- **Nothing anchors history.** If the canonical node's ledger is restored from an older
  backup, deposits that were already minted can disappear. The wrapped GFC stays on chain
  with nothing behind it, and nothing alarms until `reconcile` happens to notice.
- **Independent attesters have no common view.** The ledger has no global order, so two
  attesters on different nodes can legitimately see different balances. The audit's point:
  three attesters reading three different databases isn't independent confirmation of one
  history.

## Proposal

**1. The canonical node publishes signed checkpoints.**

Every few minutes, the treasury node signs and publishes:

| Field | Meaning |
|---|---|
| `network` | mainnet or testnet, so one network's checkpoint can't be replayed on another |
| `height` | the last block index included |
| `accumulator` | a running hash over every accepted row, in admission order: `acc[n] = H(acc[n-1] ‖ tx_hash[n])` |
| `escrows` | each pinned escrow's balance at `height` |
| `time` | when it was signed |
| `signature` | Ed25519, by a dedicated **checkpoint key** pinned in `config.py` (not the treasury key) |

The node serves them at `/ledger/checkpoints`, and the sync engine shares them like any
other signed row.

**2. Attesters sign only what a checkpoint covers.**
- A deposit is attested only once it's at or below a checkpoint at least
  `finality_seconds` old, and the attester's own ledger reproduces that checkpoint's
  accumulator up to that height. Attesters on separate nodes then agree on one
  history, or refuse.
- Checkpoints must only ever grow. A new checkpoint that doesn't extend the last one (a
  lower height, or an accumulator that doesn't continue it) means history was rewritten.
  Attesters stop and the bridge pauses, instead of minting on top of it. That turns
  "restored from an old backup" from silent loss into an alarm.

**3. Releases check against checkpoints too.** A payout is sent only if the latest
checkpoint's escrow balance covers it.

## What it costs and what it still trusts

- **Every node must upgrade** to serve and sync checkpoints, and the attesters' nodes must
  verify them. Like the other escrow rules, this is a coordinated release.
- **Still trusted:** the canonical node's operator decides the order of conflicting
  transfers. Checkpoints make that order public, append-only and checkable by everyone;
  they don't remove the operator. That has to be stated plainly to users. Removing it
  would mean a consensus protocol between several operators, which is a much larger
  project.
- Work: about the size of Phase 3 (one new module, sync support, attester checks, a pause
  on rollback, tests).

## Decisions for the owner

1. **Who holds the checkpoint key:** the node itself (simplest; a compromised node can sign
   a bad checkpoint), or a separate signer on your machine that signs automatically (safer,
   and it must be online).
2. **Interval:** every 5 minutes is a reasonable start. Deposits then wait at most
   `finality_seconds` + 5 minutes.
3. **Scope:** bridge only (attesters and releases check checkpoints), or the whole ledger
   (every node treats rows below a checkpoint as final). Bridge only is enough for
   mainnet; whole-ledger finality is a bigger change.
