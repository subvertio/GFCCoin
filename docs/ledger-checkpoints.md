# Signed ledger checkpoints

This is the rest of audit finding F08. The bridge's attesters judge deposits against one
signed, append-only history of the canonical ledger, and stop signing if that history is
ever rolled back or rewritten.

Decided (2026-11-01):
- **Key holder:** the canonical node holds the checkpoint key.
- **Interval:** every 5 minutes.
- **Scope:** bridge only. Ordinary transfers work as before.

## What it fixes

Before this, each attester trusted its own node's database as a whole:
- **Rows written straight into SQLite counted.** Anyone who could write to that database
  could add a row that looked consistent.
- **A restore went unnoticed.** If the canonical ledger was restored from an older backup,
  deposits that had already been minted could vanish, and nothing raised an alarm.
- **Attesters could disagree.** Attesters on different nodes could see different histories.

## How it works

**The canonical node** (`ledger_checkpoints.py`) keeps a log of every transaction it
accepted, ordered by block, then tx_hash, with a running hash over it:

```
acc[0] = sha256("gfc-checkpoint:v1:<network>")
acc[n] = sha256(acc[n-1] || tx_hash[n])
```

Every 5 minutes it signs a checkpoint containing:
- the number of rows in the log and the running hash at that point;
- the last block;
- the balance of each escrow;
- the time;
- the hash of the previous checkpoint.

The signing key is a dedicated checkpoint key held by the node. It is never the treasury
key, and its public key is pinned in `config.PINNED_CHECKPOINT_PUBKEYS`. The node refuses
to sign if its log no longer matches its last checkpoint. It serves:
- `GET /ledger/checkpoint`: the latest signed checkpoint;
- `GET /ledger/checkpoint/log?start=N&limit=L`: rows of the log, up to that checkpoint.

**Each attester** (`bridge/checkpoints.py`) keeps its own copy of the log. It builds the
copy only from checkpoints signed by a pinned key, and recomputes the running hash itself:
- **A deposit is signed only once a checkpoint covers it,** and that checkpoint was signed
  at least `finality_seconds` ago. Every attester then judges the same history. A row that
  exists only in one node's database never counts.
- **A checkpoint that doesn't extend the copy halts the attester.** That includes fewer
  rows, a different running hash, or a time that goes backwards. A halted attester signs
  nothing until a person investigates and runs `python -m bridge reset-checkpoints`.

**Reconcile** reports a halted copy as a problem, and so pauses the bridge. It also checks
that the latest checkpoint's escrow balance covers the wrapped supply.

On mainnet, the bridge service refuses to move funds without checkpoints configured.

## What it still trusts

- **The canonical node's operator** decides which of two conflicting transfers counts, and
  holds the checkpoint key. Checkpoints make those decisions public, append-only and
  checkable by every attester; they don't remove the operator. Say so plainly to users.
- **A compromised canonical node** could sign a checkpoint over a row it never really
  accepted. It could already do that to its own ledger. What it can't do is quietly take
  back history the attesters have already copied.

## Setting it up

**On the canonical node** (the live node):
1. Set `GFC_CHECKPOINT_PASSPHRASE` (12+ characters; you type it in `gfc config`):
   ```powershell
   ssh -t gfc-node "sudo gfc config"
   ```
2. Create the key. It's encrypted from the start, and the command prints only its public key:
   ```powershell
   ssh -t gfc-node "sudo gfc new-checkpoint-key"
   ```
3. Pin that public key in `config.PINNED_CHECKPOINT_PUBKEYS`, merge, then:
   ```powershell
   ssh -t gfc-node "sudo gfc update"
   ```
   The node logs `[Checkpoints] signing a checkpoint every 300 s`, and `/ledger/checkpoint`
   answers.

**On each attester and the relayer:**
- set `GFC_BRIDGE_CHECKPOINT_URL` to the canonical node (`https://node.galacticfederation.tech`);
- set `GFC_BRIDGE_CHECKPOINT_DB` if the copy should live somewhere other than next to the
  bridge state.

**On a testnet:**
- set `GFC_CHECKPOINT_PUBKEYS` instead of pinning;
- optionally set `GFC_CHECKPOINT_INTERVAL=60`, so deposits don't wait 5 minutes for a
  checkpoint.

## Tests

`tests/test_ledger_checkpoints.py` covers:
- the running hash and the signature, including a forged escrow balance being rejected;
- the node refusing to sign over a changed history;
- a deposit counting only once an old-enough checkpoint covers it;
- a row present only in an attester's own database never counting;
- a ledger restored from an older backup halting the attesters, even after it grows back;
- a rewritten history halting them;
- an unpinned key being refused;
- an attester signing only checkpointed deposits;
- reconcile's escrow check;
- the node's two endpoints.
