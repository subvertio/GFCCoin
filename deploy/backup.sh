#!/usr/bin/env bash
# Nightly GFC backup: a consistent copy of the ledger database plus the node's
# secrets, as /var/backups/gfc/gfc-YYYYmmdd-HHMMSS.tar.gz (root-only, 14 kept).
# Wallet keys inside the database are encrypted with each user's password.
# The phone HMAC key is NOT encrypted, so treat these files as secrets.
# Seed media files are not included (they are re-synced from peers, and the
# droplet backup covers them).
set -euo pipefail

DATA_DIR="${GFC_DATA_DIR:-/var/lib/gfc}"
BACKUP_DIR="${GFC_BACKUP_DIR:-/var/backups/gfc}"
KEEP="${GFC_BACKUP_KEEP:-14}"

stamp="$(date -u +%Y%m%d-%H%M%S)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
umask 077

if [[ ! -f "$DATA_DIR/gfc_ledger.db" ]]; then
    echo "no ledger database at $DATA_DIR/gfc_ledger.db yet; nothing to back up" >&2
    exit 0
fi

# SQLite online backup: safe while the node is running
sqlite3 "$DATA_DIR/gfc_ledger.db" ".backup '$work/gfc_ledger.db'"
for f in treasury_key.hex phone_hmac_key.hex known_peers.json; do
    [[ -f "$DATA_DIR/$f" ]] && cp -p "$DATA_DIR/$f" "$work/"
done

mkdir -p "$BACKUP_DIR"
tar -czf "$BACKUP_DIR/gfc-$stamp.tar.gz" -C "$work" .
chmod 600 "$BACKUP_DIR/gfc-$stamp.tar.gz"

# Keep the newest $KEEP backups
ls -1t "$BACKUP_DIR"/gfc-*.tar.gz | tail -n +"$((KEEP + 1))" | xargs -r rm -f
echo "backup written: $BACKUP_DIR/gfc-$stamp.tar.gz"
