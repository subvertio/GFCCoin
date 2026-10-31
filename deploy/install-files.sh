#!/usr/bin/env bash
# Install the node's systemd units and helper commands from the checked-out code.
# Called by setup.sh and by gfc-update, so updates also refresh these files.
# Usage (as root): bash install-files.sh [DOMAIN]   (DOMAIN also rewrites the Caddyfile)
set -euo pipefail

APP_DIR=/opt/gfc/app
DOMAIN="${1:-}"

install -m 644 "$APP_DIR/deploy/gfc-node.service" /etc/systemd/system/gfc-node.service
install -m 644 "$APP_DIR/deploy/gfc-backup.service" /etc/systemd/system/gfc-backup.service
install -m 644 "$APP_DIR/deploy/gfc-backup.timer" /etc/systemd/system/gfc-backup.timer
install -m 644 "$APP_DIR/deploy/gfc-scan.service" /etc/systemd/system/gfc-scan.service
install -m 644 "$APP_DIR/deploy/gfc-scan.timer" /etc/systemd/system/gfc-scan.timer
install -m 755 "$APP_DIR/deploy/backup.sh" /usr/local/sbin/gfc-backup
install -m 755 "$APP_DIR/deploy/update.sh" /usr/local/sbin/gfc-update
install -m 755 "$APP_DIR/deploy/gfc" /usr/local/bin/gfc
if [[ -n "$DOMAIN" ]]; then
    sed "s#__DOMAIN__#$DOMAIN#g" "$APP_DIR/deploy/Caddyfile" > /etc/caddy/Caddyfile
elif [[ -f /etc/caddy/Caddyfile ]] && grep -Eq 'max_size (200|1100|4200)MB' /etc/caddy/Caddyfile; then
    # Existing nodes: raise the upload limit to 8 GB videos (the rest of their Caddyfile stays as is)
    sed -i -E 's/max_size (200|1100|4200)MB/max_size 8300MB/' /etc/caddy/Caddyfile
    systemctl reload caddy >/dev/null 2>&1 || true
fi
systemctl daemon-reload
systemctl enable --now gfc-scan.timer >/dev/null 2>&1 || true
