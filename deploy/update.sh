#!/usr/bin/env bash
# Update the GFC node to the latest code on its branch and restart it.
# Takes a backup first. Usage (as root): gfc-update
set -euo pipefail

APP_DIR=/opt/gfc/app
VENV=/opt/gfc/venv
BRANCH="${GFC_BRANCH:-master}"

/usr/local/sbin/gfc-backup
git -C "$APP_DIR" fetch -q origin "$BRANCH"
echo "updating $(git -C "$APP_DIR" rev-parse --short HEAD) -> $(git -C "$APP_DIR" rev-parse --short "origin/$BRANCH")"
git -C "$APP_DIR" reset -q --hard "origin/$BRANCH"
"$VENV/bin/pip" install -q -r "$APP_DIR/requirements.txt"
bash "$APP_DIR/deploy/install-files.sh"   # refresh units and helper commands
systemctl restart gfc-node
sleep 3
curl -fsS http://127.0.0.1:8000/health && echo " - node healthy"
