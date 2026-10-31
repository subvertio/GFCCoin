#!/usr/bin/env bash
# GFC public node setup for a fresh Debian 13/12 or Ubuntu 24.04 server (DigitalOcean droplet, Hetzner, ...).
#
# Usage (as root, on the server):
#   curl -fsSL https://raw.githubusercontent.com/subvertio/GFCCoin/master/deploy/setup.sh -o setup.sh
#   bash setup.sh node.galacticfederation.tech
#
# Safe to re-run: existing config, keys and data are kept.
set -euo pipefail

DOMAIN="${1:-}"
REPO="${GFC_REPO:-https://github.com/subvertio/GFCCoin.git}"
BRANCH="${GFC_BRANCH:-master}"
APP_DIR=/opt/gfc/app
VENV=/opt/gfc/venv
DATA_DIR=/var/lib/gfc
ETC_DIR=/etc/gfc
BACKUP_DIR=/var/backups/gfc

if [[ -z "$DOMAIN" ]]; then
    echo "usage: bash setup.sh <domain, e.g. node.galacticfederation.tech>" >&2
    exit 2
fi
if [[ $EUID -ne 0 ]]; then
    echo "run as root" >&2
    exit 1
fi
. /etc/os-release
case "${ID:-}" in
    debian|ubuntu) ;;
    *) echo "warning: written for Debian 13/12 and Ubuntu 24.04, this is ${PRETTY_NAME:-unknown}" >&2 ;;
esac

echo "==> Installing packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -y -q python3 python3-venv python3-pip git sqlite3 ufw caddy curl ca-certificates unattended-upgrades ffmpeg
if ! python3 -c 'import sys; sys.exit(sys.version_info < (3, 11))'; then
    echo "Python 3.11+ required, found $(python3 --version)" >&2
    exit 1
fi

# Automatic security updates (on by default in Ubuntu, not in Debian)
cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF

echo "==> Creating gfc user and directories"
id gfc &>/dev/null || useradd --system --home-dir "$DATA_DIR" --shell /usr/sbin/nologin gfc
install -d -o gfc -g gfc -m 750 "$DATA_DIR"
install -d -o root -g gfc -m 750 "$ETC_DIR"
install -d -o root -g root -m 700 "$BACKUP_DIR"
install -d -o root -g root -m 755 /opt/gfc

echo "==> Fetching code ($REPO, $BRANCH)"
if [[ -d "$APP_DIR/.git" ]]; then
    git -C "$APP_DIR" fetch -q origin "$BRANCH"
    git -C "$APP_DIR" checkout -q "$BRANCH"
    git -C "$APP_DIR" reset -q --hard "origin/$BRANCH"
else
    git clone -q --branch "$BRANCH" "$REPO" "$APP_DIR"
fi
[[ -d "$VENV" ]] || python3 -m venv "$VENV"
"$VENV/bin/pip" install -q --upgrade pip
"$VENV/bin/pip" install -q -r "$APP_DIR/requirements.txt"

echo "==> Writing config (existing $ETC_DIR/gfc.env is kept)"
if [[ ! -f "$ETC_DIR/gfc.env" ]]; then
    sed "s#__DOMAIN__#$DOMAIN#g" "$APP_DIR/deploy/gfc.env.example" > "$ETC_DIR/gfc.env"
fi
chown root:gfc "$ETC_DIR/gfc.env"
chmod 640 "$ETC_DIR/gfc.env"

bash "$APP_DIR/deploy/clamav.sh" || echo "ClamAV setup failed: downloads stay held until it works (rerun gfc update)"
bash "$APP_DIR/deploy/install-files.sh" "$DOMAIN"

echo "==> Firewall: SSH, HTTP(S), P2P sync"
ufw allow OpenSSH >/dev/null
ufw allow 80/tcp >/dev/null
ufw allow 443/tcp >/dev/null
ufw allow 6881/tcp >/dev/null   # P2P sync with other GFC nodes
ufw --force enable >/dev/null

# Key-only SSH, but only if a key is installed (otherwise we'd lock you out)
if [[ -s /root/.ssh/authorized_keys ]]; then
    printf 'PasswordAuthentication no\nKbdInteractiveAuthentication no\n' > /etc/ssh/sshd_config.d/60-gfc-keys-only.conf
    systemctl reload ssh || systemctl reload sshd || true
fi

echo "==> Starting services"
systemctl enable --now gfc-node.service
systemctl enable --now gfc-backup.timer
systemctl restart caddy

for _ in $(seq 1 20); do
    if curl -fsS http://127.0.0.1:8000/health >/dev/null 2>&1; then
        break
    fi
    sleep 1
done
if curl -fsS http://127.0.0.1:8000/health >/dev/null 2>&1; then
    echo "==> Node is up on 127.0.0.1:8000"
else
    echo "!! Node did not answer /health yet; check: journalctl -u gfc-node -n 50" >&2
fi

cat <<EOF

Done. Next steps (see deploy/README.md):
  1. Point DNS: A record  $DOMAIN  ->  $(curl -fsS -4 https://ifconfig.me 2>/dev/null || echo '<this server IP>')
     Caddy gets an HTTPS certificate automatically once DNS resolves.
  2. Restore the treasury key:  gfc restore-treasury
     Add the Firebase config:       gfc config
  3. Check everything:           gfc check
EOF
