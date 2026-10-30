#!/usr/bin/env bash
# Virus scanning for GFC downloads (filescan.py). Safe to run again; called by setup.sh and gfc-update.
# - ClamAV + clamav-freshclam: definitions are checked every hour (at least daily), and
#   gfc-scan.timer rescans every download each day with them.
# - Small servers (< 2 GB RAM): 2 GB of swap, and no always-on clamd (it keeps ~1-1.5 GB of
#   definitions in memory); each download is scanned with clamscan instead (slower).
#   On 2 GB+ the clamav-daemon service runs and scans take seconds.
set -euo pipefail

mem_kb="$(awk '/MemTotal/ {print $2}' /proc/meminfo)"
big_enough=$(( mem_kb >= 1900000 ))

if [[ $big_enough -eq 0 ]] && ! swapon --show --noheadings | grep -q .; then
    echo "adding 2 GB of swap (this server has $(( mem_kb / 1024 )) MB of RAM)"
    fallocate -l 2G /swapfile
    chmod 600 /swapfile
    mkswap /swapfile >/dev/null
    swapon /swapfile
    grep -q '^/swapfile ' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
fi

if ! command -v clamscan >/dev/null 2>&1 || ! command -v freshclam >/dev/null 2>&1; then
    echo "installing ClamAV"
    DEBIAN_FRONTEND=noninteractive apt-get update -q >/dev/null
    DEBIAN_FRONTEND=noninteractive apt-get install -y -q clamav clamav-freshclam >/dev/null
fi
systemctl enable --now clamav-freshclam >/dev/null 2>&1 || true

# The first definitions download can take a few minutes; scans wait for it
if ! ls /var/lib/clamav/*.c[lv]d >/dev/null 2>&1; then
    echo "downloading ClamAV definitions (first time)"
    systemctl stop clamav-freshclam >/dev/null 2>&1 || true
    freshclam --quiet || echo "freshclam failed; the updater service will retry"
    systemctl start clamav-freshclam >/dev/null 2>&1 || true
fi

if [[ $big_enough -eq 1 ]]; then
    if ! command -v clamdscan >/dev/null 2>&1; then
        DEBIAN_FRONTEND=noninteractive apt-get install -y -q clamav-daemon clamdscan >/dev/null
    fi
    systemctl enable --now clamav-daemon >/dev/null 2>&1 || true
else
    systemctl disable --now clamav-daemon >/dev/null 2>&1 || true
fi
