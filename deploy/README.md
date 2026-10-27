# Running the public GFC node (DigitalOcean, Debian)

This server is the network's **treasury and gateway node**. It's the always-on
peer that:
- signs grants and rewards with the treasury key;
- runs phone verification (Twilio) behind Turnstile;
- serves public share pages;
- syncs with everyone's home nodes over TCP 6881.

Ports and paths:

| What | Where |
|---|---|
| API (behind HTTPS) | `https://node.galacticfederation.tech` (Caddy on 443, which proxies to 127.0.0.1:8000) |
| P2P sync | TCP 6881 |
| Data | `/var/lib/gfc` (owned by the `gfc` user) |
| Config and secrets | `/etc/gfc/gfc.env` |
| Code | `/opt/gfc/app` (a git checkout of `master`) |
| Backups | `/var/backups/gfc` (nightly at 03:30 UTC, 14 kept) |

## 1. Create the droplet

In DigitalOcean, choose **Create → Droplets** and set:
- **Region:** New York (NYC3) or San Francisco (SFO3)
- **Configuration type:** Bundled
- **Image:** Debian 13 x64. Debian 12 and Ubuntu 24.04 also work, but Debian 13's Python 3.13 is the version the test suite runs on.
- **Size:** Basic, Regular, $6/month (1 vCPU, 1 GB). You can resize later.
- **Authentication:** **SSH key**. If you don't have one, run `ssh-keygen -t ed25519` in PowerShell and paste in the contents of `C:\Users\<you>\.ssh\id_ed25519.pub`.
- **Backups:** on.

Also turn on two-factor login for your DigitalOcean account. Whoever controls
that account controls the treasury server.

## 2. Run the setup script

From PowerShell on your PC (replace `SERVER_IP`):

```powershell
ssh root@SERVER_IP
```

Then, on the server:

```bash
apt-get update -q && apt-get install -y -q curl
curl -fsSL https://raw.githubusercontent.com/subvertio/GFCCoin/master/deploy/setup.sh -o setup.sh
bash setup.sh node.galacticfederation.tech
```

The script does the following:
- installs Python, Caddy and the firewall, and turns on automatic security updates;
- creates the unprivileged `gfc` user;
- clones the code and installs its dependencies;
- starts the node as a systemd service;
- opens only ports 22, 80, 443 and 6881;
- turns off SSH password logins (only if your key is installed);
- schedules nightly backups.

It's safe to run again.

## 3. Point the domain at the server

In your domain's DNS settings (Wix: **Domains → galacticfederation.tech →
Manage DNS records**), add an **A record**:

| Host | Value |
|---|---|
| `node` | `SERVER_IP` |

Once DNS resolves, which takes minutes to a few hours, Caddy gets an HTTPS
certificate automatically. Check it with:

```bash
curl https://node.galacticfederation.tech/health
```

## 4. Restore the treasury key

Copy the encrypted backup up from your PC (PowerShell):

```powershell
scp F:\GFC\treasury.backup root@SERVER_IP:/var/lib/gfc/treasury.backup
```

On the server, restore it as the `gfc` user. It asks for the backup
passphrase.

```bash
chown gfc:gfc /var/lib/gfc/treasury.backup
cd /opt/gfc/app
runuser -u gfc -- env GFC_TREASURY_KEY_FILE=/var/lib/gfc/treasury_key.hex /opt/gfc/venv/bin/python signing.py restore /var/lib/gfc/treasury.backup
rm /var/lib/gfc/treasury.backup
```

Optionally, encrypt the key file on disk. Then put the passphrase in
`/etc/gfc/gfc.env` as `GFC_TREASURY_PASSPHRASE=...`:

```bash
runuser -u gfc -- env GFC_TREASURY_KEY_FILE=/var/lib/gfc/treasury_key.hex /opt/gfc/venv/bin/python signing.py encrypt
```

Encrypting means a leaked disk snapshot or backup doesn't expose the key. It
doesn't protect against someone who gets root on the running server, because
the passphrase sits in the env file. The treasury limits (fixed grant size,
capped rewards) bound the damage, and you can rotate to a new key.

Check that the node loaded the key:

```bash
systemctl restart gfc-node
runuser -u gfc -- bash -c 'set -a; . /etc/gfc/gfc.env; cd /opt/gfc/app; /opt/gfc/venv/bin/python -c "import signing; print(\"treasury key loaded:\", bool(signing.load_treasury_private_key()))"'
```

## 5. Add the Twilio and Turnstile secrets

Edit the config with `nano /etc/gfc/gfc.env`:

- `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, `TWILIO_VERIFY_SERVICE_SID`: from
  the Twilio console (Verify → Services). While these are empty, the node uses
  a fake provider that's only suitable for testing.
- `GFC_TURNSTILE_SECRET`: from the Cloudflare dashboard (Turnstile → Add
  widget, domain `galacticfederation.tech`). The *site key* goes into the app
  or website; the *secret* goes here.

Then restart:

```bash
systemctl restart gfc-node
journalctl -u gfc-node -n 50
```

## Day to day

| Task | Command (on the server) |
|---|---|
| Status / logs | `systemctl status gfc-node` / `journalctl -u gfc-node -f` |
| Update to the latest `master` (backs up first) | `gfc-update` |
| Back up now | `gfc-backup` |
| Operator endpoints (blocked from the internet) | `curl http://127.0.0.1:8000/p2p/sync_debug` |

To copy the newest backup to your PC (PowerShell, from the repo folder):

```powershell
.\deploy\pull-backup.ps1 -Server SERVER_IP
```

That saves it to `F:\GFC\server-backups`. Backups contain the phone-hash key
unencrypted, so keep them private. Wallet keys inside them stay encrypted with
each user's password.

## What's exposed

- The whole API is served over HTTPS. Debug and operator routes return 404 to
  the internet:
  `/p2p/add_peer`, `/p2p/force_sync`, `/p2p/sync_debug`, `/p2p/diagnose`,
  `/podt/report_transfer`.
- Uploads are capped at 200 MB per request in Caddy.
- The app runs as `gfc` with systemd hardening. It can only write to
  `/var/lib/gfc`.
- It must run as a **single worker**, because the P2P engine lives in the app
  process.
