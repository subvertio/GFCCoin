# Running the public GFC node (DigitalOcean, Debian)

This server is the network's **treasury and gateway node**. It's the always-on
peer that:
- signs grants and rewards with the treasury key;
- runs phone verification (Firebase phone sign-in in the browser);
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

In PowerShell on your PC, save a shortcut so `ssh gfc-node` reaches the server
with your key (replace `SERVER_IP`):

```powershell
Add-Content "$env:USERPROFILE\.ssh\config" "`nHost gfc-node`n  HostName SERVER_IP`n  User root`n  IdentityFile ~/.ssh/id_ed25519_gfc`n"
```

To avoid typing the key's passphrase every time, load it into the Windows SSH
agent. The first line opens an administrator prompt; click **Yes**:

```powershell
Start-Process powershell -Verb RunAs -ArgumentList '-NoProfile -Command "Get-Service ssh-agent | Set-Service -StartupType Automatic; Start-Service ssh-agent"'
```

```powershell
ssh-add "$env:USERPROFILE\.ssh\id_ed25519_gfc"
```

Then run the setup:

```powershell
ssh gfc-node "apt-get update -q && apt-get install -y -q curl && curl -fsSL https://raw.githubusercontent.com/subvertio/GFCCoin/master/deploy/setup.sh -o setup.sh && bash setup.sh node.galacticfederation.tech"
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

```powershell
Invoke-RestMethod https://node.galacticfederation.tech/health
```

If Caddy tried before DNS existed, it retries with growing waits. To retry now,
run `ssh gfc-node "systemctl restart caddy"`.

## 4. Restore the treasury key

Copy the encrypted backup up from your PC (PowerShell):

```powershell
scp F:\GFC\treasury.backup gfc-node:/var/lib/gfc/treasury.backup
```

Then restore it. It asks for the backup passphrase, deletes the uploaded copy,
restarts the node and confirms the key is loaded:

```powershell
ssh -t gfc-node gfc restore-treasury
```

Optionally, encrypt the key file on disk. First save a passphrase of at least
12 characters in the settings as `GFC_TREASURY_PASSPHRASE=...`, pasted from your
password manager. Wrap it in single quotes if it has spaces or symbols like `$`.

```powershell
ssh -t gfc-node gfc config
```

Then encrypt. It uses the saved passphrase, so there's nothing to retype. It
keeps a safety copy, and rolls back if the node can't unlock the result:

```powershell
ssh gfc-node gfc encrypt-treasury
```

**What encrypting protects:** the GFC backup files (`gfc backup`, and the
copies you pull to your PC) then hold only the encrypted key. The passphrase
lives in `/etc/gfc/gfc.env`, which isn't backed up.

**What it doesn't protect:** anyone with root on the server, and DigitalOcean's
own droplet backups or snapshots. Those copy the whole disk, so they contain
both the key file and the passphrase. Two-factor login on your DigitalOcean
account and your SSH key's passphrase are what guard those. If the worst
happens, the treasury limits (fixed grant size, capped rewards) bound the
damage, and you can rotate to a new key.

## 5. Turn on phone verification (Firebase)

Open the settings with `ssh -t gfc-node gfc config` (it restarts the node when you save)
and set `GFC_FIREBASE_CONFIG` to the Firebase web app's public config, as one line of
JSON in single quotes. The Firebase console setup (phone sign-in, authorized domain,
SMS regions) is in [docs/moderation-and-web-verify.md](../docs/moderation-and-web-verify.md#phone-verification-in-a-browser-app_webverifypy).
While it's empty, phone verification is off, and so are the grants and rewards that need it.

Account recovery (`/reset`: forgot password, verify an email, change the phone number) uses
the same Firebase project. For the email parts, also switch on email links in the Firebase
console: **Authentication > Sign-in method > Email/Password**, enable it and tick
**Email link (passwordless sign-in)**. Firebase sends the emails itself, so no mail service
is needed. Recovery by phone works without that switch.

Then check everything at once:

```powershell
ssh gfc-node gfc check
```

## Day to day

Everything goes through one `gfc` command. Run it from PowerShell on your PC
with `ssh gfc-node gfc ...`, adding `-t` for commands that prompt or open an
editor:

| Task | Command |
|---|---|
| Plain-English status: services, HTTPS, treasury key, Firebase, last backup | `ssh gfc-node gfc check` |
| Node log | `ssh gfc-node gfc logs` (or `gfc logs 200`) |
| Edit settings and secrets, then restart | `ssh -t gfc-node gfc config` |
| Update to the latest `master` (backs up first) | `ssh gfc-node gfc update` |
| Back up now | `ssh gfc-node gfc backup` |
| Restart | `ssh gfc-node gfc restart` |
| Grant GFC (hackathon prize, node host, other); checks every rule, then asks to confirm; public | `ssh -t gfc-node gfc grant WALLET AMOUNT PURPOSE "MEMO"` |
| List every operator grant (also public at `/treasury/grants`) | `ssh gfc-node gfc grants` |
| Publish a new Android app version at `/app` (release-signed APKs only) | see [Publishing the Android app](#publishing-the-android-app) |

To copy the newest backup to your PC (PowerShell, from the repo folder):

```powershell
.\deploy\pull-backup.ps1 -Server SERVER_IP
```

That saves it to `F:\GFC\server-backups`. Backups contain the phone-hash key
unencrypted, so keep them private. Wallet keys inside them stay encrypted with
each user's password.

## Publishing the Android app

The node serves the app at `https://YOUR_DOMAIN/app`: a download page, the APK at
`/app/gfc.apk` and `/app/release.json` for update checks. Share pages and the web feed
show "Get the app" once a version is published, and "Open in GFC" on a phone without
the app goes there.

Only APKs signed with the release key can be published, so a development build never
reaches people (they couldn't install later updates over it).

1. Once: put the release key's fingerprint (printed by `Scripts\CreateReleaseKey.ps1`
   in GFC-Client) in `GFC_ANDROID_CERT_SHA256` with `ssh -t gfc-node gfc config`. It's
   public; App Links use it too.
2. Each release, from PowerShell after `.\Scripts\PackageAndroid.ps1 -Release`:

```powershell
$apk = Get-ChildItem D:\projects\GFC-Client\Packaged\Release -Recurse -Filter *.apk | Sort-Object LastWriteTime -Descending | Select-Object -First 1
scp $apk.FullName gfc-node:/tmp/gfc.apk
ssh gfc-node "gfc publish-app /tmp/gfc.apk 0.1.0 && rm /tmp/gfc.apk"
```

Use a new version number each time. The APK lives in `/var/lib/gfc/app/` and isn't in
the nightly backups (it's rebuilt from GFC-Client).

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
