# Discord verification

The GFC Discord server's **Verified GFC** role goes only to members who prove they own a
phone-verified GFC account. It uses the same eligibility check that GFC Connect gives partner
sites (`app_connect.member_status`: a row in `phone_verifications`). Knowing a username, a wallet
address or holding GFC proves nothing here.

## How it works

1. In the GFC app: account menu → **Link Discord** → **Get a code**. The node issues a code like
   `GFC-7Q4K-2M9X` (`POST /discord/code`). It needs a full login session (not a limited api
   token) and a verified phone, and it's valid for 10 minutes. It's stored only as a SHA-256 hash,
   and a new code replaces the previous one.
2. In Discord, in `#how-to-verify`: `/verify GFC-7Q4K-2M9X`.
3. Discord POSTs the command to `https://node.galacticfederation.tech/discord/interactions`,
   signed with the application's Ed25519 key. The node checks:
   - that the signature is valid and under 5 minutes old;
   - that it comes from the configured server, and from `#how-to-verify` if
     `GFC_DISCORD_VERIFY_CHANNEL_ID` is set.

   Then, in one database transaction, it checks that the code is unused and not expired, the
   account is still phone verified, the GFC account has no other Discord account linked, and the
   Discord user has no other GFC account linked. Then it uses the code up and records the link.
   Concurrent attempts on one code link at most once.
4. The node adds the **Verified GFC** role through Discord's REST API with the bot token. It only
   ever touches the role in `GFC_DISCORD_ROLE_ID` on the server in `GFC_DISCORD_GUILD_ID`. Every
   reply is ephemeral: only the member sees it, and the code is never echoed.

There's no bot process: Discord calls the node, and the node calls Discord. The bot never needs
to be online.

### Limits

- **Codes:** 10 per account per hour, one valid at a time, 10 minutes each.
- **Wrong attempts:** 5 wrong or expired codes per Discord user per 15 minutes, then they wait.
- **Total load:** 60 `/verify` calls per minute across everyone.

The attempt counters live in memory, so a node restart resets them. The code space (31⁸) and the
10-minute expiry make guessing hopeless either way.

### Failures, unlinking and revocation

| Situation | What happens |
|---|---|
| Discord down or rate limiting when the role is added | The link is saved as `pending` and the member is told the role comes within minutes. A background pass every 5 minutes retries. |
| The member isn't on the server (left) | Saved as `left`, and granted again by the next pass if they rejoin. |
| Member unlinks in the app (`POST /discord/unlink`) | The link ends and the role is removed. A failed removal is retried by the next pass. They can then link again, to any Discord account. |
| Operator revokes: `gfc discord unlink USERNAME [reason]` | Same as above. |
| The account loses its phone verification | The next pass ends the link and removes the role. |
| A moderator removes the role by hand | **The link stays, and the next pass gives the role back.** To take access away, use `gfc discord unlink`, or ban the member in Discord. |
| Same Discord user relinks before an old removal went through | The old removal is skipped, so the new link keeps its role. |

Moderators can't grant the role by hand. They have no Manage Roles permission, and a username
alone doesn't prove ownership. There is no manual verification path: members verify through the
app.

**What is logged:**
- `#mod-log` (optional), with mentions turned off: the outcome of each attempt (verified, invalid
  or expired code, not verified, already linked) and each unlink.
- The node log: role-change failures.

Codes, tokens and phone data are never logged.

## Setup

### 1. Discord application (developer portal)

1. Go to <https://discord.com/developers/applications> → **New Application**. Name it
   **GFC Verification**. Avoid "GFC Bot": the server's AutoMod name rule reserves it.
2. **General Information:** copy the **Application ID** and the **Public Key**.
3. **Bot:**
   - Turn **off** *Public Bot*, so only you can add it to servers.
   - Leave all three *Privileged Gateway Intents* off, since none are used.
   - Click **Reset Token** and copy the token. It's shown once. Treat it like a password: never
     paste it into chat, a repo or a ticket.
4. **Installation:** set Install Link to *None*. Then go to **OAuth2 → URL Generator**, select
   the scopes `bot` and `applications.commands`, and the bot permission **Manage Roles** only.
   That gives a URL ending in `permissions=268435456`. Open it and add the bot to
   **Galactic Federation Coin (GFC)**.

### 2. Discord server

1. **Role order.** Adding the bot creates its own role, *GFC Verification* (managed by Discord).
   Under **Server Settings → Roles**, drag it to sit **directly above Verified GFC** and
   **below Moderator**. A bot can only add roles below its own highest role. The placeholder
   role **GFC Bot** can be deleted, or kept with no permissions: the bot doesn't use it. Never
   give the bot *Administrator*.
2. **`#how-to-verify`.** Edit the channel → Permissions → `@everyone`:
   - **Use Application Commands: ✅ allow.**
   - Keep *Send Messages*, *Add Reactions* and the thread permissions denied.

   This is the one deliberate exception to the LOBBY category sync: members can run `/verify`
   but still can't post. Slash command replies are private, so nothing appears in the channel.
3. **`#mod-log`** (optional, for outcome messages). Edit the channel → Permissions → add the
   *GFC Verification* role: **View Channel** and **Send Messages** allowed. The bot needs no
   access to any other channel.
4. **`/verify` only in `#how-to-verify`.** Go to Server Settings → Integrations → *GFC
   Verification* → `/verify` → Channels: deny *All Channels*, allow `#how-to-verify`. Setting
   `GFC_DISCORD_VERIFY_CHANNEL_ID` enforces the same thing on the node.

### 3. Node settings

On the node, add these to `/etc/gfc/gfc.env` (root-owned, mode 600) **without echoing the
token**. `sudo nano /etc/gfc/gfc.env` is fine; don't put the token on a command line, where it
would land in shell history:

```
GFC_DISCORD_APP_ID=<application id>
GFC_DISCORD_PUBLIC_KEY=<public key, 64 hex characters>
GFC_DISCORD_BOT_TOKEN=<bot token>
GFC_DISCORD_GUILD_ID=1566799981438959616
GFC_DISCORD_ROLE_ID=0
```

Find the real role and channel ids. Don't guess them:

```
sudo gfc discord ids
```

This lists every role and channel with its id. Set `GFC_DISCORD_ROLE_ID` to the id of
**Verified GFC**, and optionally `GFC_DISCORD_VERIFY_CHANNEL_ID` (`#how-to-verify`) and
`GFC_DISCORD_LOG_CHANNEL_ID` (`#mod-log`). Then run:

```
sudo gfc restart
sudo gfc discord register     # creates /verify on the server
gfc check                     # "Discord verification on (server …, role …)"
```

### 4. Interactions endpoint

In the developer portal → **General Information → Interactions Endpoint URL**, enter
`https://node.galacticfederation.tech/discord/interactions` and save. Discord sends a signed
PING, which the node answers only if `GFC_DISCORD_PUBLIC_KEY` is set correctly, so the save
fails otherwise.

## Launch test (with a second, non-admin Discord account)

Admins bypass AutoMod and channel permissions, so test with an ordinary account:

- [ ] Unverified: sees only LOBBY, can't post or react anywhere, and can run `/verify` only in
      `#how-to-verify`.
- [ ] An invalid code, an expired code (wait 10 minutes) and a reused code each get a private
      refusal and no role.
- [ ] A fresh code from a phone-verified GFC account gives **Verified GFC** and nothing else.
      COMMUNITY appears, STAFF stays hidden.
- [ ] An account without a verified phone gets no code in the app.
- [ ] A second GFC account can't link the same Discord user, and the first account can't get
      a new code while linked.
- [ ] **Unlink Discord** in the app removes the role within seconds, and COMMUNITY disappears.
- [ ] `#mod-log` shows the outcomes with no codes in them.

## Channel text (to post)

### `#how-to-verify`

> **Getting full access**
>
> The community channels are for members with a phone-verified GFC account.
>
> 1. Open the GFC app (download links in #official-links) and log in.
> 2. Account menu → **Link Discord** → **Get a code**.
> 3. Here, type `/verify` followed by your code, e.g. `/verify GFC-7Q4K-2M9X`.
>
> The reply is private, and only you see it. Codes work once and expire after 10 minutes.
>
> 🔒 **Staff will never DM you first.** No one from GFC will ever ask for your seed phrase,
> recovery phrase, private key or password, or ask you to send tokens or "validate" a wallet.
> Only trust links posted in #official-links.

Until the bot is live, replace the steps with:

> Verification opens soon. Watch #announcements. Until then the community channels stay closed:
> there's no manual verification, and no one will DM you to "verify" you.

### `#official-links`

> - Website: https://www.galacticfederation.tech
> - App downloads (Windows and Android): https://node.galacticfederation.tech/app
> - White paper: https://www.galacticfederation.tech/gfcwhitepaper
> - Source code: https://github.com/subvertio/GFCCoin
> - GFC token on Base: `0xc32695f463947170EC142F7987DaC93aa7243336`
> - Uniswap pool (GFC/WETH): https://base.blockscout.com/address/0xD64D155f4AB27Ef21CE4917FDB0c3Dc91a0F6C5E
> - This server's only invite: https://discord.gg/dDwFhzykcn
>
> Anything else claiming to be GFC isn't us.

### `#rules`

> 1. Be respectful. No harassment, hate or threats.
> 2. No spam, no self-promotion outside #creators-showcase, and no links: links are off for now.
> 3. Never share your seed phrase, private key or password, with anyone, for any reason.
> 4. Staff never DM first. Report anyone who does, or anyone posing as staff.
> 5. No price talk dressed up as advice. GFC credits are not money and have no guaranteed value.
> 6. Moderators' decisions are final. Questions go to #help.
