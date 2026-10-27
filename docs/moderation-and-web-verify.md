# Reports, blocks, and phone verification in the browser

## Reports and blocks (`moderation.py`, `app_moderation.py`)

| Call | What it does |
|---|---|
| `POST /seeds/{id}/report` (form: `reason`, `detail`) | One report per account per post; you can't report your own. Reasons: spam, nudity, violence, harassment, hate, scam, copyright, other. |
| `POST /users/{name}/block` | That account's posts disappear from your feed, search and seed lists. |
| `DELETE /users/{name}/block` | Undo. |
| `GET /users/me/blocks` | Who you've blocked. |

A post reported by `GFC_REPORT_HIDE_THRESHOLD` different accounts (default 3) is hidden on this node:
gone from the feed, search and `/seeds`, and `/seeds/{id}` and its share page answer 410. Its creator
still sees it in their own feed.

The operator reviews on the server:

```
ssh gfc-node "gfc reports"
ssh gfc-node "gfc moderate <seed_id> remove"    # keep it hidden for good
ssh gfc-node "gfc moderate <seed_id> restore"   # show it again; its old reports stop counting
ssh gfc-node "gfc moderate <seed_id> hide"      # hide now, without waiting for reports
```

Moderation is per node. Peers make their own calls; the file isn't deleted, so it can be reviewed.

## Phone verification in a browser (`app_webverify.py`)

Turnstile, Cloudflare's bot check, only runs in a web page, so the phone app verifies in the browser:

1. The app calls `POST /verify/link` with its token and opens the returned URL
   (`/verify?c=<code>`; one account, 15 minutes, single use).
2. The page asks for the number and shows the Turnstile widget; `POST /verify/web/start` checks
   Turnstile and texts a code (same rate limits as `/verify/phone/start`).
3. `POST /verify/web/check` checks the code. On success the account is verified and gets the
   100 GFC welcome grant and any pending first post bonus (if it has a wallet), exactly as
   `/verify/phone/check` does.
4. "Back to GFC" opens `gfc://verified`; the app refreshes and plays the earnings burst.

The pages run no script of their own (only Turnstile's), send no Referer and aren't cached, so the
code in the URL stays on the node. `GET /verify/status` tells the app whether to offer verification.

Setup: add `GFC_TURNSTILE_SITEKEY` (the public key of the widget whose secret is
`GFC_TURNSTILE_SECRET`) with `gfc config`, and add the node's domain to the widget's hostnames in
the Cloudflare dashboard. Without the site key, the page says verification isn't set up yet.
