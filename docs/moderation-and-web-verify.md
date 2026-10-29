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

Verification uses Firebase phone sign-in, whose web SDK and reCAPTCHA only run in a web page, so the
apps verify in the browser. The node never sends an SMS itself:

1. The app calls `POST /verify/link` with its token and opens the returned URL
   (`/verify?c=<code>`; one account, 15 minutes, single use).
2. The page asks for the number. `POST /verify/web/fb/start` (link code + number) checks one account
   per phone and the rate limits (5 starts per user and per number a day), then returns the number in
   E.164.
3. The page's script has Firebase text the code (`signInWithPhoneNumber`; Google's invisible reCAPTCHA
   is the bot check) and checks the code the person types.
4. Firebase hands the page an ID token, which it posts to `POST /verify/web/fb/check`. The node checks
   the token against Google's published keys (RS256; this project's audience and issuer; phone sign-in
   in the last 10 minutes), takes the number from it, and requires it to be the number started in
   step 2. Then the account is verified and gets the 100 GFC welcome grant and any pending first post
   bonus (if it has a wallet).
5. "Back to GFC" opens `gfc://verified`; the app refreshes and plays the earnings burst.
   `GET /verify/status` tells the app whether to offer verification and what verifying paid.

Firebase keeps nothing in the browser (in-memory persistence, signed out at the end). The page sends
no Referer and isn't cached, so the code in the URL stays on the node, and its CSP allows only Google's
Firebase, reCAPTCHA and API hosts. Firebase does create a sign-in user per number in the project; the
node never uses it.

### Setup

In the Firebase console (project `gfc-coin`):
- Authentication > Sign-in method: Phone enabled. Test numbers with fixed codes can be added there.
- Authentication > Settings > Authorized domains: the node's domain.
- Authentication > Settings > SMS region policy: Allow, with the countries to text (US and Canada).
- Without a billing account (Blaze plan), Firebase sends at most 10 real SMS a day.

Then set the web app's public config on the node with `gfc config`, as one line of JSON in single
quotes (systemd and bash strip double quotes otherwise):

```
GFC_FIREBASE_CONFIG='{"apiKey":"...","authDomain":"gfc-coin.firebaseapp.com","projectId":"gfc-coin","appId":"..."}'
```

Without it, the page says verification isn't set up yet, and accounts can't verify (so no grants or
play rewards). For a local node, set the same config (Firebase authorizes `localhost` by default);
Firebase's test numbers then verify without sending a text.

The API key in it is public (it identifies the project, it isn't a secret). To limit it, restrict it
to the node's domain in Google Cloud console > APIs & Services > Credentials.
