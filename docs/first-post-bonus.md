# First post bonus

An account's first original post earns a one-time bonus, 1,000 GFC by default,
from the treasury. Code: `first_post.py`, `blockchain.process_first_post_mint`.

## Who gets it

- The first seed an account posts through `POST /seeds/upload` that isn't a
  repost. A seed the repost check (`reposts.py`) matches to someone else's
  original earns nothing and doesn't use up the bonus; the account's next
  original post still earns it.
- Only phone-verified accounts with a wallet on this node are paid, the same
  bar as the 100 GFC new-user grant. Phone verification is one account per real
  (non-VoIP) number, which is what stops someone farming 1,000 GFC per throwaway
  account.
- If the account isn't verified or has no wallet yet, the bonus is recorded as
  **pending** and paid when it creates its first wallet (`POST /wallets/create`)
  or verifies its phone (`POST /verify/phone/check`), whichever completes the
  requirements. A pending bonus left by a short treasury is retried on the
  account's next upload.

## Paid once

`first_post_bonus` has one row per account (`username` is the primary key) and
rows are never deleted:

- The bonus is claimed with `INSERT OR IGNORE`, so concurrent or retried uploads,
  and deleting the first seed and posting again, can't earn a second one.
- The payout moves the row from `pending` to `paying` with a conditional
  `UPDATE`; only the caller that changes the row mints. It ends `paid` with the
  transaction id. If the mint fails partway the row stays `paying` (never paid
  twice; check it by hand).

## Ledger

- `FIRST_POST` is a treasury mint like `REFERRAL` and `REPOST`, with the memo
  "First post bonus", so it shows in wallet history and counts in circulation.
- The amount is node config, so peers don't check an exact value. They reject a
  `FIRST_POST` above `FIRST_POST_BONUS_MAX_CENTS` (1,000 GFC) or a second one to
  the same wallet. Raising the bonus above 1,000 GFC needs a code change on
  every node.
- As with every mint, it's only network-wide when the paying node holds the
  treasury key. Nodes running code from before this change reject `FIRST_POST`
  rows as an unknown type until they upgrade.

## Config

| Variable | Default | |
|---|---|---|
| `GFC_FIRST_POST_BONUS_GFC` | `1000` | Amount in GFC; capped at 1,000 |
| `GFC_FIRST_POST_BONUS_ENABLED` | `1` | `0` turns it off: nothing is earned or paid, and pending bonuses wait |

An account that posts while the bonus is off hasn't used it up: if it's turned
back on, that account's next original post earns it.

## API

`POST /seeds/upload` adds, only on the upload that earned or paid the bonus:

```json
"first_post_bonus": 1000.0,
"first_post_bonus_pending": true
```

`first_post_bonus_pending` is there only when the bonus is waiting for a wallet
or a verified phone. Both fields are absent on every other upload. Clients (the
Unreal app plays its coin animation) should key off `first_post_bonus` being
present. `POST /verify/phone/check` also returns `first_post_bonus` when it pays
a pending one; `POST /wallets/create` includes it in `gfc_balance`.
