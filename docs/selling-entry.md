# Selling entry (residency) to your island

Entry is the third thing an island can sell, after numbers and their resale:
the right to open an account here, paid once. On an open island it buys
residency (the resident mark, the invites a resident may hand out); with the
registration policy set to **paid** the code is what opens the door.

The island never touches money. Your **till** watches your wallets, and when a
transfer lands it signs an **access code** the buyer pastes into the app. The
island checks the signature, spends the code once, and marks the account a
resident.

The till we run is a Cloudflare Worker and its source is
[rcq-messenger/rcq-till](https://github.com/rcq-messenger/rcq-till): deploy
your own copy, on your own Cloudflare account, watching your own wallets. You
are not required to use it. The island only ever sees one thing from a till, a
signed document, so a till you write yourself is a first-class till; the wire
contract is `POST /entry/payout-target` and the `entry` voucher, both specified
in [`app/services/uin_voucher.py`](../app/services/uin_voucher.py) and pinned
by `test_entry_voucher_local.py`.

## What to set, and where

Everything is in the admin console (`https://<host>/admin/console`), with the
`.env` values as defaults:

| Console | Setting | What it does |
|---|---|---|
| Limits → Price of entry | `entry_price_cents` | What you charge, in US cents. `0` = not sold. Changes live: the till asks the island for the price when it writes an invoice. |
| Numbers → Your wallets | `uin_payout_addresses` | Where buyers pay YOU, one address per chain. The same wallets serve numbers and entry. |
| Numbers → Your checkout | `uin_till_url` | Your till's address, https. Published on `/server/info` as `till_url`; without it no client draws the in-app checkout. |
| Numbers → Your till's public key | `uin_voucher_pubkey` | The public half of the key your till signs with. Empty = the island sells nothing. |
| Branding → Your terms and refund page | `terms_url` | Your own terms. Linked beside the payment in the apps; leave it empty and the apps say refunds are your decision. |
| Limits → Where entry is bought | `entry_url` | A web page of yours, for clients that cannot draw the checkout (iOS never does). Optional. |
| Limits → This island's own address | `island_host` | The bare hostname people type to reach you, `api.rcq.app` shaped. It is what a voucher's signature is checked against, so it must equal your till's `ENTRY_HOSTS` exactly. **Empty sells nothing**, silently: the island answers your till `sales_disabled` while `/server/info` keeps advertising the price. |

Then deploy your till with `UIN_ISLAND_API` and `ENTRY_HOSTS` both set to your
host, and `UIN_VOUCHER_PRIVKEY` as its secret. Its README walks through the
whole thing: the D1 database and its migrations, generating the keypair (the
two halves are in different encodings, and it gives both), and the one-line
deploy.

## What the buyer sees

* Web, desktop and the sideloaded Android app: **Buy entry** (or **Buy
  residency** on an open island) inside the create-account form, and
  **Residency** in Settings for an account that already exists. The sheet
  quotes your price, shows your wallet for the chain they pick, names YOU as
  the seller (island name and host) and links your `terms_url`.
* iOS and the Play build of Android: the price as a fact, no checkout, no
  link. Store rules, not ours. Their buyers use your web page.

## Who is the seller

You are. The RCQ team's terms at rcq.app cover the flagship island only; a
client never links them for a sale on another island. Write your own refund
policy (the flagship's is one paragraph: refundable while the code is unused,
nothing left to return once it has been redeemed, exchange-rate movement not
compensated) and put its address in `terms_url`.

## Checking it works

1. `curl https://<your-till>/v1/entry/quote?host=<host>` must answer your
   `price_cents` and the chains you set wallets for. `price_cents: 0` means
   the till could not get an answer from the island: wrong `UIN_ISLAND_API`,
   a key that does not match, no price, no wallets, or `island_host` empty or
   spelled differently from your till's `ENTRY_HOSTS`.
2. `curl https://<host>/server/info` must show `till_url` and `terms_url`
   under `capabilities`.
3. In the web app, pick your island, open the create form, tap Buy: the
   address on the invoice must be the wallet you typed in the console.
