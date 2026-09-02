# RCQ — backend reference server

FastAPI + Postgres + Redis backend that powers the [RCQ messenger][ios].
Open-sourced so users behind censorship or hostile network conditions
can run their own instance instead of trusting `api.rcq.app`.

[ios]: https://github.com/rcq-messenger/rcq-ios

## Status

**Beta, but live in production.** This is the same code that runs
`api.rcq.app`, which serves real users today across a federated network
of islands, with iOS, Android and web clients. It's released open
source (AGPL-3.0) as the reference implementation and so anyone can run
their own island. It's still beta — the protocol and features evolve —
and the *self-hosted* path specifically is the newer surface (fewer
operators have run it than the flagship). The included
`docker-compose.yml` covers TLS (Caddy + Let's Encrypt, or the island's own
pinned certificate when no authority will issue to you:
[`docs/tls-without-a-ca.md`](docs/tls-without-a-ca.md)) and APNs setup
is documented in [`docs/apns.md`](docs/apns.md). Open items: a wider
testing pass on the self-hosted path, and the non-Docker relay
self-host story — track those in [Issues](../../issues).

If you have a small VPS and ten minutes, the quick-start below stands a
working server up. A domain you can point at it is the normal case; an
island reached by IP alone is a supported one
([`docs/tls-without-a-ca.md`](docs/tls-without-a-ca.md)). If you'd
rather wait for the friction-light path (one-command install,
hosted-key tooling), keep an eye on releases.

## What this server does

* **Sealed-sender end-to-end encrypted messaging** (libsignal v2 envelopes
  for stage-3-capable clients, ECIES + Ed25519 fallback for legacy).
  The server stores ciphertext, public keys, and group metadata. It
  never holds plaintext message bodies, never sees a sender UIN on a
  1:1 envelope, and never holds media decryption keys.
* **UIN identity** — 7-9 digit anonymous handles, no phone number, no
  email. Allocator is a tiny secret-randbelow loop that skips RESERVED
  numbers: six digits or fewer, and recognisable shapes (repdigits, ABAB,
  ladders, four trailing zeros). Those are finite stock and leave only
  through an operator (`POST /admin/uin/grant`, or an invite minted with the
  number on it), never out of the allocator or a free claim — see
  `app/services/uin.is_reserved_uin`.
* **WebSocket fan-out** — presence, typing, group changes, call and
  audio-room signalling. Cross-worker via Redis pub/sub.
* **APNs push** — both alert pushes (NSE-decrypted on the device) and
  VoIP pushes for inbound calls.
* **Encrypted media blobs** — opaque bytes by mass; per-blob AES key
  exchanged inside the encrypted envelope.
* **`.rcq` sites** — your island can host static pages people reach by name
  (`blog.<your-island>.rcq`) from inside the app: `app/routers/sites.py`,
  quotas of one site per account / 20 MB / 64 files, and the file type decided
  by our own table rather than by whatever the uploader claimed. Every bundle
  is signed by the owner's key with a hash per file, so a reader verifies it
  and pins the key: your island can refuse to serve a site, it cannot alter
  one. Reads are UNAUTHENTICATED on purpose - a token would build exactly the
  "who read what" journal an island should not hold. Set `RCQ_SITES_DIR` to a
  persistent volume, and see the operator's list at `/admin/sites` (freeze
  holds a site while a complaint is looked at; unlist only stops advertising
  it in the catalogue). `python -m app.tools.publish_site` publishes the
  island's own pages from the command line.
* **Cross-island federation** — your island joins the wider RCQ network by
  address (`uin@host`): home-island records, multihoming (backup islands),
  gossip key/record sync, and cross-island 1:1, media, groups and calls — all
  bridged client-side, no server-to-server trust.
* **Sender-keys group broadcast** — encrypt-once group messages
  (`/messages/group-broadcast` + a per-account capability flag) so a large
  group doesn't cost an O(N) per-member fan-out.
* **Relay broker (circumvention)** — built in (`app/routers/broker.py`): a
  signed `POST /broker/register` lets a community relay self-register, an
  IP-bucketed `GET /broker/bridges` distributes them with anti-enumeration, and
  a canary liveness-gates what's served. Pairs with the standalone relay
  installer.
* **Account migration + UIN shop** — atomic re-key of every owned-by-uin
  row from old UIN to new. UIN shop uses a mock IAP receipt today; the
  real StoreKit hook lives at one function on the iOS side.
* **Reports / moderation** — bug-bounty submissions, abuse reports
  with encrypted-media evidence, admin SPA at `admin.<your-domain>`. A report
  is a CONVERSATION since 2026-08-16: the reporter writes back on their own
  report (`POST /reports/mine/{id}/messages`, 20/hour) and both sides see the
  whole thread. Deliberately server-side plaintext and never dressed up as a
  chat message — this island holds no keys, so a channel where the server puts
  text in front of a person has to look like what it is.
* **Built-in admin console (self-host)** — open
  `https://<your-server>/admin/console` and log in with the
  `ADMIN_USERNAME` / `ADMIN_PASSWORD` you set in `.env`. One self-contained
  page (no extra hosting) to see stats, search + ban users, work the reports
  queue, and mint invites — **including handing out specific (vanity) UINs**:
  create an invite with a reserved UIN (`{"uin": 777777, "max_uses": 1}`) and
  whoever redeems that code registers as exactly that number. Reserved UINs
  also work on an open-registration server (pass the code at sign-up); a
  plain invite without a UIN still gets a random number.

## One-line install (recommended)

On a fresh Ubuntu / Debian VPS, as root or via sudo:

```bash
curl -fsSL https://raw.githubusercontent.com/rcq-messenger/rcq-server-ref/main/install.sh | bash
```

Asks whether you have a domain. With one: sanity-checks DNS, installs
Docker if missing, generates a random `JWT_SECRET` + `POSTGRES_PASSWORD`,
writes `.env`, brings the stack up, waits for the Let's Encrypt cert,
smoke-tests `/health`, prints the next-step instructions. Without one:
the same, except the island issues its own certificate and the script
ends with the fingerprint and the `address#fingerprint` line your users
type ([`docs/tls-without-a-ca.md`](docs/tls-without-a-ca.md)).

If you'd rather inspect first (recommended for any non-throwaway
box):

```bash
curl -fsSL https://raw.githubusercontent.com/rcq-messenger/rcq-server-ref/main/install.sh -o install.sh
less install.sh
bash install.sh
```

Prereqs the script assumes you've already done:
* You have a VPS or other always-on host.
* You own a domain (or subdomain) and have pointed an A-record at
  the host. Optional: without one the island runs in fingerprint
  mode, reached by IP, and the apps pin its certificate
  ([`docs/tls-without-a-ca.md`](docs/tls-without-a-ca.md)); the web
  client cannot join an island without a certificate authority.
* Ports 80 + 443 are reachable on the host (Caddy needs both for
  the ACME HTTP-01 challenge; fingerprint mode needs only 443).

## Quick start (manual docker-compose)

Prereqs: a VPS with Docker installed, a domain (or subdomain) you can
point at it, and an open port 80 + 443 (Caddy needs both for ACME).
No domain, or no certificate authority that will issue to you:
[`docs/tls-without-a-ca.md`](docs/tls-without-a-ca.md).

```bash
# 1. DNS: point an A-record at this host. Wait for propagation
#    (`dig +short rcq.example.com` should return the host's IP).

# 2. Clone + configure
git clone https://github.com/rcq-messenger/rcq-server-ref.git
cd rcq-server-ref
cp .env.example .env
$EDITOR .env
# Fill at minimum:
#   ENV=prod
#   RCQ_DOMAIN=rcq.example.com
#   JWT_SECRET=<output of `openssl rand -hex 32`>
#   POSTGRES_PASSWORD=<anything other than the "rcq" default>
# (Optional) Push notifications: see docs/apns.md, then drop your
# apns.p8 next to docker-compose.yml and fill the APNS_* block.

# 3. Bring the stack up
docker compose up -d --build
# Caddy fetches a Let's Encrypt cert on first request to the new
# hostname — takes a few seconds. Confirm with:
curl https://rcq.example.com/health   # → {"ok":true,"app":"RCQ","version":"2026.08.07"}
```

Once `/health` answers over HTTPS, point a client at the new backend
via Settings → Privacy & Network → Custom server. The picker takes any
`https://` URL that exposes the RCQ API and **adds a new account on
that instance** (its own UIN/identity) alongside your current one,
then switches to it. This is NOT destructive: your existing account
(UIN, contacts, groups, history) stays on the device, and you can
switch between accounts anytime from the account switcher. (Older
builds replaced the active backend in place and wiped local state —
that is no longer the case; RCQ is multi-account.)

## Quick start (no Docker)

Prereqs: Python 3.12, Postgres 16, Redis 7.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# Edit .env — at minimum set JWT_SECRET and DATABASE_URL.
./run.sh
```

`run.sh` starts uvicorn on `:8000` with `--reload`. Strip `--reload`
for production and run via systemd / a process supervisor.

For a full **production** deploy on Debian without Docker — Postgres + Redis
setup, a systemd service, and HTTPS via Caddy, step by step — see
[docs/bare-metal.md](docs/bare-metal.md).

## APNs (push notifications)

iOS push requires an Apple Developer account, an APNs `.p8` key, and
a registered Bundle ID. The key lives entirely on your server — the
iOS client never sees it. Full step-by-step in
[`docs/apns.md`](docs/apns.md): generating the `.p8`, finding your
Key/Team/Bundle IDs, choosing `production` vs `sandbox`, and the
docker-compose mount.

Leave the key fields blank in `.env` to disable push entirely. The
server no-ops the sender path and your users still get messages on
next WebSocket connect, just without iOS alert pushes.

## Hiding from passive scanners (opt-in)

By default, your `RCQ_DOMAIN` answers `/health`, `/auth/register` and
the rest of the RCQ surface to anyone who asks. That's fine for public
instances and most self-host setups. If you'd rather not show up in
Shodan / Censys datasets as "an RCQ backend", an opt-in masquerade
config gates the entire surface behind a pre-shared header. Requests
carrying `X-RCQ-Auth: <your-token>` reach FastAPI; everything else sees
a generic decoy landing page.

To enable:

1. Add a long random token to `.env`:

   ```bash
   echo "RCQ_AUTH_TOKEN=$(openssl rand -hex 32)" >> .env
   ```

2. Drop your decoy `index.html` into `./deploy/decoy/`. The shipped
   stub is a generic "Coming soon" page — replace it with a personal
   blog, generic SaaS landing, or anything that doesn't look like RCQ.

3. Point the caddy service at the masquerade config and mount the
   decoy directory (in `docker-compose.yml`; the Caddyfile line can also
   be `RCQ_CADDYFILE=./deploy/Caddyfile.masquerade.compose` in `.env`,
   leaving `docker-compose.yml` untouched):

   ```yaml
   caddy:
     volumes:
       - ./deploy/Caddyfile.masquerade.compose:/etc/caddy/Caddyfile:ro
       - ./deploy/decoy:/srv/decoy:ro
   ```

4. `docker compose up -d`

5. Distribute the token to your iOS users out of band (Signal /
   Telegram / face-to-face). When they add your server in the iOS
   "Add account" sheet, the optional "Auth token" field below the URL
   takes the token; subsequent requests are stamped with the header
   transparently.

Treat the token like a password. Rotating is `docker compose restart
caddy` after editing `.env`, plus re-issuing to your users.

For a **fully private (closed) island with per-person, one-time, revocable
access tokens** (mint/revoke them in the admin console instead of one shared
secret), use `deploy/Caddyfile.masquerade-tokens.compose` instead — see
**[docs/private-island.md](docs/private-island.md)**. Closed islands are
native-only (iOS/Android/desktop).

## TLS without a certificate authority

Let's Encrypt is a policy, not a protocol: if it stops issuing to your
address, or you have no domain at all, the island still runs. In order of
cost: validate over DNS instead of port 80 (`docker-compose.dns.yml`), use
another ACME authority (a ready-to-uncomment block in
`deploy/Caddyfile.compose`), or drop the authority entirely and let the
apps pin the island's own certificate by its SHA-256 fingerprint, the way
SSH pins a host key. `install.sh` sets the last one up when you answer
"no" to the domain question, and ends with the line to hand your users:
`203.0.113.5#ab12…`. Android, iOS, the desktop app and the CLI open such an
island; a browser cannot. The three answers, what users see, rotation and
the move to an authority later:
[`docs/tls-without-a-ca.md`](docs/tls-without-a-ca.md). The trust model is
one paragraph in [SECURITY.md](SECURITY.md#islands-trusted-by-fingerprint).

## What's intentionally NOT in this repo

* **APNs `.p8` key** — Apple ties this to your own developer account,
  not to RCQ's. Generate yours, never commit it. `.gitignore` is
  preemptive.
* **Production secrets** — there's no `.env` here, only `.env.example`.
* **The relay rotation infrastructure** — `relay.rcq.app/v1/config` is
  a Cloudflare Worker that signs a JSON catalog of VLESS+Reality and
  Hysteria2 relays the iOS client picks from when direct TLS fails.
  That's a separate, RCQ-specific operational layer. A self-hosted
  instance doesn't need it: clients reach you over direct TLS to
  whatever domain you point at this server.
* **Apple receipt validation** — `/uin/purchase` accepts any non-empty
  `receipt` string today (mock). Wire `App Store Server Notifications
  V2` + receipt validation there before taking real money. Do not ship
  a price to users until you have: a screen that charges nothing while
  showing a figure is worse than a free feature.

## Keeping it up to date

`deploy/rcq-update.sh` pulls, rebuilds and health-checks in one pass, and
refuses to run when a tracked file has local edits. It dumps the database
first and keeps the last five dumps. Install the timer and it runs daily with
a random delay of up to four hours, so every island does not restart at the
same minute:

```bash
sudo bash deploy/rcq-update.sh --install-timer
```

Details, the manual path, and how to roll back: [`docs/updating.md`](docs/updating.md).

## Protocol

The wire protocol is specified in a separate repo:
[`rcq-messenger/rcq-spec`](https://github.com/rcq-messenger/rcq-spec).
That's the document to read if you're implementing a client.

## Public directory of instances

Once your instance is up and you want users to find it without
manually trading hostnames, open a PR against
[`rcq-messenger/rcq-servers`](https://github.com/rcq-messenger/rcq-servers).
That's a small JSON catalogue clients fetch on first launch and
present as a picker. Each RCQ server is an independent island; the
directory is for discoverability. (Cross-island messaging —
federation — is implemented: a client bridges people across islands by
`uin@host` using published home-island records + multihoming, no
server-to-server trust. The catalogue just feeds discovery.)

## Contributing

Issues and PRs welcome. Before opening a PR with non-trivial changes,
file an issue or short RFC first — the maintainer is one person and
batches reviews.

## Licence

[AGPL-3.0](LICENSE). The matching iOS client is also AGPL-3.0
([`rcq-messenger/rcq-ios`](https://github.com/rcq-messenger/rcq-ios)).
If you run a modified version of this server as a public service, you
must offer the modified source to your users — that's the "A" in AGPL
working as intended.
