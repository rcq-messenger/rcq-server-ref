# RCQ — backend reference server

FastAPI + Postgres + Redis backend that powers the [RCQ messenger][ios].
Open-sourced so users behind censorship or hostile network conditions
can run their own instance instead of trusting `api.rcq.app`.

[ios]: https://github.com/rcq-messenger/rcq-ios

## Status

**Early. Reference, not yet production-tested by anyone but the
maintainer.** The code is the same code that runs on `api.rcq.app`
today. The included `docker-compose.yml` covers TLS (Caddy + Let's
Encrypt) and APNs setup is documented in [`docs/apns.md`](docs/apns.md).
Open items: Android client pointing at custom servers, automated
migrations, and a wider testing pass on the self-hosted path. Track
those in [Issues](../../issues).

If you have a small VPS, a domain you can point at it, and ten
minutes, the quick-start below stands a working server up. If you'd
rather wait for the friction-light path (one-command install,
hosted-key tooling), keep an eye on releases.

## What this server does

* **Sealed-sender end-to-end encrypted messaging** (libsignal v2 envelopes
  for stage-3-capable clients, ECIES + Ed25519 fallback for legacy).
  The server stores ciphertext, public keys, and group metadata. It
  never holds plaintext message bodies, never sees a sender UIN on a
  1:1 envelope, and never holds media decryption keys.
* **UIN identity** — 6-9 digit anonymous handles, no phone number, no
  email. Allocator is a tiny secret-randbelow loop.
* **WebSocket fan-out** — presence, typing, group changes, call
  signalling, hood-bucket chat, story announcements. Cross-worker via
  Redis pub/sub.
* **APNs push** — both alert pushes (NSE-decrypted on the device) and
  VoIP pushes for inbound calls.
* **Encrypted media blobs** — opaque bytes by mass; per-blob AES key
  exchanged inside the encrypted envelope.
* **Account migration + UIN shop** — atomic re-key of every owned-by-uin
  row from old UIN to new. UIN shop uses a mock IAP receipt today; the
  real StoreKit hook lives at one function on the iOS side.
* **Hood** — geohash-bucket chat + paid district-banner board. Optional
  on a self-hosted instance; if you don't want it, every endpoint
  cleanly no-ops when nobody calls it.
* **Reports / moderation** — bug-bounty submissions, abuse reports
  with encrypted-media evidence, admin SPA at `admin.<your-domain>`.

## One-line install (recommended)

On a fresh Ubuntu / Debian VPS, as root or via sudo:

```bash
curl -fsSL https://raw.githubusercontent.com/rcq-messenger/rcq-server-ref/main/install.sh | bash
```

Asks you for the public domain, sanity-checks DNS, installs Docker
if missing, generates a random `JWT_SECRET` + `POSTGRES_PASSWORD`,
writes `.env`, brings the stack up, waits for the Let's Encrypt
cert, smoke-tests `/health`, prints the next-step instructions.

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
  the host.
* Ports 80 + 443 are reachable on the host (Caddy needs both for
  the ACME HTTP-01 challenge).

## Quick start (manual docker-compose)

Prereqs: a VPS with Docker installed, a domain (or subdomain) you can
point at it, and an open port 80 + 443 (Caddy needs both for ACME).

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
curl https://rcq.example.com/health        # → {"ok":true,"app":"RCQ Backend"}
```

Once `/health` answers over HTTPS, point an iOS client at the new
backend via Settings → Privacy & Network → Custom server. The picker
takes any `https://` URL that exposes the RCQ API, writes it to
`UserDefaults`, and the next launch boots against your instance
instead of `api.rcq.app`. Note that switching servers is destructive
locally (the client treats it as a fresh install) — your account on
the old server is unaffected, you simply allocate a new UIN on the new
one.

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
   decoy directory (in `docker-compose.yml`):

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
* **Apple receipt validation** — `/uin/purchase` and
  `/hood/banners` POSTs accept any non-empty `receipt` string today
  (mock). Wire `App Store Server Notifications V2` + receipt-validation
  at those two endpoints for real money.

## Protocol

The wire protocol is specified in a separate repo:
[`rcq-messenger/rcq-spec`](https://github.com/rcq-messenger/rcq-spec).
That's the document to read if you're implementing a client.

## Public directory of instances

Once your instance is up and you want users to find it without
manually trading hostnames, open a PR against
[`rcq-messenger/rcq-servers`](https://github.com/rcq-messenger/rcq-servers).
That's a small JSON catalogue clients fetch on first launch and
present as a picker. Each RCQ server is an isolated island — the
directory is for discoverability, not federation.

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
