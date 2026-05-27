# RCQ — backend reference server

FastAPI + Postgres + Redis backend that powers the [RCQ messenger][ios].
Open-sourced so users behind censorship or hostile network conditions
can run their own instance instead of trusting `api.rcq.app`.

[ios]: https://github.com/rcq-messenger/rcq-ios

## Status

**Early. Reference, not yet production-tested by anyone but the
maintainer.** The code is the same code that runs on `api.rcq.app`
today — what is missing is a polished self-hosting story: per-instance
TLS, an Android client that points at custom servers (iOS support
incoming), automated migrations, and an installation walkthrough that
handles the APNs setup hop. Track those items in [Issues](../../issues).

If you're comfortable wiring up FastAPI + Postgres + Redis behind a
reverse proxy yourself, the `docker-compose.yml` in this repo will get
you a working server in about ten minutes. If you're not, wait a beat —
the friction-light path is on the roadmap.

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

## Quick start (docker-compose)

```bash
git clone https://github.com/rcq-messenger/rcq-server-ref.git
cd rcq-server-ref
cp .env.example .env
# At minimum set JWT_SECRET=$(openssl rand -hex 32).
# Set POSTGRES_PASSWORD too if you'd rather not use the "rcq" default.
docker compose up -d --build
curl http://localhost:8000/health        # → {"ok":true,"app":"RCQ Backend"}
```

Once `:8000` answers, put a TLS-terminating reverse proxy in front
(the reference Caddyfile from the rcq.app production deploy is in
[deploy/Caddyfile](deploy/Caddyfile)), point your DNS at the host,
and you have a server.

For iOS clients to connect to your instance instead of `api.rcq.app`,
**a "custom server" picker in Settings is coming in the next iOS
release** — it's already on the roadmap. Until then, self-hosting is
most useful for people building their own client or testing
modifications.

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
a registered Bundle ID. The keys live entirely on your server — the
iOS client never sees them. Configure via the `APNS_*` block in
`.env.example`. Leave the key fields blank to disable push entirely;
the server no-ops the sender path and your users still get messages
on next WebSocket connect, just without iOS alert pushes.

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
