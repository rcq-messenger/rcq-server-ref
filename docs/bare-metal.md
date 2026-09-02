# Self-hosting RCQ on Debian without Docker

A complete, step-by-step production deploy on a fresh Debian 12 server, with no
Docker. The stack is plain: PostgreSQL + Redis + the FastAPI app under uvicorn
(managed by systemd) + Caddy as the TLS reverse proxy.

If you just want to try it locally, the README's "Quick start (no Docker)" is
enough. This guide is for a real, internet-facing island with HTTPS.

Prerequisites:
- A Debian 12 server with a public IP and root (or sudo).
- A domain or subdomain pointed at that IP with an `A` record
  (e.g. `island.example.com`); Caddy issues a free Let's Encrypt certificate
  for it automatically. Without one, or when no certificate authority will
  issue to you, the island serves its own certificate and the apps pin it:
  step 7a.

Throughout, replace `island.example.com` with your hostname and choose a strong
database password where noted.

## 1. System packages

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip postgresql redis-server git curl debian-keyring debian-archive-keyring apt-transport-https

# Caddy is not in Debian's default repos — add the official one:
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list
sudo apt update
sudo apt install -y caddy
```

The app needs Python 3.12. Debian 12 ships 3.11; if `python3 --version` is below
3.12, install 3.12 (e.g. from `deadsnakes` or `pyenv`) and use that interpreter
for the venv in step 4.

## 2. PostgreSQL

```bash
sudo -u postgres psql <<'SQL'
CREATE USER rcq WITH PASSWORD 'CHANGE_ME_STRONG_PASSWORD';
CREATE DATABASE rcq OWNER rcq;
SQL
```

The app creates and migrates its own tables on first boot — no manual schema
step. Postgres listening on localhost (the Debian default) is correct; the app
connects over `127.0.0.1:5432`.

## 3. Redis

Redis powers the WebSocket pub/sub fan-out and rate-limit buckets, so it is
required (not optional). Enable append-only persistence and start it:

```bash
sudo sed -i 's/^appendonly no/appendonly yes/' /etc/redis/redis.conf
sudo systemctl enable --now redis-server
```

## 4. The app

```bash
sudo git clone https://github.com/rcq-messenger/rcq-server-ref.git /opt/rcq
cd /opt/rcq
python3 -m venv .venv
./.venv/bin/pip install --upgrade pip
./.venv/bin/pip install -r requirements.txt
```

## 5. Configuration (`.env`)

```bash
cp .env.example .env
```

Edit `/opt/rcq/.env`. At minimum:

```ini
ENV=prod
JWT_SECRET=<paste `openssl rand -hex 32`>
DATABASE_URL=postgresql+asyncpg://rcq:CHANGE_ME_STRONG_PASSWORD@127.0.0.1:5432/rcq
REDIS_URL=redis://127.0.0.1:6379/0
RCQ_DOMAIN=island.example.com
```

Push notifications (APNs) are optional — leave the APNs fields blank to disable
push entirely. To enable iOS push, see [apns.md](apns.md).

> Generate the secret with `openssl rand -hex 32`. With `ENV=prod` the app
> refuses to boot on the placeholder JWT secret, by design.

## 6. systemd service

Create `/etc/systemd/system/rcq.service`:

```ini
[Unit]
Description=RCQ backend
After=network.target postgresql.service redis-server.service
Wants=postgresql.service redis-server.service

[Service]
WorkingDirectory=/opt/rcq
EnvironmentFile=/opt/rcq/.env
# Bind to localhost only — Caddy terminates TLS and proxies to it.
# --workers >1 is fine: shared state rides Redis. No --reload in production.
ExecStart=/opt/rcq/.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000 --workers 2
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now rcq
sudo systemctl status rcq          # should be active (running)
curl -fsS http://127.0.0.1:8000/health && echo OK
```

## 7. Caddy (HTTPS reverse proxy)

Replace `/etc/caddy/Caddyfile` with:

```caddyfile
island.example.com {
	reverse_proxy 127.0.0.1:8000
}
```

```bash
sudo systemctl reload caddy
```

On first request Caddy obtains a Let's Encrypt certificate for the domain
(ports 80 and 443 must be reachable from the internet). Verify end to end:

```bash
curl -fsS https://island.example.com/health && echo "island is live"
```

### 7a. Without a certificate authority (fingerprint mode)

If no authority will issue to you, or the island has no domain, Caddy serves a
certificate the island made itself and the RCQ apps (Android, iOS, desktop,
CLI; not a browser) pin its SHA-256 fingerprint. Issue it once, for the address
users will type (a bare IP is fine; `DNS:island.example.com` in the SAN and as
the CN for a name):

```bash
sudo openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out /etc/caddy/island.key
sudo openssl req -new -x509 -key /etc/caddy/island.key -sha256 -days 3650 \
    -subj "/CN=203.0.113.5" -addext "subjectAltName=IP:203.0.113.5" -out /etc/caddy/island.crt
sudo chown caddy:caddy /etc/caddy/island.key /etc/caddy/island.crt
sudo chmod 600 /etc/caddy/island.key
```

Keep OpenSSL 3's `-x509` defaults (`CA:TRUE` and a subject key identifier) and
the address in the SAN: the CLI runs on Node and can only be handed a trust
anchor, and a certificate without them is refused there and nowhere else. Then
`/etc/caddy/Caddyfile` becomes:

```caddyfile
{
	# No authority to ask, and no redirect from :80 (both are auto_https).
	auto_https off
	# A client dialling a bare IP sends no SNI; this names the certificate for it.
	default_sni 203.0.113.5
}

:443 {
	tls /etc/caddy/island.crt /etc/caddy/island.key
	reverse_proxy 127.0.0.1:8000
}

:80 {
	respond 404
}
```

```bash
sudo systemctl reload caddy
openssl x509 -noout -fingerprint -sha256 -in /etc/caddy/island.crt
```

Hand out `203.0.113.5#<fingerprint>`, the fingerprint lowercased and without
colons. What users see, how to rotate the certificate, and how to move to a
certificate authority later without disturbing anyone:
[tls-without-a-ca.md](tls-without-a-ca.md).

## 8. Point a client at it

In the RCQ app: Settings → Network → Custom server → enter `island.example.com`.
The app registers a fresh account on your island; your flagship account stays on
the device (RCQ is multi-account, nothing is wiped).

## Calls (optional: TURN)

Voice/video calls are WebRTC. **Signalling** (finding the other party, exchanging
SDP/ICE) runs over the WebSocket of *this island* — the backend is a dumb relay
for the offer/answer/hangup, and the call media itself goes peer-to-peer
(DTLS-SRTP); the server is never in the media path. So basic calls work with no
extra service.

A **TURN** server is only needed to relay media when peers are behind hard
(symmetric) NATs and can't reach each other directly. Without TURN configured,
the app falls back to STUN-only: calls work on permissive networks and fail
behind symmetric NAT. To make calls reliable everywhere, run coturn:

```bash
sudo apt install -y coturn
sudo sed -i 's/^#TURNSERVER_ENABLED=1/TURNSERVER_ENABLED=1/' /etc/default/coturn
```

Put this in `/etc/turnserver.conf` (pick a strong secret — it must match
`TURN_SECRET` in the app's `.env`):

```ini
listening-port=3478
fingerprint
use-auth-secret
static-auth-secret=CHANGE_ME_TURN_SECRET
realm=island.example.com
min-port=49152
max-port=65535
no-cli
# REQUIRED on a cloud host behind 1:1 NAT (DigitalOcean, most VPS): coturn must
# advertise the PUBLIC IP in its relay candidates, or the relayed candidate
# points at an unroutable address and the call connects in the UI but carries no
# media. Use `external-ip=<public>` — or `external-ip=<public>/<private>` when
# the NIC only sees a private address.
external-ip=PUBLIC_IP_OF_THIS_HOST
```

```bash
sudo systemctl enable --now coturn
```

Then add to `/opt/rcq/.env` and restart the app:

```ini
TURN_HOST=island.example.com
TURN_SECRET=CHANGE_ME_TURN_SECRET
# TURN_TTL_SECONDS=86400   # credential lifetime, optional (default 24h)
```

Open the firewall for TURN: TCP+UDP **3478** (control) and UDP **49152-65535**
(the relay range above). The backend mints short-lived HMAC credentials per call
(TURN REST API pattern), so no per-user TURN accounts are needed.

### TURN-over-TLS (calls on censored / DPI'd mobile networks)

Plain TURN on UDP/TCP **3478** is exactly what DPI and CGNAT firewalls on hostile
mobile networks (e.g. RU carriers) drop — so calls there "connect" in the UI (on
the SDP answer) but no media ever flows. **TURN-over-TLS** fixes this: a `turns:`
allocation rides TLS and, on port **443**, is indistinguishable from ordinary
HTTPS, so it gets through. This is the single biggest reliability win for calls
on censored networks.

Add a cert whose SAN covers `TURN_HOST` (reuse the island's existing TLS cert)
and a TLS listener to `/etc/turnserver.conf`:

```ini
tls-listening-port=5349
cert=/path/to/fullchain.pem
pkey=/path/to/privkey.pem
```

Then advertise it to clients — set in `/opt/rcq/.env` and restart the app:

```ini
TURN_TLS_PORT=5349
```

**Which port?** Use **443** for maximum reach (looks like HTTPS) *only on a host
where 443 is free* — i.e. a dedicated TURN box. If coturn shares the host with
the web server (Caddy/nginx already own 443), use **5349** here; it still rides
TLS, just on a non-443 port. Open the chosen port in the firewall (TCP+UDP).

**Verify the relay actually works** (don't trust `nc -z 3478` — that only proves
the port is open, not that a relay allocation succeeds). From a machine *outside*
the host's network:

```bash
turnutils_uclient -t -u <user> -w <cred> -p 3478 TURN_HOST     # plain TCP
turnutils_uclient -t -S -p 5349 TURN_HOST                       # TURN-over-TLS
```

A successful run prints round-trip packet stats; a hang or auth error means the
relay isn't reachable end-to-end (check `external-ip`, the firewall, and the cert).

## Files and media

Unlike calls, file transfer is **store-and-forward through the island** (it has
to be — the recipient may be offline), the same shape as Matrix's media repo or
XMPP's HTTP File Upload, but with mandatory client-side encryption. The flow:

1. The sender encrypts the file on-device with a fresh per-file key (AES-GCM)
   and uploads the **ciphertext** via `POST /media/upload`, getting back a
   `media_id` (a uuid4).
2. The sender then sends a normal end-to-end-encrypted message that carries the
   `media_id` + the file's decryption key. That message is sealed, so the
   **key never reaches the server** — only the recipient can read it.
3. The recipient fetches the ciphertext via `GET /media/{media_id}` and decrypts
   it locally.

Blobs live on the local filesystem under `media/uploads/{uuid}.bin` (relative to
the app's working directory, so `/opt/rcq/media/uploads/` with the systemd unit
above; override with `RCQ_MEDIA_DIR`). The server only ever holds opaque
encrypted bytes — it cannot read your files. The `/media` endpoints are
unauthenticated by design: security rests on the encryption plus the unguessable
uuid id, not on access control over an already-encrypted blob. (`PUT /media/{id}`
also exists so a sender can deposit the same blob on several islands for
cross-island/federated delivery.)

- **Size limit:** 2 GB per upload. Behind nginx, also raise
  `client_max_body_size` (see the nginx section) or the proxy rejects large
  uploads before they reach the app.
- **Retention:** a blob is swept once it is older than
  `RCQ_MEDIA_MAX_AGE_DAYS` (30 by default) and no row still points at it;
  avatars and report evidence are exempt. Account for disk growth, and include
  `media/uploads/` in backups if you want media to survive a fresh device
  fetch. The text/queue side keeps nothing
  durable — the offline queue holds only undelivered sealed envelopes, deleted on
  delivery.

## Operating it

```bash
# Logs
journalctl -u rcq -f
sudo journalctl -u caddy -f          # TLS / cert issuance problems

# Update to a newer release
cd /opt/rcq && sudo git pull
./.venv/bin/pip install -r requirements.txt
sudo systemctl restart rcq

# Backups — everything durable is in Postgres; back the database up:
pg_dump -U rcq -h 127.0.0.1 rcq > rcq-$(date +%F).sql
```

Note that RCQ keeps **no message history on the server** — the offline queue
holds only undelivered sealed envelopes and is emptied on delivery. The durable
data is accounts, contacts, group rosters and keys, all in Postgres. History
lives on the clients.

## Option B: nginx + certbot instead of Caddy

If you already run nginx, use this in place of step 1's `caddy` package and
step 7. Caddy is only recommended because it auto-issues TLS; nginx works fine
with certbot. (RCQ uses WebSockets, so the `Upgrade`/`Connection` headers below
are required — without them the socket won't connect.)

```bash
sudo apt install -y nginx certbot python3-certbot-nginx
```

Create `/etc/nginx/sites-available/rcq`:

```nginx
server {
    listen 80;
    listen [::]:80;
    server_name island.example.com;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        # WebSocket upgrade (required for live message delivery)
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        # Don't time the WebSocket out after 60s of quiet
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }

    # IMPORTANT: nginx defaults client_max_body_size to 1 MB, which would
    # reject any media upload bigger than that. The app accepts up to 2 GB
    # per blob, so raise (or cap) this to taste. Caddy has no such default
    # limit, which is why the Caddy section above needs nothing extra.
    client_max_body_size 2g;
}
```

Enable it and issue the certificate — certbot rewrites this block to add the
`listen 443 ssl` server and the HTTP→HTTPS redirect for you:

```bash
sudo ln -s /etc/nginx/sites-available/rcq /etc/nginx/sites-enabled/rcq
sudo nginx -t && sudo systemctl reload nginx
sudo certbot --nginx -d island.example.com   # gets + installs the LE cert, sets auto-renewal
```

Verify end to end:

```bash
curl -fsS https://island.example.com/health && echo "island is live"
```

You can skip the `caddy` install in step 1 entirely if you go this route.
