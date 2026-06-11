# Self-hosting RCQ on Debian without Docker

A complete, step-by-step production deploy on a fresh Debian 12 server, with no
Docker. The stack is plain: PostgreSQL + Redis + the FastAPI app under uvicorn
(managed by systemd) + Caddy as the TLS reverse proxy.

If you just want to try it locally, the README's "Quick start (no Docker)" is
enough. This guide is for a real, internet-facing island with HTTPS.

Prerequisites:
- A Debian 12 server with a public IP and root (or sudo).
- A domain or subdomain pointed at that IP with an `A` record
  (e.g. `island.example.com`). iOS clients require HTTPS, so a real hostname
  is mandatory; Caddy issues a free Let's Encrypt certificate automatically.

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

## 8. Point a client at it

In the RCQ app: Settings → Network → Custom server → enter `island.example.com`.
The app registers a fresh account on your island; your flagship account stays on
the device (RCQ is multi-account, nothing is wiped).

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
