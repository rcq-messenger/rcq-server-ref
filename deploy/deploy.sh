#!/usr/bin/env bash
#
# Push the local backend/ tree to the droplet and restart uvicorn.
# Usage:
#   bash deploy/deploy.sh <droplet-ip-or-hostname> [ssh-user]
#
# Defaults:
#   ssh-user = root  (works after droplet creation; once you've added a sudo
#                     user, pass it explicitly)
#
# What it does:
#   1. rsync backend/ to /opt/rcq/app/backend/ (excludes the local SQLite db,
#      __pycache__, .venv, media uploads — those stay on the server)
#   2. installs/updates Python dependencies inside the droplet venv
#   3. installs the systemd unit + Caddyfile if not present yet
#   4. systemctl daemon-reload + restart rcq-backend, reload caddy
#   5. tails the journal for 5s so you see startup logs

set -euo pipefail

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <droplet-ip-or-hostname> [ssh-user]"
    exit 1
fi

HOST=$1
USER=${2:-root}
SSH="ssh ${USER}@${HOST}"

REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$REPO_ROOT"

echo "==> rsync backend/"
rsync -az --delete \
    --exclude '__pycache__' \
    --exclude '.venv' \
    --exclude 'rcq.db' \
    --exclude 'rcq.db-shm' \
    --exclude 'rcq.db-wal' \
    --exclude 'media/' \
    --exclude 'news_media/' \
    --exclude 'evidence/' \
    --exclude '.env' \
    backend/ "${USER}@${HOST}:/opt/rcq/app/backend/"

echo "==> rsync deploy/ artifacts"
rsync -az deploy/ "${USER}@${HOST}:/opt/rcq/app/deploy/"

echo "==> chown to rcq user"
$SSH "chown -R rcq:rcq /opt/rcq/app/backend /opt/rcq/app/deploy"

echo "==> ensure redis-server installed + running"
# Idempotent install. apt-get install is a no-op if redis-server is
# already on the box at the right version. systemctl enable --now
# starts it AND wires it to come up on boot — needed because the
# rcq-backend.service unit declares `Requires=redis-server.service`
# (multi-worker uvicorn relies on Redis for pub/sub fanout, queue
# state, and leader election).
$SSH "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq redis-server >/dev/null && \
      systemctl enable --now redis-server"

echo "==> pip install -r requirements.txt"
$SSH "sudo -u rcq /opt/rcq/venv/bin/pip install --upgrade pip --quiet && \
      sudo -u rcq /opt/rcq/venv/bin/pip install -r /opt/rcq/app/backend/requirements.txt --quiet"

echo "==> install systemd unit + Caddyfile (if changed)"
$SSH "install -m 644 /opt/rcq/app/deploy/rcq-backend.service /etc/systemd/system/rcq-backend.service && \
      install -m 644 /opt/rcq/app/deploy/Caddyfile /etc/caddy/Caddyfile && \
      systemctl daemon-reload"

echo "==> restart rcq-backend, reload caddy"
$SSH "systemctl enable --now rcq-backend && \
      systemctl restart rcq-backend && \
      systemctl reload caddy"

echo "==> tail journal (5s)"
$SSH "timeout 5 journalctl -u rcq-backend -n 30 --no-pager || true"

echo ""
echo "==> Smoke test:"
echo "    curl -i https://api.rcq.app/health"
