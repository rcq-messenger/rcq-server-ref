#!/usr/bin/env bash
#
# Push this repo's app/ tree to a droplet and restart uvicorn.
# Usage:
#   bash deploy/deploy.sh <droplet-ip-or-hostname> [ssh-user]
#
# Defaults:
#   ssh-user = root  (works after droplet creation; once you've added a sudo
#                     user, pass it explicitly)
#
# What it does:
#   1. rsync app/ and requirements.txt to /opt/rcq/app/ (excludes the local
#      SQLite db,
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

echo "==> rsync app/"
rsync -az --delete \
    --exclude '__pycache__' \
    --exclude '.venv' \
    --exclude '*.db' \
    --exclude '*.db-shm' \
    --exclude '*.db-wal' \
    --exclude 'media/' \
    --exclude 'news_media/' \
    --exclude 'evidence/' \
    --exclude '.env' \
    app/ "${USER}@${HOST}:/opt/rcq/app/backend/app/"

# requirements.txt lives at the repo root, not inside app/, and the pip step
# below installs from the copy on the server — without this it installs
# whatever was there from the last deploy.
rsync -az requirements.txt "${USER}@${HOST}:/opt/rcq/app/backend/requirements.txt"

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

echo "==> Caddyfile preflight: no vhost may disappear"
# 2026-08-08: this script was run from the wrong tree and installed a Caddyfile
# with fewer vhosts than the one serving. Five hosts vanished in a single
# reload, push delivery among them, and nothing in the output looked wrong,
# because installing a *valid* Caddyfile is a successful deploy as far as caddy
# is concerned. Compare against what is actually serving and refuse to take a
# vhost away by accident.
INCOMING_HOSTS=$(grep -oE '^[a-z0-9.-]+\.[a-z]+ \{' deploy/Caddyfile | sed 's/ {$//' | sort -u)
LIVE_HOSTS=$($SSH "grep -oE '^[a-z0-9.-]+\\.[a-z]+ \\{' /etc/caddy/Caddyfile 2>/dev/null | sed 's/ {\$//' | sort -u" || true)
if [[ -n "$LIVE_HOSTS" ]]; then
    VANISHING=$(comm -13 <(echo "$INCOMING_HOSTS") <(echo "$LIVE_HOSTS") || true)
    if [[ -n "$VANISHING" ]]; then
        echo ""
        echo "REFUSING TO DEPLOY: these vhosts are serving now and are absent from"
        echo "the Caddyfile this run would install:"
        echo "$VANISHING" | sed 's/^/    /'
        echo ""
        echo "Check you are deploying from the intended tree. If removing them is"
        echo "genuinely intended, re-run with RCQ_DEPLOY_ALLOW_VHOST_REMOVAL=1."
        [[ "${RCQ_DEPLOY_ALLOW_VHOST_REMOVAL:-0}" == "1" ]] || exit 1
    fi
fi

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
echo "    curl -i https://${HOST}/health"
