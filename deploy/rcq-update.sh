#!/usr/bin/env bash
#
# Keep a self-hosted island up to date.
#
# Until now an operator learned about a new version from a banner in the admin
# console and then had to remember two commands. That is fine for the week the
# island is new and useless six months later — and the things that go out in a
# release are increasingly not features but fixes an island cannot do without.
# 16.08 made that concrete twice: registration on one island had been answering
# 500 for days because of a schema drift the update fixes, and group messages
# were broken on every SQLite island for the same kind of reason.
#
# So: this script does the update, and the systemd timer beside it runs the
# script. Both are OPTIONAL and off unless the operator turns them on — an
# island that pulls code by itself is a trust decision, and it is theirs.
#
#   rcq-update.sh            check, update if behind, restart if updated
#   rcq-update.sh --check    say what would happen, change nothing
#   rcq-update.sh --force    update even when the version file says we are current
#
# Exit codes: 0 = up to date or updated, 1 = something went wrong.
#
# ⚠ It only ever fast-forwards `main`. A checkout with local commits or dirty
# files is left alone with a loud message: somebody has been working in it, and
# a self-updater that discards that would be worse than one that never runs.

set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-/opt/rcq-server}"
BRANCH="${RCQ_UPDATE_BRANCH:-main}"
STATE_DIR="$INSTALL_DIR/state"
LOG="$STATE_DIR/update.log"
MODE="${1:-}"

log() { printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" | tee -a "$LOG"; }
die() { log "ERROR: $*"; exit 1; }

[ -d "$INSTALL_DIR/.git" ] || die "$INSTALL_DIR is not a git checkout"
mkdir -p "$STATE_DIR"
cd "$INSTALL_DIR"

# ── refuse to touch a checkout somebody is working in ────────────────────────
#
# ⚠ TRACKED files only (`--untracked-files=no`). Every island has untracked
# files by definition — `.env` is one, and so is anything the operator left
# lying around — so counting those would mean this script refused to run on
# literally every install. Caught on the first live run against is2, which has
# `.env` plus a handful of old `.bak` files.
if [ -n "$(git status --porcelain --untracked-files=no 2>/dev/null || true)" ]; then
    die "tracked files were modified in $INSTALL_DIR — update by hand, nothing was touched"
fi

git fetch --quiet origin "$BRANCH" || die "cannot reach the repository"

LOCAL=$(git rev-parse HEAD)
REMOTE=$(git rev-parse "origin/$BRANCH")
CURRENT_VERSION=$(cat VERSION 2>/dev/null || echo unknown)
REMOTE_VERSION=$(git show "origin/$BRANCH:VERSION" 2>/dev/null || echo unknown)

if [ "$LOCAL" = "$REMOTE" ] && [ "$MODE" != "--force" ]; then
    log "up to date ($CURRENT_VERSION)"
    printf '{"checked_at":"%s","current":"%s","latest":"%s","updated":false}\n' \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$CURRENT_VERSION" "$REMOTE_VERSION" > "$STATE_DIR/update-status.json"
    exit 0
fi

if [ "$MODE" = "--check" ]; then
    log "behind: $CURRENT_VERSION -> $REMOTE_VERSION ($(git rev-list --count HEAD.."origin/$BRANCH") commits)"
    printf '{"checked_at":"%s","current":"%s","latest":"%s","updated":false,"behind":true}\n' \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$CURRENT_VERSION" "$REMOTE_VERSION" > "$STATE_DIR/update-status.json"
    exit 0
fi

# ── back the database up first ───────────────────────────────────────────────
#
# ⚠ The one step that must not be skipped. An update runs the start-up
# migrations, and a migration that goes wrong on somebody's data with no dump
# beside it is the worst outcome this script can produce. Best-effort by
# design: an island with no Postgres container (SQLite) has its file inside the
# volume and is covered by the compose snapshot instead.
if docker compose ps --services 2>/dev/null | grep -q '^postgres$'; then
    # ⚠ Sealed when the operator has set it up: a plaintext dump kept beside
    # the database extends every "deleted" on the island by however long it
    # sits there (a burnt account, a swept queue row, a resolved request all
    # live on in it). With `age` installed and a recipient key at
    # /etc/rcq/backup.pub (the PRIVATE half kept OFF this box), the dump is
    # encrypted on the way to disk and the plaintext never touches it:
    #   age-keygen -o backup.key          # on your own machine, keep it there
    #   grep "public key" backup.key      # -> /etc/rcq/backup.pub on the island
    #   restore: age -d -i backup.key pre-update-*.sql.gz.age | gunzip | psql
    # Without both, the dump is plaintext as before: a dump you cannot read on
    # the day you need it is worse than one the disk can.
    SEAL=""
    if command -v age >/dev/null 2>&1 && [ -s /etc/rcq/backup.pub ]; then
        SEAL="age -R /etc/rcq/backup.pub"
    fi
    BACKUP="$STATE_DIR/pre-update-$(date -u +%Y%m%d-%H%M%S).sql.gz${SEAL:+.age}"
    log "dumping the database to $BACKUP${SEAL:+ (sealed to /etc/rcq/backup.pub)}"
    if docker compose exec -T postgres pg_dump -U rcq rcq 2>/dev/null | gzip | ${SEAL:-cat} > "$BACKUP"; then
        # Keep the last five, not every one: this runs on somebody else's disk.
        # `|| true`: under pipefail an unmatched glob makes ls fail and the
        # whole script die silently right after a successful dump.
        { ls -1t "$STATE_DIR"/pre-update-*.sql.gz "$STATE_DIR"/pre-update-*.sql.gz.age 2>/dev/null || true; } | tail -n +6 | xargs -r rm -f
        log "dump ok ($(du -h "$BACKUP" | cut -f1))"
    else
        rm -f "$BACKUP"
        die "database dump failed — refusing to update on top of no backup"
    fi
fi

log "updating $CURRENT_VERSION -> $REMOTE_VERSION"
git merge --ff-only "origin/$BRANCH" || die "cannot fast-forward — update by hand"

docker compose up -d --build app || die "rebuild failed — the old container may still be running"

# ── prove it came back ───────────────────────────────────────────────────────
#
# ⚠ Asked from INSIDE the container first, and that order is the point. From
# the host, port 8000 is not published (only Caddy is), and the public name
# depends on DNS and a certificate — so a perfectly healthy island would look
# dead. Python rather than curl: the image is slim and has no curl.
#
# ⚠ `RCQ_DOMAIN` can list SEVERAL names, comma-separated, because Caddy accepts
# that ("is2.rcq.app, is2.165-22-95-218.sslip.io" on a real island). Feeding the
# whole string to curl produces "malformed URL" and a false alarm — which is
# exactly what the first live run reported, on an island that had updated fine.
DOMAIN=$(grep -E '^RCQ_DOMAIN=' .env 2>/dev/null | cut -d= -f2- | cut -d, -f1 | tr -d ' ' || true)
HEALTH_OK=false
# Why the last attempt failed, so a timeout can be acted on instead of merely
# announced. 19.08 this loop declared an island dead for two minutes while it
# had in fact been serving users since twelve seconds after the restart, and
# the message said only "check the logs" — the logs were clean, because
# nothing was wrong with the island. A probe that cannot say what it saw is
# not a health check, it is a rumour.
WHY=""
for _ in $(seq 1 24); do
    sleep 5
    # 1. From inside the container: the most direct answer, and the only one
    #    that works before Caddy has a certificate.
    if WHY=$(docker compose exec -T app python -c \
         'import urllib.request,sys; sys.exit(0 if urllib.request.urlopen("http://127.0.0.1:8000/health", timeout=5).status == 200 else 1)' \
         2>&1); then
        HEALTH_OK=true
        break
    fi
    # 2. Through the island's own front door, over loopback.
    #    ⚠ Not plain `http://127.0.0.1/health`: Caddy answers that with a 308
    #    to https, which `curl -f` counts as a failure — an island that
    #    redirects correctly looked broken. And not `-L` either, because the
    #    redirect lands on https://127.0.0.1, where the certificate is for the
    #    DOMAIN and TLS fails. `--resolve` asks the real vhost by name while
    #    pinning it to loopback: valid certificate, no dependency on public DNS.
    if [ -n "$DOMAIN" ] && WHY=$(curl -fsS -m 5 --resolve "$DOMAIN:443:127.0.0.1" \
         "https://$DOMAIN/health" 2>&1); then
        HEALTH_OK=true
        break
    fi
    # 3. The public name, last: it depends on DNS and a certificate, so it is
    #    the slowest to become true and the least specific when it is false.
    if [ -n "$DOMAIN" ] && WHY=$(curl -fsS -m 5 "https://$DOMAIN/health" 2>&1); then
        HEALTH_OK=true
        break
    fi
done

NEW_VERSION=$(cat VERSION 2>/dev/null || echo unknown)
printf '{"checked_at":"%s","current":"%s","latest":"%s","updated":true,"healthy":%s}\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$NEW_VERSION" "$REMOTE_VERSION" "$HEALTH_OK" \
    > "$STATE_DIR/update-status.json"

if [ "$HEALTH_OK" = true ]; then
    log "updated to $NEW_VERSION, health ok"
else
    # Deliberately NOT an automatic rollback. Rolling the code back does not
    # roll the database back, and doing that unattended is how a bad minute
    # becomes lost data. The operator gets a loud line and a dump to work from.
    die "updated to $NEW_VERSION but /health did not answer in two minutes (last probe said: ${WHY:-nothing}) — check: cd $INSTALL_DIR && docker compose logs app"
fi
