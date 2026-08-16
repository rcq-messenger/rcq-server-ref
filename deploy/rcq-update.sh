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
    BACKUP="$STATE_DIR/pre-update-$(date -u +%Y%m%d-%H%M%S).sql.gz"
    log "dumping the database to $BACKUP"
    if docker compose exec -T postgres pg_dump -U rcq rcq 2>/dev/null | gzip > "$BACKUP"; then
        # Keep the last five, not every one: this runs on somebody else's disk.
        ls -1t "$STATE_DIR"/pre-update-*.sql.gz 2>/dev/null | tail -n +6 | xargs -r rm -f
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
DOMAIN=$(grep -E '^RCQ_DOMAIN=' .env 2>/dev/null | cut -d= -f2- || true)
HEALTH_OK=false
for _ in $(seq 1 24); do
    sleep 5
    if curl -fsS -m 5 "http://127.0.0.1:8000/health" >/dev/null 2>&1 ||
       { [ -n "$DOMAIN" ] && curl -fsS -m 5 "https://$DOMAIN/health" >/dev/null 2>&1; }; then
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
    die "updated to $NEW_VERSION but /health did not answer in two minutes — check: cd $INSTALL_DIR && docker compose logs app"
fi
