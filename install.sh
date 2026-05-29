#!/usr/bin/env bash
#
# RCQ self-host installer.
#
# Usage on a fresh Ubuntu / Debian VPS, as root or via sudo:
#
#   curl -fsSL https://raw.githubusercontent.com/rcq-messenger/rcq-server-ref/main/install.sh | bash
#
# Or save first + inspect (recommended for any non-throwaway box):
#
#   curl -fsSL https://raw.githubusercontent.com/rcq-messenger/rcq-server-ref/main/install.sh -o install.sh
#   less install.sh
#   bash install.sh
#
# Unattended / scripted provisioning (e.g. standing up a managed island
# from a control plane). Pass values via env to skip every prompt:
#
#   RCQ_DOMAIN=org-acme.rcq.app RCQ_UNATTENDED=1 bash install.sh
#
#   RCQ_DOMAIN     public domain whose A-record already points here
#   RCQ_UNATTENDED non-empty -> never prompt; abort (don't hang) if DNS
#                  isn't ready yet, unless RCQ_FORCE=1 is also set
#   RCQ_FORCE      non-empty -> proceed even on a DNS mismatch (ACME may
#                  fail until DNS propagates)
#
# What this script does:
#   1. Installs Docker (via the official get-docker.com script) + git +
#      openssl + dig, if missing.
#   2. Clones rcq-server-ref into /opt/rcq-server (or $INSTALL_DIR if set).
#   3. Asks you for the public domain you want to use, sanity-checks
#      its A-record points at this host, refuses to continue on a
#      DNS mismatch unless you confirm.
#   4. Generates a fresh JWT_SECRET + POSTGRES_PASSWORD, writes a
#      production-shaped .env (mode 0600). Skipped if .env exists
#      already, so re-running the installer doesn't overwrite live
#      secrets.
#   5. Brings the stack up with `docker compose up -d --build`.
#   6. Waits up to 60 seconds for Caddy to obtain a Let's Encrypt
#      certificate and for /health to answer 200 over HTTPS.
#   7. Prints next-step instructions for wiring an iOS client at it
#      + ops cheat-sheet (logs / restart / update / APNs).
#
# What this script does NOT do:
#   - Buy you a VPS. Get one yourself from Hetzner / DO / Vultr.
#   - Buy you a domain. Get one from Namecheap / Porkbun / wherever.
#   - Configure your DNS. Point an A-record at the host yourself.
#   - Set up APNs (push notifications). The script points at
#     docs/apns.md and stops — wire it later if you want push.

set -euo pipefail

# ─────────────────────────────────────────────────────────────────────
# Pretty output (only if stdout is a tty; otherwise plain text for
# pipe + log capture)
# ─────────────────────────────────────────────────────────────────────
if [ -t 1 ]; then
    BOLD=$(tput bold); RESET=$(tput sgr0)
    GREEN=$(tput setaf 2); YELLOW=$(tput setaf 3); RED=$(tput setaf 1)
else
    BOLD=""; RESET=""; GREEN=""; YELLOW=""; RED=""
fi

say()  { echo "${BOLD}==>${RESET} $*"; }
warn() { echo "${YELLOW}==>${RESET} $*"; }
fail() { echo "${RED}==> $*${RESET}" >&2; exit 1; }

# Interactive y/N confirm, except under RCQ_UNATTENDED where we never
# block on stdin: abort with $2 unless RCQ_FORCE is set. Keeps scripted
# provisioning from hanging on a prompt.
confirm_or_abort() {
    local prompt="$1" abort_msg="$2" reply
    if [ -n "${RCQ_UNATTENDED:-}" ]; then
        [ -n "${RCQ_FORCE:-}" ] || fail "$abort_msg (set RCQ_FORCE=1 to override in unattended mode)"
        return 0
    fi
    read -r -p "$prompt" reply
    [[ "${reply:-N}" =~ ^[Yy] ]] || fail "$abort_msg"
}

# ─────────────────────────────────────────────────────────────────────
# Preflight
# ─────────────────────────────────────────────────────────────────────
[ "$(id -u)" = "0" ] || fail "Run as root (or via sudo) — Docker install and ports 80/443 need root."

# Sanity-check OS family
. /etc/os-release || warn "Can't read /etc/os-release; continuing blind."
case "${ID:-unknown}" in
    ubuntu|debian) ;;
    *) warn "Untested OS (${ID:-unknown}). Will continue but no promises." ;;
esac

# ─────────────────────────────────────────────────────────────────────
# Required tooling
# ─────────────────────────────────────────────────────────────────────
say "Checking tooling…"
command -v docker  >/dev/null || { say "Installing Docker via get-docker.com…"; curl -fsSL https://get.docker.com | sh; }
command -v git     >/dev/null || { apt-get update -qq && apt-get install -y -qq git; }
command -v openssl >/dev/null || apt-get install -y -qq openssl
command -v dig     >/dev/null || apt-get install -y -qq dnsutils
command -v python3 >/dev/null || apt-get install -y -qq python3

# ─────────────────────────────────────────────────────────────────────
# Source checkout
# ─────────────────────────────────────────────────────────────────────
INSTALL_DIR="${INSTALL_DIR:-/opt/rcq-server}"
say "Install directory: $INSTALL_DIR"

if [ -d "$INSTALL_DIR/.git" ]; then
    say "Updating existing checkout…"
    git -C "$INSTALL_DIR" pull --ff-only
else
    say "Cloning rcq-server-ref…"
    git clone https://github.com/rcq-messenger/rcq-server-ref.git "$INSTALL_DIR"
fi
cd "$INSTALL_DIR"

# ─────────────────────────────────────────────────────────────────────
# .env configuration (idempotent: skipped if .env already exists)
# ─────────────────────────────────────────────────────────────────────
if [ -f .env ]; then
    warn ".env already exists — keeping it. Edit by hand if you need to change values."
else
    say "Configuring .env…"

    # Domain from RCQ_DOMAIN for unattended/scripted provisioning, else prompt.
    if [ -n "${RCQ_DOMAIN:-}" ]; then
        DOMAIN="$RCQ_DOMAIN"
        say "Using domain from RCQ_DOMAIN: $DOMAIN"
    else
        read -r -p "${BOLD}Public domain pointing at this host${RESET} (e.g. rcq.example.com): " DOMAIN
    fi
    [ -z "${DOMAIN:-}" ] && fail "Domain is required (Caddy + Let's Encrypt need one)."

    # Best-effort DNS sanity check. Failing this isn't fatal — the
    # user might have just-configured DNS that's still propagating —
    # but we warn loudly so they don't end up debugging a wedged ACME
    # cert issuance for 30 minutes.
    RESOLVED=$(dig +short "$DOMAIN" 2>/dev/null | tail -1)
    PUBLIC_IP=$(curl -fsS -m 5 https://api.ipify.org 2>/dev/null || echo "")
    if [ -z "$RESOLVED" ]; then
        warn "$DOMAIN doesn't resolve. Configure the A-record to point at ${PUBLIC_IP:-this host}, then re-run."
        confirm_or_abort "Continue anyway? (y/N): " "Aborted. Configure DNS and re-run."
    elif [ -n "$PUBLIC_IP" ] && [ "$RESOLVED" != "$PUBLIC_IP" ]; then
        warn "$DOMAIN resolves to $RESOLVED but this host is $PUBLIC_IP. Let's Encrypt HTTP-01 challenge will fail."
        confirm_or_abort "Continue anyway? (y/N): " "Aborted. Fix DNS and re-run."
    fi

    JWT_SECRET=$(openssl rand -hex 32)
    POSTGRES_PASSWORD=$(openssl rand -hex 16)

    cp .env.example .env
    # Pass values via env so bash escaping doesn't bite us on
    # special characters from openssl-random output (none today, but
    # belt-and-suspenders).
    DOMAIN="$DOMAIN" JWT_SECRET="$JWT_SECRET" POSTGRES_PASSWORD="$POSTGRES_PASSWORD" python3 - <<'PY'
import os
from pathlib import Path
domain = os.environ["DOMAIN"]
jwt = os.environ["JWT_SECRET"]
pgpw = os.environ["POSTGRES_PASSWORD"]
p = Path(".env")
lines = p.read_text().splitlines()
out = []
seen = {"ENV": False, "RCQ_DOMAIN": False, "JWT_SECRET": False, "POSTGRES_PASSWORD": False}
for line in lines:
    key = line.split("=", 1)[0].strip() if "=" in line and not line.lstrip().startswith("#") else None
    if key == "ENV":
        out.append("ENV=prod"); seen["ENV"] = True
    elif key == "RCQ_DOMAIN":
        out.append(f"RCQ_DOMAIN={domain}"); seen["RCQ_DOMAIN"] = True
    elif key == "JWT_SECRET":
        out.append(f"JWT_SECRET={jwt}"); seen["JWT_SECRET"] = True
    elif key == "POSTGRES_PASSWORD":
        out.append(f"POSTGRES_PASSWORD={pgpw}"); seen["POSTGRES_PASSWORD"] = True
    else:
        out.append(line)
if not seen["POSTGRES_PASSWORD"]:
    out.append(f"POSTGRES_PASSWORD={pgpw}")
p.write_text("\n".join(out) + "\n")
PY
    chmod 600 .env
    say ".env configured (mode 0600). Secrets live at $INSTALL_DIR/.env — back them up somewhere safe."
fi

# ─────────────────────────────────────────────────────────────────────
# APNs is opt-in. Just point at the walkthrough and continue.
# ─────────────────────────────────────────────────────────────────────
say "Optional: iOS push notifications walkthrough is in $INSTALL_DIR/docs/apns.md"
echo "         (skip for now if you don't need push; wire it later)"

# ─────────────────────────────────────────────────────────────────────
# Bring up + verify
# ─────────────────────────────────────────────────────────────────────
say "Bringing up the stack…"
docker compose up -d --build

DOMAIN_VAL=$(grep '^RCQ_DOMAIN=' .env | cut -d= -f2-)
say "Waiting for Caddy + Let's Encrypt (up to 60s)…"
for _ in $(seq 1 12); do
    sleep 5
    if curl -fsS -m 5 "https://$DOMAIN_VAL/health" >/dev/null 2>&1; then
        echo
        say "${GREEN}Server is live at https://$DOMAIN_VAL${RESET}"
        echo
        echo "Next steps:"
        echo "  • In the RCQ iOS app, open the account switcher (top-left pill),"
        echo "    tap 'New server', enter https://$DOMAIN_VAL"
        echo "  • Or open a PR to list your instance in the public catalogue:"
        echo "    https://github.com/rcq-messenger/rcq-servers"
        echo
        echo "Operations:"
        echo "  Tail logs:    cd $INSTALL_DIR && docker compose logs -f app"
        echo "  Restart:      cd $INSTALL_DIR && docker compose restart app"
        echo "  Update:       cd $INSTALL_DIR && git pull && docker compose up -d --build"
        echo "  APNs setup:   $INSTALL_DIR/docs/apns.md"
        exit 0
    fi
done

warn "Health endpoint didn't respond in 60s. Diagnostics:"
echo "  docker compose logs caddy   # Let's Encrypt issuance problems"
echo "  docker compose logs app     # app startup errors"
echo "  curl -v https://$DOMAIN_VAL/health"
exit 1
