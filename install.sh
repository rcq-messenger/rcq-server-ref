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
#   RCQ_TLS=fingerprint RCQ_UNATTENDED=1 bash install.sh     # no domain at all
#
#   RCQ_DOMAIN     public domain whose A-record already points here
#   RCQ_TLS        "ca" (the default when a domain is given): Caddy gets a
#                  Let's Encrypt certificate. "fingerprint": no certificate
#                  authority at all; the island serves its own ten-year
#                  certificate, the RCQ apps pin its fingerprint, and users
#                  add it as `address#fingerprint`. A domain is optional in
#                  that mode (the address is the public IP without one).
#                  See docs/tls-without-a-ca.md.
#   RCQ_PUBLIC_IP  the address to put on the fingerprint certificate when
#                  detection is blocked or the box sits behind 1:1 NAT
#   RCQ_UNATTENDED non-empty -> never prompt; abort (don't hang) if DNS
#                  isn't ready yet, unless RCQ_FORCE=1 is also set
#   RCQ_FORCE      non-empty -> proceed even on a DNS mismatch (ACME may
#                  fail until DNS propagates)
#
# What this script does:
#   1. Installs Docker (via the official get-docker.com script) + git +
#      openssl + dig, if missing.
#   2. Clones rcq-server-ref into /opt/rcq-server (or $INSTALL_DIR if set).
#   3. Asks whether you have a domain. With one: sanity-checks its
#      A-record points at this host, refuses to continue on a DNS
#      mismatch unless you confirm. Without one: issues the island's own
#      certificate for this host's public IP (fingerprint mode).
#   4. Generates a fresh JWT_SECRET + POSTGRES_PASSWORD, writes a
#      production-shaped .env (mode 0600). Skipped if .env exists
#      already, so re-running the installer doesn't overwrite live
#      secrets.
#   5. Brings the stack up with `docker compose up -d --build`.
#   6. Waits up to 60 seconds for Caddy to obtain a Let's Encrypt
#      certificate (or to serve the island's own one) and for /health to
#      answer 200 over HTTPS.
#   7. Prints next-step instructions for wiring an iOS client at it
#      + ops cheat-sheet (logs / restart / update / APNs). In fingerprint
#      mode also the fingerprint and the `address#fingerprint` line to
#      hand to your users.
#
# What this script does NOT do:
#   - Buy you a VPS. Get one yourself from Hetzner / DO / Vultr.
#   - Buy you a domain. Get one from Namecheap / Porkbun / wherever, or
#     run without one (fingerprint mode).
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
# Fingerprint mode: an island without a certificate authority. The apps
# pin the SHA-256 fingerprint of the certificate below the way SSH pins a
# host key; docs/tls-without-a-ca.md is the operator's side of it.
# ─────────────────────────────────────────────────────────────────────
is_ip_literal() {
    [[ "$1" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || [[ "$1" == *:* ]]
}

# The public address, best effort. RCQ_PUBLIC_IP wins; then two lookup
# services, because one of them is blocked exactly where this mode is
# needed; then the source address of the default route, which is only
# right when the NIC carries the public IP itself and not on 1:1 NAT.
detect_public_ip() {
    local ip="${RCQ_PUBLIC_IP:-}"
    [ -n "$ip" ] || ip=$(curl -fsS -m 5 https://api.ipify.org 2>/dev/null || true)
    [ -n "$ip" ] || ip=$(curl -fsS -m 5 https://ifconfig.me/ip 2>/dev/null || true)
    [ -n "$ip" ] || ip=$(ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p' | head -1 || true)
    printf '%s' "$ip"
}

# Issue the island's own certificate: EC P-256, self-signed, ten years,
# the address in the SAN (and the public IP too when the address is a name,
# so the IP form of the address keeps working).
#
# ⚠ Left on OpenSSL 3's `req -x509` defaults on purpose. Those add
# basicConstraints CA:TRUE and a subject key identifier, and that pair is
# what makes the certificate acceptable as a TRUST ANCHOR: to the
# `curl --cacert` check below and to Node in the CLI (NODE_EXTRA_CA_CERTS).
# The phones and the desktop pin the fingerprint and would accept any
# certificate; the CLI would not. A hand-made certificate without those
# extensions, or without the address in the SAN, works everywhere except
# there. The recipe, for rotating by hand:
#
#   openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out certs/island.key
#   openssl req -new -x509 -key certs/island.key -sha256 -days 3650 \
#       -subj "/CN=<address>" -addext "subjectAltName=IP:<ip>" -out certs/island.crt
#
# (DNS:<name> in the SAN instead of, or as well as, IP:<ip> for a name.)
issue_island_cert() {
    local address="$1" ip="$2" san
    if is_ip_literal "$address"; then san="IP:$address"; else san="DNS:$address"; fi
    if [ -n "$ip" ] && [ "$ip" != "$address" ]; then san="$san,IP:$ip"; fi
    mkdir -p certs
    (
        umask 077
        openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out certs/island.key 2>/dev/null
        openssl req -new -x509 -key certs/island.key -sha256 -days 3650 \
            -subj "/CN=$address" -addext "subjectAltName=$san" -out certs/island.crt 2>/dev/null
    ) || fail "openssl could not issue the island certificate (OpenSSL 3 is required for -addext)."
    chmod 600 certs/island.key certs/island.crt
}

# Canonical fingerprint (what the apps store and what goes after the `#`
# in the address): SHA-256 over the DER certificate, 64 lowercase hex
# characters, no separators. Exactly openssl's output with the colons
# and the case normalised.
cert_fingerprint() {
    openssl x509 -noout -fingerprint -sha256 -in "$1" | cut -d= -f2 | tr -d ':' | tr '[:upper:]' '[:lower:]'
}

# Display form, the one the apps show: sixteen groups of four, four to a line.
fingerprint_display() {
    local fp="$1" i line=""
    for ((i = 0; i < ${#fp}; i += 4)); do
        line="$line${line:+ }${fp:i:4}"
        if [ $(( (i / 4) % 4 )) -eq 3 ]; then echo "$line"; line=""; fi
    done
    [ -z "$line" ] || echo "$line"
}

# The fingerprint of whatever the wire presents for this address, the
# way a client will see it: SNI for a name, none for an IP (an IP is not
# a name, and a client never sends one). Empty when nothing answers.
presented_fingerprint() {
    local host="$1" sni=()
    is_ip_literal "$host" || sni=(-servername "$host")
    local t=()
    command -v timeout >/dev/null 2>&1 && t=(timeout 10)
    ${t[@]+"${t[@]}"} openssl s_client -connect "$host:443" ${sni[@]+"${sni[@]}"} </dev/null 2>/dev/null \
        | openssl x509 -noout -fingerprint -sha256 2>/dev/null \
        | cut -d= -f2 | tr -d ':' | tr '[:upper:]' '[:lower:]' || true
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

    # How the island proves who it is. "ca": Let's Encrypt, needs a domain.
    # "fingerprint": its own certificate, pinned by the apps, domain
    # optional. A domain given by RCQ_DOMAIN means CA unless RCQ_TLS says
    # otherwise; no domain and nothing decided means we ask.
    TLS_MODE="${RCQ_TLS:-}"
    case "$TLS_MODE" in
        ""|ca|fingerprint) ;;
        *) fail "RCQ_TLS must be \"ca\" or \"fingerprint\" (got: $TLS_MODE)." ;;
    esac

    # Domain from RCQ_DOMAIN for unattended/scripted provisioning, else prompt.
    if [ -n "${RCQ_DOMAIN:-}" ]; then
        DOMAIN="$RCQ_DOMAIN"
        say "Using domain from RCQ_DOMAIN: $DOMAIN"
    elif [ "$TLS_MODE" = "fingerprint" ] || [ -n "${RCQ_UNATTENDED:-}" ]; then
        # Fingerprint mode needs no name. Unattended without a name fails
        # below rather than guess an address on somebody's control plane.
        DOMAIN=""
    else
        read -r -p "${BOLD}Do you have a domain name pointing at this host?${RESET} [y/N] " HAS_DOMAIN
        if [[ "${HAS_DOMAIN:-N}" =~ ^[Yy] ]]; then
            read -r -p "${BOLD}Public domain pointing at this host${RESET} (e.g. rcq.example.com): " DOMAIN
        else
            DOMAIN=""
            TLS_MODE="fingerprint"
        fi
    fi

    if [ "$TLS_MODE" = "fingerprint" ]; then
        PUBLIC_IP=$(detect_public_ip)
        if [ -z "$PUBLIC_IP" ] && [ -z "${DOMAIN:-}" ]; then
            [ -z "${RCQ_UNATTENDED:-}" ] || fail "Could not detect this host's public IP. Set RCQ_PUBLIC_IP and re-run."
            read -r -p "${BOLD}Could not detect the public IP of this host. Enter it:${RESET} " PUBLIC_IP
            [ -n "${PUBLIC_IP:-}" ] || fail "An address is required: the certificate is issued for it and your users type it in."
        fi
        # The address users type and the certificate is issued for: the
        # name when there is one, else the IP. Never both: the apps key
        # their trust on the address, and a name can move to a real CA
        # later without anybody noticing (docs/tls-without-a-ca.md).
        DOMAIN="${DOMAIN:-$PUBLIC_IP}"
        if [ -n "$PUBLIC_IP" ] && ! is_ip_literal "$DOMAIN"; then
            RESOLVED=$(dig +short "$DOMAIN" 2>/dev/null | tail -1)
            if [ "$RESOLVED" != "$PUBLIC_IP" ]; then
                warn "$DOMAIN resolves to ${RESOLVED:-nothing} but this host is $PUBLIC_IP. The certificate covers both, so the IP form of the address works meanwhile."
            fi
        fi
        say "No certificate authority: issuing the island's own certificate for $DOMAIN…"
        issue_island_cert "$DOMAIN" "$PUBLIC_IP"
    else
        [ -z "${DOMAIN:-}" ] && fail "Domain is required (Caddy + Let's Encrypt need one). Without a domain, set RCQ_TLS=fingerprint: see docs/tls-without-a-ca.md."

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
    fi

    JWT_SECRET=$(openssl rand -hex 32)
    POSTGRES_PASSWORD=$(openssl rand -hex 16)

    cp .env.example .env
    # Pass values via env so bash escaping doesn't bite us on
    # special characters from openssl-random output (none today, but
    # belt-and-suspenders).
    DOMAIN="$DOMAIN" JWT_SECRET="$JWT_SECRET" POSTGRES_PASSWORD="$POSTGRES_PASSWORD" TLS_MODE="$TLS_MODE" python3 - <<'PY'
import os
from pathlib import Path
domain = os.environ["DOMAIN"]
jwt = os.environ["JWT_SECRET"]
pgpw = os.environ["POSTGRES_PASSWORD"]
# "" or "ca": the example's own TLS lines stay as they are (CA mode).
fingerprint = os.environ["TLS_MODE"] == "fingerprint"
caddyfile = "./deploy/Caddyfile.fingerprint.compose"
p = Path(".env")
lines = p.read_text().splitlines()
out = []
seen = {"ENV": False, "RCQ_DOMAIN": False, "JWT_SECRET": False, "POSTGRES_PASSWORD": False,
        "RCQ_TLS_MODE": False, "RCQ_CADDYFILE": False}
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
    elif key == "RCQ_TLS_MODE" and fingerprint:
        out.append("RCQ_TLS_MODE=fingerprint"); seen["RCQ_TLS_MODE"] = True
    elif key == "RCQ_CADDYFILE" and fingerprint:
        out.append(f"RCQ_CADDYFILE={caddyfile}"); seen["RCQ_CADDYFILE"] = True
    else:
        out.append(line)
if not seen["POSTGRES_PASSWORD"]:
    out.append(f"POSTGRES_PASSWORD={pgpw}")
if fingerprint and not seen["RCQ_TLS_MODE"]:
    out.append("RCQ_TLS_MODE=fingerprint")
if fingerprint and not seen["RCQ_CADDYFILE"]:
    out.append(f"RCQ_CADDYFILE={caddyfile}")
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
DOMAIN_VAL=$(grep '^RCQ_DOMAIN=' .env | cut -d= -f2-)
# Absent from a .env written before fingerprint mode existed: that is CA.
TLS_MODE_VAL=$(grep '^RCQ_TLS_MODE=' .env | cut -d= -f2- | tr -d ' ' || true)

# A fingerprint island whose certificate is gone (a re-run on a box that
# lost certs/) cannot come up at all, so issue a new one. Loudly: a new
# certificate is a new fingerprint, and every user gets the red banner.
if [ "$TLS_MODE_VAL" = "fingerprint" ] && [ ! -s certs/island.crt ]; then
    warn "RCQ_TLS_MODE=fingerprint but certs/island.crt is missing: issuing a NEW certificate."
    warn "Every user of this island will be asked to trust the new fingerprint."
    issue_island_cert "$DOMAIN_VAL" "$(detect_public_ip)"
fi

say "Bringing up the stack…"
docker compose up -d --build

if [ "$TLS_MODE_VAL" = "fingerprint" ]; then
    FP=$(cert_fingerprint certs/island.crt)
    say "Waiting for Caddy to serve the island certificate (up to 60s)…"
    for _ in $(seq 1 12); do
        sleep 5
        # Two proofs, in that order: the wire presents exactly the
        # certificate in certs/ (the one the apps will pin), and the app
        # answers through it with curl trusting that file and nothing else.
        [ "$(presented_fingerprint "$DOMAIN_VAL")" = "$FP" ] || continue
        if curl -fsS -m 5 --cacert certs/island.crt "https://$DOMAIN_VAL/health" >/dev/null 2>&1; then
            echo
            say "${GREEN}Server is live at https://$DOMAIN_VAL${RESET}"
            echo
            echo "Certificate fingerprint (SHA-256), the one the apps show on first connection:"
            fingerprint_display "$FP" | sed 's/^/    /'
            echo
            echo "${BOLD}Give your users: $DOMAIN_VAL#$FP${RESET}"
            echo
            echo "Next steps:"
            echo "  • In RCQ on Android, iOS, the desktop or the CLI: add a server and enter"
            echo "    the line above, fingerprint included. Typed that way the app checks the"
            echo "    island against it before trusting anything. Without it the app pins"
            echo "    whatever it sees first and shows this fingerprint once, to compare."
            echo "  • The web client cannot join: a browser has no way to trust this certificate."
            echo "  • Print this again any time:  $INSTALL_DIR/deploy/island-fingerprint.sh"
            echo "  • Back up $INSTALL_DIR/certs/ together with .env: a lost key is a new"
            echo "    fingerprint for every user. Moving to a certificate authority later, and"
            echo "    rotating: $INSTALL_DIR/docs/tls-without-a-ca.md"
            echo
            echo "Operations:"
            echo "  Tail logs:    cd $INSTALL_DIR && docker compose logs -f app"
            echo "  Restart:      cd $INSTALL_DIR && docker compose restart app"
            echo "  Update now:   $INSTALL_DIR/deploy/rcq-update.sh"
            echo "  Update daily: see $INSTALL_DIR/docs/updating.md (off by default)"
            echo "  APNs setup:   $INSTALL_DIR/docs/apns.md"
            exit 0
        fi
    done

    warn "Health endpoint didn't respond in 60s. Diagnostics:"
    echo "  docker compose logs caddy   # did it load /certs/island.crt?"
    echo "  docker compose logs app     # app startup errors"
    echo "  openssl s_client -connect $DOMAIN_VAL:443 </dev/null | openssl x509 -noout -fingerprint -sha256"
    echo "  curl -v --cacert certs/island.crt https://$DOMAIN_VAL/health"
    exit 1
fi

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
        echo "  Update now:   $INSTALL_DIR/deploy/rcq-update.sh"
        echo "  Update daily: see $INSTALL_DIR/docs/updating.md (off by default)"
        echo "  APNs setup:   $INSTALL_DIR/docs/apns.md"
        exit 0
    fi
done

warn "Health endpoint didn't respond in 60s. Diagnostics:"
echo "  docker compose logs caddy   # Let's Encrypt issuance problems"
echo "  docker compose logs app     # app startup errors"
echo "  curl -v https://$DOMAIN_VAL/health"
exit 1
