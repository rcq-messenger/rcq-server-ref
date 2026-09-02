#!/usr/bin/env bash
#
# RCQ self-host installer.
#
# Usage on a fresh Ubuntu / Debian VPS, as root or via sudo:
#
#   curl -fsSL https://raw.githubusercontent.com/rcq-messenger/rcq-server-ref/main/install.sh | RCQ_DOMAIN=rcq.example.com bash
#   curl -fsSL https://raw.githubusercontent.com/rcq-messenger/rcq-server-ref/main/install.sh | RCQ_TLS=fingerprint bash
#
# ⚠ Piped in like that, the script IS bash's stdin, so it cannot ask anything:
# `read` would take the next line of this file as the answer (a blank one once
# selected fingerprint mode with nobody asked). With stdin not a terminal the
# script never prompts, wants RCQ_DOMAIN or RCQ_TLS in the environment, and
# otherwise behaves as RCQ_UNATTENDED. To be asked, save it first, which is
# the recommended way for any non-throwaway box anyway:
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
#   RCQ_ADDRESS    this host's public IP, for when the lookup is blocked or
#                  the box sits behind 1:1 NAT: it goes on the fingerprint
#                  certificate and into the line users type. Never guessed
#                  from the box's own interfaces (detect_public_ip says why).
#   RCQ_UNATTENDED non-empty -> never prompt; abort (don't hang) if DNS
#                  isn't ready yet, unless RCQ_FORCE=1 is also set
#   RCQ_FORCE      non-empty -> proceed on a DNS mismatch (ACME may fail
#                  until DNS propagates), and issue for a private address
#                  (an island meant for a LAN or a VPN)
#
# What this script does:
#   1. Installs Docker (via the official get-docker.com script) + git +
#      openssl + dig, if missing.
#   2. Clones rcq-server-ref into /opt/rcq-server (or $INSTALL_DIR if set).
#   3. Asks whether you have a domain (on a terminal; otherwise RCQ_DOMAIN
#      or RCQ_TLS decides). With one: sanity-checks its A-record points at
#      this host, refuses to continue on a DNS mismatch unless you confirm.
#      Without one: issues the island's own certificate for this host's
#      public IP (fingerprint mode).
#   4. Generates a fresh JWT_SECRET + POSTGRES_PASSWORD, writes a
#      production-shaped .env (mode 0600). Skipped if .env exists
#      already, so re-running the installer doesn't overwrite live
#      secrets.
#   5. Brings the stack up with `docker compose up -d --build`.
#   6. In fingerprint mode prints the fingerprint and the
#      `address#fingerprint` line to hand to your users FIRST, then waits
#      up to 60 seconds for Caddy to serve that certificate and for /health
#      to answer 200 through it; an address that answers with a different
#      certificate is a stop, not a wait. In CA mode waits the same way for
#      the Let's Encrypt certificate and /health.
#   7. Prints next-step instructions for wiring an iOS client at it
#      + ops cheat-sheet (logs / restart / update / APNs).
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

# ─────────────────────────────────────────────────────────────────────
# Questions. They need a terminal on stdin. Under the `curl … | bash`
# line above stdin IS the script, and `read` takes the next line of this
# file as the answer: a blank one once selected fingerprint mode with
# nobody asked, and before that failed the install as "Domain is
# required". So: no terminal, no questions, and every question turns
# into the environment variable that answers it. RCQ_UNATTENDED asks for
# the same behaviour on purpose.
# ─────────────────────────────────────────────────────────────────────
if [ -n "${RCQ_UNATTENDED:-}" ]; then
    CAN_ASK=""; CANNOT_ASK_WHY="RCQ_UNATTENDED is set"
elif [ -t 0 ]; then
    CAN_ASK=1; CANNOT_ASK_WHY=""
else
    CAN_ASK=""; CANNOT_ASK_WHY="stdin is not a terminal, as under \`curl … | bash\`"
fi

# ask VAR "prompt" "what answers it instead": the question when there can
# be one, else a stop that names the environment variable.
ask() {
    local var="$1" prompt="$2" instead="$3"
    [ -n "$CAN_ASK" ] || fail "Cannot ask ($CANNOT_ASK_WHY). $instead; or save the script and run \`bash install.sh\` to be asked."
    read -r -p "$prompt" "$var"
}

# y/N confirm, or under RCQ_FORCE none at all. Without a terminal it is an
# abort with $2: scripted provisioning must not hang on a prompt, and a
# pipe must not answer one.
confirm_or_abort() {
    local prompt="$1" abort_msg="$2" reply
    [ -z "${RCQ_FORCE:-}" ] || return 0
    [ -n "$CAN_ASK" ] || fail "$abort_msg (cannot ask: $CANNOT_ASK_WHY; set RCQ_FORCE=1 to go ahead anyway)"
    read -r -p "$prompt" reply
    [[ "${reply:-N}" =~ ^[Yy] ]] || fail "$abort_msg"
}

# ─────────────────────────────────────────────────────────────────────
# Fingerprint mode: an island without a certificate authority. The apps
# pin the SHA-256 fingerprint of the certificate below the way SSH pins a
# host key; docs/tls-without-a-ca.md is the operator's side of it.
# ─────────────────────────────────────────────────────────────────────

# An IPv4 dotted quad or an IPv6 literal, brackets or not. Two colons at
# least for IPv6: `island.example:8443` has one and is a name with a port.
is_ipv6_literal() {
    local a="${1#\[}"; a="${a%\]}"
    [[ "$a" == *:*:* ]] && [[ "$a" =~ ^[0-9A-Fa-f:.]+$ ]]
}
# The shape, and then whether it is an address at all: `203.0.113.300` has
# the shape, went into the SAN, and openssl's refusal came back as "OpenSSL
# 3 is required". python3 is installed before the first call (Required
# tooling), and ipaddress refuses exactly what openssl refuses.
is_ip_literal() {
    local a="${1#\[}"; a="${a%\]}"
    { [[ "$a" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || is_ipv6_literal "$a"; } \
        && python3 -c 'import ipaddress, sys; ipaddress.ip_address(sys.argv[1])' "$a" 2>/dev/null
}

# The address as it goes into a URL, after -connect, and into the line users
# type: an IPv6 literal in brackets (the apps key their trust on
# `[2001:db8::1]`, brackets included), everything else as it is.
url_host() {
    if is_ipv6_literal "$1" && [[ "$1" != \[* ]]; then printf '[%s]' "$1"; else printf '%s' "$1"; fi
}

# Brackets off, lowercase, and an IPv6 literal compressed: one spelling for
# the SAN, .env, the dig compare and the line users type. dig prints AAAA
# records compressed, so `2001:0db8::1` typed as RCQ_ADDRESS never matched
# the name's record and was handed out as typed, and the apps key their
# trust on the address as typed: `[2001:0db8::1]` and `[2001:db8::1]` were
# two islands. Anything ipaddress does not parse (a name, a typo) comes back
# as it is, for check_island_ip to judge.
normalise_ip() {
    local a="${1#\[}"; a="${a%\]}"
    a=$(printf '%s' "$a" | tr -d ' ' | tr '[:upper:]' '[:lower:]')
    python3 -c 'import ipaddress, sys; print(ipaddress.ip_address(sys.argv[1]).compressed)' "$a" 2>/dev/null \
        || printf '%s' "$a"
}

# RFC 1918, CGNAT (100.64/10), link-local and loopback, and the IPv6 kin
# (ULA fc00::/7, fe80::/10, ::1): nobody outside the network can dial them.
is_private_ip() {
    local a="${1#\[}"; a="${a%\]}"
    case "$a" in
        10.*|192.168.*|127.*|169.254.*) return 0 ;;
        172.1[6-9].*|172.2[0-9].*|172.3[01].*) return 0 ;;
        100.6[4-9].*|100.[7-9][0-9].*|100.1[01][0-9].*|100.12[0-7].*) return 0 ;;
        ::1|[fF][cCdD]*|[fF][eE][89aAbB]*) return 0 ;;
    esac
    return 1
}

# The public address: RCQ_ADDRESS when the operator says so, else what a
# lookup service sees us as; two of them, because one is blocked exactly
# where this mode is needed. Empty when neither answers, and the caller
# asks or stops.
#
# ⚠ Never the source address of the default route. On 1:1 NAT (most clouds)
# that is the private NIC address, and with both lookups blocked an island
# was once issued for, health-checked at (the box dials its own 10.x just
# fine) and handed out as 10.x without a word.
detect_public_ip() {
    local ip="${RCQ_ADDRESS:-}"
    [ -n "$ip" ] || ip=$(curl -fsS -m 5 https://api.ipify.org 2>/dev/null || true)
    [ -n "$ip" ] || ip=$(curl -fsS -m 5 https://ifconfig.me/ip 2>/dev/null || true)
    normalise_ip "$ip"
}

# The address the certificate is issued for has to be one users can reach.
# A private one is a stop, not a warning: nothing downstream would notice
# (the box dials it fine, the health check passes), and the first to notice
# would be a user with an address that goes nowhere. RCQ_FORCE says the
# LAN or the VPN is the point. Not a name either: a name goes in RCQ_DOMAIN
# and lands in the SAN as one. And not the unspecified address, which no
# lookup returns but a hand can type: nothing dials 0.0.0.0, with RCQ_FORCE
# or without, and openssl issues for it without a word.
check_island_ip() {
    local ip="$1"
    is_ip_literal "$ip" || fail "Not an IP address: $ip. RCQ_ADDRESS takes this host's public IP; a name goes in RCQ_DOMAIN."
    case "$ip" in
        0.0.0.0|::) fail "$ip is the unspecified address: nothing can dial it, so there is nothing to issue for. RCQ_ADDRESS takes this host's public IP." ;;
    esac
    is_private_ip "$ip" || return 0
    warn "$ip is a private address (RFC 1918, CGNAT, link-local or loopback): nobody outside this network can dial it."
    [ -n "${RCQ_FORCE:-}" ] || fail "Refusing to issue the island's certificate for $ip. Pass the public address as RCQ_ADDRESS=<ip>, or RCQ_FORCE=1 if this island is meant to live on a LAN or a VPN and $ip is what its users dial."
}

# Whether $1 resolves to $2, by any A or AAAA record (a CNAME chain ends in
# one). grep reads to the end on purpose: -q could quit before dig is done
# writing, and pipefail would then call a match a miss.
resolves_to() {
    { dig +short "$1" A 2>/dev/null || true; dig +short "$1" AAAA 2>/dev/null || true; } \
        | grep -xF "$2" >/dev/null
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
    local address="$1" ip="$2" san err
    if is_ip_literal "$address"; then san="IP:$address"; else san="DNS:$address"; fi
    if [ -n "$ip" ] && [ "$ip" != "$address" ]; then san="$san,IP:$ip"; fi
    mkdir -p certs
    # openssl's own words on failure, not a fixed hint: they name the value
    # it refused (`bad ip address ... value=203.0.113.300`), where the hint
    # sent an operator with a typo in RCQ_ADDRESS off to upgrade OpenSSL.
    if ! err=$(
        umask 077
        openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out certs/island.key 2>&1 \
        && openssl req -new -x509 -key certs/island.key -sha256 -days 3650 \
            -subj "/CN=$address" -addext "subjectAltName=$san" -out certs/island.crt 2>&1
    ); then
        err=$(printf '%s' "$err" | tr '\n' ' ')
        case "$err" in *[Uu]nknown\ option*) err="$err (the -addext option needs OpenSSL 3)" ;; esac
        fail "openssl could not issue the island certificate for $san: ${err:-no output}"
    fi
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

# The fingerprint of what the wire at $2 presents for address $1, the way
# a client will see it: SNI for a name, none for an IP (an IP is not a
# name, and a client never sends one). The socket goes to $2 whatever DNS
# says, so a name that does not point here yet is still checked at its IP.
# Empty when nothing answers.
presented_fingerprint() {
    local address="$1" via="$2" sni=()
    is_ip_literal "$address" || sni=(-servername "$address")
    local t=()
    command -v timeout >/dev/null 2>&1 && t=(timeout 10)
    ${t[@]+"${t[@]}"} openssl s_client -connect "$(url_host "$via"):443" ${sni[@]+"${sni[@]}"} </dev/null 2>/dev/null \
        | openssl x509 -noout -fingerprint -sha256 2>/dev/null \
        | cut -d= -f2 | tr -d ':' | tr '[:upper:]' '[:lower:]' || true
}

# Two proofs, in that order: the wire at $2 presents exactly the
# certificate in certs/ for address $1 (the one the apps will pin), and the
# app answers /health through it, with curl trusting that file and nothing
# else. --connect-to keeps the URL, and with it the name check, on the
# address while the socket goes to $2.
#
# Three answers, not two. 0: live. 2: nothing answered at $2, or the app is
# not up behind it yet; worth another round, and loopback is a fair second
# try. 1: the wire at $2 presented a DIFFERENT certificate, left in
# PRESENTED_FP. Waiting never fixes that one: whoever answers there is not
# this Caddy (RCQ_ADDRESS typed as a neighbour's IP, a port forward that
# lands elsewhere, something terminating TLS in front), or it is this Caddy
# still serving an old file. ⚠ Folded into "not yet" it let the loopback
# probe pass, and the installer called an island live on an address whose
# wire is somebody else's, right after handing that address out.
# deploy/island-fingerprint.sh calls the same wire a different certificate
# and stops; so does the installer now.
PRESENTED_FP=""
probe_island() {
    local address="$1" via="$2" fp="$3"
    PRESENTED_FP=$(presented_fingerprint "$address" "$via")
    [ -n "$PRESENTED_FP" ] || return 2
    [ "$PRESENTED_FP" = "$fp" ] || return 1
    curl -fsS -m 5 --cacert certs/island.crt --connect-to "::$(url_host "$via"):443" \
        "https://$(url_host "$address")/health" >/dev/null 2>&1 || return 2
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
    elif [ "$TLS_MODE" = "fingerprint" ]; then
        # Needs no name: the address is the public IP.
        DOMAIN=""
    elif [ "$TLS_MODE" = "ca" ]; then
        # The mode was chosen in the environment and only the name is
        # missing, so "no domain" is not an answer here: an operator who
        # said "ca" does not get a fingerprint island because they had no
        # name at hand, they get "Domain is required" below.
        ask DOMAIN "${BOLD}Public domain pointing at this host${RESET} (e.g. rcq.example.com): " \
            "RCQ_TLS=ca needs RCQ_DOMAIN=<name>"
    else
        ask HAS_DOMAIN "${BOLD}Do you have a domain name pointing at this host?${RESET} [y/N] " \
            "Pass RCQ_DOMAIN=<name> for a Let's Encrypt island, or RCQ_TLS=fingerprint for one without a certificate authority (docs/tls-without-a-ca.md)"
        if [[ "${HAS_DOMAIN:-N}" =~ ^[Yy] ]]; then
            ask DOMAIN "${BOLD}Public domain pointing at this host${RESET} (e.g. rcq.example.com): " \
                "Pass RCQ_DOMAIN=<name>"
        else
            DOMAIN=""
            TLS_MODE="fingerprint"
        fi
    fi

    if [ "$TLS_MODE" = "fingerprint" ]; then
        PUBLIC_IP=$(detect_public_ip)
        if [ -z "$PUBLIC_IP" ] && [ -z "${DOMAIN:-}" ]; then
            ask PUBLIC_IP "${BOLD}Could not detect the public IP of this host. Enter it:${RESET} " \
                "Could not detect this host's public IP (both lookups blocked?). Pass it as RCQ_ADDRESS=<ip>"
            PUBLIC_IP=$(normalise_ip "${PUBLIC_IP:-}")
            [ -n "$PUBLIC_IP" ] || fail "An address is required: the certificate is issued for it and your users type it in."
        fi
        if [ -n "$PUBLIC_IP" ]; then
            check_island_ip "$PUBLIC_IP"
        else
            warn "Could not detect this host's public IP: the certificate carries only $DOMAIN, and the IP form of the address will not work. RCQ_ADDRESS=<ip> puts it on."
        fi
        # The address users type and the certificate is issued for: the
        # name when there is one, else the IP. Never both: the apps key
        # their trust on the address, and only a name can move to a real
        # CA later, at the cost of one banner for the users who typed the
        # fingerprint and nothing for the rest (docs/tls-without-a-ca.md).
        DOMAIN="${DOMAIN:-$PUBLIC_IP}"
        if [ -n "$PUBLIC_IP" ] && ! is_ip_literal "$DOMAIN" && ! resolves_to "$DOMAIN" "$PUBLIC_IP"; then
            RESOLVED=$(dig +short "$DOMAIN" 2>/dev/null | tail -1 || true)
            warn "$DOMAIN resolves to ${RESOLVED:-nothing} but this host is $PUBLIC_IP. The certificate covers both, so the IP form of the address works meanwhile; the line to hand out below says which."
        fi
        say "No certificate authority: issuing the island's own certificate for ${DOMAIN}…"
        issue_island_cert "$DOMAIN" "$PUBLIC_IP"
    else
        [ -z "${DOMAIN:-}" ] && fail "Domain is required (Caddy + Let's Encrypt need one). Without a domain, set RCQ_TLS=fingerprint: see docs/tls-without-a-ca.md."

        # Best-effort DNS sanity check. Failing this isn't fatal — the
        # user might have just-configured DNS that's still propagating —
        # but we warn loudly so they don't end up debugging a wedged ACME
        # cert issuance for 30 minutes.
        RESOLVED=$(dig +short "$DOMAIN" 2>/dev/null | tail -1 || true)
        PUBLIC_IP=$(detect_public_ip)
        if [ -z "$RESOLVED" ]; then
            warn "$DOMAIN doesn't resolve. Configure the A-record to point at ${PUBLIC_IP:-this host}, then re-run."
            confirm_or_abort "Continue anyway? (y/N): " "Aborted. Configure DNS and re-run."
        elif [ -n "$PUBLIC_IP" ] && ! resolves_to "$DOMAIN" "$PUBLIC_IP"; then
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
        "RCQ_TLS_MODE": False, "RCQ_CADDYFILE": False, "APP_NAME": False}
for line in lines:
    key = line.split("=", 1)[0].strip() if "=" in line and not line.lstrip().startswith("#") else None
    if key == "ENV":
        out.append("ENV=prod"); seen["ENV"] = True
    elif key == "RCQ_DOMAIN":
        out.append(f"RCQ_DOMAIN={domain}"); seen["RCQ_DOMAIN"] = True
    elif key == "APP_NAME":
        # The island's public name until the operator types one in the admin
        # console: it is what /server/info answers with and, since
        # 2026.09.02.5, what an announcement is signed by. The template ships
        # "RCQ Backend", a developer-facing string that would go out under
        # every unlabelled post and would be frozen into those rows for good,
        # so a fresh install names itself after the address its members type.
        out.append(f"APP_NAME={domain}"); seen["APP_NAME"] = True
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
if not seen["APP_NAME"]:
    out.append(f"APP_NAME={domain}")
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
# lost certs/, or a restore that brought back one file of the pair) cannot
# come up at all, so issue a new one. Either file missing counts: Caddy
# needs both, and a certificate without its key is as gone as no
# certificate. Loudly: a new certificate is a new fingerprint, and every
# user gets the red banner.
if [ "$TLS_MODE_VAL" = "fingerprint" ] && { [ ! -s certs/island.crt ] || [ ! -s certs/island.key ]; }; then
    warn "RCQ_TLS_MODE=fingerprint but certs/island.crt or certs/island.key is missing: issuing a NEW certificate."
    warn "Every user of this island will be asked to trust the new fingerprint."
    if is_ip_literal "$DOMAIN_VAL"; then REISSUE_IP="$DOMAIN_VAL"; else REISSUE_IP=$(detect_public_ip); fi
    issue_island_cert "$DOMAIN_VAL" "$REISSUE_IP"
fi

say "Bringing up the stack…"
docker compose up -d --build

if [ "$TLS_MODE_VAL" = "fingerprint" ]; then
    FP=$(cert_fingerprint certs/island.crt)

    # Where the island is dialled from here, and what users can dial today.
    # An IP island: the IP. A name: its public IP, which the certificate
    # carries beside the name (the first run has it in hand, a re-run
    # detects it again), and whether DNS already points there. No IP
    # known at all leaves only the name to dial, so it counts as live.
    if is_ip_literal "$DOMAIN_VAL"; then
        ISLAND_IP="$DOMAIN_VAL"; NAME_LIVE=1
    else
        ISLAND_IP="${PUBLIC_IP:-}"
        [ -n "$ISLAND_IP" ] || ISLAND_IP=$(detect_public_ip)
        NAME_LIVE=""
        if [ -z "$ISLAND_IP" ] || resolves_to "$DOMAIN_VAL" "$ISLAND_IP"; then NAME_LIVE=1; fi
    fi

    # The fingerprint and the line to hand out come BEFORE the wait: they
    # are the certificate's, not the wire's, and the one thing an operator
    # must leave with. A wait that fails (DNS not there yet, a box that
    # cannot dial its own public address) used to take them with it.
    echo
    echo "Certificate fingerprint (SHA-256), the one the apps show on first connection:"
    fingerprint_display "$FP" | sed 's/^/    /'
    echo
    if [ -n "$NAME_LIVE" ]; then
        echo "${BOLD}Give your users: $(url_host "$DOMAIN_VAL")#$FP${RESET}"
    else
        echo "${BOLD}Give your users: $(url_host "$ISLAND_IP")#$FP${RESET}"
        echo "    $DOMAIN_VAL does not point at this host yet. The certificate carries the IP"
        echo "    too, so that is the address that works meanwhile. Once the A-record is live,"
        echo "    hand out $DOMAIN_VAL#$FP instead: only an island added"
        echo "    by name can move to a certificate authority later (users who typed the"
        echo "    fingerprint accept one banner then; nobody else notices). By IP, the address"
        echo "    itself changes, and everyone adds the island again."
    fi
    echo
    echo "Next steps:"
    echo "  • In RCQ on Android, iOS, the desktop or the CLI: add a server and enter"
    echo "    the line above, fingerprint included. Typed that way the app checks the"
    echo "    island against it before trusting anything. Without it the app pins"
    echo "    whatever it sees first and shows this fingerprint once, to compare."
    echo "  • The web client cannot join: a browser has no way to trust this certificate."
    echo "  • Print this again any time:  $INSTALL_DIR/deploy/island-fingerprint.sh"
    echo "  • Back up $INSTALL_DIR/certs/ together with .env (docs/backup-and-recovery.md):"
    echo "    a lost key is a new fingerprint for every user. Moving to a certificate"
    echo "    authority later, and rotating: $INSTALL_DIR/docs/tls-without-a-ca.md"
    echo

    # Dial the public address first, exactly as a user will; loopback
    # second, because a box behind NAT often cannot reach its own public
    # address and that says nothing about the island. Whichever answers
    # is reported as such.
    VIA=()
    if [ -n "$ISLAND_IP" ]; then VIA+=("$ISLAND_IP"); else VIA+=("$DOMAIN_VAL"); fi
    VIA+=(127.0.0.1)
    SNI_HINT=""
    is_ip_literal "$DOMAIN_VAL" || SNI_HINT=" -servername $DOMAIN_VAL"
    LIVE_VIA=""; FOREIGN_VIA=""; FOREIGN_FP=""
    say "Waiting for Caddy to serve the island certificate (up to 60s)…"
    DEADLINE=$((SECONDS + 60))
    while [ "$SECONDS" -lt "$DEADLINE" ]; do
        sleep 5
        for via in "${VIA[@]}"; do
            probe_island "$DOMAIN_VAL" "$via" "$FP" && rc=0 || rc=$?
            case "$rc" in
                0) LIVE_VIA="$via"; break 2 ;;
                1) FOREIGN_VIA="$via"; FOREIGN_FP="$PRESENTED_FP"; break 2 ;;
            esac
            # Nothing answered at $via: the next one, then another round.
        done
    done

    # A different certificate on the wire is a stop, not a wait, and not a
    # reason to try loopback: the line above must not go out for an address
    # whose wire is not this island. Users who typed it would be told the
    # island is intercepted, or pin the wrong host on first use.
    if [ -n "$FOREIGN_VIA" ]; then
        echo
        warn "https://$(url_host "$FOREIGN_VIA") presents a DIFFERENT certificate than certs/island.crt:"
        echo "    on the wire:  $FOREIGN_FP"
        echo "    in the file:  $FP"
        if [ "$FOREIGN_VIA" = 127.0.0.1 ]; then
            echo "  Caddy on this box is serving another file. It reads certs/ at start, so after a"
            echo "  re-issue it needs:  docker compose restart caddy   (docker compose logs caddy says"
            echo "  which files it loaded)."
        else
            echo "  Whatever answers at that address is not this island: RCQ_ADDRESS is not this box's"
            echo "  public IP, or 443 there is forwarded somewhere else, or something in front of the"
            echo "  box terminates TLS. Do NOT hand out the line above until that address is this"
            echo "  island. A wrong address: put the right one in RCQ_DOMAIN in .env, remove"
            echo "  certs/island.crt and certs/island.key, and re-run install.sh (it issues for the"
            echo "  corrected address, and nobody holds the old line yet). A forward or a front: fix"
            echo "  it and re-run."
        fi
        echo "  $INSTALL_DIR/deploy/island-fingerprint.sh   # the file against the wire, any time"
        exit 1
    fi

    if [ -n "$LIVE_VIA" ]; then
        echo
        if [ "$LIVE_VIA" = "${VIA[0]}" ]; then
            LIVE_AT="$DOMAIN_VAL"; [ -n "$NAME_LIVE" ] || LIVE_AT="$ISLAND_IP"
            say "${GREEN}Server is live at https://$(url_host "$LIVE_AT")${RESET}"
        else
            say "${GREEN}Server is live${RESET}, answered over loopback: this box cannot dial $(url_host "${VIA[0]}") itself,"
            echo "    which NAT often forbids and which says nothing about users. From another machine:"
            echo "    openssl s_client -connect $(url_host "${VIA[0]}"):443$SNI_HINT </dev/null | openssl x509 -noout -fingerprint -sha256"
        fi
        echo
        echo "Operations:"
        echo "  Tail logs:    cd $INSTALL_DIR && docker compose logs -f app"
        echo "  Restart:      cd $INSTALL_DIR && docker compose restart app"
        echo "  Update now:   $INSTALL_DIR/deploy/rcq-update.sh"
        echo "  Update daily: see $INSTALL_DIR/docs/updating.md (off by default)"
        echo "  APNs setup:   $INSTALL_DIR/docs/apns.md"
        exit 0
    fi

    warn "Nothing answered on 443 in 60s, at $(url_host "${VIA[0]}") or over loopback. The fingerprint above is the file's and stays right; what is not proven is that the wire serves it. Diagnostics:"
    echo "  docker compose logs caddy   # did it load /certs/island.crt and /certs/island.key?"
    echo "  docker compose logs app     # app startup errors"
    echo "  openssl s_client -connect $(url_host "${VIA[0]}"):443$SNI_HINT </dev/null | openssl x509 -noout -fingerprint -sha256"
    echo "  curl -v --cacert certs/island.crt https://$(url_host "$DOMAIN_VAL")/health"
    echo "  $INSTALL_DIR/deploy/island-fingerprint.sh   # the line again, and the file against the wire"
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
