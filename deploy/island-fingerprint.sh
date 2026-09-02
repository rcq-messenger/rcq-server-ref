#!/usr/bin/env bash
#
# What to hand a user of an island run without a certificate authority: the
# SHA-256 fingerprint of certs/island.crt and the `address#fingerprint` line,
# in the forms the apps use (docs/tls-without-a-ca.md).
#
#   deploy/island-fingerprint.sh        # from anywhere; finds the checkout itself
#
# Reads .env for the mode and the address, the certificate from certs/, and
# then asks the running island what it actually presents. ⚠ That last step is
# the reason this script exists: after a rotation Caddy keeps serving the OLD
# certificate until it is restarted, and the file on disk says nothing about
# that. Exit 1 when the wire and the file disagree.

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

env_value() {
    # ⚠ RCQ_DOMAIN may list several names, comma-separated (Caddy accepts
    # that in CA mode); the first is the address.
    grep -E "^$1=" .env 2>/dev/null | cut -d= -f2- | cut -d, -f1 | tr -d ' ' || true
}

is_ip_literal() {
    [[ "$1" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || [[ "$1" == *:* ]]
}

# openssl's `sha256 Fingerprint=AB:CD:…` to the canonical form the apps store
# and the address carries: 64 lowercase hex characters, no separators.
canonical() {
    cut -d= -f2 | tr -d ':' | tr '[:upper:]' '[:lower:]'
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

MODE=$(env_value RCQ_TLS_MODE)
ADDRESS=$(env_value RCQ_DOMAIN)

if [ "${MODE:-ca}" != "fingerprint" ]; then
    echo "This island is trusted through a certificate authority (RCQ_TLS_MODE=${MODE:-ca})."
    echo "There is no fingerprint to compare: the apps verify the certificate chain the"
    echo "way a browser does, and the certificate changes on every renewal anyway."
    echo "Running without a certificate authority: docs/tls-without-a-ca.md"
    exit 0
fi

if [ ! -s certs/island.crt ]; then
    echo "RCQ_TLS_MODE=fingerprint but certs/island.crt is missing. Restore it from your" >&2
    echo "backup, or re-run install.sh to issue a new one (a new fingerprint for every user)." >&2
    exit 1
fi
if [ -z "$ADDRESS" ]; then
    echo "RCQ_DOMAIN is empty in .env; it is the address that goes before the #." >&2
    exit 1
fi

FP=$(openssl x509 -noout -fingerprint -sha256 -in certs/island.crt | canonical)
UNTIL=$(openssl x509 -noout -enddate -in certs/island.crt | cut -d= -f2)

echo "Island certificate: certs/island.crt (valid until $UNTIL)"
echo
echo "SHA-256 fingerprint, as the apps show it:"
fingerprint_display "$FP" | sed 's/^/    /'
echo
echo "Canonical form:  $FP"
echo "Give your users: $ADDRESS#$FP"
echo

# What the wire presents, the way a client sees it: SNI for a name, none for
# an IP (an IP is not a name, and a client never sends one as SNI).
SNI=()
is_ip_literal "$ADDRESS" || SNI=(-servername "$ADDRESS")
T=()
command -v timeout >/dev/null 2>&1 && T=(timeout 10)
LIVE=$(${T[@]+"${T[@]}"} openssl s_client -connect "$ADDRESS:443" ${SNI[@]+"${SNI[@]}"} </dev/null 2>/dev/null \
    | openssl x509 -noout -fingerprint -sha256 2>/dev/null | canonical || true)

if [ -z "$LIVE" ]; then
    echo "Could not reach https://$ADDRESS from here to compare (not up yet, or this box"
    echo "cannot dial its own public address). Users see whatever the wire presents:"
    echo "    openssl s_client -connect $ADDRESS:443 </dev/null | openssl x509 -noout -fingerprint -sha256"
elif [ "$LIVE" = "$FP" ]; then
    echo "Live check: https://$ADDRESS presents this certificate."
else
    echo "⚠ Live check: https://$ADDRESS presents a DIFFERENT certificate:"
    echo "    $LIVE"
    echo "  Caddy is still serving the old file. Restart it: docker compose restart caddy"
    exit 1
fi
