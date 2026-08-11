"""How a request reached this island: direct, through the Cloudflare front, or
out of one of our own relays.

⚠ Why this lives in the backend at all. The same question was already answered
hourly by `scripts/transport-mix.py`, which parses Caddy's access log. That
worked until the log started masking client addresses to /24 so a user's
address stops landing on disk — and the relay test, which compared the logged
address to an exact relay IP, stopped matching anything. The panel then read
"relay: 0" for four hours while 29% of traffic was in fact coming out of
relays, which looks exactly like the fleet dying.

This module answers it where the address is still whole: in the request, before
anything is written down. Nothing here stores an IP. It reads one, compares it
against two lists, and keeps a counter — the same thing the log parser did,
minus the part where the address had to survive on disk to be counted.

The log parser stays for the long view and for the country breakdown; this is
the live, exact number.
"""

from __future__ import annotations

import ipaddress
import os
from functools import lru_cache

# Cloudflare's published egress ranges. A request arriving from one of these is
# a request that came through the front rather than straight at the island.
# Kept in sync with the same list in scripts/transport-mix.py.
CF_RANGES = (
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
)

RELAYS_YAML = os.environ.get("RCQ_RELAYS_YAML", "/opt/rcq/relay/relays.yaml")


@lru_cache(maxsize=1)
def _cf_networks() -> tuple[ipaddress.IPv4Network, ...]:
    return tuple(ipaddress.ip_network(n) for n in CF_RANGES)


@lru_cache(maxsize=1)
def _relay_addresses() -> frozenset[str]:
    """Our relay machines, read once per process.

    Best-effort by design: a missing file (a self-hosted island that runs no
    relays, a dev box) just means relay traffic reads as direct, which is what
    it looked like before this existed. It does not mean an error page.

    ⚠ Cached for the life of the process, so a fleet change needs a backend
    restart to show up here. Deploys are frequent and a relay's address change
    already requires a signed-config push, so this has not been worth a watcher.
    """
    try:
        import yaml  # noqa: PLC0415 — optional dependency, only needed here

        with open(RELAYS_YAML) as fh:
            data = yaml.safe_load(fh) or {}
    except Exception:
        return frozenset()
    out = set()
    for r in data.get("relays") or []:
        server = r.get("server") if isinstance(r, dict) else None
        if server:
            out.add(str(server))
    return frozenset(out)


def classify(ip: str | None) -> str:
    """`direct` | `front` | `relay` for one client address.

    Unparseable or absent reads as `direct`: it is the honest default for "we
    could not tell", and it never invents relay usage that did not happen.
    """
    if not ip:
        return "direct"
    if ip in _relay_addresses():
        return "relay"
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "direct"
    if addr.version == 4 and any(addr in net for net in _cf_networks()):
        return "front"
    return "direct"
