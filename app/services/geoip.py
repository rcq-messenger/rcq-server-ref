"""IP -> ISO country lookup for region-scoped relay liveness.

The broker serves a community relay to a client only where it's actually
reachable (region quorum, see routers/broker.py). "Region" is the reporter's
country, derived here from a compact, vendored IP->country table compiled from
the public RIR delegation files (tools/build_geoip.py). No external service, no
licensed DB, no runtime updates — just a static ~1 MB data file bisected in
memory.

Degrades safely: if the data file is absent or unreadable the server still boots
and country_of() returns "ZZ" (unknown) for everything, which the broker treats
as a single catch-all region.
"""
import bisect
import gzip
import ipaddress
import logging
import os

log = logging.getLogger(__name__)

UNKNOWN = "ZZ"
_DATA = os.path.join(os.path.dirname(__file__), "..", "data", "geoip_cc.csv.gz")

# Parallel sorted arrays for a cheap bisect: _starts[i] <= ip <= _ends[i] -> _ccs[i].
_starts: list[int] = []
_ends: list[int] = []
_ccs: list[str] = []


def _load() -> None:
    if not os.path.exists(_DATA):
        log.warning("geoip: %s missing — region detection disabled (all=ZZ)", _DATA)
        return
    try:
        with gzip.open(_DATA, "rt", encoding="ascii") as fh:
            for line in fh:
                s, e, cc = line.rstrip("\n").split(",")
                _starts.append(int(s))
                _ends.append(int(e))
                _ccs.append(cc)
        log.info("geoip: loaded %d ranges", len(_starts))
    except (OSError, ValueError) as exc:  # corrupt file: fail open, don't crash boot
        log.warning("geoip: failed to load %s (%s) — region detection disabled", _DATA, exc)
        _starts.clear(); _ends.clear(); _ccs.clear()


_load()


def country_of(ip: str) -> str:
    """ISO-3166 alpha-2 country for an IPv4 address, or "ZZ" if unknown / IPv6 /
    no table. Never raises — a bad input maps to "ZZ"."""
    if not _starts:
        return UNKNOWN
    try:
        addr = ipaddress.ip_address(ip.strip("[]"))
    except ValueError:
        return UNKNOWN
    if addr.version != 4:
        return UNKNOWN  # IPv4-only table for now
    n = int(addr)
    # Rightmost range whose start <= n, then bounds-check its end.
    i = bisect.bisect_right(_starts, n) - 1
    if i >= 0 and n <= _ends[i]:
        return _ccs[i]
    return UNKNOWN
