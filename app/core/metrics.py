"""What this island is actually doing, minute by minute.

Everything here is in-process and in-memory: a ring of one-minute buckets, a
counter or two per bucket, and nothing written to disk. That is deliberate.
The questions this has to answer are all "what is happening RIGHT NOW and what
was happening an hour ago" — which endpoint is being hammered, how long
`/groups` takes, whether the database pool is the wall we are hitting — and
those were answered until now by ssh'ing in and reading Caddy logs by hand.
Caddy's log also cannot answer half of them: it sees a request and a duration
to the client, not our own work, not the pool, not who was asking.

⚠ Deliberately NOT a per-account history. The bucket keeps how many DISTINCT
accounts were seen and how many boot chains they started, not which ones. An
operator panel that quietly turned into a per-user request log would be a
worse thing to run than the problem it solves; the one place a uin matters
(one client in a loop drowning the island) is served by the top-talker count
without naming anyone.
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field

# One hour at a minute each. Long enough to see a spike and what preceded it,
# small enough that the whole structure is a few hundred kilobytes.
WINDOW_MINUTES = 60

# A boot chain is the burst of requests a client fires when it starts: the
# contact list, the groups, the queue, presence, capabilities. Counting the
# chains rather than the requests is what made the socket storm legible —
# one account was starting 2.7 of them a second, which no per-endpoint rate
# would have named as a single broken client.
BOOT_CHAIN_PATH = "/contacts"


@dataclass
class Bucket:
    minute: int
    # path template -> (count, total seconds, errors)
    calls: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    seconds: dict[str, float] = field(default_factory=lambda: defaultdict(float))
    errors: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    # Slowest single call per path this minute: an average hides the one
    # request that took four seconds behind ninety that took thirty
    # milliseconds, and the slow one is the one a person felt.
    worst: dict[str, float] = field(default_factory=lambda: defaultdict(float))
    accounts: set[int] = field(default_factory=set)
    boot_chains: int = 0
    boot_chains_by_uin: dict[int, int] = field(default_factory=lambda: defaultdict(int))
    sockets_opened: int = 0
    sockets_closed: int = 0
    # Sampled once per request rather than averaged: pool saturation is a
    # high-water mark question ("did we run out"), not an average one.
    pool_peak_in_use: int = 0
    pool_waits: int = 0


_buckets: dict[int, Bucket] = {}


def _now_minute() -> int:
    return int(time.time() // 60)


def _bucket() -> Bucket:
    m = _now_minute()
    b = _buckets.get(m)
    if b is None:
        b = _buckets[m] = Bucket(minute=m)
        # Drop anything older than the window. Done on write so there is no
        # timer to own and nothing to leak when the island is idle.
        for old in [k for k in _buckets if k <= m - WINDOW_MINUTES]:
            _buckets.pop(old, None)
    return b


def record_request(
    path: str,
    seconds: float,
    status_code: int,
    uin: int | None,
    pool_in_use: int | None = None,
    pool_waited: bool = False,
) -> None:
    b = _bucket()
    b.calls[path] += 1
    b.seconds[path] += seconds
    if seconds > b.worst[path]:
        b.worst[path] = seconds
    if status_code >= 500:
        b.errors[path] += 1
    if uin is not None:
        b.accounts.add(uin)
        if path == BOOT_CHAIN_PATH:
            b.boot_chains += 1
            b.boot_chains_by_uin[uin] += 1
    if pool_in_use is not None and pool_in_use > b.pool_peak_in_use:
        b.pool_peak_in_use = pool_in_use
    if pool_waited:
        b.pool_waits += 1


def record_socket(opened: bool) -> None:
    b = _bucket()
    if opened:
        b.sockets_opened += 1
    else:
        b.sockets_closed += 1


def snapshot(minutes: int = 60, top_paths: int = 12) -> dict:
    """The last `minutes` of buckets, oldest first, plus a per-path roll-up."""
    m = _now_minute()
    wanted = [_buckets.get(k) for k in range(m - minutes + 1, m + 1)]

    series = []
    for i, b in enumerate(wanted):
        minute = m - minutes + 1 + i
        if b is None:
            series.append({
                "minute": minute, "requests": 0, "errors": 0, "accounts": 0,
                "boot_chains": 0, "sockets_opened": 0, "sockets_closed": 0,
                "pool_peak_in_use": 0, "pool_waits": 0, "busiest_account_chains": 0,
            })
            continue
        series.append({
            "minute": minute,
            "requests": sum(b.calls.values()),
            "errors": sum(b.errors.values()),
            "accounts": len(b.accounts),
            "boot_chains": b.boot_chains,
            "sockets_opened": b.sockets_opened,
            "sockets_closed": b.sockets_closed,
            "pool_peak_in_use": b.pool_peak_in_use,
            "pool_waits": b.pool_waits,
            # The single busiest account's chain count, unnamed. A healthy
            # minute has this in the low single digits; the storm had one
            # account at 160.
            "busiest_account_chains": max(b.boot_chains_by_uin.values(), default=0),
        })

    totals: dict[str, dict] = {}
    for b in wanted:
        if b is None:
            continue
        for path, n in b.calls.items():
            t = totals.setdefault(path, {"path": path, "calls": 0, "seconds": 0.0, "errors": 0, "worst": 0.0})
            t["calls"] += n
            t["seconds"] += b.seconds[path]
            t["errors"] += b.errors[path]
            t["worst"] = max(t["worst"], b.worst[path])
    paths = sorted(totals.values(), key=lambda t: t["seconds"], reverse=True)[:top_paths]
    for t in paths:
        # Mean seconds per call, which with `worst` beside it says both how
        # heavy a path is on average and how bad it gets.
        t["mean_ms"] = round(1000 * t["seconds"] / t["calls"], 1) if t["calls"] else 0.0
        t["worst_ms"] = round(1000 * t["worst"], 1)
        t["per_min"] = round(t["calls"] / max(1, minutes), 2)
        t.pop("seconds", None)
        t.pop("worst", None)

    return {"minutes": minutes, "series": series, "paths": paths}
