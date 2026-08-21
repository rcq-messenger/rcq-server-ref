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

⚠ Until 2026-08-22 the paragraph above described the OUTPUT accurately and the
storage not at all: two lines below it the bucket kept `set[int]` of uins and a
`dict[uin -> chains]`, for sixty rolling minutes, and the metadata audit found
it (§1.8). It now keeps [_pseudonym] values instead. Every number this module
publishes is bit-for-bit what it was (both consumers want cardinality, one
`len()` and one `max()`), and there is no uin left in the process to read.
"""

from __future__ import annotations

import hashlib
import os
import time
from collections import defaultdict
from dataclasses import dataclass, field

# Per-process, per-boot salt for [_pseudonym]. Never written down, never sent
# anywhere, gone when the worker restarts.
_PSEUDONYM_SALT = os.urandom(16)


def _pseudonym(uin: int) -> int:
    """A stand-in number for one account, stable within this worker process.

    The two structures that hold these need CARDINALITY and nothing else: "how
    many distinct accounts this minute" and "how many boot chains did the
    busiest of them start". Neither ever prints a uin, so neither ever needed
    one, and a hash preserves both answers exactly.

    Random per-process salt on purpose, and note that this is the OPPOSITE
    choice from `core/rate_limit.bucket_name`, which derives its secret from
    the JWT secret so all four workers agree. The reasoning is the same
    reasoning reaching a different answer: the limiter's buckets HAVE to be
    shared across workers or every limit multiplies by four, while these
    buckets are per-process, in-memory and served to the panel by whichever
    worker answered, so there is nothing to gain from a value that survives a
    restart, and something to lose from one an attacker could recompute.
    """
    return int.from_bytes(
        hashlib.blake2b(_PSEUDONYM_SALT + str(uin).encode("ascii"), digest_size=8).digest(),
        "big",
    )


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
    # How each request reached us: direct / front / relay. Counted here rather
    # than parsed out of Caddy's log because the log masks client addresses now
    # (see core/transport.py) and an exact relay match needs the whole one.
    transport: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    seconds: dict[str, float] = field(default_factory=lambda: defaultdict(float))
    errors: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    # Slowest single call per path this minute: an average hides the one
    # request that took four seconds behind ninety that took thirty
    # milliseconds, and the slow one is the one a person felt.
    worst: dict[str, float] = field(default_factory=lambda: defaultdict(float))
    # [_pseudonym] values, NOT uins. The names say so because the previous
    # names (`accounts`, `boot_chains_by_uin`) are what made it easy to read
    # the header's promise and the field list as agreeing with each other.
    account_ids: set[int] = field(default_factory=set)
    boot_chains: int = 0
    boot_chains_by_account: dict[int, int] = field(default_factory=lambda: defaultdict(int))
    sockets_opened: int = 0
    sockets_closed: int = 0
    sockets_refused: int = 0
    # Sampled once per request rather than averaged: pool saturation is a
    # high-water mark question ("did we run out"), not an average one.
    pool_peak_in_use: int = 0
    # Requests that found every connection already handed out. NOT a wait
    # time: SQLAlchemy gives no hook between asking for a connection and
    # getting one, so this is the honest measurable thing — how often we were
    # AT the wall. A minute of these with no 5xx means the pool is fully used
    # and nobody timed out; the same minute with 5xx is starvation.
    pool_at_ceiling: int = 0


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
    pool_ceiling: int | None = None,
    transport: str | None = None,
) -> None:
    b = _bucket()
    b.calls[path] += 1
    if transport:
        b.transport[transport] += 1
    b.seconds[path] += seconds
    if seconds > b.worst[path]:
        b.worst[path] = seconds
    if status_code >= 500:
        b.errors[path] += 1
    if uin is not None:
        # Hashed on the way IN, so the uin never lands in the ring at all.
        account = _pseudonym(uin)
        b.account_ids.add(account)
        if path == BOOT_CHAIN_PATH:
            b.boot_chains += 1
            b.boot_chains_by_account[account] += 1
    if pool_in_use is not None:
        if pool_in_use > b.pool_peak_in_use:
            b.pool_peak_in_use = pool_in_use
        if pool_ceiling and pool_in_use >= pool_ceiling:
            b.pool_at_ceiling += 1


def record_socket(opened: bool) -> None:
    b = _bucket()
    if opened:
        b.sockets_opened += 1
    else:
        b.sockets_closed += 1


def record_socket_refused() -> None:
    """A dial turned away by the per-account connect ceiling. Counted apart
    from opens and closes: a refusal is not a session that ended, it is one
    that never started, and mixing them would hide whether the ceiling is
    doing anything."""
    _bucket().sockets_refused += 1


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
                "boot_chains": 0, "sockets_opened": 0, "sockets_closed": 0, "sockets_refused": 0,
                "pool_peak_in_use": 0, "pool_at_ceiling": 0, "busiest_account_chains": 0,
            })
            continue
        series.append({
            "minute": minute,
            "requests": sum(b.calls.values()),
            "errors": sum(b.errors.values()),
            "accounts": len(b.account_ids),
            "boot_chains": b.boot_chains,
            "sockets_opened": b.sockets_opened,
            "sockets_closed": b.sockets_closed,
            "sockets_refused": b.sockets_refused,
            "pool_peak_in_use": b.pool_peak_in_use,
            "pool_at_ceiling": b.pool_at_ceiling,
            # The single busiest account's chain count, unnamed. A healthy
            # minute has this in the low single digits; the storm had one
            # account at 160.
            "busiest_account_chains": max(b.boot_chains_by_account.values(), default=0),
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

    # Transport totals over the same window. Exact, unlike the log-derived
    # figure, because the address was whole when it was classified.
    transport: dict[str, int] = defaultdict(int)
    for b in wanted:
        if b is None:
            continue
        for kind, n in b.transport.items():
            transport[kind] += n

    return {
        "minutes": minutes,
        "series": series,
        "paths": paths,
        "transport": dict(transport),
    }
