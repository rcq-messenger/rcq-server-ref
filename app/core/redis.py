"""Async Redis client + lifecycle hooks for the multi-worker era.

Single shared client per worker process. Backed by `redis.asyncio` (the
official async client), which uses an internal connection pool tuned
for the kind of small-payload, high-frequency calls our app makes:
sliding-window rate buckets, fanout-pubsub, queue ops, etc.

What lives here
---------------
- `get_redis()` — module-level accessor returning the singleton client.
  Lazy-init: the first call constructs the pool, subsequent calls
  reuse it. No need to pass a client around dependency-tree.

- `init_redis()` / `close_redis()` — startup / shutdown hooks. Wired
  from `app.main`'s lifespan span.

- `LEADER_KEY_PREFIX` + `acquire_leadership()` / `release_leadership()`
  — primitives for the leader-elected background loops (crash game
  round loop, UIN auction loop, random-chat expire loop). Built on
  Redis SETNX with TTL so a crashed leader's lock auto-expires and
  another worker can take over.

Connection target
-----------------
Reads `REDIS_URL` env var; defaults to `redis://localhost:6379/0` for
local dev (which is also where prod Redis listens, since it lives on
the same droplet as the FastAPI process — pub/sub latency is in
microseconds when client + server share localhost).
"""
from __future__ import annotations

import asyncio
import logging
import os

from redis.asyncio import Redis, from_url

log = logging.getLogger(__name__)

# Single per-process client. Constructed on first `get_redis()`
# call; reused thereafter. Connection pooling lives inside the
# client itself.
_client: Redis | None = None
_client_lock = asyncio.Lock()


def _redis_url() -> str:
    return os.environ.get("REDIS_URL", "redis://localhost:6379/0")


async def get_redis() -> Redis:
    """Return the singleton Redis client. Lazy-init on first call."""
    global _client
    if _client is not None:
        return _client
    async with _client_lock:
        if _client is None:
            _client = from_url(
                _redis_url(),
                decode_responses=True,
                encoding="utf-8",
                health_check_interval=30,
            )
            # Cheap smoke-test on first hit so a misconfigured URL
            # surfaces immediately rather than at the first real call.
            try:
                await _client.ping()
                log.info("Redis client connected: %s", _redis_url())
            except Exception as exc:  # noqa: BLE001
                log.exception("Redis ping failed: %s", exc)
                # Keep the client around — `from_url` doesn't open a
                # connection until a command runs, so the pool is fine
                # to reuse once Redis comes back up.
        assert _client is not None  # for type checker
        return _client


async def close_redis() -> None:
    """Tear the client down on shutdown. Safe to call multiple times."""
    global _client
    if _client is None:
        return
    try:
        await _client.aclose()
    except Exception:  # noqa: BLE001
        pass
    _client = None


# ── Leader election ────────────────────────────────────────────────
#
# Pattern: a worker holds the leadership lock by setting a Redis key
# with a TTL. As long as the leader heartbeats (refreshes the key
# before TTL expires), it owns the loop. If the leader dies, the key
# expires within `LEADER_TTL_SECONDS` and another worker can take
# over by doing the SETNX again.
#
# The lock value is the worker's process id + a random fingerprint,
# so a worker that loses the lock (because it stalled past TTL) can
# detect that someone else now holds it and back off cleanly.

LEADER_KEY_PREFIX = "leader:"
# Lock duration. Long enough that a transient pause (GC, slow query)
# doesn't lose leadership; short enough that a crashed leader is
# replaced within ~30 seconds.
LEADER_TTL_SECONDS: int = 30
# How often the leader refreshes its lock. Refreshing at half the TTL
# keeps the lock alive even if a heartbeat lags.
LEADER_RENEW_SECONDS: int = LEADER_TTL_SECONDS // 2


async def acquire_leadership(role: str, identity: str) -> bool:
    """Try to become the leader for `role`. Returns True if we got it,
    False if somebody else already holds the lock.

    `identity` should be a stable per-worker string (e.g. `f"{pid}-{uuid}"`)
    so heartbeats and release calls can verify ownership.
    """
    redis = await get_redis()
    key = LEADER_KEY_PREFIX + role
    # NX = only set if key doesn't exist. EX = TTL in seconds.
    ok = await redis.set(key, identity, nx=True, ex=LEADER_TTL_SECONDS)
    return bool(ok)


async def renew_leadership(role: str, identity: str) -> bool:
    """Refresh our hold on the leader lock. Returns False if we no
    longer own it (someone else took over while we were processing).

    Uses a small Lua script for the check-and-set so the verify and
    extend happen atomically — without it, a leader could read the
    value, see itself, then have another worker take over before the
    EXPIRE call lands.
    """
    redis = await get_redis()
    key = LEADER_KEY_PREFIX + role
    script = """
    if redis.call('GET', KEYS[1]) == ARGV[1] then
        redis.call('EXPIRE', KEYS[1], ARGV[2])
        return 1
    end
    return 0
    """
    result = await redis.eval(script, 1, key, identity, LEADER_TTL_SECONDS)
    return bool(result)


async def release_leadership(role: str, identity: str) -> None:
    """Voluntarily release the lock on shutdown. Safe to call even if
    we don't currently hold it (the Lua check ensures we only DEL our
    own value)."""
    redis = await get_redis()
    key = LEADER_KEY_PREFIX + role
    script = """
    if redis.call('GET', KEYS[1]) == ARGV[1] then
        redis.call('DEL', KEYS[1])
        return 1
    end
    return 0
    """
    try:
        await redis.eval(script, 1, key, identity)
    except Exception:  # noqa: BLE001
        pass
