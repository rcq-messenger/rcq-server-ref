"""Hourly island-wide activity counters, kept in Redis.

Why this exists next to `app/core/metrics.py`: the in-memory ring answers
"what is happening NOW" and deliberately dies with a deploy — and it counts
per WORKER, so with `--workers 4` it sees a quarter of the island. The
question the operator actually asks about activity ("when are the peaks?",
"was last night busier than the one before?") needs numbers that are
island-wide and survive restarts. Redis is both, and it is already a hard
dependency of the app.

One hash per UTC hour, `act:h:YYYYMMDDHH`, fields incremented from the hot
paths (a message accepted, a group send, a registration, a socket born, a
call ringing) plus an `online_max` peak written by a five-minute sampler off
the cluster-wide `ws:online_uins` set. Hashes expire after RETENTION_DAYS.

⚠ Counters must never cost the hot path anything: `bump_bg` is
fire-and-forget and swallows every error. A Redis hiccup loses a tick of
telemetry, not a message.
"""

import asyncio
import logging
from datetime import datetime, timezone

from app.core.redis import get_redis

log = logging.getLogger("rcq.activity")

RETENTION_DAYS = 45
SAMPLE_INTERVAL_S = 300

_KEY_PREFIX = "act:h:"
# When the counters started existing at all — the panel needs to tell "a
# quiet hour" apart from "an hour before this feature shipped".
_SINCE_KEY = "act:since"

FIELDS = ("msg", "gmsg", "reg", "ws", "call")


def hour_key(dt: datetime | None = None) -> str:
    dt = dt or datetime.now(timezone.utc)
    return _KEY_PREFIX + dt.strftime("%Y%m%d%H")


async def _bump(field: str, n: int) -> None:
    redis = await get_redis()
    key = hour_key()
    pipe = redis.pipeline(transaction=False)
    pipe.hincrby(key, field, n)
    pipe.expire(key, RETENTION_DAYS * 86400)
    pipe.set(_SINCE_KEY, datetime.now(timezone.utc).isoformat(), nx=True)
    await pipe.execute()


def bump_bg(field: str, n: int = 1) -> None:
    """Count one event into the current hour. Never raises, never awaited."""

    async def run() -> None:
        try:
            await _bump(field, n)
        except Exception:  # noqa: BLE001 — telemetry must not break the caller
            log.debug("activity bump dropped (%s)", field, exc_info=True)

    try:
        asyncio.get_running_loop().create_task(run())
    except RuntimeError:
        # No loop (sync test context) — the tick is not worth a thread.
        pass


async def activity_sampler_loop() -> None:
    """Every five minutes, record the cluster-wide online count into the
    current hour's `online_max`/`online_last`.

    SCARD over `ws:online_uins` can run a few ghosts high right after a
    worker dies (the SREM on disconnect is best-effort — see
    connection_manager), which is acceptable for a peak curve; the live
    console number stays the reconciled one in /admin/presence.
    """
    # Let the workers finish booting before the first sample.
    await asyncio.sleep(20)
    while True:
        try:
            from app.services.connection_manager import _ONLINE_KEY

            redis = await get_redis()
            n = int(await redis.scard(_ONLINE_KEY) or 0)
            key = hour_key()
            cur = int(await redis.hget(key, "online_max") or 0)
            pipe = redis.pipeline(transaction=False)
            if n > cur:
                pipe.hset(key, "online_max", n)
            pipe.hset(key, "online_last", n)
            pipe.expire(key, RETENTION_DAYS * 86400)
            pipe.set(_SINCE_KEY, datetime.now(timezone.utc).isoformat(), nx=True)
            await pipe.execute()
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            log.debug("activity sample dropped", exc_info=True)
        await asyncio.sleep(SAMPLE_INTERVAL_S)


async def read_hours(hours: int) -> tuple[list[dict], str | None]:
    """The last `hours` buckets, oldest first, zeros where nothing counted."""
    from datetime import timedelta

    redis = await get_redis()
    now = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
    stamps = [now - timedelta(hours=i) for i in range(hours - 1, -1, -1)]
    pipe = redis.pipeline(transaction=False)
    for dt in stamps:
        pipe.hgetall(hour_key(dt))
    raw = await pipe.execute()
    since = await redis.get(_SINCE_KEY)
    if isinstance(since, bytes):
        since = since.decode()

    points: list[dict] = []
    for dt, row in zip(stamps, raw):
        vals = {
            (k.decode() if isinstance(k, bytes) else k): int(v)
            for k, v in (row or {}).items()
        }
        points.append(
            {
                "hour": dt.isoformat(),
                **{f: vals.get(f, 0) for f in FIELDS},
                "online_max": vals.get("online_max", 0),
            }
        )
    return points, since
