"""One-worker-per-cycle election for the periodic background sweeps.

`app.main.lifespan` runs in EVERY uvicorn worker, so every `--workers 4`
deployment was running four copies of each sweep loop simultaneously. That
was survivable while the sweeps were near no-ops, and stopped being
survivable the moment the offline-queue sweep started issuing batched
DELETEs: four workers hammered the same half-million rows at once, taking
four pooled DB connections and contending on the same row locks.

The random-chat expire loop already solved this with the Redis leader lock
in `app.core.redis`, but its shape assumes a fast tick it can renew inside.
A sweep that runs every 5 minutes to 6 hours wants the opposite: claim the
lock for THIS cycle, do the work, and let the claim lapse so the next cycle
re-elects freely (any worker may win; none is special).

The claim must therefore last most of the CYCLE, not `LEADER_TTL_SECONDS`
(30s). That distinction is not academic: workers do not boot together — a
cold start runs the schema migration and can take a minute — so with a 30s
claim the late workers found the key already expired and every one of them
elected itself. Observed on prod as three workers issuing batched DELETEs
against the same table at once.

Fail-open on Redis trouble: a sweep that never runs is a table that grows
forever, which is worse than a sweep that occasionally runs twice.
"""
from __future__ import annotations

import logging
import os
import uuid

from app.core.redis import LEADER_KEY_PREFIX, get_redis

log = logging.getLogger(__name__)

# Stable per-worker identity, same convention as routers/random.py.
_WORKER_IDENTITY = f"{os.getpid()}-{uuid.uuid4()}"


async def lead_this_cycle(role: str, cycle_seconds: int) -> bool:
    """True if THIS worker should run `role`'s work this cycle.

    The claim is held for 90% of `cycle_seconds`: long enough that no other
    worker can elect itself for the same cycle however staggered its boot,
    short enough that it has always lapsed by the time the next cycle starts
    (so a worker that died mid-sweep costs one skipped cycle, not a stuck job).
    """
    try:
        redis = await get_redis()
        ok = await redis.set(
            LEADER_KEY_PREFIX + role,
            _WORKER_IDENTITY,
            nx=True,
            ex=max(30, int(cycle_seconds * 0.9)),
        )
        return bool(ok)
    except Exception:  # noqa: BLE001 — see the fail-open note above
        log.exception("[%s] leader election failed; running anyway", role)
        return True
