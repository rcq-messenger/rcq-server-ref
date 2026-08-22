"""Periodic deletion of expired People-Nearby check-ins.

`nearby_checkins` rows carry a `bucket_id`: an opaque level-6 geohash the
client computed, so the server never learns coordinates. But a bucket is
still roughly a 1.5km tile, and the row ties it to a UIN — so a check-in
from March is a statement about where somebody was in March, kept for no
reason.

Until this module existed nothing ever deleted them. `expires_at` was
enforced on READ only (`routers/nearby` filters expired rows out of the
listing), which hides stale rows from users while the location data itself
stays in the table forever. `models/nearby.py` says as much in its own
docstring: "an occasional sweeper would be nice-to-have once the table
grows." It is not a size problem — prod holds all of 168 rows — it is a
retention problem, and the fix is the same either way.

Runs every 15 minutes; one worker per cycle via `periodic_leader`, same as
the offline-queue and media sweeps.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from sqlalchemy import delete

from app.core.db import SessionLocal
from app.models.nearby import NearbyCheckin
from app.services.periodic_leader import lead_this_cycle

SWEEP_INTERVAL_SECONDS: int = 15 * 60


async def sweep_once() -> int:
    """One pass. Returns the number of check-ins deleted."""
    async with SessionLocal() as db:
        now = datetime.now(timezone.utc)
        result = await db.execute(
            delete(NearbyCheckin).where(NearbyCheckin.expires_at < now)
        )
        await db.commit()
        return result.rowcount or 0


async def nearby_sweep_loop() -> None:
    """Forever-running task. Wired into `main.py` lifespan startup."""
    while True:
        try:
            if await lead_this_cycle("nearby-sweep", SWEEP_INTERVAL_SECONDS):
                await sweep_once()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            print(f"[nearby_sweep] {type(exc).__name__}: {exc}")
        await asyncio.sleep(SWEEP_INTERVAL_SECONDS)
