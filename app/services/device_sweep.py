"""Retention for revoked device slots.

Two halves, and only the second one is here. `keys._strip_revoked_device`
reduces the row to `(uin, device_id, revoked_at)` at the moment of revocation,
which is when the key material, the label and the lifespan actually stop being
needed. This loop removes what is left once the slot number itself is safe to
recycle.

Why the tombstone has to exist at all, and therefore why the horizon is long:
`keys.register_device` allocates the next libsignal deviceId as `max(device_id)
+ 1` over EVERY row of the account, revoked included. Delete the highest
tombstone and the next linked device gets that number back. Two things still
point at the old one when that happens. A sender's cached device roster (the
web refetches on `TARGETS_TTL_MS`, five minutes, but an offline client holds
whatever it last saw), and any envelope already deposited against
`offline_messages.to_device_id`, which lives up to `OFFLINE_QUEUE_TTL_DAYS`.
Either would deliver ciphertext sealed to the retired install's keys to a brand
new install that cannot open it: no bubble, no error, nothing to report.

So the default is six months, which is not derived from anything as tight as
the prekey horizon. It is "far past every cache and every queued copy, and
still bounded". The cost of being generous is one integer per retired slot in a
128-wide space: an account would have to link and retire 126 devices inside the
window before `register_device` starts answering 409 "device limit reached".
Nobody has retired one yet (0 revoked rows on the flagship, 2026-08-22).

Hourly, leader-elected, bounded per cycle.
`RCQ_DEVICE_SWEEP_DRY_RUN=1` counts and logs without deleting.
"""
from __future__ import annotations

import asyncio
import logging
import os
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, func, select

from app.core.db import SessionLocal
from app.models.device import Device
from app.services.periodic_leader import lead_this_cycle

log = logging.getLogger(__name__)

SWEEP_INTERVAL_SECONDS: int = 60 * 60

REVOKED_MAX_AGE_DAYS: int = int(os.environ.get("RCQ_DEVICE_REVOKED_MAX_AGE_DAYS", "180"))
MAX_DELETIONS_PER_CYCLE: int = int(os.environ.get("RCQ_DEVICE_SWEEP_MAX_PER_CYCLE", "500"))
DRY_RUN: bool = os.environ.get("RCQ_DEVICE_SWEEP_DRY_RUN", "") == "1"


async def sweep_once() -> int:
    """One pass. Returns how many tombstones went (or would have, dry)."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=REVOKED_MAX_AGE_DAYS)
    async with SessionLocal() as db:
        where = (Device.revoked_at.is_not(None), Device.revoked_at < cutoff)
        if DRY_RUN:
            n = int(
                (
                    await db.execute(select(func.count()).select_from(Device).where(*where))
                ).scalar_one()
            )
            if n:
                log.warning("[device-sweep] dry-run: %d revoked slot(s) past %dd",
                            n, REVOKED_MAX_AGE_DAYS)
            return n
        ids = (
            await db.scalars(
                select(Device.id).where(*where).limit(MAX_DELETIONS_PER_CYCLE)
            )
        ).all()
        if not ids:
            return 0
        res = await db.execute(delete(Device).where(Device.id.in_(ids)))
        await db.commit()
        n = res.rowcount or 0
    if n:
        log.warning("[device-sweep] released %d revoked device slot(s) older than %dd",
                    n, REVOKED_MAX_AGE_DAYS)
    return n


async def device_sweep_loop() -> None:
    while True:
        try:
            # One worker per cycle (see services/periodic_leader).
            if await lead_this_cycle("device-sweep", SWEEP_INTERVAL_SECONDS):
                await sweep_once()
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            log.exception("[device-sweep] pass failed; retrying next cycle")
        await asyncio.sleep(SWEEP_INTERVAL_SECONDS)
