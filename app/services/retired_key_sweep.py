"""Retention for `retired_signing_keys`, the markers behind `identity_rotated`.

A marker says "the account that carried this key is alive under a new one". It
has a reader for as long as some install of that account still holds the old
key and has not yet asked: a phone in a drawer, a browser that was closed for
the week. The rotating client gives its own cascade 30 days before it asks the
user to finish or forget (spec F3, critic 10), so the marker has to outlive
that with room to spare.

But it is also a row that ties a (hashed) old key to a number, which is exactly
the kind of record the metadata map keeps finding outliving its purpose. So it
is swept, and the horizon is the one the spec proposes: 90 days. Whether that
should be 30 (the token lifetime) is the founder's open question (f); the env
switch is here so an island can shorten it without a release. Shortening is the
direction that costs a user something: after the horizon an old install hears
`identity_not_found` again, which older clients read as "wipe".

A burn does not wait for this: the row is in `uin_rows.PER_UIN_COLUMNS`.
"""

import asyncio
import logging
import os
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete

from app.core.db import SessionLocal
from app.models.retired_signing_key import RetiredSigningKey
from app.services.periodic_leader import lead_this_cycle

log = logging.getLogger("rcq.retired_key_sweep")

MAX_AGE_DAYS = int(os.environ.get("RCQ_RETIRED_SIGNING_KEY_MAX_AGE_DAYS", "90"))
# Rows age in days, so an hourly-scale cadence would be work for nothing.
SWEEP_INTERVAL_SECONDS = 6 * 60 * 60
DRY_RUN: bool = os.environ.get("RCQ_RETIRED_KEY_SWEEP_DRY_RUN", "") == "1"


async def sweep_once(now: datetime | None = None) -> int:
    """One pass. Returns how many markers were (or in dry run, would be) removed."""
    cutoff = (now or datetime.now(timezone.utc)) - timedelta(days=MAX_AGE_DAYS)
    async with SessionLocal() as db:
        res = await db.execute(
            delete(RetiredSigningKey).where(RetiredSigningKey.rotated_at < cutoff)
        )
        if DRY_RUN:
            await db.rollback()
        else:
            await db.commit()
        n = res.rowcount or 0
    if n:
        log.info(
            "%sswept %d retired signing key marker(s) older than %dd",
            "dry-run: " if DRY_RUN else "", n, MAX_AGE_DAYS,
        )
    return n


async def retired_key_sweep_loop() -> None:
    while True:
        try:
            # One worker per cycle (see services/periodic_leader).
            if await lead_this_cycle("retired-key-sweep", SWEEP_INTERVAL_SECONDS):
                await sweep_once()
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            log.exception("retired signing key sweep failed; retrying next cycle")
        await asyncio.sleep(SWEEP_INTERVAL_SECONDS)
