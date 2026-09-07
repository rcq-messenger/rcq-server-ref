"""Retention for the two forms on the website.

⚠⚠ THIS EXISTS BECAUSE THE PRIVACY POLICY NOW PROMISES IT. `/free` and
`/organizations` are the only places in the whole project that ask a person for
a way to be reached — a name, an email or a handle, an organisation, a country —
and until today that table had no retention at all: every enquiry ever left was
still there, while section 2 of the policy said we never ask for a real-world
identifier. A promise the code does not keep is worse than no promise, so the
policy grew a section 5c saying "no longer than a year", and this is the half
that makes it true.

A year is deliberately generous. These are conversations with journalists and
organisations that can take months to go anywhere, and an enquiry deleted out
from under a half-finished thread costs somebody real work. The operator's own
queue is the fast path: dismissing an enquiry there removes it at once.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, func, select

from app.core.db import SessionLocal
from app.models.relay_inquiry import RelayInquiry
from app.services.periodic_leader import lead_this_cycle

log = logging.getLogger("rcq.inquiry_sweep")

#: Once a day is plenty for a year-long horizon.
SWEEP_INTERVAL_SECONDS = 24 * 3600

#: What section 5c of the privacy policy says. Change one and change the other.
MAX_AGE_DAYS = 365


async def sweep_once() -> int:
    cutoff = datetime.now(timezone.utc) - timedelta(days=MAX_AGE_DAYS)
    async with SessionLocal() as db:
        n = await db.scalar(
            select(func.count()).select_from(RelayInquiry).where(RelayInquiry.created_at < cutoff)
        )
        if not n:
            return 0
        await db.execute(delete(RelayInquiry).where(RelayInquiry.created_at < cutoff))
        await db.commit()
    log.info("inquiry sweep: removed %s enquiries older than %s days", n, MAX_AGE_DAYS)
    return int(n)


async def inquiry_sweep_loop() -> None:
    while True:
        try:
            # One worker per cycle (see services/periodic_leader).
            if await lead_this_cycle("inquiry-sweep", SWEEP_INTERVAL_SECONDS):
                await sweep_once()
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            log.exception("inquiry sweep failed; retrying next cycle")
        await asyncio.sleep(SWEEP_INTERVAL_SECONDS)
