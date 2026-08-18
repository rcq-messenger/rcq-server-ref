"""Retention for ACCEPTED contact requests.

Once a request is accepted the two `contacts` rows are the relationship, and
the request itself has no reader anywhere: `GET /contacts/pending` filters to
`pending`, `GET /contacts/outgoing` serves `pending`+`declined` explicitly, and
no client compares a state against "accepted". All the row did afterwards was
leave the island a permanent record that A asked B on date D. 515 of them had
accumulated since April before this existed.

⚠⚠ DECLINED rows are NOT swept and must not be added here. A decline sends no
push, deliberately; the row served by /contacts/outgoing IS how the sender
learns the answer, and all three clients render it with a Dismiss that deletes
it themselves. Sweeping those would make a refused request silently look like
it was never sent.

Why a delay rather than deleting inline in `respond`: a second tap on Accept —
slow network, impatient finger — would then hit a request_id that no longer
exists and get a 404 for something that in fact succeeded, which the web client
turns into an error banner. An hour of retention buys an idempotent endpoint.
"""

import asyncio
import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, func, or_

from app.core.db import SessionLocal
from app.models.contact import ContactRequest
from app.services.periodic_leader import lead_this_cycle

log = logging.getLogger("rcq.contact_request_sweep")

# Long enough to cover a double-tap and a client retry, short enough that the
# record is not a record.
ACCEPTED_GRACE_MINUTES = 60
SWEEP_INTERVAL_SECONDS = 30 * 60


async def sweep_once() -> int:
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=ACCEPTED_GRACE_MINUTES)
    async with SessionLocal() as db:
        res = await db.execute(
            delete(ContactRequest).where(
                ContactRequest.state == "accepted",
                # Measured from the ACCEPTANCE, not from when the request was
                # raised: a week-old request accepted a minute ago is inside
                # its grace, and keying off created_at would sweep it out from
                # under a client still retrying.
                #
                # An island that predates `resolved_at` has accepted rows with
                # a null stamp; those were resolved long before this shipped,
                # so created_at is the honest fallback and lets a self-host
                # clear its own backlog on the first cycle.
                or_(
                    ContactRequest.resolved_at < cutoff,
                    ContactRequest.resolved_at.is_(None) & (ContactRequest.created_at < cutoff),
                ),
            )
        )
        await db.commit()
        n = res.rowcount or 0
    if n:
        log.info("swept %d accepted contact request(s)", n)
    return n


async def contact_request_sweep_loop() -> None:
    while True:
        try:
            # One worker per cycle (see services/periodic_leader).
            if await lead_this_cycle("contact-request-sweep", SWEEP_INTERVAL_SECONDS):
                await sweep_once()
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            log.exception("contact request sweep failed; retrying next cycle")
        await asyncio.sleep(SWEEP_INTERVAL_SECONDS)
