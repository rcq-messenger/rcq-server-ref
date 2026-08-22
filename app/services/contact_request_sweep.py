"""Retention for RESOLVED contact requests: two states, two very different
horizons.

ACCEPTED. Once a request is accepted the two `contacts` rows are the
relationship, and the request itself has no reader anywhere: `GET
/contacts/pending` filters to `pending`, `GET /contacts/outgoing` serves
`pending`+`declined` explicitly, and no client compares a state against
"accepted". All the row did afterwards was leave the island a permanent record
that A asked B on date D. 515 of them had accumulated since April before this
existed.

Why a delay rather than deleting inline in `respond`: a second tap on Accept,
with a slow network and an impatient finger, would then hit a request_id that no longer
exists and get a 404 for something that in fact succeeded, which the web client
turns into an error banner. An hour of retention buys an idempotent endpoint.

DECLINED. ⚠⚠ These are NOT the same thing and must never be given the accepted
grace. A decline sends no push, deliberately; the row served by
/contacts/outgoing IS how the sender learns the answer, and all three clients
render it with a Dismiss that deletes it themselves. Sweeping it on an hour
would make a refused request silently look like it was never sent.

But un-swept was not the answer either, and until 2026-08-22 that is what they
were: `contacts.respond` never stamped `resolved_at` on a decline, so a refusal
had no clock at all and stayed forever. The verdict in the metadata map is TTL,
not KEEP, and the horizon is what makes it safe: six months. That is six times
the 1:1 queue TTL, so a declined request outlives by a wide margin every piece
of actual mail addressed to the same person. Somebody who has not opened the
app in half a year and then does is not owed an answer to a request they no
longer remember sending, and they are not shown a lie either, because the row
is gone rather than reverted to pending.

Legacy declined rows have a NULL stamp because nothing wrote one. They are NOT
given the created_at fallback the accepted ones get: that is the request's
clock, not the refusal's, and using it could delete a "no" the sender never
saw. Instead the first pass STAMPS them with now, so their six months start
from this release. Conservative in the only direction that matters, and it
self-heals on the first cycle.
"""

import asyncio
import logging
import os
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, or_, update

from app.core.db import SessionLocal
from app.models.contact import ContactRequest
from app.services.periodic_leader import lead_this_cycle

log = logging.getLogger("rcq.contact_request_sweep")

# Long enough to cover a double-tap and a client retry, short enough that the
# record is not a record.
ACCEPTED_GRACE_MINUTES = 60
# See the ⚠⚠ above. Env-tunable, and shortening is the direction that costs a
# sender their answer, so raise before you lower.
DECLINED_MAX_AGE_DAYS = int(os.environ.get("RCQ_DECLINED_REQUEST_MAX_AGE_DAYS", "180"))
SWEEP_INTERVAL_SECONDS = 30 * 60
DRY_RUN: bool = os.environ.get("RCQ_CONTACT_REQUEST_SWEEP_DRY_RUN", "") == "1"


async def sweep_once() -> tuple[int, int]:
    """One pass. Returns (accepted swept, declined swept)."""
    now = datetime.now(timezone.utc)
    accepted_cutoff = now - timedelta(minutes=ACCEPTED_GRACE_MINUTES)
    declined_cutoff = now - timedelta(days=DECLINED_MAX_AGE_DAYS)
    async with SessionLocal() as db:
        # Backfill first, so a legacy row is never measured against a clock it
        # does not have. Runs on every pass and matches nothing after the
        # first, which is cheaper than a one-shot marker for two SQL predicates.
        if not DRY_RUN:
            await db.execute(
                update(ContactRequest)
                .where(
                    ContactRequest.state == "declined",
                    ContactRequest.resolved_at.is_(None),
                )
                .values(resolved_at=now)
            )

        accepted = await db.execute(
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
                    ContactRequest.resolved_at < accepted_cutoff,
                    ContactRequest.resolved_at.is_(None)
                    & (ContactRequest.created_at < accepted_cutoff),
                ),
            )
        )
        declined = await db.execute(
            delete(ContactRequest).where(
                ContactRequest.state == "declined",
                # No created_at fallback here, on purpose. See the docstring.
                # A row the backfill above has not reached yet simply waits a
                # cycle.
                ContactRequest.resolved_at.is_not(None),
                ContactRequest.resolved_at < declined_cutoff,
            )
        )
        if DRY_RUN:
            await db.rollback()
        else:
            await db.commit()
        a, d = accepted.rowcount or 0, declined.rowcount or 0
    if a or d:
        log.info(
            "%sswept %d accepted and %d declined (>%dd) contact request(s)",
            "dry-run: " if DRY_RUN else "", a, d, DECLINED_MAX_AGE_DAYS,
        )
    return a, d


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
