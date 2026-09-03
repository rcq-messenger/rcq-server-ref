"""Retention for CONSUMED one-time prekeys.

`models/prekey.py` promised this sweeper in a docstring and never had one, so
`consumed=True` rows had accumulated since April. What they are, once the key
is spent, is a per-account counter of how many NEW sessions strangers opened
toward you, each one dated. Nothing reads that number and nobody asked for it.

⚠ MEASURE FIRST, and the audit did not. `metadata-map-2026-08-22.md` files this
under "52 MB, the second largest table on the island", which reads as though
consumed rows are the 52 MB. They are not. Counted on the flagship on
2026-08-22, immediately before this shipped: 253722 rows total, of which 17951
consumed and 235771 LIVE: 2662 accounts times a `TARGET_PREKEY_COUNT` of 100.
The table is honestly sized for what it does. This sweep reclaims about 7% of
it, roughly 3.6 MB, and the reason to run it is the dated stranger-counter, not
the disk.

THE HORIZON, and why it is not a taste question
-----------------------------------------------
A consumed row is never served again, since `_claim_opk` filters `consumed == False`.
Its one remaining job is to be a tombstone: both replenish endpoints
(`keys.replenish_prekeys`, `keys.replenish_device_prekeys`) skip an incoming
`prekey_id` that already exists in the pool, consumed included, so while the
tombstone stands the owner cannot re-publish that id.

Delete it too early and this happens: sender A fetches the bundle and gets OPK
17, builds a PreKeySignalMessage against it, and deposits. The recipient is
offline, so the envelope sits in `offline_messages`, for up to
`offline_queue_sweep.TTL_DAYS`, thirty days by default, which is the point.
Meanwhile the tombstone expires, the recipient's client tops up, re-offers id
17 (Android and iOS both draw ids at random from 1..2^31-1, so this is unlikely
per key and certain across a big enough pool over a long enough time), stores a
NEW private key under that id and overwrites the old one. Sender B now gets a
live OPK 17 whose private half no longer exists. When the recipient finally
drains, one of the two messages is `InvalidKeyId`: undecryptable, no bubble, no
unread, and a generic push. That is the ~10% first-in-session failure
`_claim_opk`'s own comment was written to close, re-opened from the other end.

So the horizon is derived, not chosen: it must exceed the longest a prekey
message can stay in flight, which is the 1:1 queue TTL. Read from that constant
rather than hardcoded, so an operator who raises `OFFLINE_QUEUE_TTL_DAYS` on
their island does not silently shorten this guarantee. Plus a margin, because
the queue sweep runs on its own six-hour cycle and the recipient still has to
come back and decrypt after the row is served.

Rows consumed BEFORE `consumed_at` existed have a NULL stamp, and the first
version of this module measured those against `created_at`, the upload, on the
argument that "the upload is always older than the consumption, so the fallback
can only ever make a legacy row look YOUNGER than the horizon". ⚠⚠ THAT IS
BACKWARDS and it shipped. The predicate is `clock < cutoff`, so substituting an
OLDER timestamp makes a row MORE likely to match, not less: a key uploaded 40
days ago and claimed yesterday was a one-day-old tombstone measured as
forty-day-old and deleted, while the PreKeySignalMessage it protects can sit in
`offline_messages` for another thirty. That is exactly the failure the horizon
exists to prevent, and `models/prekey.py` states the rule correctly two files
over ("a key uploaded in June and claimed yesterday is a live tombstone").

So a legacy row is STAMPED rather than guessed at: the first pass writes
`consumed_at = now` on every consumed row that has none, and its horizon runs
from this release. Same shape, and the same reasoning, as the legacy declined
rows in `contact_request_sweep`. The backfill matches nothing after the first
pass, so a second cycle costs one indexed query.

Hourly, leader-elected, bounded per cycle.
`RCQ_PREKEY_SWEEP_DRY_RUN=1` counts and logs without deleting.
"""
from __future__ import annotations

import asyncio
import logging
import os
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, func, select, update

from app.core.db import SessionLocal
from app.models.prekey import OneTimePreKey
from app.services.offline_queue_sweep import TTL_DAYS as QUEUE_TTL_DAYS
from app.services.periodic_leader import lead_this_cycle

log = logging.getLogger(__name__)

SWEEP_INTERVAL_SECONDS: int = 60 * 60

# Slack on top of the queue TTL: the queue sweep itself only runs every six
# hours, a client that comes back on day 30 still has to drain and decrypt, and
# a week costs nothing when the rows being kept are a few thousand.
CONSUMED_GRACE_DAYS: int = int(os.environ.get("RCQ_PREKEY_CONSUMED_GRACE_DAYS", "7"))
# The horizon proper. Env-settable as an absolute override for an operator who
# knows what they are doing; unset, it tracks the queue TTL, which is the
# relationship that actually has to hold.
CONSUMED_MAX_AGE_DAYS: int = int(
    os.environ.get(
        "RCQ_PREKEY_CONSUMED_MAX_AGE_DAYS", str(QUEUE_TTL_DAYS + CONSUMED_GRACE_DAYS)
    )
)
# One pass. The first pass on the flagship has ~17.5k rows to clear, so this
# empties the backlog in one cycle while still bounding a runaway.
MAX_DELETIONS_PER_CYCLE: int = int(
    os.environ.get("RCQ_PREKEY_SWEEP_MAX_PER_CYCLE", "50000")
)
DRY_RUN: bool = os.environ.get("RCQ_PREKEY_SWEEP_DRY_RUN", "") == "1"


def _expired(cutoff: datetime):
    """The predicate, shared by the count and the delete so a dry run reports
    exactly what a real pass would remove.

    No `created_at` fallback: an unstamped row is stamped by the backfill in
    `sweep_once` and waits its full horizon from there. See the ⚠⚠ in the
    module docstring for what the fallback did instead.
    """
    return (
        OneTimePreKey.consumed == True,  # noqa: E712
        OneTimePreKey.consumed_at.is_not(None),
        OneTimePreKey.consumed_at < cutoff,
    )


async def sweep_once() -> int:
    """One pass. Returns how many tombstones went (or would have, dry)."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=CONSUMED_MAX_AGE_DAYS)
    async with SessionLocal() as db:
        if not DRY_RUN:
            # Give every legacy tombstone a clock before anything is measured
            # against one. Covered by `ix_one_time_prekeys_consumed_at`, so on
            # every pass after the first this is an index scan that matches
            # nothing, which is cheaper than a one-shot marker for one UPDATE.
            stamped = (
                await db.execute(
                    update(OneTimePreKey)
                    .where(
                        OneTimePreKey.consumed == True,  # noqa: E712
                        OneTimePreKey.consumed_at.is_(None),
                    )
                    .values(consumed_at=datetime.now(timezone.utc))
                )
            ).rowcount or 0
            if stamped:
                await db.commit()
                log.warning(
                    "[prekey-sweep] stamped %d legacy consumed prekey(s); their %dd "
                    "starts now", stamped, CONSUMED_MAX_AGE_DAYS,
                )
        if DRY_RUN:
            n = int(
                (
                    await db.execute(
                        select(func.count())
                        .select_from(OneTimePreKey)
                        .where(*_expired(cutoff))
                    )
                ).scalar_one()
            )
            if n:
                log.warning("[prekey-sweep] dry-run: %d consumed prekey(s) are past %dd",
                            n, CONSUMED_MAX_AGE_DAYS)
            return n
        # Bounded by id rather than a bare DELETE: the ORM's `delete().where()`
        # cannot express a LIMIT, and an unbounded statement on a table this
        # size holds one of the few pooled connections for the whole run.
        ids = (
            await db.scalars(
                select(OneTimePreKey.id).where(*_expired(cutoff)).limit(MAX_DELETIONS_PER_CYCLE)
            )
        ).all()
        if not ids:
            return 0
        res = await db.execute(delete(OneTimePreKey).where(OneTimePreKey.id.in_(ids)))
        await db.commit()
        n = res.rowcount or 0
    if n:
        # warning, not info: prod runs at WARNING and this is the number you
        # want in the journal the day somebody asks whether the sweep is alive.
        log.warning("[prekey-sweep] reaped %d consumed prekey(s) older than %dd%s",
                    n, CONSUMED_MAX_AGE_DAYS,
                    " (CAPPED, more next cycle)" if n >= MAX_DELETIONS_PER_CYCLE else "")
    return n


async def prekey_sweep_loop() -> None:
    while True:
        try:
            # One worker per cycle (see services/periodic_leader).
            if await lead_this_cycle("prekey-sweep", SWEEP_INTERVAL_SECONDS):
                await sweep_once()
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            log.exception("[prekey-sweep] pass failed; retrying next cycle")
        await asyncio.sleep(SWEEP_INTERVAL_SECONDS)
