"""Demote a device that stopped reading the group log, so its account eats again.

⚠⚠ THIS EXISTS BECAUSE THE READER MARK WAS A ONE-WAY LATCH AND PEOPLE STOPPED
RECEIVING GROUP MESSAGES ENTIRELY.

Stage 5 gave each account two possible paths for a group message: the shared log,
which one fetch serves for a whole room, and the legacy per-member queue, which
costs a row per recipient. `services/group_log.log_readers` decides per account,
and the moment ANY of its devices reads the log once, `mark_reader` writes a row
and the island stops writing that account legacy rows for ever. There was nothing
anywhere that took the mark back.

So a device that read the log once and then stopped, for any reason at all, left
its account on a path nobody was walking. Measured on the flagship on 13.09.2026,
nine accounts that had been online within two days were behind their rooms by
between 41 and 2011 rows, the worst of them last having read on 29.08 while being
seen the same afternoon. The island had written them no legacy row since the day
they were marked. From the outside this is report #981, "групповые сообщения
доставляются не всем участникам", and it is not a delivery bug in the fan-out at
all: the fan-out wrote exactly what it was told to write.

THE RULE, and why it is this one
--------------------------------
A mark is dropped when it has not been refreshed for `STALE_READER_DAYS` AND the
account has been seen within `ACCOUNT_ALIVE_DAYS`. Both halves matter.

The second half is what keeps this from punishing absence. Somebody on holiday
for three weeks is missing nothing in real time: their log rows are waiting, they
will read them, and their mark will refresh on the first fetch. It is the account
that is demonstrably HERE, and whose reader has gone quiet anyway, that is losing
messages, and that is the only one this touches.

⚠ The first draft of this said "seen more recently than the mark" rather than
"seen recently", and a dry run against the flagship would have demoted 287 of
523 marks. Almost all of them were accounts last seen a few SECONDS after their
one and only fetch and never again: people who tried the app once. Demoting them
buys nobody a message and starts writing legacy rows for hundreds of accounts
that are not coming back. The narrow rule takes 64.

The first half has to be longer than any normal gap between fetches and shorter
than the queue's own retention, or a demoted account starts collecting legacy
rows for messages it has already missed. Seven days sits between a client that
fetches on every launch and the thirty-day queue TTL.

WHAT IT DOES NOT DO, said plainly
---------------------------------
It does not deliver the backlog. Legacy rows are written when a message is sent,
so a demotion fixes the next message and not the last two thousand: those sit in
`group_log` and only a fetch will bring them. This sweep stops the bleeding; it
does not transfuse. A client that has stopped fetching the log is still a client
bug, and this is the island refusing to make that bug silent.

It also does not touch `group_log_cursors`. The cursor is where the device would
resume, and a demoted device that comes back should carry on from where it was
rather than from the head, or the demotion would itself lose the gap.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select

from app.core.db import SessionLocal
from app.models.group_log import GroupLogReader
from app.models.user import User
from app.services.periodic_leader import lead_this_cycle

log = logging.getLogger("rcq.stale_reader_sweep")

#: Hourly. The horizon is days, but a person who has been starved for a week
#: should not wait another day for the island to notice.
SWEEP_INTERVAL_SECONDS = 3600

#: Longer than any gap between fetches by a healthy client, shorter than the
#: legacy queue's own retention. See the note above.
STALE_READER_DAYS = 7

#: "The person is here." Two days covers a weekend away without covering
#: somebody who left in August.
ACCOUNT_ALIVE_DAYS = 2

#: A SAFETY VALVE, and it is here because the first draft of the rule above
#: would have demoted more than half the island in one cycle. A sweep that
#: touches the delivery path should refuse to act on a number that looks like a
#: bug in itself, and say so, rather than carry it out at three in the morning.
#: 64 of 523 on the flagship the day this was written.
MAX_SHARE_PER_CYCLE = 0.25


def _stale_marks(cutoff: datetime, alive_since: datetime):
    """Marks not refreshed since `cutoff` whose ACCOUNT has been seen since.

    ⚠ `User.last_seen` is NEVER NULL: `models/user.py:209` defaults it to the
    moment of registration, so "the island has never seen them" is not a state
    that exists and must not be relied on here. What DOES exist is an account
    whose last_seen is old, which the second condition handles.

    ⚠ Selects the ROWS, not their keys. The delete below removes them one at a
    time through the session rather than by a tuple IN, which Postgres would
    take and the self-host SQLite path would not. There are sixteen of these on
    the flagship today, so the loop costs nothing and travels everywhere.
    """
    return (
        select(GroupLogReader)
        .join(User, User.uin == GroupLogReader.uin)
        .where(
            GroupLogReader.last_seen < cutoff,
            User.last_seen > alive_since,
        )
    )


async def sweep_once() -> int:
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=STALE_READER_DAYS)
    alive_since = now - timedelta(days=ACCOUNT_ALIVE_DAYS)
    async with SessionLocal() as db:
        rows = (await db.execute(_stale_marks(cutoff, alive_since))).scalars().all()
        if not rows:
            return 0
        total = await db.scalar(select(func.count()).select_from(GroupLogReader)) or 0
        if total and len(rows) > total * MAX_SHARE_PER_CYCLE:
            log.error(
                "stale reader sweep REFUSING to run: %s of %s marks match, which is "
                "more than %.0f%% and reads as a bug in the rule rather than a day's "
                "worth of stale readers. Nothing demoted.",
                len(rows), total, MAX_SHARE_PER_CYCLE * 100,
            )
            return 0
        # Named in the log, because each one is a person who has been missing
        # group messages and somebody may have to tell them so.
        for row in rows:
            log.warning(
                "stale reader: uin=%s device=%s has not read the log in %s+ days "
                "while the account was seen; falling back to the legacy queue",
                row.uin, row.device_id[:8], STALE_READER_DAYS,
            )
            await db.delete(row)
        await db.commit()
    log.warning("stale reader sweep: demoted %s device(s)", len(rows))
    return len(rows)


async def stale_reader_sweep_loop() -> None:
    while True:
        try:
            # One worker per cycle (see services/periodic_leader).
            if await lead_this_cycle("stale-reader-sweep", SWEEP_INTERVAL_SECONDS):
                await sweep_once()
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            log.exception("stale reader sweep failed; retrying next cycle")
        await asyncio.sleep(SWEEP_INTERVAL_SECONDS)
