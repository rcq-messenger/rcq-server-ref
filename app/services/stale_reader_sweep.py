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

WHAT THE MARK CANNOT SEE: ONE ROOM STARVING
-------------------------------------------
The mark belongs to a DEVICE, and any ack that moves any room refreshes it. A
device stuck in one room (a row its client cannot open holds that cursor) while
it acks live posts in another is "reading" as far as the mark can tell, so the
rule above never touches it, and nothing showed that it was missing that room
(report 981, second half). `starving_rooms` is the detector for exactly that,
read off the cursors rather than the mark: a device that has read SOMETHING
within `READING_WITHIN_DAYS`, whose cursor in a room has not moved for
`STARVED_ROOM_DAYS` while a row it can see has been waiting above it for as
long. It only reports: one log line per pair and a count in the console. What
to do for such a pair (send it the room by the legacy queue as well, say) is a
decision nobody has taken, and the cure is in the clients, which are the ones
that have to write such a row off.

THE VALVE, and what it does when it trips
-----------------------------------------
More than `MAX_SHARE_PER_CYCLE` of all marks matching in one cycle reads as a
bug in the rule, and the sweep used to refuse outright and write one line to
the journal. But the other way to get that number is a client release whose log
reading broke, and then refusing meant every one of those people starving in
silence, for as long as nobody looked. So it no longer refuses whole. It
demotes only the matches that the CURSORS confirm, devices with a row they can
see waiting above one of their cursors for longer than `STALE_READER_DAYS`,
which a bug in the mark rule cannot fake; oldest mark first, and never more
than the share in one cycle. The rest are held back, the line says how many,
and the console shows the count until a cycle passes clean.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import and_, func, or_, select

from app.core.config import log_identity
from app.core.db import SessionLocal
from app.models.group import GroupMember
from app.models.group_log import GroupLog, GroupLogCursor, GroupLogReader, GroupSeq
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
#: 64 of 523 on the flagship the day this was written. Past it the cycle
#: demotes only what the cursors confirm, at most this share (see above).
MAX_SHARE_PER_CYCLE = 0.25

#: The per-room detector. "Reading": the device's mark moved within this.
READING_WITHIN_DAYS = 1

#: "Starving": the cursor has not moved, and a row it can see has waited above
#: it, for this long. Longer than a weekend without the app, shorter than the
#: mark's own seven days, which is the horizon this exists to see inside.
STARVED_ROOM_DAYS = 3

#: Lines one cycle writes about starving pairs. The count is exact regardless.
STARVED_LOG_LIMIT = 50

#: Where the last cycle's numbers live for the console (`/admin/stats`): Redis,
#: because the sweep runs on whichever worker won the cycle and the panel is
#: answered by any of them. Counts only, never who. Expires after a few missed
#: cycles, so a sweep that stopped running stops claiming anything.
STATUS_KEY = "rcq:stale_reader:status"
STATUS_TTL_SECONDS = 3 * SWEEP_INTERVAL_SECONDS


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


def _unread_since_before(cutoff: datetime):
    """For a `GroupLogCursor` row: a row its member can see sits above it and
    was written before `cutoff`.

    Asked of the FIRST visible row above the cursor only, which is the oldest
    one it has not read (rows are written in seq order), so each half is one
    probe of `ix_group_log_gid_to_seq` (group_id, to_uin, seq) rather than a
    walk of the room. Two halves because a member sees two kinds of row, the
    broadcasts (`to_uin` NULL) and the ones sealed to it; one OR'd probe would
    have to step over every row sealed to somebody else, and a reaction in the
    flagship is two thousand of those.
    """
    def first(seen_by):
        return (
            select(GroupLog.received_at)
            .where(
                GroupLog.group_id == GroupLogCursor.group_id,
                seen_by,
                GroupLog.seq > GroupLogCursor.last_seq,
            )
            .order_by(GroupLog.seq.asc())
            .limit(1)
            .correlate(GroupLogCursor)
            .scalar_subquery()
        )

    return or_(
        first(GroupLog.to_uin.is_(None)) < cutoff,
        first(GroupLog.to_uin == GroupLogCursor.uin) < cutoff,
    )


async def _confirmed_by_cursors(db, rows, cutoff: datetime) -> set[tuple[int, str]]:
    """Of these marks, the devices with a cursor that has had an unread row
    waiting since before `cutoff`: starving by the log's own evidence, which a
    bug in the mark rule cannot produce."""
    uins = list({row.uin for row in rows})
    if not uins:
        return set()
    found = (await db.execute(
        select(GroupLogCursor.uin, GroupLogCursor.device_id)
        .where(GroupLogCursor.uin.in_(uins), _unread_since_before(cutoff))
        .distinct()
    )).all()
    return {(int(uin), str(device)) for uin, device in found}


#: The numbers of the cycle that just ran, for `_publish_status`.
_last_sweep: dict = {}


async def sweep_once() -> int:
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=STALE_READER_DAYS)
    alive_since = now - timedelta(days=ACCOUNT_ALIVE_DAYS)
    _last_sweep.clear()
    async with SessionLocal() as db:
        rows = (await db.execute(_stale_marks(cutoff, alive_since))).scalars().all()
        if not rows:
            return 0
        total = await db.scalar(select(func.count()).select_from(GroupLogReader)) or 0
        held_back = 0
        if total and len(rows) > total * MAX_SHARE_PER_CYCLE:
            # Not a refusal any more; see "THE VALVE" above. What the cursors
            # confirm, oldest mark first, at most the share.
            starving = await _confirmed_by_cursors(db, rows, cutoff)
            confirmed = [row for row in rows if (row.uin, row.device_id) in starving]
            cap = int(total * MAX_SHARE_PER_CYCLE)
            safe = sorted(confirmed, key=lambda row: row.last_seen)[:cap]
            held_back = len(rows) - len(safe)
            log.error(
                "stale reader sweep HELD BACK: %s of %s marks match, which is more "
                "than %.0f%% and reads as a bug in the rule or a broken client "
                "release. Demoting only the %s the cursors confirm (%s confirmed, "
                "at most %s a cycle); %s held back until the share comes down.",
                len(rows), total, MAX_SHARE_PER_CYCLE * 100, len(safe),
                len(confirmed), cap, held_back,
            )
            rows = safe
        _last_sweep.update(marks=int(total), held_back=held_back)
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
    _last_sweep["demoted"] = len(rows)
    log.warning("stale reader sweep: demoted %s device(s)", len(rows))
    return len(rows)


async def starving_rooms() -> list[tuple[int, int, str, int]]:
    """(group_id, uin, device_id, seq gap) for every device that is reading
    yet stuck in a room. See "WHAT THE MARK CANNOT SEE" above. Read only.

    The gap is in room seqs, so it counts rows sealed to other members too: a
    size, not a number of messages.
    """
    now = datetime.now(timezone.utc)
    reading_since = now - timedelta(days=READING_WITHIN_DAYS)
    stuck_since = now - timedelta(days=STARVED_ROOM_DAYS)
    member = (
        select(GroupMember.id)
        .where(GroupMember.group_id == GroupLogCursor.group_id, GroupMember.uin == GroupLogCursor.uin)
        .exists()
    )
    async with SessionLocal() as db:
        found = (await db.execute(
            select(
                GroupLogCursor.group_id,
                GroupLogCursor.uin,
                GroupLogCursor.device_id,
                GroupSeq.next_seq - GroupLogCursor.last_seq,
            )
            .join(GroupLogReader, and_(
                GroupLogReader.uin == GroupLogCursor.uin,
                GroupLogReader.device_id == GroupLogCursor.device_id,
            ))
            .join(GroupSeq, GroupSeq.group_id == GroupLogCursor.group_id)
            .where(
                GroupLogReader.last_seen >= reading_since,
                GroupSeq.next_seq > GroupLogCursor.last_seq,
                or_(GroupLogCursor.updated_at.is_(None), GroupLogCursor.updated_at < stuck_since),
                member,
                _unread_since_before(stuck_since),
            )
            .order_by(GroupLogCursor.group_id, GroupLogCursor.uin)
        )).all()
    pairs = [(int(g), int(u), str(d), int(gap)) for g, u, d, gap in found]
    # The account is named, as for a demotion above, because somebody may have
    # to tell them. The room is not, unless the operator switched identities
    # on: a number next to a room id is a line of the membership table.
    for gid, uin, device_id, gap in pairs[:STARVED_LOG_LIMIT]:
        log.warning(
            "starving room: uin=%s device=%s room=%s has not moved in %s+ days while "
            "the device reads elsewhere (seq gap %s)",
            uin, device_id[:8], log_identity(gid), STARVED_ROOM_DAYS, gap,
        )
    if pairs:
        log.warning(
            "stale reader sweep: %s starving room cursor(s) on %s device(s) in %s room(s)",
            len(pairs), len({(u, d) for _, u, d, _ in pairs}), len({g for g, _, _, _ in pairs}),
        )
    return pairs


async def _publish_status(starving: list[tuple[int, int, str, int]]) -> None:
    status = {
        "at": datetime.now(timezone.utc).isoformat(),
        "demoted": int(_last_sweep.get("demoted", 0)),
        "held_back": int(_last_sweep.get("held_back", 0)),
        "starving_cursors": len(starving),
        "starving_devices": len({(u, d) for _, u, d, _ in starving}),
    }
    try:
        from app.core.redis import get_redis

        redis = await get_redis()
        await redis.set(STATUS_KEY, json.dumps(status), ex=STATUS_TTL_SECONDS)
    except Exception:  # noqa: BLE001 - a counter must never fail the sweep
        log.warning("stale reader sweep: status not published", exc_info=True)


async def read_status() -> dict:
    """The last cycle's numbers, or {} when there are none (no Redis, or no
    cycle within STATUS_TTL_SECONDS)."""
    try:
        from app.core.redis import get_redis

        raw = await (await get_redis()).get(STATUS_KEY)
        return json.loads(raw) if raw else {}
    except Exception:  # noqa: BLE001 - a panel must never be the thing that breaks
        return {}


async def run_cycle() -> None:
    await sweep_once()
    await _publish_status(await starving_rooms())


async def stale_reader_sweep_loop() -> None:
    while True:
        try:
            # One worker per cycle (see services/periodic_leader).
            if await lead_this_cycle("stale-reader-sweep", SWEEP_INTERVAL_SECONDS):
                await run_cycle()
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            log.exception("stale reader sweep failed; retrying next cycle")
        await asyncio.sleep(SWEEP_INTERVAL_SECONDS)
