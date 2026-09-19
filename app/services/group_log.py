"""Stage 5 helpers shared by the message writers and the group router."""
from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime, timezone

from sqlalchemy import case, func, select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import engine
from app.models.group_log import GroupLogCursor, GroupLogReader
from app.models.queue_cursor import QueueCursor


def _dialect_upsert():
    """The two dialect-dependent pieces every upsert here needs.

    Postgres spells the monotonic rule `greatest()`, SQLite (the local test
    harness) `max()`. Same split as `services/queue_drain.upsert_cursor`, which
    is the sibling of these functions on the 1:1 queue; deliberately not shared
    with it, so neither module has to import the other's subject.
    """
    pg = engine.dialect.name == "postgresql"
    return (pg_insert if pg else sqlite_insert), (func.greatest if pg else func.max)


async def log_readers(db: AsyncSession, uins: Iterable[int]) -> set[int]:
    """Which of these accounts need NO legacy per-member row any more.

    An account qualifies when at least one of its devices has read the log
    and none of its legacy-draining devices (its `queue_cursors` rows) is
    still without a reader mark. So a phone that updated first keeps the
    account on the old path for its old desktop, until that desktop updates
    or its stale cursor is reaped."""
    uins = list(set(uins))
    if not uins:
        return set()
    has_reader = set((await db.execute(
        select(GroupLogReader.uin).where(GroupLogReader.uin.in_(uins)).distinct()
    )).scalars().all())
    if not has_reader:
        return set()
    # Legacy devices of those accounts that have never read the log.
    blocked = set((await db.execute(
        select(QueueCursor.uin)
        .where(
            QueueCursor.uin.in_(list(has_reader)),
            ~select(GroupLogReader.uin).where(
                GroupLogReader.uin == QueueCursor.uin,
                GroupLogReader.device_id == QueueCursor.device_id,
            ).exists(),
        )
        .distinct()
    )).scalars().all())
    return has_reader - blocked


async def mark_reader(db: AsyncSession, uin: int, device_id: str) -> None:
    """This device just read the log.

    ⚠ One upsert, for the same reason as `upsert_log_cursor` below and with
    more urgency: this runs in the SAME transaction as the cursor write on both
    `/messages/group-log/fetch` and `/messages/group-log/ack`. Read-then-insert
    here meant two overlapping requests from one device could collide on
    `group_log_readers_pkey`, and that collision took the whole transaction
    down with it, the ack the request was carrying included. Making only the
    cursor race-proof would have left the ack hostage to this row.

    `first_seen` is never rewritten, exactly as before: it is the day this
    install joined the new path. Nothing reads it yet; `stale_reader_sweep`
    works off `last_seen`, which every call here moves.
    """
    now = datetime.now(timezone.utc)
    dialect_insert, _ = _dialect_upsert()
    ins = dialect_insert(GroupLogReader).values(
        uin=uin, device_id=device_id, first_seen=now, last_seen=now,
    )
    await db.execute(ins.on_conflict_do_update(
        index_elements=[GroupLogReader.uin, GroupLogReader.device_id],
        set_={"last_seen": now},
    ))


async def room_head(db: AsyncSession, group_id: int) -> int:
    row = (await db.execute(
        text("SELECT next_seq FROM group_seq WHERE group_id = :g"), {"g": group_id}
    )).scalar_one_or_none()
    return int(row or 0)


async def upsert_log_cursor(
    db: AsyncSession,
    group_id: int,
    uin: int,
    device_id: str,
    *,
    seq: int = 0,
    seed: int = 0,
) -> int:
    """Create or advance THIS device's cursor in THIS room, in one statement.

    Returns the `last_seq` the row holds afterwards, which is not always what
    this caller asked for: the winner of a race may already be further along.

    ⚠ Why not read-then-write. Every writer of a room-log cursor used to
    `db.get` the row and `db.add` it when the read came back empty. Two acks
    from one device overlap all the time (the client acks each page of a
    catch-up, a reconnect re-sends the page whose answer it never saw, a phone
    and its own retry), and both then read "no cursor for this room", both
    INSERT, and the loser came back as `IntegrityError: duplicate key value
    violates unique constraint "group_log_cursors_pkey"`, a 500 at the client.
    Worse here than on the 1:1 queue: the loser's transaction was rolled back
    whole, so the ack it carried was lost and the island rebuilt the identical
    page from the identical cursor on the next fetch (the #981 starvation loop,
    entered from the side), and `ack_group_log` swallowed the error, so the
    client was told 200 while nothing had moved.

    `INSERT ... ON CONFLICT (group_id, uin, device_id) DO UPDATE` lets the loser
    apply its ack instead of dying: Postgres waits for the winner to commit and
    then updates the row the winner wrote.

    The monotonic rule is the one the handler applied before, moved inside the
    statement so a race cannot skip it. A cursor only ever goes FORWARD: a stale
    or out-of-order ack is a no-op, never a rewind. A rewind is not cosmetic
    here either, it re-serves the whole span it uncovers as unread.

    `seq` is the mark to apply to a row that already exists (0, the default,
    means "do not move it"; room seqs start at 1, so 0 can never uncover a row).
    `seed` is used ONLY when this statement is the one that creates the row.

    ⚠ A row that appeared under us mid-race is deliberately NOT lifted onto
    `seed`. Whoever created it read the head themselves, and raising a lagging
    device's cursor would bury the posts it has not been served yet.
    """
    now = datetime.now(timezone.utc)
    dialect_insert, biggest = _dialect_upsert()
    ins = dialect_insert(GroupLogCursor).values(
        group_id=group_id,
        uin=uin,
        device_id=device_id,
        last_seq=max(seq, seed),
        updated_at=now,
    )
    stmt = ins.on_conflict_do_update(
        index_elements=[
            GroupLogCursor.group_id, GroupLogCursor.uin, GroupLogCursor.device_id,
        ],
        set_={
            "last_seq": biggest(GroupLogCursor.last_seq, seq),
            # The stamp moves only when the cursor does, exactly as the handler
            # did it. Nothing reads this column today, and a stamp that meant
            # "last asked" rather than "last advanced" would be a lie the day
            # something starts to: that is #981 in one field, where a mark
            # earned by asking instead of by receiving hid a starving device.
            "updated_at": case(
                (GroupLogCursor.last_seq < seq, now), else_=GroupLogCursor.updated_at,
            ),
        },
    ).returning(GroupLogCursor.last_seq)
    return int((await db.execute(stmt)).scalar_one())


async def seed_cursors_on_join(db: AsyncSession, group_id: int, uin: int) -> None:
    """A member just joined this room: give each of its log-reading devices a
    cursor at the room's head NOW. Otherwise a reader account added while its
    devices are offline would get no legacy rows (it is a reader) AND start
    at whatever the head is at its first fetch, losing every post in between.
    Best-effort: a race with that first fetch is harmless either way."""
    devices = (await db.execute(
        select(GroupLogReader.device_id).where(GroupLogReader.uin == uin)
    )).scalars().all()
    if not devices:
        return
    head = await room_head(db, group_id)
    for device_id in devices:
        # Seed only: `seq` stays 0, so a device that fetched this room between
        # the head read above and this statement keeps its own position.
        #
        # ⚠ The `except IntegrityError: await db.rollback()` this replaces was
        # worse than the collision it caught. The caller is mid-join, with the
        # `group_members` row already flushed on this same session, so rolling
        # back here undid the join itself and answered 200.
        await upsert_log_cursor(db, group_id, uin, device_id, seed=head)
