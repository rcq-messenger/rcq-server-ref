"""Stage 5 helpers shared by the message writers and the group router."""
from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime, timezone

from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.group_log import GroupLogCursor, GroupLogReader
from app.models.queue_cursor import QueueCursor


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
    """This device just read the log."""
    now = datetime.now(timezone.utc)
    row = await db.get(GroupLogReader, (uin, device_id))
    if row is None:
        db.add(GroupLogReader(uin=uin, device_id=device_id, first_seen=now, last_seen=now))
    else:
        row.last_seen = now


async def room_head(db: AsyncSession, group_id: int) -> int:
    row = (await db.execute(
        text("SELECT next_seq FROM group_seq WHERE group_id = :g"), {"g": group_id}
    )).scalar_one_or_none()
    return int(row or 0)


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
    now = datetime.now(timezone.utc)
    for device_id in devices:
        if await db.get(GroupLogCursor, (group_id, uin, device_id)) is None:
            db.add(GroupLogCursor(group_id=group_id, uin=uin, device_id=device_id, last_seq=head, updated_at=now))
    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
