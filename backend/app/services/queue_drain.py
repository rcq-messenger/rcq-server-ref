"""Where a device starts reading the offline queue.

The drain is `id > cursor` on a per-(uin, device) watermark. Everything here
exists to answer one question consistently in every place that touches it:
what is the floor for THIS device right now?

* The device has a cursor -> its own values. Never the account maximum: a
  phone that lags behind a linked browser must keep receiving what it has not
  acknowledged yet.
* The device has no cursor -> the furthest any device of this account got to,
  never zero. Reinstalling mints a new device id, and starting such a device at
  zero replays up to the whole 30-day queue as fresh notifications.

⚠ The zero case used to be answered in ONE of the three places (the fetch) and
not in the other two (the ack, and the cursor row the ack creates). A brand-new
device therefore read from the right floor, acked what it got, and had a cursor
written at 0 for whichever axis it had nothing to acknowledge on — after which
its next fetch handed it the entire queue on that axis. On prod that had already
happened to 27 cursors across 26 accounts. Keep the answer in one function.
"""

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.queue_cursor import QueueCursor


async def account_watermark(db: AsyncSession, uin: int) -> tuple[int, int]:
    """The furthest (direct, group) ids any device of this account has drained."""
    row = (
        await db.execute(
            select(
                func.coalesce(func.max(QueueCursor.last_direct_id), 0),
                func.coalesce(func.max(QueueCursor.last_group_id), 0),
            ).where(QueueCursor.uin == uin)
        )
    ).one()
    return int(row[0]), int(row[1])


async def drain_floor(
    db: AsyncSession, uin: int, device_id: str
) -> tuple[int, int, QueueCursor | None]:
    """Floor this device reads above, plus its cursor row if it has one.

    Callers that go on to move the cursor should pass the returned row back to
    `advance_cursor` rather than re-fetching it.
    """
    cursor = await db.get(QueueCursor, (uin, device_id))
    if cursor is not None:
        return cursor.last_direct_id, cursor.last_group_id, cursor
    direct, group = await account_watermark(db, uin)
    return direct, group, None
