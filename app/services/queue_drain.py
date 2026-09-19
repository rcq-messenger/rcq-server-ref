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

from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import engine
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


async def upsert_cursor(
    db: AsyncSession,
    uin: int,
    device_id: str,
    *,
    direct: int = 0,
    group: int = 0,
    seed_direct: int = 0,
    seed_group: int = 0,
) -> tuple[int, int]:
    """Create or advance THIS device's cursor in one statement, never backwards.

    Returns the (direct, group) marks the row holds after the write, which is not
    always what this caller asked for: the winner of a race may already be
    further along.

    ⚠ Why not read-then-write. Drains of the same account overlap all day long: a
    push wakes the phone while the linked browser polls, a client retries a
    request whose answer it never saw, one device holds two sockets for a moment
    after a reconnect. Both requests read "this device has no cursor", both
    INSERT, and the loser got `UniqueViolationError: duplicate key value violates
    unique constraint "queue_cursors_pkey"` back as a 500. A few times a day on
    the flagship, and never harmless: the ack that request carried died with its
    transaction, so those rows were served again on the next drain (as
    notifications), and on the fetch path the rows went out to the client with no
    cursor pinned behind them at all.

    `INSERT ... ON CONFLICT (uin, device_id) DO UPDATE` lets the loser apply its
    ack instead of dying. Postgres waits for the winner to commit and then updates
    the row the winner wrote; SQLite (the local test harness) has the same upsert,
    spelling `greatest()` as `max()`.

    The monotonic rule is the one the ORM code applied before, moved into the
    statement so a race cannot skip it: a cursor only ever goes FORWARD, so a
    stale or out-of-order ack is a no-op rather than a rewind that buries queued
    rows below the watermark for good.

    `direct` / `group` are the marks to apply to a row that already exists, per
    axis, because the two axes advance independently (a group-only ack must not
    touch the 1:1 mark). `seed_direct` / `seed_group` are used ONLY when this
    statement is the one that creates the row, and carry the account-watermark
    rule: a brand-new cursor starts where this account's furthest device got to,
    never at zero.

    ⚠ A row that appeared under us mid-race is deliberately NOT lifted onto that
    seed. Whoever created it seeded it from their own view of the account, and
    raising a lagging install's mark would bury the very rows it is still holding
    (the `_acked_prefix` failure, entered from the side).
    """
    now = datetime.now(timezone.utc)
    pg = engine.dialect.name == "postgresql"
    dialect_insert = pg_insert if pg else sqlite_insert
    biggest = func.greatest if pg else func.max
    ins = dialect_insert(QueueCursor).values(
        uin=uin,
        device_id=device_id,
        last_direct_id=max(direct, seed_direct),
        last_group_id=max(group, seed_group),
        updated_at=now,
    )
    stmt = ins.on_conflict_do_update(
        index_elements=[QueueCursor.uin, QueueCursor.device_id],
        set_={
            "last_direct_id": biggest(QueueCursor.last_direct_id, direct),
            "last_group_id": biggest(QueueCursor.last_group_id, group),
            # This install is demonstrably alive: it is draining right now.
            # `_reap_below_min` reads the stamp to tell a phone that is switched
            # off from an install that is gone.
            "updated_at": now,
        },
    ).returning(QueueCursor.last_direct_id, QueueCursor.last_group_id)
    row = (await db.execute(stmt)).one()
    return int(row[0]), int(row[1])
