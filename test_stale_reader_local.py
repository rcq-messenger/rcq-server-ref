"""Local-only verification of the stale-reader demotion (13.09.2026).

What this guards is one rule, and the reason it has a test is that the rule was
WRONG on the first attempt in a way no amount of reading catches. The first
draft dropped a mark when the account had been seen "more recently than the
mark", which sounds like "the person is here and their reader has gone quiet"
and is not: almost everybody who ever opened the app was seen a few seconds
after their one and only fetch and never again, so a dry run against the
flagship matched 287 of 523 marks. The rule that ships is "the mark is stale AND
the account has been seen RECENTLY", which matched 64.

So the five cases below are the five ways to get this wrong:

1. stale mark, account here now              -> demoted, this is the bug being fixed
2. stale mark, account long gone             -> left alone, they are missing nothing
3. fresh mark, account here now              -> left alone, the reader is working
4. stale mark, account seen just over the horizon -> left alone, at the boundary
5. more than a quarter of all marks match    -> the valve trips: only what the
   cursors confirm is demoted, oldest first and at most a quarter (but at
   least one, or a three-mark island is refused for ever), the rest is held
   back and counted (it used to refuse whole, which left a broken client
   release starving in silence; report 981)

And the per-room detector (report 981, second half), which the mark cannot
replace: a device reading one room while stuck in another has a fresh mark.

⚠ There is no "account never seen" case, and an early draft of this file had
one. `models/user.py:209` defaults `last_seen` to the moment of registration,
so the column is never NULL and a test that passes None gets `now()` written
under it, which then matched the rule and failed the case it was written to
prove. The column's default is the fact; the test says so rather than asserting
a state the schema cannot produce.

Direct unit test against a throwaway SQLite DB, no HTTP.
Run: cd backend && PYTHONPATH=. .venv/bin/python test_stale_reader_local.py
"""
import asyncio
import os
from datetime import datetime, timedelta, timezone

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test_stale_reader.db"
os.environ["REDIS_URL"] = "redis://localhost:6379/15"
os.environ.setdefault("RCQ_JWT_SECRET", "test-secret-for-the-stale-reader-sweep")

for leftover in ("./test_stale_reader.db",):
    if os.path.exists(leftover):
        os.remove(leftover)

from app.core.db import Base, SessionLocal, engine, init_db  # noqa: E402
from app.core.redis import close_redis, get_redis  # noqa: E402
from app.models.group import Group, GroupMember  # noqa: E402
from app.models.group_log import GroupLog, GroupLogCursor, GroupLogReader, GroupSeq  # noqa: E402
from app.models.user import User  # noqa: E402
from app.services import stale_reader_sweep as sweep  # noqa: E402

# ⚠ The metadata is only complete once every model module has been imported,
# and the list of them is hand-maintained inside init_db (core/db.py). Borrow
# it rather than keeping a second copy here that would rot: a missing import
# makes create_all fail on a foreign key to a table nobody registered.
import app.models.user, app.models.contact, app.models.message, app.models.group  # noqa: E402,F401
import app.models.device_token, app.models.prekey, app.models.device  # noqa: E402,F401
import app.models.audio_room, app.models.report, app.models.news, app.models.invite  # noqa: E402,F401
import app.models.queue_cursor, app.models.federation, app.models.capability  # noqa: E402,F401
import app.models.broker, app.models.access_token, app.models.server_setting  # noqa: E402,F401
import app.models.uin_epoch, app.models.owned_uin, app.models.relay_inquiry  # noqa: E402,F401
import app.models.mailbox_seq, app.models.group_log, app.models.vault  # noqa: E402,F401
import app.models.island_logo, app.models.site, app.models.uin_sale  # noqa: E402,F401
import app.models.uin_listing, app.models.guest_card  # noqa: E402,F401

NOW = datetime.now(timezone.utc)
LONG_AGO = NOW - timedelta(days=40)
STALE = NOW - timedelta(days=30)
FRESH = NOW - timedelta(hours=2)
HERE = NOW - timedelta(hours=6)

ok = True


def check(name: str, got, want) -> None:
    global ok
    if got == want:
        print(f"  ok   {name}")
    else:
        ok = False
        print(f"  FAIL {name}: got {got!r}, want {want!r}")


async def seed(rows) -> None:
    """rows: (uin, mark_last_seen, account_last_seen)"""
    async with SessionLocal() as db:
        for uin, mark_seen, acct_seen in rows:
            db.add(User(
                uin=uin,
                nickname=f"u{uin}",
                identity_key="x" * 43,
                signing_key="y" * 43,
                last_seen=acct_seen,
            ))
            db.add(GroupLogReader(
                uin=uin, device_id=f"dev-{uin}", first_seen=mark_seen, last_seen=mark_seen,
            ))
        await db.commit()


async def room(gid: int, head: int, rows) -> None:
    """A room at `head`, with log rows (seq, to_uin, received_at)."""
    async with SessionLocal() as db:
        db.add(Group(id=gid, name=f"g{gid}", owner_uin=1))
        db.add(GroupSeq(group_id=gid, next_seq=head))
        for seq, to_uin, at in rows:
            db.add(GroupLog(
                group_id=gid, seq=seq, to_uin=to_uin, envelope_type="gmsg",
                cls=1, payload="x", received_at=at,
            ))
        await db.commit()


async def device(uin: int, dev: str, mark_seen, cursors, member_of=()) -> None:
    """A reading device: its mark, its cursors {gid: (last_seq, updated_at)},
    and the rooms its account sits in."""
    async with SessionLocal() as db:
        if await db.get(User, uin) is None:
            db.add(User(uin=uin, nickname=f"u{uin}", identity_key="x" * 43,
                        signing_key="y" * 43, last_seen=HERE))
        db.add(GroupLogReader(uin=uin, device_id=dev, first_seen=mark_seen, last_seen=mark_seen))
        for gid, (last_seq, moved_at) in cursors.items():
            db.add(GroupLogCursor(group_id=gid, uin=uin, device_id=dev,
                                  last_seq=last_seq, updated_at=moved_at))
        for gid in member_of:
            db.add(GroupMember(group_id=gid, uin=uin, role="member"))
        await db.commit()


async def remaining() -> set[int]:
    from sqlalchemy import select
    async with SessionLocal() as db:
        return set((await db.execute(select(GroupLogReader.uin))).scalars().all())


async def reset() -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)


async def main() -> None:
    print("stale reader sweep")

    # ── 1-4: the four shapes, all present at once ───────────────────────────
    await reset()
    await seed([
        (1001, STALE, HERE),       # 1: the bug being fixed
        (1002, STALE, LONG_AGO),   # 2: gone, missing nothing
        (1003, FRESH, HERE),       # 3: working
        (1004, STALE, NOW - timedelta(days=3)),  # 4: seen, but before the horizon
    ])
    n = await sweep.sweep_once()
    check("demotes only the stale mark of an account that is here", n, 1)
    check("the right rows survive", await remaining(), {1002, 1003, 1004})

    # ── 5: the safety valve ────────────────────────────────────────────────
    await reset()
    await seed([(2000 + i, STALE, HERE) for i in range(8)])
    n = await sweep.sweep_once()
    check("past a quarter, nothing the cursors do not confirm is demoted", n, 0)
    check("and every mark stays in place", len(await remaining()), 8)
    check("  ... all eight counted as held back", sweep._last_sweep.get("held_back"), 8)

    # ── 5b: the valve demotes the cursor-confirmed ones, oldest first ──────
    # Twelve marks, all stale while the account is here. Four of the devices
    # have a row they can see waiting in room 50 since well before the mark
    # went stale: starving by the log's own evidence. The other eight are
    # level (the room is quiet for them), which is exactly what a bug in the
    # mark rule would look like. The share is 3 of 12, so the three OLDEST
    # confirmed marks go, and nine are held back.
    await reset()
    await room(50, 10, [(s_, None, LONG_AGO) for s_ in range(1, 11)])
    for i in range(4):
        await device(4000 + i, f"dev-{4000 + i}", NOW - timedelta(days=30 + i), {50: (0, LONG_AGO)}, (50,))
    for i in range(8):
        await device(4100 + i, f"dev-{4100 + i}", STALE, {50: (10, STALE)}, (50,))
    n = await sweep.sweep_once()
    check("the tripped valve demotes a quarter of the marks", n, 3)
    left = await remaining()
    check("  ... the three oldest of the confirmed ones", {4001, 4002, 4003} & left, set())
    check("  ... the fourth confirmed one waits for the next cycle", 4000 in left, True)
    check("  ... no level device is touched", {4100 + i for i in range(8)} <= left, True)
    check("  ... nine held back", sweep._last_sweep.get("held_back"), 9)
    n = await sweep.sweep_once()
    check("next cycle the last confirmed one goes", n, 1)
    check("  ... and the level ones stay held back while they are the bulk",
          (await remaining(), sweep._last_sweep.get("held_back")),
          ({4100 + i for i in range(8)}, 8))

    # ── 5c: a small island is not refused for ever ─────────────────────────
    # Three marks (one family). One device stopped reading while the account is
    # here: 1 of 3 trips the valve, and a quarter of 3 rounds down to nothing,
    # which used to hold that person back every hour indefinitely. At least one
    # cursor-confirmed mark goes through each cycle.
    await reset()
    await room(70, 10, [(s_, None, LONG_AGO) for s_ in range(1, 11)])
    await device(7001, "dev-7001", STALE, {70: (0, LONG_AGO)}, (70,))
    await device(7002, "dev-7002", FRESH, {70: (10, FRESH)}, (70,))
    await device(7003, "dev-7003", FRESH, {70: (10, FRESH)}, (70,))
    n = await sweep.sweep_once()
    check("a three-mark island demotes its one confirmed stale mark", n, 1)
    check("  ... it is gone", 7001 in await remaining(), False)
    check("  ... nothing held back", sweep._last_sweep.get("held_back"), 0)
    # The same island, but the stale device is level and the room quiet: the
    # cursors do not confirm it, so the valve still holds it back.
    await reset()
    await room(70, 10, [(s_, None, LONG_AGO) for s_ in range(1, 11)])
    await device(7001, "dev-7001", STALE, {70: (10, STALE)}, (70,))
    await device(7002, "dev-7002", FRESH, {70: (10, FRESH)}, (70,))
    await device(7003, "dev-7003", FRESH, {70: (10, FRESH)}, (70,))
    n = await sweep.sweep_once()
    check("an unconfirmed stale mark on a three-mark island is held back", n, 0)
    check("  ... it stays", 7001 in await remaining(), True)
    check("  ... and is counted", sweep._last_sweep.get("held_back"), 1)

    # ── the valve lets a normal day through ────────────────────────────────
    await reset()
    await seed([(3000, STALE, HERE)] + [(3000 + i, FRESH, HERE) for i in range(1, 9)])
    n = await sweep.sweep_once()
    check("one stale mark among nine is demoted normally", n, 1)

    # ── 6: the per-room detector ───────────────────────────────────────────
    # Room 60 has had a broadcast waiting since 5 days ago and new ones since.
    # Room 61 has only a row sealed to somebody else that old, then fresh
    # broadcasts. Room 62 has an old row sealed to 5003 itself.
    await reset()
    five_days = NOW - timedelta(days=5)
    await room(60, 6, [(1, None, five_days), (2, None, five_days), (3, None, FRESH), (6, None, FRESH)])
    await room(61, 4, [(1, 9999, five_days), (2, None, FRESH), (4, None, FRESH)])
    await room(62, 3, [(2, 5003, five_days), (3, None, FRESH)])
    # 5001: reads (fresh mark), stuck in 60 for 5 days: the case.
    await device(5001, "phone-a", FRESH, {60: (0, five_days)}, (60,))
    # 5002: same room, but its cursor moved an hour ago: catching up, not stuck.
    await device(5002, "phone-b", FRESH, {60: (1, FRESH)}, (60,))
    # 5003: stuck in 61 behind a row that is not for it, and in 62 behind one
    # that is. Only 62 is starving.
    await device(5003, "phone-c", FRESH, {61: (0, five_days), 62: (0, five_days)}, (61, 62))
    # 5004: level with room 60.
    await device(5004, "phone-d", FRESH, {60: (6, five_days)}, (60,))
    # 5005: stuck in 60, but its mark is a week old: the device sweep's case.
    await device(5005, "phone-e", NOW - timedelta(days=8), {60: (0, five_days)}, (60,))
    # 5006: stuck in 60, but no longer a member (cursor not reaped yet).
    await device(5006, "phone-f", FRESH, {60: (0, five_days)}, ())
    found = await sweep.starving_rooms()
    check("the detector finds exactly the stuck pairs of reading devices",
          sorted((g, u) for g, u, _, _ in found), [(60, 5001), (62, 5003)])
    check("  ... with the seq gap to the head", sorted(gap for _, _, _, gap in found), [3, 6])

    # The hourly line names nobody unless the operator switched identities on.
    import logging
    from app.core.config import settings

    class Grab(logging.Handler):
        def __init__(self):
            super().__init__()
            self.lines: list[str] = []

        def emit(self, record):
            self.lines.append(record.getMessage())

    grab = Grab()
    sweep.log.addHandler(grab)
    was = settings.RCQ_LOG_IDENTITIES
    try:
        settings.RCQ_LOG_IDENTITIES = False
        await sweep.starving_rooms()
        lines = [line for line in grab.lines if line.startswith("starving room:")]
        check("the starving-room line is written per pair", len(lines), 2)
        check("  ... with no uin, device or room in it",
              any(s_ in line for line in lines for s_ in ("5001", "5003", "phone-", "room=60", "room=62")),
              False)
        grab.lines.clear()
        settings.RCQ_LOG_IDENTITIES = True
        await sweep.starving_rooms()
        lines = [line for line in grab.lines if line.startswith("starving room:")]
        check("  ... and names them with RCQ_LOG_IDENTITIES on",
              any("uin=5001" in line and "room=60" in line for line in lines), True)
    finally:
        settings.RCQ_LOG_IDENTITIES = was
        sweep.log.removeHandler(grab)

    # ── 7: the console's numbers ───────────────────────────────────────────
    redis = await get_redis()
    await redis.delete(sweep.STATUS_KEY)
    check("no status before a cycle", await sweep.read_status(), {})
    await sweep.run_cycle()
    status = await sweep.read_status()
    check("a cycle publishes the starving count", status.get("starving_cursors"), 2)
    check("  ... and the devices behind it", status.get("starving_devices"), 2)
    check("  ... and nothing about who", sorted(status), ["at", "demoted", "held_back", "starving_cursors", "starving_devices"])
    from app.routers.admin import stats as admin_stats
    async with SessionLocal() as db:
        out = await admin_stats(db)
    check("/admin/stats carries it to the console", (out.group_log_starving, out.stale_readers_held_back), (2, 0))
    await redis.delete(sweep.STATUS_KEY)
    await close_redis()

    await engine.dispose()
    if os.path.exists("./test_stale_reader.db"):
        os.remove("./test_stale_reader.db")
    print("\nstale reader:", "ALL PASS" if ok else "FAILURES ABOVE")
    raise SystemExit(0 if ok else 1)


asyncio.run(main())
