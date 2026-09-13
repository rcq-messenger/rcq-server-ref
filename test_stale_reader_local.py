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
5. more than a quarter of all marks match    -> nothing demoted, and it says so

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
os.environ.setdefault("RCQ_JWT_SECRET", "test-secret-for-the-stale-reader-sweep")

for leftover in ("./test_stale_reader.db",):
    if os.path.exists(leftover):
        os.remove(leftover)

from app.core.db import Base, SessionLocal, engine, init_db  # noqa: E402
from app.models.group_log import GroupLogReader  # noqa: E402
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
    check("refuses a cycle that would demote more than a quarter", n, 0)
    check("and leaves every mark in place", len(await remaining()), 8)

    # ── the valve lets a normal day through ────────────────────────────────
    await reset()
    await seed([(3000, STALE, HERE)] + [(3000 + i, FRESH, HERE) for i in range(1, 9)])
    n = await sweep.sweep_once()
    check("one stale mark among nine is demoted normally", n, 1)

    await engine.dispose()
    if os.path.exists("./test_stale_reader.db"):
        os.remove("./test_stale_reader.db")
    print("\nstale reader:", "ALL PASS" if ok else "FAILURES ABOVE")
    raise SystemExit(0 if ok else 1)


asyncio.run(main())
