"""Local-only verification that two overlapping drains cannot collide.

The bug this pins: every writer of a queue cursor read the row first and then
INSERTed it. Two drains of one account overlap constantly (a push wakes the
phone while the linked browser polls, a client retries a request whose answer it
never saw, one install holds two sockets for a moment after a reconnect), both
read "this device has no cursor", both insert, and the loser came back as

    sqlalchemy.exc.IntegrityError: duplicate key value violates unique
    constraint "queue_cursors_pkey"

which the client saw as a 500. A few times a day on the flagship. Never
harmless either: the ack that request carried died with its transaction, so the
same rows were handed out again on the next drain (as notifications), and on the
fetch path the envelopes went to the client with no cursor pinned behind them.

Under test: `app/services/queue_drain.upsert_cursor`, one
`INSERT ... ON CONFLICT (uin, device_id) DO UPDATE` carrying the monotonic rule,
and its three callers. The checks below are the two halves of the guarantee:
the loser of the race must not raise, and it must not lose its ack or rewind
what the winner wrote.

⚠ The interleaving of the first block is pinned by hand (two sessions, the
second one committing between the first one's read and its write) because a
gather cannot promise the overlap: SQLite serialises writers, and the race then
depends on which task the loop happens to run first. The gathered HTTP block
that follows exercises the same path through the real stack, where a pass is
evidence and not proof.

Runs the real FastAPI stack in-process via httpx ASGITransport on a throwaway
SQLite DB. NOT part of the prod suite; NOT deployed.
Run: cd backend && PYTHONPATH=. .venv/bin/python test_queue_cursor_race_local.py
"""
import asyncio
import base64
import os

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test_queue_cursor_race.db"
os.environ["REDIS_URL"] = "redis://localhost:6379/15"
os.environ["ENV"] = "dev"

for f in ("test_queue_cursor_race.db",):
    try:
        os.remove(f)
    except FileNotFoundError:
        pass

import httpx  # noqa: E402
from sqlalchemy import func, select  # noqa: E402

from app.core.db import SessionLocal, init_db  # noqa: E402
from app.core.security import issue_token  # noqa: E402
from app.main import app  # noqa: E402
from app.models.group import OfflineGroupMessage  # noqa: E402
from app.models.message import OfflineMessage  # noqa: E402
from app.models.queue_cursor import QueueCursor  # noqa: E402
from app.models.user import User  # noqa: E402
from app.routers.messages import _acked_prefix, _advance_cursor  # noqa: E402
from app.services.queue_drain import drain_floor, upsert_cursor  # noqa: E402

fails = 0


def check(name, cond):
    global fails
    print(f"  {'PASS' if cond else 'FAIL'}  {name}")
    if not cond:
        fails += 1


def b64(n=33):
    return base64.b64encode(os.urandom(n)).decode()


UIN = 4200
GID = 11
# A second account with exactly ONE device, for the reap check at the end. It
# needs its own uin because every other block here deliberately keeps a lagging
# device, and a lagging device pins the account's reap floor at zero.
SOLO = 4202


async def enqueue(direct: int, group: int) -> tuple[list[int], list[int]]:
    async with SessionLocal() as db:
        d_rows = [
            OfflineMessage(to_uin=UIN, envelope_type="message", payload=b64())
            for _ in range(direct)
        ]
        g_rows = [
            OfflineGroupMessage(to_uin=UIN, group_id=GID, envelope_type="message", payload=b64())
            for _ in range(group)
        ]
        for r in d_rows + g_rows:
            db.add(r)
        await db.commit()
        return [r.id for r in d_rows], [r.id for r in g_rows]


async def cursor_of(device_id: str) -> tuple[int, int] | None:
    async with SessionLocal() as db:
        c = await db.get(QueueCursor, (UIN, device_id))
        return None if c is None else (c.last_direct_id, c.last_group_id)


async def cursor_rows(device_id: str) -> int:
    async with SessionLocal() as db:
        return int(await db.scalar(
            select(func.count()).select_from(QueueCursor).where(
                QueueCursor.uin == UIN, QueueCursor.device_id == device_id
            )
        ))


async def ack_like_the_endpoint(db, device_id: str, direct_ids, group_ids) -> None:
    """Exactly what POST /messages/queue/ack does, minus the routing, so the
    interleaving can be pinned: read the floor, measure the acked prefix, move
    the cursor. The caller commits."""
    base_direct, base_group, cursor = await drain_floor(db, UIN, device_id)
    max_direct = await _acked_prefix(db, OfflineMessage, UIN, base_direct, direct_ids, 1)
    max_group = await _acked_prefix(db, OfflineGroupMessage, UIN, base_group, group_ids)
    await _advance_cursor(db, UIN, device_id, max_direct, max_group, cursor)


async def main():
    await init_db()
    async with SessionLocal() as db:
        db.add(User(uin=UIN, nickname="dora", identity_key=b64(32), signing_key=b64(32)))
        await db.commit()

    # A lagging device that never acks anything, so nothing is reaped under us
    # mid-run: SQLite hands deleted rowids back out to the next insert and the
    # ids below would start lying (same trap as test_queue_drain_local).
    async with SessionLocal() as db:
        await upsert_cursor(db, UIN, "tablet")
        await db.commit()

    print("\nTwo drains of one account, overlapping by hand:")
    d, g = await enqueue(6, 4)

    # Both requests are in flight at once and neither can see a cursor for the
    # device, which is where the 500 came from.
    s_a, s_b = SessionLocal(), SessionLocal()
    floor_a = await drain_floor(s_a, UIN, "phone")
    floor_b = await drain_floor(s_b, UIN, "phone")
    check("both drains read the same empty floor", floor_a[:2] == (0, 0) == floor_b[:2])

    # A acks all six 1:1 rows and nothing on the group axis, and does NOT commit
    # yet: it now holds the write lock with an uncommitted cursor row, which is
    # the state a Postgres backend is in between its INSERT and its COMMIT.
    await ack_like_the_endpoint(s_a, "phone", d, [])

    # B acked three 1:1 rows and all four group rows off the same empty floor.
    # Its write goes in while A's is still open, so this is the exact interleave
    # prod hits: on SQLite it parks on the write lock, on Postgres it parks on
    # A's uncommitted key, and either way it lands AFTER A commits.
    task_b = asyncio.create_task(ack_like_the_endpoint(s_b, "phone", d[:3], g))
    for _ in range(25):
        await asyncio.sleep(0.02)
    # If this ever fails, the two writes stopped overlapping and every check
    # below has become a no-op that would pass on the unfixed code too.
    check("★ the second drain is still inside the first one's window", not task_b.done())

    await s_a.commit()
    raised = None
    try:
        await task_b
        await s_b.commit()
    except Exception as exc:  # noqa: BLE001 - the point is that nothing escapes
        raised = exc
        await s_b.rollback()
    check(f"★ the loser of the race does not raise ({type(raised).__name__ if raised else 'no exception'})",
          raised is None)
    cur = await cursor_of("phone")
    check("★ the loser's group ack is not lost with its transaction",
          cur is not None and cur[1] == g[3])
    check("★ the winner's 1:1 mark is not rewound by the loser's shorter prefix",
          cur is not None and cur[0] == d[5])
    check("and there is exactly one cursor row for the device", await cursor_rows("phone") == 1)
    await s_a.close()
    await s_b.close()

    # The monotonic rule itself, straight at the statement: a late, stale ack
    # arriving after a further one may not pull the cursor back over rows the
    # drain would then never serve again.
    async with SessionLocal() as db:
        back = await upsert_cursor(db, UIN, "phone", direct=1, group=1)
        await db.commit()
    check("★ a lower mark never moves a cursor backwards", back == (d[5], g[3]))
    check("  ... and the stored row agrees", await cursor_of("phone") == (d[5], g[3]))

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        print("\nTwo first drains of one brand-new device, gathered:")
        # The fetch path pins the floor before handing rows out, so this is the
        # other place two requests INSERTed the same row.
        fresh = {"Authorization": f"Bearer {issue_token(UIN, 0, 'browser')}"}
        d2, g2 = await enqueue(2, 1)
        ra, rb = await asyncio.gather(
            c.get("/messages/queue?ack=true", headers=fresh),
            c.get("/messages/queue?ack=true", headers=fresh),
        )
        codes = sorted([ra.status_code, rb.status_code])
        check(f"★ neither first drain 500s ({codes})", codes == [200, 200])
        check("both are served the same floor", len(ra.json()) == len(rb.json()))
        check("one cursor row, seeded at the account watermark",
              await cursor_rows("browser") == 1 and await cursor_of("browser") == (d[5], g[3]))
        check("the new arrivals are above that floor",
              sorted(r["id"] for r in ra.json() if r["group_id"] is None) == d2
              and sorted(r["id"] for r in ra.json() if r["group_id"] is not None) == g2)

        print("\nTwo acks from one device, gathered:")
        ack_dev = {"Authorization": f"Bearer {issue_token(UIN, 0, 'phone2')}"}
        d3, g3 = await enqueue(3, 0)
        r = await c.get("/messages/queue?ack=true", headers=ack_dev)
        check("the device drains first", r.status_code == 200)
        ra, rb = await asyncio.gather(
            c.post("/messages/queue/ack", json={"direct_ids": d2, "group_ids": g2}, headers=ack_dev),
            c.post("/messages/queue/ack", json={"direct_ids": d2 + d3, "group_ids": g2}, headers=ack_dev),
        )
        codes = sorted([ra.status_code, rb.status_code])
        check(f"★ neither ack 500s ({codes})", codes == [200, 200])
        check("the cursor ends at the furthest acked prefix",
              await cursor_of("phone2") == (d3[-1], g2[-1]))

        print("\nNothing else moved:")
        check("the lagging tablet is still holding the whole queue",
              await cursor_of("tablet") == (0, 0))
        r = await c.get("/messages/queue?ack=true",
                        headers={"Authorization": f"Bearer {issue_token(UIN, 0, 'tablet')}"})
        check("and still receives every queued row",
              len(r.json()) == len(d) + len(g) + len(d2) + len(g2) + len(d3) + len(g3))

        # The reap that rides on every ack, on an account whose ONLY device is
        # the one acking: the account minimum is then the mark this very request
        # just wrote, which is the one shape that can see whether the reap read
        # the write.
        #
        # ⚠ Worth its own block because the upsert writes the row by STATEMENT.
        # A `QueueCursor` the session loaded a few lines earlier (`drain_floor`
        # hands one to `_advance_cursor`) is not refreshed by that write, so
        # `_reap_below_min` re-reading it out of the identity map would compute
        # the minimum from the marks the row had BEFORE the ack, leave
        # `min_direct` at zero and delete nothing — for every ack, forever. Hence
        # `populate_existing=True` on that select. Every other block in this file
        # keeps a lagging device so that nothing is reaped mid-run, so none of
        # them can catch it.
        #
        # ⚠ Last block on purpose: it is the only one here that lets rows be
        # deleted, and SQLite hands a deleted rowid straight back to the next
        # insert, which would make the ids asserted above start lying.
        print("\nThe reap rides on the ack (single-device account):")
        async with SessionLocal() as db:
            db.add(User(uin=SOLO, nickname="solo", identity_key=b64(32), signing_key=b64(32)))
            await db.commit()
        async with SessionLocal() as db:
            solo_rows = [
                OfflineMessage(to_uin=SOLO, envelope_type="message", payload=b64())
                for _ in range(3)
            ]
            for r_ in solo_rows:
                db.add(r_)
            await db.commit()
            solo_ids = [r_.id for r_ in solo_rows]
        solo = {"Authorization": f"Bearer {issue_token(SOLO, 0, 'only-phone')}"}
        r = await c.get("/messages/queue?ack=true", headers=solo)
        check("the only device drains its three rows", len(r.json()) == 3)
        r = await c.post("/messages/queue/ack",
                         json={"direct_ids": solo_ids, "group_ids": []}, headers=solo)
        deleted = r.json().get("deleted") if r.status_code == 200 else None
        check(f"★ the ack reaps the rows it just acked (deleted={deleted})", deleted == 3)
        async with SessionLocal() as db:
            left = int(await db.scalar(
                select(func.count()).select_from(OfflineMessage)
                .where(OfflineMessage.to_uin == SOLO)
            ))
        check("and that account's queue is empty afterwards", left == 0)

    print("\nALL CURSOR-RACE CHECKS PASSED ✅" if fails == 0 else f"\n{fails} CHECK(S) FAILED ❌")
    raise SystemExit(0 if fails == 0 else 1)


asyncio.run(main())
