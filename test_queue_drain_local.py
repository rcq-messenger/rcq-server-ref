"""Local-only verification of the offline-queue drain floor.

Reproduces the replay a fresh install hit (#529) and pins the fix: a device
with no cursor must read, ack and be seeded from the account's watermark —
never from zero — on BOTH axes independently, while a device that genuinely
lags keeps everything it has not acknowledged.

Runs the real FastAPI stack in-process via httpx ASGITransport on a throwaway
SQLite DB. NOT part of the prod suite; NOT deployed.
Run: cd backend && PYTHONPATH=. .venv/bin/python test_queue_drain_local.py

⚠ A lagging device (`tablet`) is created first on purpose: it pins the reap
floor at zero, so no row is deleted mid-run. SQLite hands deleted rowids back
out to the next insert, which Postgres BIGSERIAL never does, and reused ids
would make the assertions below lie.
"""
import asyncio
import base64
import os

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test_queue_drain.db"
os.environ["ENV"] = "dev"

for f in ("test_queue_drain.db",):
    try:
        os.remove(f)
    except FileNotFoundError:
        pass

import httpx  # noqa: E402
from sqlalchemy import select  # noqa: E402
from app.main import app  # noqa: E402
from app.core.db import init_db, SessionLocal  # noqa: E402
from app.core.security import issue_token  # noqa: E402
from app.models.user import User  # noqa: E402
from app.models.message import OfflineMessage  # noqa: E402
from app.models.group import OfflineGroupMessage  # noqa: E402
from app.models.queue_cursor import QueueCursor  # noqa: E402

fails = 0


def check(name, cond):
    global fails
    print(f"  {'PASS' if cond else 'FAIL'}  {name}")
    if not cond:
        fails += 1


def b64(n=33):
    return base64.b64encode(os.urandom(n)).decode()


UIN = 2000
GID = 7


async def enqueue(direct: int, group: int) -> tuple[list[int], list[int]]:
    """Queue `direct` 1:1 rows and `group` group rows for UIN. Returns their ids."""
    async with SessionLocal() as db:
        d_rows = [OfflineMessage(to_uin=UIN, envelope_type="message", payload=b64()) for _ in range(direct)]
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


def ids_of(rows, group: bool) -> list[int]:
    return [r["id"] for r in rows if (r["group_id"] is not None) == group]


async def main():
    await init_db()
    async with SessionLocal() as db:
        db.add(User(uin=UIN, nickname="alice", identity_key=b64(32), signing_key=b64(32)))
        await db.commit()

    tablet = {"Authorization": f"Bearer {issue_token(UIN, 0, 'tablet')}"}
    old = {"Authorization": f"Bearer {issue_token(UIN, 0, 'old-phone')}"}
    fresh = {"Authorization": f"Bearer {issue_token(UIN, 0, 'reinstalled')}"}
    legacy = {"Authorization": f"Bearer {issue_token(UIN, 0, 'legacy-client')}"}

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        d_old, g_old = await enqueue(4, 6)

        # The account's FIRST device starts at zero — the queue is all its own.
        r = await c.get("/messages/queue?ack=true", headers=tablet)
        check("first device of an account gets the whole queue", len(r.json()) == 10)
        check("first device seeded at zero (it has acked nothing)", await cursor_of("tablet") == (0, 0))

        # The phone drains and acks everything.
        r = await c.get("/messages/queue?ack=true", headers=old)
        check("old phone drains its queue -> 200", r.status_code == 200)
        check("old phone sees all 10 rows", len(r.json()) == 10)
        r = await c.post("/messages/queue/ack", json={"direct_ids": d_old, "group_ids": g_old}, headers=old)
        check("old phone ack -> 200", r.status_code == 200)
        check("old phone cursor at the watermark", await cursor_of("old-phone") == (max(d_old), max(g_old)))
        check("nothing reaped while the tablet is behind", r.json()["deleted"] == 0)

        # --- Week two: only GROUP traffic arrives while the phone is off ----
        _, g_new = await enqueue(0, 3)

        # --- The reinstall: a device id the island has never seen -----------
        r = await c.get("/messages/queue?ack=true", headers=fresh)
        got = r.json()
        check("fresh install gets ONLY what arrived since", ids_of(got, group=True) == g_new)
        check("fresh install gets no 1:1 replay", ids_of(got, group=False) == [])
        check(
            "fetch seeds the cursor at the account watermark, both axes",
            await cursor_of("reinstalled") == (max(d_old), max(g_old)),
        )

        # It acks the group rows it stored. There is nothing to ack on the
        # direct axis — exactly the case that used to write a cursor of 0.
        r = await c.post("/messages/queue/ack", json={"direct_ids": [], "group_ids": g_new}, headers=fresh)
        check("fresh install ack -> 200", r.status_code == 200)
        cur = await cursor_of("reinstalled")
        check("★ direct axis NOT reset to zero by an empty ack", cur is not None and cur[0] == max(d_old))
        check("group axis advanced over the acked rows", cur is not None and cur[1] == max(g_new))

        # The bug's payoff: the SECOND drain of the fresh install.
        r = await c.get("/messages/queue?ack=true", headers=fresh)
        check("★ second drain of a fresh install is empty (no replay)", r.json() == [])

        # --- A hole in the ack still stops the cursor (13.08 fix intact) ----
        d_hole, _ = await enqueue(3, 0)
        r = await c.get("/messages/queue?ack=true", headers=fresh)
        check("fresh install sees the 3 new 1:1 rows", ids_of(r.json(), group=False) == d_hole)
        # Ack the first and the third: the middle one is a hole.
        await c.post(
            "/messages/queue/ack",
            json={"direct_ids": [d_hole[0], d_hole[2]], "group_ids": []},
            headers=fresh,
        )
        cur = await cursor_of("reinstalled")
        check("cursor stops at the first hole, not at max(acked)", cur is not None and cur[0] == d_hole[0])
        r = await c.get("/messages/queue?ack=true", headers=fresh)
        check("the un-acked rows come back on the next drain", ids_of(r.json(), group=False) == d_hole[1:])

        # --- Lagging devices are never rebased onto a sibling's watermark ---
        check("old phone's cursor untouched by the others", await cursor_of("old-phone") == (max(d_old), max(g_old)))
        r = await c.get("/messages/queue?ack=true", headers=old)
        check(
            "old phone still receives everything it never acked",
            ids_of(r.json(), group=True) == g_new and ids_of(r.json(), group=False) == d_hole,
        )
        r = await c.get("/messages/queue?ack=true", headers=tablet)
        check("the lagging tablet still holds the FULL queue", len(r.json()) == 10 + len(g_new) + len(d_hole))

        # --- Legacy drain-on-fetch path (ack=false) -------------------------
        d_last, g_last = await enqueue(2, 2)
        floor_direct, floor_group = max(d_hole), max(g_new)  # furthest cursor = the fresh install
        r = await c.get("/messages/queue", headers=legacy)
        rows = r.json()
        check(
            "legacy fetch starts at the watermark, not at zero",
            rows and min(ids_of(rows, group=False)) > floor_direct - len(d_hole)
            and all(i > floor_group for i in ids_of(rows, group=True)),
        )
        check("legacy fetch includes the newest rows", set(d_last) <= set(ids_of(rows, group=False))
              and set(g_last) <= set(ids_of(rows, group=True)))
        r = await c.get("/messages/queue", headers=legacy)
        check("legacy fetch drains on read (second call empty)", r.json() == [])

        # --- No cursor may sit at zero on an axis the account has drained ---
        async with SessionLocal() as db:
            cursors = (await db.execute(select(QueueCursor).where(QueueCursor.uin == UIN))).scalars().all()
        offenders = [
            c_.device_id for c_ in cursors
            if c_.device_id != "tablet" and (c_.last_direct_id == 0 or c_.last_group_id == 0)
        ]
        check(f"★ no drained device left at zero (offenders: {offenders})", not offenders)

    print("\nALL QUEUE-DRAIN CHECKS PASSED ✅" if fails == 0 else f"\n{fails} CHECK(S) FAILED ❌")
    raise SystemExit(0 if fails == 0 else 1)


asyncio.run(main())
