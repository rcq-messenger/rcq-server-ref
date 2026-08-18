"""Local-only verification of the superseded-cursor rule in `_reap_below_min`.

An abandoned install (reinstalled, uninstalled, wiped) keeps a drain cursor
that never moves again, and until 18.08 that cursor pinned the account's whole
queue above the reap floor for THIRTY days. Measured on prod: two accounts
alone were holding 3926 sealed envelopes behind cursors last touched a
fortnight earlier, while their live devices sat at zero pending.

The rule under test: a cursor stops holding the queue after
SUPERSEDED_CURSOR_DAYS *only* when a sibling cursor of the same account is
still moving. The account's ONLY cursor keeps the old 30-day leash, because a
phone switched off for a fortnight must not lose its mail.

Direct unit test of the reaper against a throwaway SQLite DB — no HTTP, since
what is under test is the cursor arithmetic, not the routing.
Run: cd backend && PYTHONPATH=. .venv/bin/python test_cursor_reap_local.py
"""
import asyncio
import os
from datetime import datetime, timedelta, timezone

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test_cursor_reap.db"
os.environ["ENV"] = "dev"

for f in ("test_cursor_reap.db",):
    try:
        os.remove(f)
    except FileNotFoundError:
        pass

from sqlalchemy import func, select  # noqa: E402

from app.core.db import SessionLocal, init_db  # noqa: E402
from app.models.message import OfflineMessage  # noqa: E402
from app.models.queue_cursor import QueueCursor  # noqa: E402
from app.routers.messages import _reap_below_min  # noqa: E402

PASS, FAIL = [], []


def check(name: str, ok: bool, detail: str = "") -> None:
    (PASS if ok else FAIL).append(name)
    print(f"  {'ok  ' if ok else 'FAIL'} {name}{'' if ok else '  ← ' + detail}")


async def seed(db, uin: int, n: int) -> list[int]:
    ids = []
    for _ in range(n):
        row = OfflineMessage(to_uin=uin, envelope_type="message", payload="x",
                             received_at=datetime.now(timezone.utc))
        db.add(row)
        await db.flush()
        ids.append(row.id)
    await db.commit()
    return ids


async def pending(db, uin: int) -> int:
    return int(await db.scalar(
        select(func.count(OfflineMessage.id)).where(OfflineMessage.to_uin == uin)
    ) or 0)


async def main() -> None:
    await init_db()
    now = datetime.now(timezone.utc)

    async with SessionLocal() as db:
        # ── 1. abandoned install beside a live device ───────────────────────
        uin = 1001
        ids = await seed(db, uin, 10)
        db.add(QueueCursor(uin=uin, device_id="dead-install", last_direct_id=ids[2],
                           last_group_id=0, updated_at=now - timedelta(days=14)))
        db.add(QueueCursor(uin=uin, device_id="live-phone", last_direct_id=ids[-1],
                           last_group_id=0, updated_at=now))
        await db.commit()
        await _reap_below_min(db, uin)
        await db.commit()
        left = await pending(db, uin)
        check("abandoned cursor stops holding the queue", left == 0, f"{left} rows left")
        rows = (await db.execute(select(QueueCursor).where(QueueCursor.uin == uin))).scalars().all()
        check("the live cursor survives", {c.device_id for c in rows} == {"live-phone"},
              str({c.device_id for c in rows}))

        # ── 2. single device, quiet for a fortnight (the holiday) ───────────
        uin = 1002
        ids = await seed(db, uin, 10)
        db.add(QueueCursor(uin=uin, device_id="only-phone", last_direct_id=ids[2],
                           last_group_id=0, updated_at=now - timedelta(days=14)))
        await db.commit()
        await _reap_below_min(db, uin)
        await db.commit()
        left = await pending(db, uin)
        check("a lone quiet device keeps its mail", left == 7, f"{left} rows left, expected 7")
        rows = (await db.execute(select(QueueCursor).where(QueueCursor.uin == uin))).scalars().all()
        check("its cursor is not dropped", len(rows) == 1, f"{len(rows)} cursors")

        # ── 3. two devices, both merely idle (neither superseded) ───────────
        uin = 1003
        ids = await seed(db, uin, 10)
        db.add(QueueCursor(uin=uin, device_id="a", last_direct_id=ids[2],
                           last_group_id=0, updated_at=now - timedelta(days=14)))
        db.add(QueueCursor(uin=uin, device_id="b", last_direct_id=ids[4],
                           last_group_id=0, updated_at=now - timedelta(days=13)))
        await db.commit()
        await _reap_below_min(db, uin)
        await db.commit()
        left = await pending(db, uin)
        check("two idle devices both keep their mail", left == 7, f"{left} rows left, expected 7")

        # ── 4. the 30-day rule still applies to a lone ancient cursor ───────
        uin = 1004
        ids = await seed(db, uin, 10)
        db.add(QueueCursor(uin=uin, device_id="ancient", last_direct_id=ids[2],
                           last_group_id=0, updated_at=now - timedelta(days=40)))
        await db.commit()
        await _reap_below_min(db, uin)
        await db.commit()
        rows = (await db.execute(select(QueueCursor).where(QueueCursor.uin == uin))).scalars().all()
        check("a 40-day-old lone cursor is still dropped", len(rows) == 0, f"{len(rows)} cursors")

        # ── 5. a lagging device that is still acking holds its rows ─────────
        uin = 1005
        ids = await seed(db, uin, 10)
        db.add(QueueCursor(uin=uin, device_id="slow-but-alive", last_direct_id=ids[2],
                           last_group_id=0, updated_at=now - timedelta(hours=6)))
        db.add(QueueCursor(uin=uin, device_id="fast", last_direct_id=ids[-1],
                           last_group_id=0, updated_at=now))
        await db.commit()
        await _reap_below_min(db, uin)
        await db.commit()
        left = await pending(db, uin)
        check("a lagging LIVE device still holds its unread", left == 7, f"{left} rows left, expected 7")

    print(f"\n{len(PASS)}/{len(PASS) + len(FAIL)} pass")
    if FAIL:
        raise SystemExit("FAILED: " + ", ".join(FAIL))


asyncio.run(main())
