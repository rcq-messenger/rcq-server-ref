"""Local-only verification: one room cannot take the whole group-log page.

Report 981, second half. /messages/group-log/fetch used to fill its page room by
room in gid order until `limit` or the 128 KiB byte budget ran out. A room with
a long tail therefore took the page, and when its client could not ack (a row
it cannot open holds the cursor) every page was the same page of that room:
the rooms with a larger gid got `more: true` and never a row, and the clients
stop paging when a page moves nothing. Pins:
  * a stuck low-gid room with more than a page behind it does not keep a
    one-row room and a five-row room out of the FIRST page;
  * rows of each room are contiguous and ascending from its cursor, rooms are
    answered in gid order, the page stays within the byte budget, `more` set;
  * with the stuck room still stuck, a later post in another room arrives;
  * a row bigger than the whole budget at the head of a room waits while any
    other room has a row that fits, and goes out ALONE once none does;
  * a row that fits an empty page but not what a stalled lower room leaves of
    it still goes out on the first page (once a page, under twice the budget);
  * the row `limit` is shared too: a three-row room is served whole beside a
    hundred-row room;
  * rows sealed to other members neither show nor count;
  * a room listed twice is served once;
  * the reader mark moves only on an ack that moves a cursor.

Runs the real FastAPI stack in-process on a throwaway SQLite DB with Redis
db 15. NOT deployed.
Run: PYTHONPATH=. .venv/bin/python test_group_log_fair_page_local.py
"""
import asyncio
import base64
import os
from datetime import datetime, timedelta, timezone

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test_fair_page.db"
os.environ["ENV"] = "dev"
os.environ["REDIS_URL"] = "redis://localhost:6379/15"
for f in ("test_fair_page.db",):
    try:
        os.remove(f)
    except FileNotFoundError:
        pass

import httpx  # noqa: E402
from sqlalchemy import select, update  # noqa: E402

from app.core.db import SessionLocal, init_db  # noqa: E402
from app.core.redis import close_redis, get_redis  # noqa: E402
from app.core.security import issue_token  # noqa: E402
from app.main import app  # noqa: E402
from app.models.capability import UserCapability  # noqa: E402
from app.models.group import Group, GroupMember  # noqa: E402
from app.models.group_log import GroupLog, GroupLogCursor, GroupLogReader, GroupSeq  # noqa: E402
from app.models.user import User  # noqa: E402
from app.routers.messages import GROUP_LOG_PAGE_BYTES  # noqa: E402

fails = 0


def check(name, cond):
    global fails
    print(f"  {'PASS' if cond else 'FAIL'}  {name}")
    if not cond:
        fails += 1


def b64(n=32):
    return base64.b64encode(os.urandom(n)).decode()


OWNER, OTHER = 7000, 7999
KB = "k" * 1024


async def make_user(uin):
    async with SessionLocal() as db:
        db.add(User(uin=uin, nickname=f"u{uin}", identity_key=b64(), signing_key=b64()))
        db.add(UserCapability(uin=uin, sender_keys=True))
        await db.commit()


async def make_room(members, rows):
    """A room with `members` and log rows [(payload, to_uin)], seqs from 1."""
    async with SessionLocal() as db:
        g = Group(name="r", owner_uin=OWNER)
        db.add(g)
        await db.flush()
        for u in members:
            db.add(GroupMember(group_id=g.id, uin=u, role="owner" if u == OWNER else "member"))
        now = datetime.now(timezone.utc)
        for i, (payload, to_uin) in enumerate(rows, start=1):
            db.add(GroupLog(group_id=g.id, seq=i, to_uin=to_uin, envelope_type="gmsg",
                            cls=1, payload=payload, received_at=now))
        db.add(GroupSeq(group_id=g.id, next_seq=len(rows)))
        await db.commit()
        return g.id


async def add_rows(gid, rows):
    async with SessionLocal() as db:
        head = (await db.execute(select(GroupSeq.next_seq).where(GroupSeq.group_id == gid))).scalar_one()
        now = datetime.now(timezone.utc)
        for i, (payload, to_uin) in enumerate(rows, start=head + 1):
            db.add(GroupLog(group_id=gid, seq=i, to_uin=to_uin, envelope_type="gmsg",
                            cls=1, payload=payload, received_at=now))
        await db.execute(update(GroupSeq).where(GroupSeq.group_id == gid).values(next_seq=head + len(rows)))
        await db.commit()


async def cursors_at_zero(uin, device, gids):
    async with SessionLocal() as db:
        for gid in gids:
            db.add(GroupLogCursor(group_id=gid, uin=uin, device_id=device, last_seq=0))
        await db.commit()


def by_room(rows):
    out = {}
    for r in rows:
        out.setdefault(r["gid"], []).append(r["seq"])
    return out


def well_formed(body, starts):
    """Each room's rows contiguous-ascending from its start (no visible row
    skipped: every room here is all-broadcast), rooms in gid order."""
    rooms = by_room(body["rows"])
    order = [r["gid"] for r in body["rows"]]
    grouped = order == sorted(order)
    contiguous = all(seqs == list(range(starts[g] + 1, starts[g] + 1 + len(seqs))) for g, seqs in rooms.items())
    return grouped and contiguous


async def main():
    global fails
    await init_db()
    redis = await get_redis()
    await redis.flushdb()
    await make_user(OWNER)
    await make_user(OTHER)
    H = lambda t: {"Authorization": f"Bearer {t}"}  # noqa: E731
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        # ── the report ──────────────────────────────────────────────────────
        print("\nA stuck low-gid room with a long tail (report 981):")
        M = 7001
        await make_user(M)
        tok = issue_token(M, 0, "m-phone")
        stuck = await make_room((OWNER, M), [(KB, None)] * 300)  # ~300 KB behind
        one = await make_room((OWNER, M), [(KB, None)])
        five = await make_room((OWNER, M), [(KB, None)] * 5)
        check("the stuck room has the smallest gid", stuck < one < five)
        await cursors_at_zero(M, "m-phone", (stuck, one, five))
        r = await c.post("/messages/group-log/fetch", headers=H(tok), json={})
        body = r.json()
        rooms = by_room(body["rows"])
        check("the one-row room is in the FIRST page", rooms.get(one) == [1])
        check("  ... so is the five-row room, whole", rooms.get(five) == [1, 2, 3, 4, 5])
        check("  ... and the stuck room still gets the rest of it", len(rooms.get(stuck, [])) > 100)
        check("  ... within the byte budget", sum(len(x["payload"]) for x in body["rows"]) <= GROUP_LOG_PAGE_BYTES)
        check("  ... saying there is more", body["more"] is True)
        check("  ... rooms in gid order, each contiguous from its cursor",
              well_formed(body, {stuck: 0, one: 0, five: 0}))
        # The client acks the two small rooms and cannot get past seq 1 of the
        # stuck one, so it acks nothing there.
        r = await c.post("/messages/group-log/ack", headers=H(tok), json={"rooms": [
            {"gid": one, "upto": 1}, {"gid": five, "upto": 5},
        ]})
        check("the small rooms ack", r.status_code == 200 and r.json()["deleted"] == 2)
        r = await c.post("/messages/group-log/fetch", headers=H(tok), json={})
        rooms = by_room(r.json()["rows"])
        check("the next page is the stuck room again, from its cursor", list(rooms) == [stuck] and rooms[stuck][0] == 1)
        await add_rows(five, [(KB, None)])
        r = await c.post("/messages/group-log/fetch", headers=H(tok), json={})
        rooms = by_room(r.json()["rows"])
        check("a later post in another room still arrives while the stuck one is stuck", rooms.get(five) == [6])

        # ── fairness by bytes across many rooms ───────────────────────────────
        print("\nFour rooms each with more than a page behind them:")
        M = 7002
        await make_user(M)
        tok = issue_token(M, 0, "m-phone")
        big = [await make_room((OWNER, M), [(KB, None)] * 200) for _ in range(4)]
        await cursors_at_zero(M, "m-phone", big)
        r = await c.post("/messages/group-log/fetch", headers=H(tok), json={})
        body = r.json()
        counts = [len(by_room(body["rows"]).get(g, [])) for g in big]
        check(f"every room gets a share ({counts})", min(counts) > 0)
        check("  ... an equal one, give or take a row", max(counts) - min(counts) <= 1)
        check("  ... well formed", well_formed(body, {g: 0 for g in big}))

        # ── a row bigger than the whole budget ────────────────────────────────
        print("\nA row bigger than the whole budget at the head of a room:")
        M = 7003
        await make_user(M)
        tok = issue_token(M, 0, "m-phone")
        giant = "g" * (GROUP_LOG_PAGE_BYTES + 70_000)
        huge_room = await make_room((OWNER, M), [(giant, None), (KB, None)])
        small_room = await make_room((OWNER, M), [(KB, None)] * 3)
        await cursors_at_zero(M, "m-phone", (huge_room, small_room))
        r = await c.post("/messages/group-log/fetch", headers=H(tok), json={})
        rooms = by_room(r.json()["rows"])
        check("waits while another room has rows that fit", rooms == {small_room: [1, 2, 3]} and r.json()["more"] is True)
        await c.post("/messages/group-log/ack", headers=H(tok), json={"rooms": [{"gid": small_room, "upto": 3}]})
        r = await c.post("/messages/group-log/fetch", headers=H(tok), json={})
        body = r.json()
        check("then goes out ALONE", [(x["gid"], x["seq"]) for x in body["rows"]] == [(huge_room, 1)])
        check("  ... with more set for what is behind it", body["more"] is True)

        # ── a large row behind a stalled room ─────────────────────────────────
        # The stalled room S comes first in the turn order and is re-served on
        # every page (its client will not ack it yet). Room A's head fits an
        # empty page but not what S leaves of it, so it used to wait for ever.
        print("\nA large row in one room while a lower room stays stalled:")
        M = 7006
        await make_user(M)
        tok = issue_token(M, 0, "m-phone")
        near = "n" * (GROUP_LOG_PAGE_BYTES - 500)
        stalled = await make_room((OWNER, M), [(KB, None)] * 3)
        large = await make_room((OWNER, M), [(near, None), (near, None)])
        check("the stalled room has the smaller gid", stalled < large)
        await cursors_at_zero(M, "m-phone", (stalled, large))
        r = await c.post("/messages/group-log/fetch", headers=H(tok), json={})
        body = r.json()
        rooms = by_room(body["rows"])
        check("the large row is on the FIRST page", rooms.get(large) == [1])
        check("  ... beside the stalled room's rows", rooms.get(stalled) == [1, 2, 3])
        check("  ... the page stays under twice the budget",
              sum(len(x["payload"]) for x in body["rows"]) <= 2 * GROUP_LOG_PAGE_BYTES)
        check("  ... and the room's second large row waits (one stretch a page)", body["more"] is True)
        # The client acks the large room only; S stays where it is.
        await c.post("/messages/group-log/ack", headers=H(tok), json={"rooms": [{"gid": large, "upto": 1}]})
        r = await c.post("/messages/group-log/fetch", headers=H(tok), json={})
        body = r.json()
        rooms = by_room(body["rows"])
        check("the next page brings the next large row, S still unacked",
              rooms.get(large) == [2] and rooms.get(stalled) == [1, 2, 3])
        check("  ... again under twice the budget",
              sum(len(x["payload"]) for x in body["rows"]) <= 2 * GROUP_LOG_PAGE_BYTES)

        # ── the row limit ─────────────────────────────────────────────────────
        print("\nThe row limit is shared as well:")
        M = 7004
        await make_user(M)
        tok = issue_token(M, 0, "m-phone")
        hundred = await make_room((OWNER, M), [("t", None)] * 100)
        three = await make_room((OWNER, M), [("t", None)] * 3)
        await cursors_at_zero(M, "m-phone", (hundred, three))
        r = await c.post("/messages/group-log/fetch", headers=H(tok), json={"limit": 10})
        rooms = by_room(r.json()["rows"])
        check("the three-row room is served whole", rooms.get(three) == [1, 2, 3])
        check("  ... the hundred-row room has the rest of the ten", rooms.get(hundred) == list(range(1, 8)))
        check("  ... and more is set", r.json()["more"] is True)

        # ── rows sealed to somebody else ──────────────────────────────────────
        print("\nRows sealed to other members:")
        M = 7005
        await make_user(M)
        tok = issue_token(M, 0, "m-phone")
        mixed = await make_room((OWNER, M, OTHER), [(KB, OTHER)] * 50 + [(KB, None), (KB, M)])
        await cursors_at_zero(M, "m-phone", (mixed,))
        r = await c.post("/messages/group-log/fetch", headers=H(tok), json={})
        body = r.json()
        check("are neither served nor counted", [x["seq"] for x in body["rows"]] == [51, 52] and body["more"] is False)

        print("\nA room listed twice:")
        r = await c.post("/messages/group-log/fetch", headers=H(tok), json={"rooms": [
            {"gid": mixed, "after": 0}, {"gid": mixed, "after": 50},
        ]})
        check("is served once, from its last position", [x["seq"] for x in r.json()["rows"]] == [51, 52])

        # ── the reader mark ───────────────────────────────────────────────────
        print("\nThe reader mark moves only with a cursor:")
        await c.post("/messages/group-log/ack", headers=H(tok), json={"rooms": [{"gid": mixed, "upto": 52}]})
        long_ago = datetime.now(timezone.utc) - timedelta(days=5)
        async with SessionLocal() as db:
            await db.execute(update(GroupLogReader).where(GroupLogReader.uin == M).values(last_seen=long_ago))
            await db.commit()

        async def mark():
            async with SessionLocal() as db:
                v = (await db.execute(select(GroupLogReader.last_seen).where(GroupLogReader.uin == M))).scalar_one()
            return v if v.tzinfo else v.replace(tzinfo=timezone.utc)

        r = await c.post("/messages/group-log/ack", headers=H(tok), json={"rooms": [{"gid": mixed, "upto": 52}]})
        check("a repeated ack moves nothing", r.json()["deleted"] == 0)
        check("  ... and leaves the mark where it was", abs((await mark()) - long_ago) < timedelta(seconds=1))
        await add_rows(mixed, [(KB, None)])
        r = await c.post("/messages/group-log/ack", headers=H(tok), json={"rooms": [{"gid": mixed, "upto": 53}]})
        check("an ack that moves the cursor", r.json()["deleted"] == 1)
        check("  ... refreshes the mark", (await mark()) > datetime.now(timezone.utc) - timedelta(minutes=1))

    await redis.flushdb()
    await close_redis()
    try:
        os.remove("test_fair_page.db")
    except FileNotFoundError:
        pass
    print(f"\n{'ALL PASS' if fails == 0 else f'{fails} FAILED'}")
    return fails


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
