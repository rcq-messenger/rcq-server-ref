"""Local-only verification that two overlapping room-log acks cannot collide.

The bug this pins is the queue-cursor one (c3741b1) in its second home. Every
writer of a `group_log_cursors` row read it first and INSERTed it when the read
came back empty: the ack handler, the first fetch of a room, and the join
seeder. Two acks from one device overlap constantly: a client acks every page
of a catch-up, a reconnect re-sends the page whose answer it never saw, a phone
retries a request it never got an answer to. Both then read "no cursor for
this room", both insert, and the loser came back as

    sqlalchemy.exc.IntegrityError: UNIQUE constraint failed:
    group_log_cursors.group_id, group_log_cursors.uin,
    group_log_cursors.device_id

Worse than on the 1:1 queue, for two reasons. The rollback took the whole
transaction with it, so the ack died and the island rebuilt the identical page
from the identical cursor on the next fetch (the #981 starvation loop, entered
from the side). And `ack_group_log` SWALLOWED the error, so the client was told
200 while nothing had moved.

Under test: `app/services/group_log.upsert_log_cursor`, one
`INSERT ... ON CONFLICT (group_id, uin, device_id) DO UPDATE` carrying the
monotonic rule, and all three of its callers, plus `mark_reader`, which writes
in the SAME transaction as the ack and so could take the ack down by itself.

⚠ The interleaving of the pinned blocks is set up by hand, but the code they
drive is the REAL handler (`ack_group_log`, `fetch_group_log`), called with a
session the test holds open between the handler's read and its commit. Nothing
in this file re-implements a handler body, so a regression that puts
read-then-insert back into either one fails these blocks.

By hand because a gather cannot promise the overlap: SQLite has one writer, so
two ASGI requests serialise and never interleave at all, and the request commits
before it answers, so there is no window to park in from the outside. The
gathered HTTP blocks that follow exercise the same paths end to end, where a
pass is evidence and not proof; they are kept for the wiring (routing, auth,
JSON), not as the regression pin. Nothing they raise ends the run either (see
`gathered`): the unfixed fetch path throws out of an autoflush, and that used to
kill the script where it stood, so the blocks below it never ran and the summary
never printed.

Measured against the defect, not reasoned about: with ONLY `ack_group_log`
reverted to its read-then-insert body, 2 checks fail, both in the first block;
with both handlers reverted, 7 fail across three blocks and the run still
finishes and prints its count.

Runs the real FastAPI stack in-process via httpx ASGITransport on a throwaway
SQLite DB with Redis db 15. NOT part of the prod suite; NOT deployed.
Run: PYTHONPATH=. /Users/tager/Documents/RCQ/backend/.venv/bin/python test_group_log_cursor_race_local.py
"""
import asyncio
import base64
import os

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test_group_log_cursor_race.db"
os.environ["REDIS_URL"] = "redis://localhost:6379/15"
os.environ["ENV"] = "dev"

for f in ("test_group_log_cursor_race.db",):
    try:
        os.remove(f)
    except FileNotFoundError:
        pass

import httpx  # noqa: E402
from sqlalchemy import func, select, update  # noqa: E402

from app.core.db import SessionLocal, init_db  # noqa: E402
from app.core.redis import close_redis  # noqa: E402
from app.core.security import issue_token  # noqa: E402
from app.main import app  # noqa: E402
from app.models.capability import UserCapability  # noqa: E402
from app.models.group import Group, GroupMember  # noqa: E402
from app.models.group_log import GroupLog, GroupLogCursor, GroupLogReader  # noqa: E402
from app.models.user import User  # noqa: E402
from app.routers.messages import (  # noqa: E402
    GroupLogAckIn,
    GroupLogAckRoomIn,
    GroupLogFetchIn,
    GroupLogRoomIn,
    ack_group_log,
    fetch_group_log,
)
from app.services.group_log import (  # noqa: E402
    room_head,
    seed_cursors_on_join,
    upsert_log_cursor,
)

fails = 0


def check(name, cond):
    global fails
    print(f"  {'PASS' if cond else 'FAIL'}  {name}")
    if not cond:
        fails += 1


def b64(n=40):
    return base64.b64encode(os.urandom(n)).decode()


OWNER, A = 6200, 6201
H = lambda t: {"Authorization": f"Bearer {t}"}  # noqa: E731


async def at(gid: int, device_id: str) -> int | None:
    """Where the stored row says this device is, read on its own session."""
    async with SessionLocal() as db:
        return await db.scalar(
            select(GroupLogCursor.last_seq).where(
                GroupLogCursor.group_id == gid,
                GroupLogCursor.uin == A,
                GroupLogCursor.device_id == device_id,
            )
        )


async def cursor_rows(gid: int, device_id: str) -> int:
    async with SessionLocal() as db:
        return int(await db.scalar(
            select(func.count()).select_from(GroupLogCursor).where(
                GroupLogCursor.group_id == gid,
                GroupLogCursor.uin == A,
                GroupLogCursor.device_id == device_id,
            )
        ))


async def reader_rows(device_id: str) -> int:
    async with SessionLocal() as db:
        return int(await db.scalar(
            select(func.count()).select_from(GroupLogReader).where(
                GroupLogReader.uin == A, GroupLogReader.device_id == device_id,
            )
        ))


class Parked:
    """The session a handler is given when the test has to STOP it mid-request.

    Everything reaches the real session except `commit`, which only flushes: the
    handler's writes land in the database and take its write lock, and the
    transaction stays OPEN. That is exactly where a Postgres backend sits between
    its INSERT and its COMMIT, and it is the only window in which a second
    request can read "no cursor for this room" and then try to insert one. The
    test commits or rolls back the real session itself.

    ⚠ Not a re-implementation of anything: the handler body that runs under this
    is the shipped one, so a read-then-insert put back into `ack_group_log` or
    `fetch_group_log` fails the blocks below rather than sailing past a copy.
    """

    def __init__(self, db):
        self._db = db

    def __getattr__(self, name):
        return getattr(self._db, name)

    async def commit(self) -> None:
        await self._db.flush()


async def ack_through_the_handler(db, device_id: str, acks: list[tuple[int, int]]):
    """POST /messages/group-log/ack, the real handler, on a session we hold."""
    return await ack_group_log(
        GroupLogAckIn(rooms=[GroupLogAckRoomIn(gid=g, upto=u) for g, u in acks]),
        uin=A, device_id=device_id, db=Parked(db),
    )


async def fetch_through_the_handler(db, device_id: str, gids: list[int]):
    """POST /messages/group-log/fetch, the real handler, on a session we hold."""
    return await fetch_group_log(
        GroupLogFetchIn(rooms=[GroupLogRoomIn(gid=g) for g in gids]),
        uin=A, device_id=device_id, db=Parked(db),
    )


async def gathered(name: str, *calls):
    """Run overlapping requests and hand back their answers, or None if one of
    them raised.

    ⚠ `return_exceptions=True`, so an exception out of one request is DATA here,
    recorded as a FAIL: it never ends the run, and the other request is still
    awaited rather than abandoned half-way. The unfixed fetch path raises
    `IntegrityError` out of an autoflush inside a plain SELECT, and that used to
    kill this script where it stood, so every block after it went unrun and the
    count at the bottom never printed: a reported defect read as a broken test.
    """
    out = await asyncio.gather(*calls, return_exceptions=True)
    bad = [r for r in out if isinstance(r, BaseException)]
    why = f" ({type(bad[0]).__name__}: {str(bad[0]).splitlines()[0]})" if bad else ""
    check(f"nothing escapes the overlapping {name}{why}", not bad)
    return None if bad else out


async def room(name: str, members=(OWNER, A)) -> int:
    async with SessionLocal() as db:
        g = Group(name=name, owner_uin=OWNER)
        db.add(g)
        await db.flush()
        gid = g.id
        for u in members:
            db.add(GroupMember(group_id=gid, uin=u, role="owner" if u == OWNER else "member"))
        await db.commit()
        return gid


async def main():
    await init_db()
    async with SessionLocal() as db:
        for u in (OWNER, A):
            db.add(User(uin=u, nickname=f"u{u}", identity_key=b64(32), signing_key=b64(32)))
            db.add(UserCapability(uin=u, sender_keys=True))
        await db.commit()
    gid = await room("race-room")
    gid2 = await room("second-room")
    tok_owner = issue_token(OWNER, 0, "phone")

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        # A's phone reads once, which flips the account onto the log path, and
        # then eight posts give the room a head to ack against.
        r = await c.post("/messages/group-log/fetch", headers=H(issue_token(A, 0, "phone")), json={})
        check("A's phone reads the log once (the account is on the log path now)",
              r.status_code == 200)
        posted = 0
        for _ in range(8):
            r = await c.post("/messages/group-broadcast", headers=H(tok_owner),
                             json={"group_id": gid, "payload": b64()})
            posted += 1 if r.status_code == 200 else 0
        check("eight broadcasts into the room", posted == 8)
        async with SessionLocal() as db:
            head = await room_head(db, gid)
            logged = int(await db.scalar(
                select(func.count()).select_from(GroupLog).where(GroupLog.group_id == gid)
            ))
        check(f"  ... eight log rows, room head at 8 (head={head}, rows={logged})",
              head == 8 and logged == 8)

        print("\nTwo acks from one device through ack_group_log, overlapping by hand:")
        # A device that has never fetched either room, so neither request can see
        # a cursor and both would INSERT. That is where the 500 came from.
        s_a, s_b = SessionLocal(), SessionLocal()
        pos_a = await at(gid, "phone2")
        pos_b = await at(gid2, "phone2")
        check("no cursor for this device in either room yet", pos_a is None and pos_b is None)

        # The first request acks room 1 up to 3 and room 2 up to 7, and its
        # session is not committed: it now holds the write lock with uncommitted
        # cursor rows, which is the state a Postgres backend is in between its
        # INSERT and its COMMIT.
        await ack_through_the_handler(s_a, "phone2", [(gid, 3), (gid2, 7)])

        # The second request read the same empty positions and carries the
        # OPPOSITE pair: further along in room 1, behind in room 2. Its writes go
        # in while the first one is still open, so this is the exact interleave
        # prod hits, and it separates the two halves of the guarantee in one race.
        task_b = asyncio.create_task(ack_through_the_handler(s_b, "phone2", [(gid, 7), (gid2, 3)]))
        for _ in range(25):
            await asyncio.sleep(0.02)
        # If this ever fails the two writes stopped overlapping and every check
        # below has become a no-op that would pass on the unfixed code too.
        check("★ the second ack is still inside the first one's window", not task_b.done())

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
        check("★ the loser's further ack is not lost with its transaction",
              await at(gid, "phone2") == 7)
        check("★ and its shorter ack does not rewind the winner's room",
              await at(gid2, "phone2") == 7)
        check("one cursor row per room for the device",
              await cursor_rows(gid, "phone2") == 1 and await cursor_rows(gid2, "phone2") == 1)
        # The reader mark rides in the SAME transaction as the ack, so a
        # collision on it alone was enough to throw the ack away.
        check("★ the reader mark written beside it did not collide either",
              await reader_rows("phone2") == 1)
        await s_a.close()
        await s_b.close()

        print("\nTwo first reads through fetch_group_log, overlapping by hand:")
        # The second writer, pinned the same way. The fetch path creates the
        # cursor at the room's head before it hands any rows out, so two first
        # reads from one device (a poll and the reconnect on top of it, a retried
        # request) both read "no cursor" and both INSERTed. Here the collision was
        # not even caught where the ack's was: it came out of an autoflush inside
        # the SELECT that builds the page, so the request 500'd and the device got
        # no rows at all.
        s_a, s_b = SessionLocal(), SessionLocal()
        check("no cursor for this brand-new device yet", await at(gid, "tablet") is None)
        out_a = await fetch_through_the_handler(s_a, "tablet", [gid])
        task_b = asyncio.create_task(fetch_through_the_handler(s_b, "tablet", [gid]))
        for _ in range(25):
            await asyncio.sleep(0.02)
        check("★ the second read is still inside the first one's window", not task_b.done())
        await s_a.commit()
        raised, out_b = None, None
        try:
            out_b = await task_b
            await s_b.commit()
        except Exception as exc:  # noqa: BLE001
            raised = exc
            await s_b.rollback()
        check(f"★ the loser of the race does not raise ({type(raised).__name__ if raised else 'no exception'})",
              raised is None)
        check("★ and it is still answered: one cursor row, seeded at the head 8",
              await cursor_rows(gid, "tablet") == 1 and await at(gid, "tablet") == 8)
        check("  ... so a fresh install is owed no backlog, on either answer",
              out_a.rows == [] and out_b is not None and out_b.rows == []
              and out_a.cursors[gid] == 8 and out_b.cursors[gid] == 8)
        await s_a.close()
        await s_b.close()

        print("\nThe monotonic rule, straight at the statement:")
        # On a device of its own, so a fault in a handler above cannot make this
        # block report a fault in the statement.
        async with SessionLocal() as db:
            start = await upsert_log_cursor(db, gid, A, "stmt", seq=0, seed=7)
            await db.commit()
        check("the statement that creates the row seeds it where asked", start == 7)
        async with SessionLocal() as db:
            back = await upsert_log_cursor(db, gid, A, "stmt", seq=1, seed=1)
            await db.commit()
        check("★ a lower mark never moves a cursor backwards", back == 7)
        check("  ... and the stored row agrees", await at(gid, "stmt") == 7)
        async with SessionLocal() as db:
            fwd = await upsert_log_cursor(db, gid, A, "stmt", seq=8, seed=8)
            await db.commit()
        check("a higher mark still moves it", fwd == 8 and await at(gid, "stmt") == 8)

        print("\nTwo acks from one device, gathered through the endpoint:")
        # ⚠ Evidence, NOT the regression pin. SQLite has one writer and the ASGI
        # requests serialise, so the second ack's read already sees the first
        # one's committed row and no interleave happens: the unfixed handler
        # passes this block too (verified against a HEAD copy of messages.py).
        # It is here for the wiring the pinned block above skips, routing, auth
        # and JSON, and because on Postgres two backends do overlap here.
        tok3 = issue_token(A, 0, "phone3")
        r = await c.post("/messages/group-log/fetch", headers=H(tok3), json={"rooms": [{"gid": gid, "after": 0}]})
        check("the device is served the room from the start", len(r.json()["rows"]) == 8)
        both = await gathered(
            "acks",
            c.post("/messages/group-log/ack", headers=H(tok3), json={"rooms": [{"gid": gid, "upto": 4}]}),
            c.post("/messages/group-log/ack", headers=H(tok3), json={"rooms": [{"gid": gid, "upto": 8}]}),
        )
        codes = sorted([r.status_code for r in both]) if both else []
        check(f"neither ack 500s ({codes})", codes == [200, 200])
        check("the cursor ends at the furthest of the two, not the last to land",
              await at(gid, "phone3") == 8)
        r = await c.post("/messages/group-log/fetch", headers=H(tok3), json={})
        check("  ... and the acked page is not re-served", r.json()["rows"] == []
              and r.json()["cursors"].get(str(gid)) == 8)

        print("\nA stale ack cannot pull the cursor back (through the endpoint):")
        r = await c.post("/messages/group-log/ack", headers=H(tok3), json={"rooms": [{"gid": gid, "upto": 2}]})
        check(f"the stale ack is accepted, not an error ({r.status_code})", r.status_code == 200)
        check("  ... and reports that it moved nothing", r.json().get("deleted") == 0)
        check("★ the stored cursor is untouched", await at(gid, "phone3") == 8)
        r = await c.post("/messages/group-log/fetch", headers=H(tok3), json={})
        check("★ so the six posts above it are not re-delivered as unread",
              r.json()["rows"] == [] and r.json()["cursors"].get(str(gid)) == 8)
        # Same thing for a room the device has never fetched: a first ack seeds
        # the cursor where the client says it is, and a lower second one is inert.
        r = await c.post("/messages/group-log/ack", headers=H(tok3), json={"rooms": [{"gid": gid2, "upto": 5}]})
        check("a first ack for an unfetched room seeds the cursor there",
              r.status_code == 200 and await at(gid2, "phone3") == 5)
        r = await c.post("/messages/group-log/ack", headers=H(tok3), json={"rooms": [{"gid": gid2, "upto": 1}]})
        check("★ and a lower one after it does not rewind", await at(gid2, "phone3") == 5)

        print("\nTwo first reads of one brand-new device, gathered:")
        # The same path as the pinned fetch block above, end to end. This one DOES
        # catch the unfixed handler (its `IntegrityError` escapes as a 500), but
        # only because the two requests happen to overlap, so the pin stays the
        # hand-driven block; here it is the wiring that is on trial.
        fresh = H(issue_token(A, 0, "browser"))
        both = await gathered(
            "first reads",
            c.post("/messages/group-log/fetch", headers=fresh, json={}),
            c.post("/messages/group-log/fetch", headers=fresh, json={}),
        )
        codes = sorted([r.status_code for r in both]) if both else []
        check(f"neither first read 500s ({codes})", codes == [200, 200])
        check("one cursor row, seeded at the room head",
              await cursor_rows(gid, "browser") == 1 and await at(gid, "browser") == 8)
        check("  ... so a fresh install is owed no backlog",
              both is not None and all(r.json()["rows"] == [] for r in both))

    print("\nThe join seeder:")
    # A device already positioned in a room must not be lifted to the head by a
    # seed: that would bury every post it has not been served yet.
    async with SessionLocal() as db:
        # By hand, because nothing in the server moves a cursor backwards: the
        # state to reproduce is a device that read part of the room and stopped.
        await db.execute(
            update(GroupLogCursor)
            .where(
                GroupLogCursor.group_id == gid, GroupLogCursor.uin == A,
                GroupLogCursor.device_id == "phone3",
            )
            .values(last_seq=5)
        )
        await db.commit()
    check("phone3 is parked at 5, three posts below the head of 8",
          await at(gid, "phone3") == 5)
    async with SessionLocal() as db:
        await seed_cursors_on_join(db, gid, A)
        await db.commit()
    check("★ a rejoin's seed does not lift a positioned device onto the head",
          await at(gid, "phone3") == 5)

    print("\nTwo joins into one room, overlapping by hand:")
    # The third writer. The seeder used to answer a collision with
    # `await db.rollback()`, and its caller is mid-join with the `group_members`
    # row on the same session, so a collision here did not cost a cursor, it cost
    # the JOIN, and the caller still answered 200.
    #
    # ⚠ Honest about what this block proves: it is a "nothing broke" check, not a
    # regression pin. SQLite has one writer, so the parked session's own INSERT
    # lands only after the winner has committed, and its read therefore already
    # sees the winner's rows: the old check-then-insert does not collide here
    # either (verified against a clean HEAD copy). The seeder's conflict branch is
    # pinned deterministically by the rejoin check above instead, and on Postgres
    # two real backends do read the same empty row.
    gid3 = await room("join-room", members=(OWNER,))
    s_a, s_b = SessionLocal(), SessionLocal()
    async with SessionLocal() as db:
        check("nobody has a cursor in the new room yet", int(await db.scalar(
            select(func.count()).select_from(GroupLogCursor).where(GroupLogCursor.group_id == gid3)
        )) == 0)
    await seed_cursors_on_join(s_a, gid3, A)
    # The second request is the real join: the membership row and the cursor
    # seeding are one transaction, which is what made the old rollback so
    # expensive. ⚠ The membership INSERT is left to the autoflush inside the task
    # rather than flushed here, because SQLite allows exactly one writer: flushed
    # now it would park on the lock the first session is already holding, and the
    # interleave could not be set up at all.
    s_b.add(GroupMember(group_id=gid3, uin=A, role="member"))
    task_b = asyncio.create_task(seed_cursors_on_join(s_b, gid3, A))
    for _ in range(25):
        await asyncio.sleep(0.02)
    check("★ the second join is still inside the first one's window", not task_b.done())
    await s_a.commit()
    raised = None
    try:
        await task_b
        await s_b.commit()
    except Exception as exc:  # noqa: BLE001
        raised = exc
        await s_b.rollback()
    check(f"★ the loser does not raise ({type(raised).__name__ if raised else 'no exception'})",
          raised is None)
    async with SessionLocal() as db:
        joined = int(await db.scalar(
            select(func.count()).select_from(GroupMember).where(
                GroupMember.group_id == gid3, GroupMember.uin == A,
            )
        ))
        seeded = (await db.execute(
            select(GroupLogCursor.device_id, GroupLogCursor.last_seq)
            .where(GroupLogCursor.group_id == gid3, GroupLogCursor.uin == A)
        )).all()
    check("the join itself survives the seeding (nothing rolls it back)", joined == 1)
    check("one cursor per reading device, all at the new room's head 0",
          len(seeded) == len({d for d, _ in seeded}) and all(s == 0 for _, s in seeded))
    await s_a.close()
    await s_b.close()

    await close_redis()
    print("\nALL GROUP-LOG CURSOR-RACE CHECKS PASSED ✅" if fails == 0
          else f"\n{fails} CHECK(S) FAILED ❌")
    return fails


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
