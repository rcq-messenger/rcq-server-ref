"""Local-only verification of stage 5 of the metadata plan: one log per room.

A post into a room used to be written once per member. Now it is one row in
the room's log, read through a per-(room, account, device) cursor. The
per-member table survives only for accounts whose client has not yet read the
log (iOS can be weeks behind), and the switch is implicit: the first
/messages/group-log/fetch marks the account a reader. Pins:
  * before anyone reads the log a broadcast writes N legacy rows, no log row;
  * after member A reads the log once, a broadcast writes ONE log row and a
    legacy row only for B (still on the old path);
  * A's first read created its cursor at the head, so the post lands above it
    and the next fetch returns it with the right seq; the live frame carries
    seq; B keeps draining /messages/queue as before;
  * an addressed row (skdm to A) is in the log for A and not served to B;
  * fetch without ack re-serves, ack moves the cursor forward only, a second
    device of A starts at the head and sees nothing old;
  * leaving the room removes A's cursor and A's addressed rows, broadcasts stay;
  * the room counter survives an emptied log (no MAX() reseed).

Runs the real FastAPI stack in-process on a throwaway SQLite DB with Redis
db 15. NOT deployed.
Run: PYTHONPATH=. /Users/tager/Documents/RCQ/backend/.venv/bin/python test_stage5_group_log_local.py
"""
import asyncio
import base64
import os

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test_stage5.db"
os.environ["ENV"] = "dev"
os.environ["REDIS_URL"] = "redis://localhost:6379/15"
for f in ("test_stage5.db",):
    try:
        os.remove(f)
    except FileNotFoundError:
        pass

import httpx  # noqa: E402
from sqlalchemy import delete, func, select  # noqa: E402

from app.core.db import SessionLocal, init_db  # noqa: E402
from app.core.redis import close_redis  # noqa: E402
from app.core.security import issue_token  # noqa: E402
from app.main import app  # noqa: E402
from app.models.capability import UserCapability  # noqa: E402
from app.models.group import Group, GroupMember, OfflineGroupMessage  # noqa: E402
from app.models.group_log import GroupLog, GroupLogCursor, GroupLogReader  # noqa: E402
from app.models.queue_cursor import QueueCursor  # noqa: E402
from app.routers.messages import GROUP_LOG_PAGE_BYTES  # noqa: E402
from app.models.user import User  # noqa: E402

fails = 0


def check(name, cond):
    global fails
    print(f"  {'PASS' if cond else 'FAIL'}  {name}")
    if not cond:
        fails += 1


def b64(n=40):
    return base64.b64encode(os.urandom(n)).decode()


A, B, OWNER, C = 5101, 5102, 5100, 5103


async def count(model, *where):
    async with SessionLocal() as db:
        return (await db.execute(select(func.count()).select_from(model).where(*where))).scalar_one()


async def main():
    global fails
    await init_db()
    async with SessionLocal() as db:
        for u in (OWNER, A, B, C):
            db.add(User(uin=u, nickname=f"u{u}", identity_key=b64(32), signing_key=b64(32)))
            db.add(UserCapability(uin=u, sender_keys=True))
        g = Group(name="log-room", owner_uin=OWNER)
        db.add(g)
        await db.flush()
        gid = g.id
        for u in (OWNER, A, B, C):
            db.add(GroupMember(group_id=gid, uin=u, role="owner" if u == OWNER else "member"))
        # C drains the legacy queue from two devices (phone and desktop).
        db.add(QueueCursor(uin=C, device_id="c-phone", last_direct_id=0, last_group_id=0))
        db.add(QueueCursor(uin=C, device_id="c-desktop", last_direct_id=0, last_group_id=0))
        await db.commit()
    tok = {u: issue_token(u, 0, "phone") for u in (OWNER, A, B)}
    tokC1 = issue_token(C, 0, "c-phone")
    tokC2 = issue_token(C, 0, "c-desktop")
    tokA2 = issue_token(A, 0, "desktop")
    H = lambda t: {"Authorization": f"Bearer {t}"}  # noqa: E731
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        print("\nBefore anyone reads the log:")
        r = await c.post("/messages/group-broadcast", headers=H(tok[OWNER]), json={"group_id": gid, "payload": b64()})
        check("broadcast accepted", r.status_code == 200)
        check("  ... four legacy rows (owner, A, B, C)", await count(OfflineGroupMessage, OfflineGroupMessage.group_id == gid) == 4)
        check("  ... and no log row", await count(GroupLog, GroupLog.group_id == gid) == 0)

        print("\nA reads the log for the first time:")
        r = await c.post("/messages/group-log/fetch", headers=H(tok[A]), json={})
        check("fetch is 200", r.status_code == 200)
        body = r.json()
        check("  ... nothing to read yet (cursor starts at the head)", body["rows"] == [] and body["cursors"].get(str(gid)) == 0)
        check("  ... A's phone is now marked a log reader", await count(GroupLogReader, GroupLogReader.uin == A) == 1)

        print("\nA broadcast after that:")
        p2 = b64()
        r = await c.post("/messages/group-broadcast", headers=H(tok[OWNER]), json={"group_id": gid, "payload": p2})
        check("broadcast accepted", r.status_code == 200)
        check("  ... ONE log row", await count(GroupLog, GroupLog.group_id == gid) == 1)
        check("  ... legacy rows for owner, B and C only (+3)", await count(OfflineGroupMessage, OfflineGroupMessage.group_id == gid) == 7)
        r = await c.post("/messages/group-log/fetch", headers=H(tok[A]), json={})
        rows = r.json()["rows"]
        check("A's fetch returns the post with seq 1", len(rows) == 1 and rows[0]["seq"] == 1 and rows[0]["payload"] == p2 and rows[0]["envelope_type"] == "gmsg")
        check("  ... heads says the room is at 1", r.json()["heads"].get(str(gid)) == 1)
        r = await c.get("/messages/queue?ack=1", headers=H(tok[B]))
        check("B still drains the legacy queue (2 group rows)", r.status_code == 200 and len([x for x in r.json() if x["group_id"] == gid]) == 2)

        print("\nAn addressed row (skdm to A and B):")
        r = await c.post("/messages/group-sealed", headers=H(tok[OWNER]), json={
            "group_id": gid, "envelope_type": "skdm",
            "payloads": [{"to_uin": A, "payload": "skdm-for-A"}, {"to_uin": B, "payload": "skdm-for-B"}],
        })
        check("sealed fan-out accepted", r.status_code == 200, )
        check("  ... A's copy is a log row (seq 2), B's is a legacy row", await count(GroupLog, GroupLog.group_id == gid, GroupLog.to_uin == A) == 1 and await count(OfflineGroupMessage, OfflineGroupMessage.group_id == gid, OfflineGroupMessage.to_uin == B, OfflineGroupMessage.envelope_type == "skdm") == 1)
        r = await c.post("/messages/group-log/fetch", headers=H(tok[A]), json={})
        rows = r.json()["rows"]
        check("A's fetch (no ack yet) re-serves seq 1 and adds seq 2", [x["seq"] for x in rows] == [1, 2] and rows[1]["payload"] == "skdm-for-A")

        print("\nAck and cursors:")
        r = await c.post("/messages/group-log/ack", headers=H(tok[A]), json={"rooms": [{"gid": gid, "upto": 2}]})
        check("ack is 200", r.status_code == 200)
        r = await c.post("/messages/group-log/fetch", headers=H(tok[A]), json={})
        check("after ack nothing comes back", r.json()["rows"] == [] and r.json()["cursors"].get(str(gid)) == 2)
        r = await c.post("/messages/group-log/ack", headers=H(tok[A]), json={"rooms": [{"gid": gid, "upto": 1}]})
        r = await c.post("/messages/group-log/fetch", headers=H(tok[A]), json={})
        check("a backwards ack is ignored", r.json()["cursors"].get(str(gid)) == 2)
        r = await c.post("/messages/group-log/fetch", headers=H(tok[A]), json={"rooms": [{"gid": gid, "after": 0}]})
        check("an explicit after re-reads from there (2 rows)", len(r.json()["rows"]) == 2)
        r = await c.post("/messages/group-log/fetch", headers=H(tokA2), json={})
        check("A's second device starts at the head: nothing old", r.json()["rows"] == [] and r.json()["cursors"].get(str(gid)) == 2)
        r = await c.post("/messages/group-log/fetch", headers=H(tok[B]), json={"rooms": [{"gid": gid, "after": 0}]})
        rows = r.json()["rows"]
        check("B (now a reader) reading from 0 sees the broadcast but not A's skdm", [x["seq"] for x in rows] == [1])

        print("\nPer-device flip (C has an old desktop):")
        r = await c.post("/messages/group-log/fetch", headers=H(tokC1), json={})
        check("C's phone reads the log", r.status_code == 200)
        before = await count(OfflineGroupMessage, OfflineGroupMessage.group_id == gid, OfflineGroupMessage.to_uin == C)
        r = await c.post("/messages/group-broadcast", headers=H(tok[OWNER]), json={"group_id": gid, "payload": b64()})
        after = await count(OfflineGroupMessage, OfflineGroupMessage.group_id == gid, OfflineGroupMessage.to_uin == C)
        check("  ... C still gets a legacy row (its desktop has not read the log)", after == before + 1)
        r = await c.post("/messages/group-log/fetch", headers=H(tokC2), json={})
        check("C's desktop reads the log too", r.status_code == 200)
        r = await c.post("/messages/group-broadcast", headers=H(tok[OWNER]), json={"group_id": gid, "payload": b64()})
        after2 = await count(OfflineGroupMessage, OfflineGroupMessage.group_id == gid, OfflineGroupMessage.to_uin == C)
        check("  ... now C gets no legacy row", after2 == after)

        print("\nJoining a room as a reader:")
        async with SessionLocal() as db:
            g2 = Group(name="second-room", owner_uin=OWNER, share_token="tok2")
            db.add(g2); await db.flush(); gid2 = g2.id
            db.add(GroupMember(group_id=gid2, uin=OWNER, role="owner"))
            await db.commit()
        r = await c.post("/messages/group-broadcast", headers=H(tok[OWNER]), json={"group_id": gid2, "payload": b64()})
        r = await c.post(f"/groups/{gid2}/join", headers=H(tok[A]))
        check(f"A joins the second room ({r.status_code})", r.status_code in (200, 201))
        check("  ... A's cursors (phone and desktop) were seeded at the head at join time", await count(GroupLogCursor, GroupLogCursor.group_id == gid2, GroupLogCursor.uin == A) == 2)
        joined_at = b64()
        r = await c.post("/messages/group-broadcast", headers=H(tok[OWNER]), json={"group_id": gid2, "payload": joined_at})
        r = await c.post("/messages/group-log/fetch", headers=H(tok[A]), json={})
        rows2 = [x for x in r.json()["rows"] if x["gid"] == gid2]
        check("  ... A's first fetch after joining serves the post made since, not the one before", len(rows2) == 1 and rows2[0]["payload"] == joined_at)

        print("\nLeaving:")
        async with SessionLocal() as db:
            db.add(GroupMember(group_id=gid, uin=A, role="member")) if False else None
        r = await c.post(f"/groups/{gid}/leave", headers=H(tok[A]))
        if r.status_code == 404:
            r = await c.delete(f"/groups/{gid}/members/{A}", headers=H(tok[A]))
        check(f"A left ({r.status_code})", r.status_code in (200, 204))
        check("  ... A's cursors are gone", await count(GroupLogCursor, GroupLogCursor.group_id == gid, GroupLogCursor.uin == A) == 0)
        check("  ... A's addressed row is gone, the three broadcasts stay", await count(GroupLog, GroupLog.group_id == gid) == 3)

        print("\nThe counter survives an emptied log:")
        async with SessionLocal() as db:
            await db.execute(delete(GroupLog).where(GroupLog.group_id == gid))
            await db.commit()
        r = await c.post("/messages/group-broadcast", headers=H(tok[OWNER]), json={"group_id": gid, "payload": b64()})
        async with SessionLocal() as db:
            seqs = (await db.execute(select(GroupLog.seq).where(GroupLog.group_id == gid))).scalars().all()
        check("next post is seq 5, not 1", seqs == [5])

        print("\nThe page has a BYTE budget, not only a row budget (13.09.2026):")
        # 500 rows of room 21 is 558 KB of JSON, and Caddy's log that day has
        # clients walking away from bodies that size mid-transfer (45056 bytes
        # written with duration 1010 s; 217088 bytes with duration 0). A body
        # that is never fully read is a page that is never acked, so the island
        # rebuilds the identical page from the identical cursor for ever. Twelve
        # 16 KB payloads against a 128 KB budget must come back as two pages
        # with `more` set, NOT as one 192 KB page, even though `limit` is 500.
        big = base64.b64encode(os.urandom(12 * 1024)).decode()  # ~16 KB encoded
        posted = 0
        for _ in range(12):
            r = await c.post("/messages/group-broadcast", headers=H(tok[OWNER]), json={"group_id": gid, "payload": big})
            posted += 1 if r.status_code == 200 else 0
        check("twelve 16 KB broadcasts accepted (192 KB of payload)", posted == 12)
        r = await c.post("/messages/group-log/fetch", headers=H(tok[B]), json={"limit": 500})
        body = r.json()
        served = sum(len(x["payload"]) for x in body["rows"])
        check("the page stops at the byte budget", served <= GROUP_LOG_PAGE_BYTES + len(big))
        check("  ... and says there is more", body["more"] is True)
        check("  ... but serves at least one row", len(body["rows"]) >= 1)
        upto = max(x["seq"] for x in body["rows"])
        r = await c.post("/messages/group-log/ack", headers=H(tok[B]), json={"rooms": [{"gid": gid, "upto": upto}]})
        check("  ... the page it did serve acks", r.status_code == 200)
        r = await c.post("/messages/group-log/fetch", headers=H(tok[B]), json={"limit": 500})
        check("  ... the next page carries the rest", len(r.json()["rows"]) >= 1)

        print("\nA device that never acks does not earn its reader mark (#981):")
        # The mark is what stops the writers producing legacy rows for the whole
        # account. Written by the FETCH, it meant "this device asked"; a device
        # that could not digest a page still turned its account's fallback off
        # and then received nothing by either path. It now means "this device
        # took a page", so the broken device keeps its safety net.
        D = 5104
        async with SessionLocal() as db:
            db.add(User(uin=D, nickname="D", identity_key="x" * 43, signing_key="y" * 43))
            db.add(GroupMember(group_id=gid, uin=D))
            db.add(QueueCursor(uin=D, device_id="d-phone", last_direct_id=0, last_group_id=0))
            await db.commit()
        tok[D] = issue_token(D, device_id="d-phone")
        r = await c.post("/messages/group-broadcast", headers=H(tok[OWNER]), json={"group_id": gid, "payload": b64()})
        check("a broadcast while D has never read", r.status_code == 200)
        r = await c.post("/messages/group-log/fetch", headers=H(tok[D]), json={})
        check("D's first fetch is empty (cursor seeded at the head)", r.json()["rows"] == [])
        check("  ... so THAT one does mark it a reader, as before", await count(GroupLogReader, GroupLogReader.uin == D) == 1)
        # Now the case that matters: a device with no mark, served real rows,
        # that never acks.
        async with SessionLocal() as db:
            await db.execute(delete(GroupLogReader).where(GroupLogReader.uin == D))
            await db.commit()
        r = await c.post("/messages/group-broadcast", headers=H(tok[OWNER]), json={"group_id": gid, "payload": b64()})
        r = await c.post("/messages/group-log/fetch", headers=H(tok[D]), json={})
        check("D is served rows", len(r.json()["rows"]) >= 1)
        check("  ... and is NOT a reader yet: it has proved nothing", await count(GroupLogReader, GroupLogReader.uin == D) == 0)
        r = await c.post("/messages/group-log/fetch", headers=H(tok[D]), json={})
        check("  ... still not, however often it asks", await count(GroupLogReader, GroupLogReader.uin == D) == 0)
        upto = max(x["seq"] for x in r.json()["rows"])
        r = await c.post("/messages/group-log/ack", headers=H(tok[D]), json={"rooms": [{"gid": gid, "upto": upto}]})
        check("  ... the ACK is what earns the mark", await count(GroupLogReader, GroupLogReader.uin == D) == 1)

        print("\nCapabilities:")
        info = (await c.get("/server/info")).json()["capabilities"]
        check("group_log advertised", info.get("group_log") is True)

    await close_redis()
    print(f"\n{'ALL PASS' if fails == 0 else f'{fails} FAILED'}")
    return fails


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
