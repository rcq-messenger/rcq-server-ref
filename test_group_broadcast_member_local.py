"""Local-only verification: /messages/group-broadcast posts only from a member.

The sender-auth audit (11.10.2026) found that the endpoint authenticated its
caller and then never asked whether the caller sat in the room: any account on
the island could fan a `gmsg` into any room by number, a row in the room's log
and a wake for every offline member, from somebody who is not in the room.
Pins:
  * a member (and the owner) still posts, as before;
  * a guest copy with a seat posts like any member;
  * an account with no seat gets 403 `not_a_member`, and NOTHING is written:
    no log row, no legacy row, no seq taken from the room;
  * somebody who left is refused the same way;
  * a non-member is refused even in a room with slowmode and an age floor,
    whose gates used to wave a non-member through ("the membership check
    below is the gate", and there was none);
  * the anonymous sealed path stays anonymous: a deposit without a token is
    still accepted for members (its design; see send_group_sealed).

Runs the real FastAPI stack in-process on a throwaway SQLite DB with Redis
db 15. NOT deployed.
Run: PYTHONPATH=. .venv/bin/python test_group_broadcast_member_local.py
"""
import asyncio
import base64
import os

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test_broadcast_member.db"
os.environ["ENV"] = "dev"
os.environ["REDIS_URL"] = "redis://localhost:6379/15"
for f in ("test_broadcast_member.db",):
    try:
        os.remove(f)
    except FileNotFoundError:
        pass

import httpx  # noqa: E402
from sqlalchemy import delete, func, select  # noqa: E402

from app.core.db import SessionLocal, init_db  # noqa: E402
from app.core.redis import close_redis, get_redis  # noqa: E402
from app.core.security import issue_token  # noqa: E402
from app.main import app  # noqa: E402
from app.models.capability import UserCapability  # noqa: E402
from app.models.group import Group, GroupMember, OfflineGroupMessage  # noqa: E402
from app.models.group_log import GroupLog, GroupSeq  # noqa: E402
from app.models.user import User  # noqa: E402

fails = 0


def check(name, cond):
    global fails
    print(f"  {'PASS' if cond else 'FAIL'}  {name}")
    if not cond:
        fails += 1


def b64(n=40):
    return base64.b64encode(os.urandom(n)).decode()


OWNER, A, GUEST, OUTSIDER, LEAVER = 6100, 6101, 6102, 6103, 6104


async def count(model, *where):
    async with SessionLocal() as db:
        return (await db.execute(select(func.count()).select_from(model).where(*where))).scalar_one()


async def head(gid):
    async with SessionLocal() as db:
        return (await db.execute(select(GroupSeq.next_seq).where(GroupSeq.group_id == gid))).scalar_one_or_none() or 0


async def main():
    global fails
    await init_db()
    redis = await get_redis()
    # Slowmode and rate-limit counters from an earlier run must not leak in.
    await redis.flushdb()
    async with SessionLocal() as db:
        for u in (OWNER, A, GUEST, OUTSIDER, LEAVER):
            db.add(User(
                uin=u, nickname=f"u{u}", identity_key=b64(32), signing_key=b64(32),
                guest_status="proven" if u == GUEST else None,
            ))
            db.add(UserCapability(uin=u, sender_keys=True))
        g = Group(name="room", owner_uin=OWNER)
        armed = Group(name="armed-room", owner_uin=OWNER, slowmode_sec=60, min_account_age_hours=48)
        db.add_all([g, armed])
        await db.flush()
        gid, armed_gid = g.id, armed.id
        for u in (OWNER, A, GUEST, LEAVER):
            db.add(GroupMember(group_id=gid, uin=u, role="owner" if u == OWNER else "member"))
        db.add(GroupMember(group_id=armed_gid, uin=OWNER, role="owner"))
        db.add(GroupMember(group_id=armed_gid, uin=A, role="member"))
        await db.commit()
    tok = {u: issue_token(u, 0, f"dev-{u}") for u in (OWNER, A, GUEST, OUTSIDER, LEAVER)}
    H = lambda t: {"Authorization": f"Bearer {t}"}  # noqa: E731
    transport = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t")
    async with transport as c:
        print("\nMembers post as before:")
        r = await c.post("/messages/group-broadcast", headers=H(tok[OWNER]), json={"group_id": gid, "payload": b64()})
        check(f"the owner's broadcast is accepted ({r.status_code})", r.status_code == 200)
        r = await c.post("/messages/group-broadcast", headers=H(tok[A]), json={"group_id": gid, "payload": b64()})
        check(f"a member's broadcast is accepted ({r.status_code})", r.status_code == 200)
        r = await c.post("/messages/group-broadcast", headers=H(tok[GUEST]), json={"group_id": gid, "payload": b64()})
        check(f"a guest copy with a seat posts like any member ({r.status_code})", r.status_code == 200)

        print("\nAn account with no seat:")
        legacy_before = await count(OfflineGroupMessage, OfflineGroupMessage.group_id == gid)
        log_before = await count(GroupLog, GroupLog.group_id == gid)
        head_before = await head(gid)
        r = await c.post("/messages/group-broadcast", headers=H(tok[OUTSIDER]), json={"group_id": gid, "payload": b64()})
        check(f"is refused with 403 ({r.status_code})", r.status_code == 403)
        check("  ... saying why", "not_a_member" in str(r.json().get("detail")))
        check("  ... and nothing is written: no legacy row",
              await count(OfflineGroupMessage, OfflineGroupMessage.group_id == gid) == legacy_before)
        check("  ... no log row", await count(GroupLog, GroupLog.group_id == gid) == log_before)
        check("  ... no seq taken from the room", await head(gid) == head_before)
        for kind in ("reaction", "delete", "edit"):
            r = await c.post("/messages/group-broadcast", headers=H(tok[OUTSIDER]),
                             json={"group_id": gid, "envelope_type": kind, "payload": b64()})
            check(f"  ... a {kind} too ({r.status_code})", r.status_code == 403)

        print("\nA room with slowmode and an age floor (their gates used to wave a non-member on):")
        r = await c.post("/messages/group-broadcast", headers=H(tok[OUTSIDER]), json={"group_id": armed_gid, "payload": b64()})
        check(f"the non-member is refused ({r.status_code})", r.status_code == 403 and "not_a_member" in str(r.json().get("detail")))
        r = await c.post("/messages/group-broadcast", headers=H(tok[OWNER]), json={"group_id": armed_gid, "payload": b64()})
        check(f"the owner still posts there ({r.status_code})", r.status_code == 200)

        print("\nSomebody who left:")
        async with SessionLocal() as db:
            await db.execute(delete(GroupMember).where(GroupMember.group_id == gid, GroupMember.uin == LEAVER))
            await db.commit()
        r = await c.post("/messages/group-broadcast", headers=H(tok[LEAVER]), json={"group_id": gid, "payload": b64()})
        check(f"is refused like any outsider ({r.status_code})", r.status_code == 403)

        print("\nUnchanged around it:")
        r = await c.post("/messages/group-broadcast", json={"group_id": gid, "payload": b64()})
        check(f"no token is still 401 ({r.status_code})", r.status_code == 401)
        r = await c.post("/messages/group-broadcast", headers=H(tok[A]), json={"group_id": 999999, "payload": b64()})
        check(f"no such room is still 404 ({r.status_code})", r.status_code == 404)
        r = await c.post("/messages/group-sealed", json={
            "group_id": gid, "envelope_type": "message",
            "payloads": [{"to_uin": A, "payload": b64()}],
        })
        check(f"the sealed path stays anonymous for a deposit to a member ({r.status_code})", r.status_code == 200)

    await redis.flushdb()
    await close_redis()
    try:
        os.remove("test_broadcast_member.db")
    except FileNotFoundError:
        pass
    print(f"\n{'ALL PASS' if fails == 0 else f'{fails} FAILED'}")
    return fails


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
