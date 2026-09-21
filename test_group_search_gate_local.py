"""Local-only verification of what `GET /groups/search` will answer for.

Report #990 asked whether sequential group ids are a bug or a feature, and
pointed at joining rooms that are hidden from search. Reading the endpoint
turned up a second door he had not noticed, and a worse one: the exact-id
clause sat OUTSIDE the filter that the name clause obeys, in an `or_`. So a
bare number answered with the name, the description, the owner's number and
nickname and the member count of a CLOSED room — from any account, at 60 a
minute — while `/{id}/preview` for the same room hands back a stripped card
and asks for a share token. The comment above it claimed "there the LINK is the
capability, same rule as preview"; the two had drifted apart, and this was the
loose one.

Pins, so the door cannot drift open again:
  * a room in the catalogue is findable by name AND by its exact id;
  * a CLOSED room is findable by neither, even when the number is exact;
  * a room merely absent from the catalogue (which is the DEFAULT for every
    room anyone creates) is findable by neither;
  * a non-numeric needle still behaves exactly as before;
  * and the caller's own rooms stay excluded, which is what the Add screen
    relies on.

Runs the real FastAPI stack in-process on a throwaway SQLite DB with Redis
db 15. NOT deployed.
Run: PYTHONPATH=. .venv/bin/python test_group_search_gate_local.py
"""
import asyncio
import base64
import os

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test_group_search_gate.db"
os.environ["ENV"] = "dev"
os.environ["REDIS_URL"] = "redis://localhost:6379/15"
for f in ("test_group_search_gate.db",):
    try:
        os.remove(f)
    except FileNotFoundError:
        pass

import httpx  # noqa: E402

from app.core.db import SessionLocal, init_db  # noqa: E402
from app.core.redis import close_redis, get_redis  # noqa: E402
from app.core.security import issue_token  # noqa: E402
from app.main import app  # noqa: E402
from app.models.group import Group, GroupMember  # noqa: E402
from app.models.user import User  # noqa: E402
from app.services.connection_manager import manager  # noqa: E402

fails = 0


def check(name, cond):
    global fails
    print(f"  {'PASS' if cond else 'FAIL'}  {name}")
    if not cond:
        fails += 1


def b64(n=32):
    return base64.b64encode(os.urandom(n)).decode()


# OWNER makes the rooms; STRANGER is the account doing the looking, with no
# membership anywhere — the shape of somebody walking the id space.
OWNER, STRANGER = 8101, 8102


async def _no_fanout(uins, payload):
    return set()


async def search(c, headers, q):
    r = await c.get("/groups/search", headers=headers, params={"q": q})
    return r.status_code, [g["id"] for g in (r.json() if r.status_code == 200 else [])]


async def main():
    global fails
    await init_db()
    await (await get_redis()).flushdb()
    async with SessionLocal() as db:
        for u in (OWNER, STRANGER):
            db.add(User(
                uin=u, nickname=f"u{u}", identity_key=b64(), signing_key=b64(),
                group_invite_policy="everyone",
            ))
        await db.commit()

    tok = {u: issue_token(u, 0, "phone") for u in (OWNER, STRANGER)}
    H = lambda t: {"Authorization": f"Bearer {t}"}  # noqa: E731
    manager.fanout = _no_fanout  # type: ignore[assignment]
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        print("\nSetup:")
        # Rooms inserted straight into the table, with explicit two-digit ids:
        # the endpoint ignores a needle shorter than two characters, so a
        # single-digit id would never reach the exact-id clause and the test
        # would pass without testing anything.
        #
        # ⚠ `in_catalog=False, is_closed=False` is what `POST /groups` actually
        # produces — the create payload cannot set either — so "unlisted room"
        # is not a contrived case, it is every room anyone makes.
        ids = {"listed room": 41, "unlisted room": 42, "closed room": 43}
        async with SessionLocal() as db:
            for name, gid in ids.items():
                db.add(Group(
                    id=gid, name=name, owner_uin=OWNER,
                    in_catalog=(name == "listed room"),
                    is_closed=(name == "closed room"),
                ))
                db.add(GroupMember(group_id=gid, uin=OWNER, role="owner"))
            await db.commit()
        check("three rooms exist", True)

        print("\nA room its owner published:")
        st, got = await search(c, H(tok[STRANGER]), "listed")
        check("found by name", st == 200 and ids["listed room"] in got)
        st, got = await search(c, H(tok[STRANGER]), str(ids["listed room"]))
        check("found by its exact id", st == 200 and ids["listed room"] in got)

        print("\nA CLOSED room:")
        st, got = await search(c, H(tok[STRANGER]), "closed")
        check("not found by name", st == 200 and ids["closed room"] not in got)
        st, got = await search(c, H(tok[STRANGER]), str(ids["closed room"]))
        check("not found by its exact id either", st == 200 and ids["closed room"] not in got)

        print("\nA room that was simply never published (the default):")
        st, got = await search(c, H(tok[STRANGER]), "unlisted")
        check("not found by name", st == 200 and ids["unlisted room"] not in got)
        st, got = await search(c, H(tok[STRANGER]), str(ids["unlisted room"]))
        check("not found by its exact id either", st == 200 and ids["unlisted room"] not in got)

        print("\nWalking the id space finds nothing it should not:")
        leaked = []
        for gid in range(40, max(ids.values()) + 3):
            st, got = await search(c, H(tok[STRANGER]), str(gid))
            leaked += [g for g in got if g != ids["listed room"]]
        check("only the published room ever comes back", not leaked)

        print("\nAnd the rest of the endpoint is unchanged:")
        st, got = await search(c, H(tok[STRANGER]), "room")
        check("a name needle still matches the published room", st == 200 and got == [ids["listed room"]])
        st, got = await search(c, H(tok[OWNER]), str(ids["listed room"]))
        check("the owner does not see their own room in Add", st == 200 and ids["listed room"] not in got)

    await close_redis()
    print(f"\n{'ALL PASS' if fails == 0 else str(fails) + ' FAILED'}")
    raise SystemExit(1 if fails else 0)


if __name__ == "__main__":
    asyncio.run(main())
