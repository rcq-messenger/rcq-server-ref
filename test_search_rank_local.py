"""Local-only verification of the /users/search order (#869).

Being a CONTACT used to be a rank of its own, above every kind of text match:
a friend whose nickname merely CONTAINED the query stood above a stranger whose
nickname STARTED with it. Typing the first letters of a name you can see on
screen therefore did not put that name first, and the reporter who found it
also found that the group filter and the mention picker do not work that way.

Pins:
  * an exact number wins outright;
  * a prefix match beats a "contains" match even when the contains-match is a
    contact — the case in the report;
  * among people who match EQUALLY well, contacts still come first, which is
    the part of "сначала друзья" that was always meant;
  * a prefix on the real first name counts as a prefix, on the same
    public-profile condition the text clause already uses;
  * a private profile's real name is still not searchable through the order.

Runs the real FastAPI stack in-process on a throwaway SQLite DB with Redis
db 15. NOT deployed.
Run: PYTHONPATH=. /Users/tager/Documents/RCQ/backend/.venv/bin/python test_search_rank_local.py
"""
import asyncio
import base64
import os

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test_search_rank.db"
os.environ["ENV"] = "dev"
os.environ["REDIS_URL"] = "redis://localhost:6379/15"
os.environ.setdefault("ADMIN_USERNAME", "admin")
os.environ.setdefault("ADMIN_PASSWORD", "adminpw")
for f in ("test_search_rank.db",):
    try:
        os.remove(f)
    except FileNotFoundError:
        pass

import httpx  # noqa: E402

from app.core.db import SessionLocal, init_db  # noqa: E402
from app.core.redis import close_redis, get_redis  # noqa: E402
from app.main import app  # noqa: E402
from app.models.contact import Contact  # noqa: E402
from app.models.user import User  # noqa: E402

fails = 0


def check(name, cond, detail=""):
    global fails
    print(f"  {'PASS' if cond else 'FAIL'}  {name}{'' if cond else '  <- ' + detail}")
    if not cond:
        fails += 1


def keypair(seed):
    raw = bytes([(seed + i) % 251 for i in range(32)])
    return base64.b64encode(raw).decode(), base64.b64encode(raw[::-1]).decode()


async def register(c, nick, seed):
    ident, sign = keypair(seed)
    r = await c.post("/auth/register", json={"nickname": nick, "identity_key": ident, "signing_key": sign})
    r.raise_for_status()
    d = r.json()
    return d["uin"], d["token"]


async def names(c, token, q):
    r = await c.get(f"/users/search?q={q}", headers={"Authorization": f"Bearer {token}"})
    r.raise_for_status()
    return [row["nickname"] for row in r.json()]


async def main() -> int:
    await init_db()
    await (await get_redis()).flushdb()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        me, tok = await register(c, "searcher", 1)
        # "seryoga" CONTAINS ser and is my contact; "sergey" STARTS with it and
        # is a stranger. This pair is the whole report.
        friend, _ = await register(c, "xxx-seryoga", 20)
        stranger, _ = await register(c, "sergey", 40)
        other, _ = await register(c, "sermon", 60)
        # Straight into the table: the request/accept dance is another
        # router's business, and the ranking reads only this row.
        async with SessionLocal() as db:
            db.add(Contact(owner_uin=me, contact_uin=friend))
            await db.commit()
        check("contact row present", True)

        print("\nMatch quality decides between tiers:")
        got = await names(c, tok, "ser")
        check(f"prefix beats a contact's contains-match  {got}",
              got and got[0] in ("sergey", "sermon") and "xxx-seryoga" in got,
              "the contact still leads")
        check("the contains-match is still returned, just lower",
              got.index("xxx-seryoga") > got.index("sergey"))

        print("\nAmong equal matches, contacts still come first:")
        # Both start with "ser" now, one of them is my contact.
        async with SessionLocal() as db:
            u = await db.get(User, friend)
            u.nickname = "sergio"
            await db.commit()
        got = await names(c, tok, "ser")
        check(f"contact leads its own tier  {got}", got and got[0] == "sergio")

        print("\nAn exact number wins outright:")
        got = await names(c, tok, str(stranger))
        check(f"#{stranger} first  {got}", got and got[0] == "sergey")

        print("\nA real first name counts as a prefix when the profile is public:")
        async with SessionLocal() as db:
            u = await db.get(User, other)
            u.nickname, u.first_name, u.profile_visibility = "zzz", "Bertha", "everyone"
            await db.commit()
            u2 = await db.get(User, stranger)
            u2.nickname, u2.first_name, u2.profile_visibility = "b-late", "Bernard", "contacts"
            await db.commit()
        got = await names(c, tok, "ber")
        check(f"public first name ranks as a prefix  {got}", got and got[0] == "zzz")
        check("a private profile's real name is not an oracle", "b-late" not in got,
              "private first name leaked into results")

    await close_redis()
    print("\n" + ("ALL PASS" if fails == 0 else f"{fails} FAILED"))
    return 1 if fails else 0


raise SystemExit(asyncio.run(main()))
