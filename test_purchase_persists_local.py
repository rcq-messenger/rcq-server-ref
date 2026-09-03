"""Local-only proof that a number taken into the collection is actually SAVED.

⚠⚠ WHAT THIS MISSED. `POST /uin/purchase {switch: false}` answered 200 OK and
wrote nothing. `get_db` yields a session and commits nothing, so a route that
only flushes rolls its work back when the session closes: the founder bought a
number, was told it was his, and his collection stayed empty at 0/10.

The two neighbouring paths hid it. `switch: true` goes through
`_perform_migration`, which commits inside its own transaction; `/uin/redeem`
commits immediately after calling the same helper. Only the free take into the
collection had nobody to commit for it - and that branch had been closed since
01.09, so reopening it on 03.09 exposed a gap no test covered.

⚠ The check that matters is reading the row back in a DIFFERENT session, the way
the next HTTP request does. A test that inspects the same session sees the
flushed row and passes while production loses it.

Checks:
  * a free take into the collection survives into a new session;
  * `/uin/mine` on a later request still reports it;
  * two takes both persist, and the cap counts what is really there;
  * ⚠ the number is really gone from the pool afterwards (nobody else may take
    it), which is the half that would strand somebody if only the row rolled
    back.

Runs the real FastAPI stack in-process on a throwaway SQLite DB with Redis
db 15. NOT deployed.
Run: PYTHONPATH=. /Users/tager/Documents/RCQ/backend/.venv/bin/python test_purchase_persists_local.py
"""
import asyncio
import base64
import os

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test_purchase_persists.db"
os.environ["ENV"] = "dev"
os.environ["REDIS_URL"] = "redis://localhost:6379/15"
os.environ.setdefault("ADMIN_USERNAME", "admin")
os.environ.setdefault("ADMIN_PASSWORD", "adminpw")
os.environ["UIN_SHOP_ENABLED"] = "true"
for f in ("test_purchase_persists.db",):
    try:
        os.remove(f)
    except FileNotFoundError:
        pass

import httpx  # noqa: E402

from app.core.db import SessionLocal, init_db  # noqa: E402
from app.core.redis import close_redis, get_redis  # noqa: E402
from app.core.security import issue_token  # noqa: E402
from app.main import app  # noqa: E402
from app.models.owned_uin import OwnedUin  # noqa: E402
from app.models.user import User  # noqa: E402

ME = 911
fails = 0


def check(name, cond):
    global fails
    print(f"  {'PASS' if cond else 'FAIL'}  {name}")
    if not cond:
        fails += 1


def b64(n=32):
    return base64.b64encode(os.urandom(n)).decode()


async def main() -> int:
    await init_db()
    await (await get_redis()).flushdb()
    async with SessionLocal() as db:
        db.add(User(uin=ME, nickname="founder", identity_key=b64(), signing_key=b64()))
        db.add(User(uin=700900001, nickname="somebody", identity_key=b64(), signing_key=b64()))
        await db.commit()

    H = {"Authorization": f"Bearer {issue_token(ME, 0, 'desktop')}"}
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:

        print("\nTaking a number into the collection, the way web and desktop do:")
        r = await c.post("/uin/purchase", json={"uin": 7654321, "switch": False}, headers=H)
        check(f"the shop says yes ({r.status_code})", r.status_code == 200)
        body = r.json() if r.status_code == 200 else {}
        check("  the answer says the account did NOT move", body.get("switched") is False)
        check("  and lists the number as held", 7654321 in (body.get("owned") or []))

        # ⚠⚠ THE CHECK THAT WAS MISSING: a different session, like the next
        # request. A flushed-but-uncommitted row is visible in the session that
        # wrote it and gone everywhere else.
        async with SessionLocal() as db:
            deed = await db.get(OwnedUin, 7654321)
            check("⚠⚠ the deed is really in the database, not just in the session",
                  deed is not None and int(deed.owner_uin) == ME)

        mine = (await c.get("/uin/mine", headers=H)).json()
        check(f"a later request still reports it ({mine.get('owned')})",
              any(int(o["uin"]) == 7654321 for o in (mine.get("owned") or [])))
        check("  and the account still answers as 911", mine.get("active") == ME)

        print("\nAnd nobody else can take it now:")
        H2 = {"Authorization": f"Bearer {issue_token(700900001, 0, 'phone')}"}
        r = await c.post("/uin/purchase", json={"uin": 7654321, "switch": False}, headers=H2)
        check(f"⚠ a stranger is refused ({r.status_code})", r.status_code == 409)

        print("\nA second take persists too, and the cap counts what is real:")
        r = await c.post("/uin/purchase", json={"uin": 8765432, "switch": False}, headers=H)
        check(f"taken ({r.status_code})", r.status_code == 200)
        async with SessionLocal() as db:
            check("both deeds are on disk",
                  await db.get(OwnedUin, 7654321) is not None
                  and await db.get(OwnedUin, 8765432) is not None)
        mine = (await c.get("/uin/mine", headers=H)).json()
        check(f"  the collection reports two ({len(mine.get('owned') or [])}/10)",
              len(mine.get("owned") or []) == 2)

    await close_redis()
    try:
        os.remove("test_purchase_persists.db")
    except FileNotFoundError:
        pass
    print("\n" + ("ALL PASS" if fails == 0 else f"{fails} FAILED"))
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
