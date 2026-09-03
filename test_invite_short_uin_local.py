"""Local-only verification that a short number can be handed to a NEWCOMER.

The rule the whole scarce-stock design rests on: a short or patterned number
leaves through a door somebody is standing at. There are two such doors -
`POST /admin/uin/grant` for a person who is already here, and an invite minted
with the number on it for a person who is not.

⚠⚠ The second door was closed for exactly the numbers it was needed for.
`POST /admin/invites` checked the reserved number against `settings.UIN_MIN`,
which is the window the RANDOM ALLOCATOR mints from (100000), so three, four
and five digit numbers were refused. "Hand #777 to the person who earned it"
worked for every existing member and for no newcomer at all - and three-digit
numbers are not for sale at any price, which makes an invite the only way one
is ever handed over.

Checks:
  * ⚠ a three-digit number can be put on an invite, and a four-digit one;
  * the number is really reserved: the allocator and a second invite refuse it;
  * zero and a number past the ceiling are still refused;
  * ⚠ a number the till is currently selling cannot be promised by hand;
  * an expired hold does not stand in the way.

Runs the real FastAPI stack in-process on a throwaway SQLite DB with Redis
db 15. NOT deployed.
Run: PYTHONPATH=. /Users/tager/Documents/RCQ/backend/.venv/bin/python test_invite_short_uin_local.py
"""
import asyncio
import base64
import os
from datetime import datetime, timedelta, timezone

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test_invite_short.db"
os.environ["ENV"] = "dev"
os.environ["REDIS_URL"] = "redis://localhost:6379/15"
os.environ.setdefault("ADMIN_USERNAME", "admin")
os.environ.setdefault("ADMIN_PASSWORD", "adminpw")
for f in ("test_invite_short.db",):
    try:
        os.remove(f)
    except FileNotFoundError:
        pass

import httpx  # noqa: E402

from app.core.db import SessionLocal, init_db  # noqa: E402
from app.core.redis import close_redis, get_redis  # noqa: E402
from app.main import app  # noqa: E402
from app.models.uin_sale import UinHold  # noqa: E402
from app.services.uin import uin_is_taken  # noqa: E402

ADMIN = ("admin", "adminpw")
fails = 0


def check(name, cond):
    global fails
    print(f"  {'PASS' if cond else 'FAIL'}  {name}")
    if not cond:
        fails += 1


def code(r):
    try:
        return (r.json().get("detail") or {}).get("code")
    except Exception:  # noqa: BLE001
        return None


async def mint(c, uin):
    return await c.post("/admin/invites", json={"uin": uin, "max_uses": 1}, auth=ADMIN)


async def main() -> int:
    await init_db()
    await (await get_redis()).flushdb()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:

        print("\nA short number can be promised to somebody who is not here yet:")
        r = await mint(c, 777)
        check(f"⚠ three digits go on an invite ({r.status_code} {code(r)})", r.status_code == 201)
        r = await mint(c, 4242)
        check(f"so do four ({r.status_code} {code(r)})", r.status_code == 201)
        r = await mint(c, 55555)
        check(f"and five ({r.status_code} {code(r)})", r.status_code == 201)

        print("\nAnd it is really reserved:")
        async with SessionLocal() as db:
            check("the allocator and every other door see it as taken",
                  await uin_is_taken(db, 777))
        r = await mint(c, 777)
        check(f"a second invite for it is refused ({r.status_code} {code(r)})",
              r.status_code == 409 and code(r) == "uin_reserved")

        print("\nWhat is still refused:")
        for bad in (0, 99, 1_000_000_000):
            r = await mint(c, bad)
            check(f"{bad} ({r.status_code} {code(r)})",
                  r.status_code == 400 and code(r) == "uin_out_of_range")

        print("\n⚠ A number somebody is paying for cannot be promised by hand:")
        r = await c.post("/admin/uin/hold", json={"uin": 8080, "hold_id": "inv-live"}, auth=ADMIN)
        check(f"the till holds it ({r.status_code})", r.status_code == 200)
        r = await mint(c, 8080)
        check(f"the operator is stopped ({r.status_code} {code(r)})",
              r.status_code == 409 and code(r) == "uin_being_sold")
        async with SessionLocal() as db:
            hold = await db.get(UinHold, 8080)
            hold.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
            await db.commit()
        r = await mint(c, 8080)
        check(f"an EXPIRED hold stands in nobody's way ({r.status_code} {code(r)})",
              r.status_code == 201)

    await close_redis()
    try:
        os.remove("test_invite_short.db")
    except FileNotFoundError:
        pass
    print("\n" + ("ALL PASS" if fails == 0 else f"{fails} FAILED"))
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
