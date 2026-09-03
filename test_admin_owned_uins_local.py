"""Local-only verification of GET /admin/uin/owned (the register of held numbers).

The register is what an operator reads when somebody says "this number is
mine" or "I paid and got nothing". Pins:

  * it lists a deed with its holder, the door it came through and the date;
  * a number the holder is ANSWERING as is marked in_use rather than hidden —
    the deed survives being used, and a register that dropped it would say a
    bought number does not exist;
  * `q` finds a deed by the number held OR by whoever holds it, because both
    are what an operator arrives with;
  * a LIVE till hold shows on the row, an EXPIRED one does not (the cron reaps
    a minute later, and until then it must not read as a sale in flight);
  * `total` counts matches BEFORE the limit, so a truncated page can say so;
  * ⚠ the counters separate a paid deed from a free claim, which the column
    could not do until 2026-09-03 evening;
  * ⚠⚠ nothing under /admin may be stored by the browser: the response carries
    Cache-Control: no-store.

Runs the real FastAPI stack in-process on a throwaway SQLite DB with Redis
db 15. NOT deployed.
Run: PYTHONPATH=. /Users/tager/Documents/RCQ/backend/.venv/bin/python test_admin_owned_uins_local.py
"""
import asyncio
import base64
import os
from datetime import datetime, timedelta, timezone

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test_admin_owned.db"
os.environ["ENV"] = "dev"
os.environ["REDIS_URL"] = "redis://localhost:6379/15"
os.environ.setdefault("ADMIN_USERNAME", "admin")
os.environ.setdefault("ADMIN_PASSWORD", "adminpw")
for f in ("test_admin_owned.db",):
    try:
        os.remove(f)
    except FileNotFoundError:
        pass

import httpx  # noqa: E402

from app.core.db import SessionLocal, init_db  # noqa: E402
from app.core.redis import close_redis, get_redis  # noqa: E402
from app.main import app  # noqa: E402
from app.models.owned_uin import OwnedUin  # noqa: E402
from app.models.uin_sale import UinHold  # noqa: E402
from app.models.user import User  # noqa: E402

ADMIN = ("admin", "adminpw")
fails = 0


def check(name, cond):
    global fails
    print(f"  {'PASS' if cond else 'FAIL'}  {name}")
    if not cond:
        fails += 1


def b64(n=32):
    return base64.b64encode(bytes(range(n))).decode()


async def main() -> int:
    await init_db()
    await (await get_redis()).flushdb()
    now = datetime.now(timezone.utc)
    async with SessionLocal() as db:
        db.add(User(uin=808, nickname="buyer", identity_key=b64(), signing_key=b64()))
        db.add(User(uin=90909090, nickname="collector", identity_key=b64(), signing_key=b64()))
        # A bought number its owner is answering as.
        db.add(OwnedUin(uin=808, owner_uin=808, source="purchase", acquired_at=now))
        # A bought number sitting in a collection.
        db.add(OwnedUin(uin=4242, owner_uin=90909090, source="purchase",
                        acquired_at=now - timedelta(days=2)))
        # A free claim, which used to be indistinguishable from the two above.
        db.add(OwnedUin(uin=481516234, owner_uin=90909090, source="claimed",
                        acquired_at=now - timedelta(days=40)))
        db.add(OwnedUin(uin=777, owner_uin=808, source="granted",
                        acquired_at=now - timedelta(days=100)))
        # One live hold, one already expired.
        db.add(UinHold(uin=5150, hold_id="inv-live", expires_at=now + timedelta(minutes=30)))
        db.add(UinHold(uin=4242, hold_id="inv-dead", expires_at=now - timedelta(minutes=1)))
        await db.commit()

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        r = await c.get("/admin/uin/owned", auth=ADMIN)
        check(f"the register answers ({r.status_code})", r.status_code == 200)
        check("⚠⚠ and the browser may not keep it on disk",
              r.headers.get("cache-control") == "no-store")
        d = r.json()
        by = {i["uin"]: i for i in d["items"]}
        check(f"all four deeds are listed ({sorted(by)})", len(by) == 4)
        check("a bought number in use is marked, not hidden",
              by[808]["in_use"] is True and by[808]["source"] == "purchase")
        check("a number in a collection is not in use", by[4242]["in_use"] is False)
        check("the holder is named", by[4242]["owner_nickname"] == "collector")
        check(f"and its length is given ({by[4242]['length']})", by[4242]["length"] == 4)

        print("\nCounters tell a paid deed from a free claim:")
        check(f"claims_purchase 2 ({d['claims_purchase']})", d["claims_purchase"] == 2)
        check(f"claimed_free 1 ({d['claimed_free']})", d["claimed_free"] == 1)
        check(f"granted 1 ({d['granted_total']})", d["granted_total"] == 1)

        print("\nHolds:")
        check("an EXPIRED hold is not shown as one", by[4242]["hold_id"] is None)
        check(f"live_holds counts only the live one ({d['live_holds']})",
              d["live_holds"] == 1)

        print("\nSearch:")
        r = await c.get("/admin/uin/owned?q=4242", auth=ADMIN)
        check("by the number held", [i["uin"] for i in r.json()["items"]] == [4242])
        r = await c.get("/admin/uin/owned?q=90909090", auth=ADMIN)
        got = sorted(i["uin"] for i in r.json()["items"])
        check(f"by the holder, everything they hold ({got})", got == [4242, 481516234])

        print("\nFilters and truncation:")
        r = await c.get("/admin/uin/owned?source=claimed", auth=ADMIN)
        check("by door", [i["uin"] for i in r.json()["items"]] == [481516234])
        r = await c.get("/admin/uin/owned?days=7", auth=ADMIN)
        check(f"by age ({[i['uin'] for i in r.json()['items']]})",
              sorted(i["uin"] for i in r.json()["items"]) == [808, 4242])
        r = await c.get("/admin/uin/owned?limit=1", auth=ADMIN)
        j = r.json()
        check(f"a truncated page still says how many matched ({len(j['items'])} of {j['total']})",
              len(j["items"]) == 1 and j["total"] == 4)

        print("\nAuth:")
        r = await c.get("/admin/uin/owned")
        check(f"no credentials, no register ({r.status_code})", r.status_code == 401)

    await close_redis()
    try:
        os.remove("test_admin_owned.db")
    except FileNotFoundError:
        pass
    print("\n" + ("ALL PASS" if fails == 0 else f"{fails} FAILED"))
    return 1 if fails else 0


raise SystemExit(asyncio.run(main()))
