"""Local-only verification that a short number survives a move.

⚠⚠ WHAT THIS COST. The founder answered as #911. On iOS he opened the shop,
bought an ordinary seven-digit number, and #911 was on the public shelf a second
later. Twice in a row, and the seed phrase brought him back to the number he had
just bought rather than the one he had lost.

Two things met. `/uin/purchase {switch: true}` is what the RELEASED iOS client
sends - it was changed to that on 01.09, when collections were closed and the
island refused `switch: false` outright. Collections reopened on 03.09 and the
released client was not told. And the same morning the vacated number started
going back to the POOL instead of into the collection, which is right for
ordinary space (it is what stopped 161 numbers being parked in 54 hoards) and
catastrophic for a three-digit number that was handed over by name.

So: a scarce number follows its holder into the collection, like a bought one.
An ordinary number is still a loan and still goes back to the pool.

⚠ This does not reopen the hoarding door: the allocator never mints scarce
numbers, `/uin/purchase` refuses them, and `desired_uin` cannot ask for one, so
the only ways to hold one are a grant, an invite or a paid voucher.

Runs the real FastAPI stack in-process on a throwaway SQLite DB with Redis
db 15. NOT deployed.
Run: PYTHONPATH=. /Users/tager/Documents/RCQ/backend/.venv/bin/python test_scarce_survives_move_local.py
"""
import asyncio
import base64
import os

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test_scarce_move.db"
os.environ["ENV"] = "dev"
os.environ["REDIS_URL"] = "redis://localhost:6379/15"
os.environ.setdefault("ADMIN_USERNAME", "admin")
os.environ.setdefault("ADMIN_PASSWORD", "adminpw")
os.environ["UIN_SHOP_ENABLED"] = "true"
for f in ("test_scarce_move.db",):
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

fails = 0


def check(name, cond):
    global fails
    print(f"  {'PASS' if cond else 'FAIL'}  {name}")
    if not cond:
        fails += 1


def b64(n=32):
    return base64.b64encode(os.urandom(n)).decode()


def code(r):
    try:
        return (r.json().get("detail") or {}).get("code")
    except Exception:  # noqa: BLE001
        return None


async def main() -> int:
    await init_db()
    await (await get_redis()).flushdb()

    async with SessionLocal() as db:
        # The founder's shape: a three-digit number, granted by hand.
        db.add(User(uin=911, nickname="founder", identity_key=b64(), signing_key=b64()))
        # And somebody on ordinary space, for the control.
        db.add(User(uin=748392015, nickname="ordinary", identity_key=b64(), signing_key=b64()))
        await db.commit()

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:

        print("\n⚠⚠ What the RELEASED iOS client does: buy WITH switch=true")
        H = {"Authorization": f"Bearer {issue_token(911, 0, 'iphone')}"}
        r = await c.post("/uin/purchase", json={"uin": 7654321, "switch": True}, headers=H)
        check(f"the purchase goes through, as it did for him ({r.status_code})",
              r.status_code == 200)
        out = r.json() if r.status_code == 200 else {}
        check(f"  and the account is moved onto it ({out.get('new_uin')})",
              out.get("new_uin") == 7654321)

        async with SessionLocal() as db:
            check("⚠⚠ #911 is NOT on the public shelf",
                  await db.get(OwnedUin, 911) is not None)
            deed = await db.get(OwnedUin, 911)
            check("  it is in the collection of the account that left it",
                  deed is not None and int(deed.owner_uin) == 7654321)
            check("  and no stranger answers as it",
                  await db.get(User, 911) is None)
        check("  the client is told it still holds it",
              911 in (out.get("owned") or []))

        print("\nAnd he can step back onto it:")
        H2 = {"Authorization": f"Bearer {out.get('token')}"}
        r = await c.post("/uin/activate", json={"uin": 911}, headers=H2)
        back = r.json() if r.status_code == 200 else {}
        check(f"activated ({r.status_code})", r.status_code == 200)
        check("  he answers as 911 again", back.get("new_uin") == 911)
        # ⚠ And the ordinary number he passed through does NOT stay: it was a
        # loan, taken for free, and stepping off it puts it back on the shelf.
        # That asymmetry IS the rule - scarce follows the person, ordinary does
        # not - and it is the reason the shelf is not empty.
        check("  ⚠ while the ordinary number he passed through goes back to the pool",
              7654321 not in (back.get("owned") or []))

        print("\nThe loan rule still holds for ORDINARY space:")
        H3 = {"Authorization": f"Bearer {issue_token(748392015, 0, 'phone')}"}
        r = await c.post("/uin/purchase", json={"uin": 612345678, "switch": True}, headers=H3)
        check(f"an ordinary account moves to another ordinary number ({r.status_code})",
              r.status_code == 200)
        async with SessionLocal() as db:
            check("⚠ the number it left goes BACK TO THE POOL, as designed",
                  await db.get(OwnedUin, 748392015) is None
                  and await db.get(User, 748392015) is None)

    await close_redis()
    try:
        os.remove("test_scarce_move.db")
    except FileNotFoundError:
        pass
    print("\n" + ("ALL PASS" if fails == 0 else f"{fails} FAILED"))
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
