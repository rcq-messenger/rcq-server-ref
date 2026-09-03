"""Local-only verification that moving does not delete the device you left at home.

⚠⚠ `/auth/refresh` answered `identity_not_found` for any number it could not
find, and every client reads that one way: the account was burned, wipe the
local copy. But there is a second reason a number is not there, and it is the
commonest one now that numbers are bought: the owner MOVED. A phone in a drawer,
or a browser tab left open, then asks about the number its owner walked away
from - and deletes chats from a live account. Android does exactly this
(`probeBurnedAccount`), and the web client signs itself out.

Now a vacant number plus a key that resolves to exactly one account means "the
person moved", and the answer carries `moved_from` so a client can tell that
from a shared key.

Checks:
  * the ordinary case still works and reports no move;
  * ⚠ after a migration the OLD number mints a token for the NEW one and says
    where it came from;
  * ⚠ a number somebody else answers as is NOT a move: no token;
  * ⚠ a key carried by two accounts is refused - guessing a winner is how a
    device lands in a stranger's account;
  * a key nobody carries is still `identity_not_found`, which is still a burn.

Runs the real FastAPI stack in-process on a throwaway SQLite DB with Redis
db 15. NOT deployed.
Run: PYTHONPATH=. /Users/tager/Documents/RCQ/backend/.venv/bin/python test_refresh_moved_local.py
"""
import asyncio
import base64
import os

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test_refresh_moved.db"
os.environ["ENV"] = "dev"
os.environ["REDIS_URL"] = "redis://localhost:6379/15"
os.environ.setdefault("ADMIN_USERNAME", "admin")
os.environ.setdefault("ADMIN_PASSWORD", "adminpw")
for f in ("test_refresh_moved.db",):
    try:
        os.remove(f)
    except FileNotFoundError:
        pass

import httpx  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from app.core.db import SessionLocal, init_db  # noqa: E402
from app.core.redis import close_redis, get_redis  # noqa: E402
from app.main import app  # noqa: E402
from app.models.user import User  # noqa: E402
from app.routers.migrate import _perform_migration  # noqa: E402

fails = 0


def check(name, cond):
    global fails
    print(f"  {'PASS' if cond else 'FAIL'}  {name}")
    if not cond:
        fails += 1


def b64(n=32):
    return base64.b64encode(os.urandom(n)).decode()


def pub_of(k):
    return base64.b64encode(k.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()


async def refresh(c, uin, key):
    pub = pub_of(key)
    ch = (await c.post("/auth/recover/challenge", json={"signing_key": pub})).json()["challenge"]
    sig = base64.b64encode(key.sign(ch.encode())).decode()
    return await c.post("/auth/refresh", json={
        "uin": uin, "signing_key": pub, "challenge": ch, "signature": sig,
        "device_id": "dev-a",
    })


ALICE, BOB, CLAIRE = 700500001, 700500002, 700500003


async def main() -> int:
    await init_db()
    await (await get_redis()).flushdb()
    alice_key, bob_key, shared_key = (Ed25519PrivateKey.generate() for _ in range(3))

    async with SessionLocal() as db:
        db.add(User(uin=ALICE, nickname="alice", identity_key=b64(), signing_key=pub_of(alice_key)))
        db.add(User(uin=BOB, nickname="bob", identity_key=b64(), signing_key=pub_of(bob_key)))
        # Two accounts carrying one key, the shape seven keys already have on
        # the flagship.
        db.add(User(uin=CLAIRE, nickname="claire", identity_key=b64(), signing_key=pub_of(shared_key)))
        db.add(User(uin=700500004, nickname="twin", identity_key=b64(), signing_key=pub_of(shared_key)))
        await db.commit()

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        print("\nNothing has moved yet:")
        r = await refresh(c, ALICE, alice_key)
        body = r.json() if r.status_code == 200 else {}
        check(f"the ordinary refresh works ({r.status_code})", r.status_code == 200)
        check("  it hands back the same number", body.get("uin") == ALICE)
        check("  and says nothing about a move", body.get("moved_from") is None)

        print("\nAlice buys a shorter number on her laptop:")
        async with SessionLocal() as db:
            alice = await db.get(User, ALICE)
            new_uin = await _perform_migration(db, alice, target_uin=4242)
            await db.commit()
        check(f"she now answers as {new_uin}", new_uin == 4242)
        r = await refresh(c, ALICE, alice_key)
        body = r.json() if r.status_code == 200 else {}
        check(f"⚠ the phone in the drawer is NOT told the account is gone ({r.status_code})",
              r.status_code == 200)
        check("  it is handed the new number", body.get("uin") == 4242)
        check("  ... and told which one it left", body.get("moved_from") == ALICE)
        check("  ... with a token it can actually use",
              isinstance(body.get("token"), str) and len(body.get("token", "")) > 20)

        print("\nWhat is NOT a move:")
        r = await refresh(c, BOB, alice_key)
        check(f"⚠ a number somebody else answers as ({r.status_code})", r.status_code == 404)
        r = await refresh(c, 700500009, shared_key)
        check(f"⚠ a key two accounts carry ({r.status_code})", r.status_code == 404)
        lonely = Ed25519PrivateKey.generate()
        r = await refresh(c, 700500010, lonely)
        check(f"a key nobody carries is still a burn ({r.status_code})", r.status_code == 404)
        check("  ... and still says so in the same word",
              "identity_not_found" in r.text)

        print("\nAnd the number she left is free again:")
        r = await refresh(c, 4242, alice_key)
        check(f"her laptop refreshes normally ({r.status_code})", r.status_code == 200)
        check("  with no move to report", r.json().get("moved_from") is None)

    await close_redis()
    try:
        os.remove("test_refresh_moved.db")
    except FileNotFoundError:
        pass
    print("\n" + ("ALL PASS" if fails == 0 else f"{fails} FAILED"))
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
