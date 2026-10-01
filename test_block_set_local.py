"""Local-only verification that block SETS the flag when told what to set
(report 1065).

`POST /contacts/{uin}/block` flipped the flag and read no body. A flip is only
right when the caller knows the current state, and clients often do not: a
roster served as 304, or a second device that blocked first, turned a press of
"Block" into an unblock. The web has sent `{"blocked": bool}` all along and
was flipped anyway.

Pins:
  * ★ `{"blocked": true}` twice leaves it blocked, `{"blocked": false}` twice
    leaves it unblocked;
  * the old callers get exactly the old toggle: no body (iOS), `{}` (Android),
    and neither a foreign content type nor broken JSON turns into a 422;
  * anything that is not a boolean `blocked` is "no value", i.e. a toggle;
  * the answer is still `{"blocked": <flag now>}` and matches the row;
  * a pair without a row is still 404, whatever the body says.

In-process ASGI against a throwaway SQLite DB, Redis db 15 for the limiter.
NOT deployed.
Run: cd backend && PYTHONPATH=. .venv/bin/python test_block_set_local.py
"""
import asyncio
import base64
import os

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test_block_set.db"
os.environ["ENV"] = "dev"
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/15")
os.environ.setdefault("JWT_SECRET", "t" * 64)
os.environ.setdefault("REGISTER_CEILING_PER_MINUTE", "5000")
os.environ.setdefault("REGISTER_CEILING_PER_HOUR", "5000")

for f in ("test_block_set.db",):
    try:
        os.remove(f)
    except FileNotFoundError:
        pass

import httpx  # noqa: E402
from sqlalchemy import select  # noqa: E402

from app.core.db import SessionLocal, init_db  # noqa: E402
from app.core.redis import close_redis  # noqa: E402
from app.main import app  # noqa: E402
from app.models.contact import Contact  # noqa: E402
from app.services.contact_source import add_edges  # noqa: E402

fails = 0


def check(name: str, ok: bool, detail: str = "") -> None:
    global fails
    print(f"  {'PASS' if ok else 'FAIL'}  {name}{'' if ok else '  <- ' + detail}")
    if not ok:
        fails += 1


def _caller_addr():
    who = os.getpid()
    return (f"10.{(who >> 8) & 0xFF}.{who & 0xFF}.{(who >> 16) % 254 + 1}", 44444)


async def clear_limiter():
    from app.core.redis import get_redis
    try:
        redis = await get_redis()
        for pattern in ("rl:auth_register:*",):
            keys = [k async for k in redis.scan_iter(match=pattern)]
            if keys:
                await redis.delete(*keys)
    except Exception:  # noqa: BLE001
        pass


async def register(c):
    r = await c.post("/auth/register", json={
        "nickname": "someone",
        "identity_key": base64.b64encode(os.urandom(32)).decode(),
        "signing_key": base64.b64encode(os.urandom(32)).decode(),
    })
    assert r.status_code == 201, r.text
    return r.json()["uin"], {"Authorization": f"Bearer {r.json()['token']}"}


async def stored(owner, peer):
    async with SessionLocal() as s:
        return await s.scalar(select(Contact.blocked).where(
            Contact.owner_uin == owner, Contact.contact_uin == peer))


async def main() -> None:
    await init_db()
    await clear_limiter()
    transport = httpx.ASGITransport(app=app, client=_caller_addr())
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        me, h = await register(c)
        peer, _ = await register(c)
        stranger, _ = await register(c)
        async with SessionLocal() as s:
            await add_edges(s, me, peer)
            await s.commit()
        url = f"/contacts/{peer}/block"

        async def post(**kw):
            r = await c.post(url, headers={**h, **kw.pop("headers", {})}, **kw)
            return r.status_code, (r.json().get("blocked") if r.status_code == 200 else r.text[:120])

        print("\nan explicit value is SET, not flipped")
        check("{blocked: true} -> blocked", await post(json={"blocked": True}) == (200, True))
        check("★ {blocked: true} again -> still blocked", await post(json={"blocked": True}) == (200, True))
        check("and the row agrees", await stored(me, peer) is True)
        check("{blocked: false} -> unblocked", await post(json={"blocked": False}) == (200, False))
        check("★ {blocked: false} again -> still unblocked",
              await post(json={"blocked": False}) == (200, False))
        check("and the row agrees", await stored(me, peer) is False)

        print("\nold callers keep the toggle")
        check("no body (iOS) flips it on", await post() == (200, True))
        check("no body flips it off again", await post() == (200, False))
        check("{} (Android) flips it", await post(content=b"{}",
              headers={"content-type": "application/json"}) == (200, True))
        r = await post(content=b"{}", headers={"content-type": "text/plain"})
        check("★ {} as text/plain flips it, not a 422", r == (200, False), str(r))
        r = await post(content=b"{", headers={"content-type": "application/json"})
        check("★ broken JSON flips it, not a 422", r == (200, True), str(r))

        print("\nonly a real boolean counts")
        check('{"blocked": "false"} is not a boolean: flips', await post(json={"blocked": "false"}) == (200, False))
        check('{"blocked": null}: flips', await post(json={"blocked": None}) == (200, True))
        check('{"blocked": 0}: flips', await post(json={"blocked": 0}) == (200, False))
        check('a list body: flips', await post(json=[True]) == (200, True))
        check("the row agrees with the last answer", await stored(me, peer) is True)

        print("\nno row, no block")
        r = await c.post(f"/contacts/{stranger}/block", headers=h, json={"blocked": True})
        check("a stranger is still 404 with a body", r.status_code == 404, str(r.status_code))
        r = await c.post(f"/contacts/{stranger}/block", headers=h)
        check("and without one", r.status_code == 404, str(r.status_code))

    await close_redis()
    print("\n" + ("ALL PASS" if fails == 0 else f"{fails} FAILED"))
    raise SystemExit(1 if fails else 0)


asyncio.run(main())
