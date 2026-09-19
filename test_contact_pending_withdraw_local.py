"""Local-only verification of DELETE /contacts/pending/{id} (spec 2026-09-15, F1).

A person who holds a guest copy on this island answers a request addressed to
that copy from their HOME island, then clears the row here. `/respond` cannot do
the clearing honestly: accept=true writes contact edges on this island, and
accept=false leaves a "declined" row the requester reads for 180 days. So the
addressee gets a plain withdraw. Pins:

  * 204 for the addressee of a pending row;
  * the same 404 with code `no_such_request` for another account, for the
    requester themselves, for accepted and declined rows, and for a missing id,
    so the endpoint cannot be used to probe other people's request ids, and a
    client can tell "done" from an island that lost the route;
  * no `contacts` rows appear for the pair, which is the whole reason this is
    not /respond;
  * the requester's GET /contacts/outgoing no longer lists it, and neither does
    the addressee's GET /contacts/pending;
  * `contact_pending_withdraw` is advertised in /server/info;
  * GET /contacts/pending is rate limited: the 121st call inside 60 s is 429
    with Retry-After (guest drains poll it on a timer now);
  * the withdraw itself is limited at 60 an hour.

Runs the real FastAPI stack in-process on a throwaway SQLite DB with Redis
db 15. NOT deployed.
Run: PYTHONPATH=. PYTHONPATH=. .venv/bin/python test_contact_pending_withdraw_local.py
"""
import asyncio
import base64
import os

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test_contact_pending_withdraw.db"
os.environ["ENV"] = "dev"
os.environ["REDIS_URL"] = "redis://localhost:6379/15"

# ⚠ The island ceiling, raised for this file only. db 15 above keeps this file
# out of the stand's Redis, but it does NOT give it a private ceiling: every
# _local file that registers shares `rl:ceiling:auth_register:3600` in db 15, and
# the island default is 40/minute and 400/hour. A few full passes of the suite
# inside one hour push the shared counter past 400, and the next file that has
# NOT raised it answers 503 island_busy on a perfectly good registration — which
# is why the failing SET used to move between runs. Read through a lambda
# precisely so a test may raise it (core.rate_limit.island_ceiling).
os.environ.setdefault("REGISTER_CEILING_PER_MINUTE", "5000")
os.environ.setdefault("REGISTER_CEILING_PER_HOUR", "5000")


def _caller_addr():
    """A caller address nobody else shares, fresh on every run.

    `/auth/register` carries two per-caller limits hardcoded on the route — one
    per IP, one per /24 — and both live in Redis rather than in the throwaway
    database. Left at httpx's default the whole suite registers as ONE caller and
    spends the 20/hour between them, so whether this file passes depends on which
    files ran before it. The subnet moves too, because one limit is per /24.
    """
    who = os.getpid()
    return (f"10.{(who >> 8) & 0xFF}.{who & 0xFF}.{(who >> 16) % 254 + 1}", 44444)

for f in ("test_contact_pending_withdraw.db",):
    try:
        os.remove(f)
    except FileNotFoundError:
        pass

import httpx  # noqa: E402
from sqlalchemy import and_, func, or_, select  # noqa: E402

from app.core.db import SessionLocal, init_db  # noqa: E402
from app.core.redis import close_redis, get_redis  # noqa: E402
from app.main import app  # noqa: E402
from app.models.contact import Contact  # noqa: E402
from app.services.connection_manager import manager  # noqa: E402

fails = 0


def check(name, cond):
    global fails
    print(f"  {'PASS' if cond else 'FAIL'}  {name}")
    if not cond:
        fails += 1


def b64(n=32):
    return base64.b64encode(os.urandom(n)).decode()


def H(tok):
    return {"Authorization": f"Bearer {tok}"}


def code_of(r):
    try:
        detail = r.json().get("detail")
    except ValueError:
        return None
    return detail.get("code") if isinstance(detail, dict) else None


async def clear(pattern):
    redis = await get_redis()
    keys = [k async for k in redis.scan_iter(match=pattern)]
    if keys:
        await redis.delete(*keys)


async def register(c, nick):
    r = await c.post("/auth/register", json={"nickname": nick, "identity_key": b64(), "signing_key": b64()})
    assert r.status_code == 201, r.text
    body = r.json()
    return body["uin"], body["token"]


async def main() -> int:
    await init_db()
    # Db 15 is the throwaway Redis every local test shares. A cached epoch or a
    # full limiter bucket from another file would fail this one for a reason
    # unrelated to what it checks.
    await (await get_redis()).flushdb()
    transport = httpx.ASGITransport(app=app, client=_caller_addr())
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        a_uin, a_tok = await register(c, "requester")
        b_uin, b_tok = await register(c, "addressee")
        c_uin, c_tok = await register(c, "stranger")
        e_uin, e_tok = await register(c, "accepted-asker")
        f_uin, f_tok = await register(c, "declined-asker")

        r = await c.post("/contacts/request", headers=H(a_tok), json={"to_uin": b_uin})
        check(f"A asks B ({r.status_code})", r.status_code == 202)
        rid = r.json()["id"]
        r = await c.post("/contacts/request", headers=H(c_tok), json={"to_uin": b_uin})
        c_rid = r.json()["id"]
        r = await c.post("/contacts/request", headers=H(e_tok), json={"to_uin": b_uin})
        accepted_id = r.json()["id"]
        r = await c.post("/contacts/request", headers=H(f_tok), json={"to_uin": b_uin})
        declined_id = r.json()["id"]
        r = await c.post("/contacts/respond", headers=H(b_tok), json={"request_id": accepted_id, "accept": True})
        check("B accepts E's request through /respond", r.json().get("state") == "accepted")
        r = await c.post("/contacts/respond", headers=H(b_tok), json={"request_id": declined_id, "accept": False})
        check("B declines F's request through /respond", r.json().get("state") == "declined")

        print("\nOnly the addressee, only a pending row:")
        r = await c.delete(f"/contacts/pending/{rid}", headers=H(c_tok))
        check(f"★ another account gets 404 ({r.status_code})", r.status_code == 404)
        check("  ... with the endpoint's own code", code_of(r) == "no_such_request")
        r = await c.delete(f"/contacts/pending/{rid}", headers=H(a_tok))
        check("★ the REQUESTER cannot use this door either (404 no_such_request)",
              r.status_code == 404 and code_of(r) == "no_such_request")
        r = await c.delete(f"/contacts/pending/{accepted_id}", headers=H(b_tok))
        check("an accepted row is 404 no_such_request", r.status_code == 404 and code_of(r) == "no_such_request")
        r = await c.delete(f"/contacts/pending/{declined_id}", headers=H(b_tok))
        check("a declined row is 404 no_such_request", r.status_code == 404 and code_of(r) == "no_such_request")
        r = await c.delete("/contacts/pending/987654321", headers=H(b_tok))
        check("a missing id is the same 404 no_such_request", r.status_code == 404 and code_of(r) == "no_such_request")
        r = await c.get("/contacts/outgoing", headers=H(f_tok))
        check("  ... and the declined row is untouched: F still reads its answer",
              any(x["id"] == declined_id and x["state"] == "declined" for x in r.json()))

        print("\nThe withdraw:")
        r = await c.delete(f"/contacts/pending/{rid}", headers=H(b_tok))
        check(f"★ the addressee withdraws the pending row (204, got {r.status_code})", r.status_code == 204)
        r = await c.delete(f"/contacts/pending/{rid}", headers=H(b_tok))
        check("a second withdraw is 404 no_such_request", r.status_code == 404 and code_of(r) == "no_such_request")
        async with SessionLocal() as db:
            edges = await db.scalar(
                select(func.count()).select_from(Contact).where(
                    or_(
                        and_(Contact.owner_uin == a_uin, Contact.contact_uin == b_uin),
                        and_(Contact.owner_uin == b_uin, Contact.contact_uin == a_uin),
                    )
                )
            )
        check("★ no contact rows were written for the pair", edges == 0)
        r = await c.get("/contacts/outgoing", headers=H(a_tok))
        check("★ the requester's /contacts/outgoing no longer lists it",
              r.status_code == 200 and all(x["id"] != rid for x in r.json()))
        r = await c.get("/contacts/pending", headers=H(b_tok))
        check("the addressee's /contacts/pending no longer lists it, the stranger's still does",
              r.status_code == 200 and all(x["id"] != rid for x in r.json())
              and any(x["id"] == c_rid for x in r.json()))

        print("\nCapability:")
        r = await c.get("/server/info")
        check("★ /server/info advertises contact_pending_withdraw",
              r.status_code == 200 and r.json()["capabilities"].get("contact_pending_withdraw") is True)

        print("\nRate limits:")
        await clear("rl:contact_pending:*")
        statuses = [(await c.get("/contacts/pending", headers=H(b_tok))).status_code for _ in range(120)]
        check("120 polls inside a minute all answer 200", statuses == [200] * 120)
        r = await c.get("/contacts/pending", headers=H(b_tok))
        check(f"★ the 121st is 429 ({r.status_code})", r.status_code == 429)
        check("  ... with Retry-After", (r.headers.get("retry-after") or "").isdigit())
        r = await c.get("/contacts/pending", headers=H(c_tok))
        check("  ... and the bucket is per account: another one still polls", r.status_code == 200)

        await clear("rl:contact_pending_withdraw:*")
        statuses = [
            (await c.delete(f"/contacts/pending/{900000 + i}", headers=H(b_tok))).status_code
            for i in range(60)
        ]
        check("60 withdraws inside an hour are answered (404 here)", statuses == [404] * 60)
        r = await c.delete(f"/contacts/pending/{c_rid}", headers=H(b_tok))
        check(f"the 61st is 429 ({r.status_code})", r.status_code == 429)

    await manager.shutdown()
    await close_redis()
    try:
        os.remove("test_contact_pending_withdraw.db")
    except FileNotFoundError:
        pass
    print("\n" + ("ALL PASS" if fails == 0 else f"{fails} FAILED"))
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
