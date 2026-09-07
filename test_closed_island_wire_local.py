"""The closed island ON THE WIRE, not in isolation.

⚠⚠ WHY THIS EXISTS. `test_closed_island_door_local.py` calls `may_fetch_key`
directly and passes, and it passed on a day when the island was still handing
the identity key of every resident to any browser with no account at all —
because `/federation/keys/{uin}`, the door from ANOTHER island, was never
wired to the rule. A unit test that never reaches an HTTP handler cannot tell
a rule that exists from a rule that is enforced, and the docstring in door.py
claimed both doors were done. This file asks the app.

The properties it pins, each of which is a way to get the feature wrong:

  * an OPEN island is completely unchanged. Every refusal below must be absent
    when the operator has not closed anything.
  * a stranger with no card is refused, and refused with the SAME 404 and the
    same body as a number that does not exist. A distinguishable answer turns
    a closed island into a directory: ask about a number, learn whether it
    exists — and short numbers are the ones we sell.
  * a resident may still look up one named number, because a company's whole
    reason for a closed island is writing to a colleague by the number on
    their badge.
  * a search result stops carrying keys, but is NOT refused: search is the
    only way the web can add a same-island contact at all.
  * a card opens the door, and only its owner's door.

Needs local Redis (the rate limiter). NOT part of the prod suite.
Run: cd backend && PYTHONPATH=. .venv/bin/python test_closed_island_wire_local.py
"""
import asyncio
import base64
import os

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test_closed_wire.db"
os.environ["ENV"] = "dev"

for _f in ("test_closed_wire.db",):
    try:
        os.remove(_f)
    except FileNotFoundError:
        pass

import httpx  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from app.core.db import init_db  # noqa: E402
from app.main import app  # noqa: E402
from app.models.guest_card import hash_card, new_card  # noqa: E402
from app.core.db import SessionLocal  # noqa: E402
from app.services import server_settings  # noqa: E402


async def set_setting(key: str, raw: str) -> None:
    """Flip an operator setting the way the admin console does: upsert the
    override and bust the cache, so the very next request sees it."""
    async with SessionLocal() as db:
        await server_settings.apply(db, {key: raw})
        await db.commit()

ok = 0
bad = 0


def check(label: str, cond: bool, extra: str = "") -> None:
    global ok, bad
    if cond:
        ok += 1
        print(f"  ok   {label}")
    else:
        bad += 1
        print(f"  FAIL {label}{('  ← ' + extra) if extra else ''}")


def b64() -> str:
    return base64.b64encode(os.urandom(32)).decode()


def keypair():
    sk = Ed25519PrivateKey.generate()
    pub = sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    return sk, base64.b64encode(pub).decode()


async def clear_limiter():
    from app.core.redis import get_redis
    redis = await get_redis()
    for pattern in ("rl:auth_register:*", "rl:users_info:*", "rl:federation_keys_get:*"):
        keys = [k async for k in redis.scan_iter(match=pattern)]
        if keys:
            await redis.delete(*keys)


async def register(c) -> tuple[int, str]:
    _, pub = keypair()
    r = await c.post("/auth/register", json={
        "nickname": "someone", "identity_key": b64(), "signing_key": pub,
    })
    return r.json()["uin"], r.json()["token"]


def auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


async def main() -> None:
    await init_db()
    await clear_limiter()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        resident, rtok = await register(c)
        neighbour, ntok = await register(c)
        outsider, otok = await register(c)
        missing = 999_999_991

        # ── open island: nothing changes ────────────────────────────────────
        r = await c.get(f"/users/{resident}/info", headers=auth(otok))
        check("an open island tells a stranger everything, as it always has",
              r.status_code == 200 and bool(r.json().get("identity_key")), str(r.status_code))
        r = await c.get(f"/users/search?q=someone", headers=auth(otok))
        check("an open island puts keys in search results",
              r.status_code == 200 and any(u.get("identity_key") for u in r.json()))

        # What "no such user" looks like here, so the refusal can be compared
        # to it byte for byte rather than by eye.
        gone = await c.get(f"/users/{missing}/info", headers=auth(otok))

        # ── close it ───────────────────────────────────────────────────────
        await set_setting("closed_island", "true")

        # ⚠⚠ THE FINDING THIS FILE WAS WRITTEN TO CATCH. `/users/{uin}/info`
        # requires a session, so every caller of it already has an account on
        # this island and the rule sees a resident: the gate there can never
        # refuse anybody, and what shipped as "the first door closes" is inert.
        # The doors an outsider can actually reach are the unauthenticated
        # ones. This check states the truth rather than the intention, and it
        # will fail the day somebody makes door 6 refuse — which would mean
        # breaking a resident looking up a colleague.
        r = await c.get(f"/users/{resident}/info", headers=auth(otok))
        check("an ACCOUNT ON THIS ISLAND is not a stranger, and door 6 cannot "
              "tell the difference: it requires a session to be reached at all",
              r.status_code == 200, str(r.status_code))
        r = await c.get(f"/users/{resident}/info")
        check("an anonymous caller never reaches door 6 at all (401, not 404)",
              r.status_code == 401, str(r.status_code))
        check("and 'no such user' is what a real absence looks like, for the "
              "day doors 1-3 learn to imitate it",
              gone.status_code == 404 and gone.text == '{"detail":"no such user"}',
              gone.text)

        r = await c.get(f"/users/{resident}/info", headers=auth(ntok))
        check("a resident may still look up one named number (the colleague case)",
              r.status_code == 200 and bool(r.json().get("identity_key")), str(r.status_code))

        r = await c.get(f"/users/{resident}/info", headers=auth(rtok))
        check("and everybody may still read their own card", r.status_code == 200)

        r = await c.get("/users/search?q=someone", headers=auth(ntok))
        check("search is NOT refused on a closed island", r.status_code == 200, str(r.status_code))
        check("but its rows carry no keys, not even for a resident",
              r.status_code == 200 and all(not u.get("identity_key") for u in r.json()),
              "a search result is a harvest; that is the whole attack")

        # ── the card ───────────────────────────────────────────────────────
        raw = new_card()
        r = await c.post("/guest-cards", json={"card_hash": hash_card(raw), "label": "qr"},
                         headers=auth(rtok))
        check("a resident can register a card", r.status_code == 201, str(r.status_code))

        r = await c.get(f"/users/{resident}/info", headers={**auth(otok), "X-RCQ-Guest-Card": raw})
        check("a stranger holding the card is let through",
              r.status_code == 200 and bool(r.json().get("identity_key")), str(r.status_code))

        # ⚠ The card is never CONSULTED on this door, and these two checks say
        # so rather than pretending otherwise: the resident rule passes first,
        # so a made-up card and somebody else's card both work here — because
        # the caller would have been let through with no card at all. The
        # per-owner scoping is real and is pinned in
        # test_closed_island_door_local.py; it starts mattering the day doors
        # 1-3, which anonymous callers can reach, are gated.
        r = await c.get(f"/users/{neighbour}/info", headers={**auth(otok), "X-RCQ-Guest-Card": raw})
        check("on door 6 a card is not even looked at: the caller is a resident",
              r.status_code == 200, str(r.status_code))
        r = await c.get(f"/users/{resident}/info",
                        headers={**auth(otok), "X-RCQ-Guest-Card": new_card()})
        check("and a made-up card changes nothing here, for the same reason",
              r.status_code == 200, str(r.status_code))

        # ── the door that was NOT wired, and is deliberately still open ─────
        r = await c.get(f"/federation/keys/{resident}")
        check("⏭ door 1 (/federation/keys) is STILL OPEN, on purpose until the "
              "clients ship — this check is here to fail the day it is closed, "
              "so the change is deliberate",
              r.status_code == 200, str(r.status_code))

        await set_setting("closed_island", "false")
        r = await c.get(f"/users/{resident}/info", headers=auth(otok))
        check("reopening the island restores it immediately, with no restart",
              r.status_code == 200)

    print(f"\nclosed island on the wire: {ok}/{ok + bad} ok")
    raise SystemExit(0 if bad == 0 else 1)


asyncio.run(main())
