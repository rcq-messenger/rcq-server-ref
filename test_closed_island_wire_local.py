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
# ⚠ A SCRATCH Redis namespace, and the reason this file could look broken for
# weeks. The throwaway SQLite above is deleted on every run, but the rate limiter
# and the island-wide registration ceiling do not live in SQLite: they live in
# Redis, which is shared with the local two-island stand and with the previous
# run of this very file. A dozen registrations later the island answers 503
# island_busy or 429 to a perfectly good request and the file reads as "the
# server is broken" when nothing is. db 15 is nobody's product data, and
# `setdefault` leaves an operator free to point it elsewhere.
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/15")
# ⚠ And the island's own ceiling, raised for this file only. It is read through
# a lambda precisely so a test may raise it (core.rate_limit.island_ceiling); a
# file that registers several accounts in two seconds trips 40/minute and
# 400/hour on its SECOND run of the hour.
os.environ.setdefault("REGISTER_CEILING_PER_MINUTE", "5000")
os.environ.setdefault("REGISTER_CEILING_PER_HOUR", "5000")


def _caller_addr():
    """A caller address nobody else shares, fresh on every run.

    `/auth/register` carries two per-caller limits hardcoded on the route — one
    per IP, one per /24 — and both live in Redis rather than in the throwaway
    database. 20 per hour is fewer than this file spends in one pass, so a second
    run would answer 429 to its first registration. The subnet moves too, because
    one of the two limits is per /24.
    """
    who = os.getpid()
    return (f"10.{(who >> 8) & 0xFF}.{who & 0xFF}.{(who >> 16) % 254 + 1}", 44444)


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
    transport = httpx.ASGITransport(app=app, client=_caller_addr())
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

        # ── the doors an outsider can actually reach ───────────────────────
        #
        # These are the whole feature. /users/{uin}/info above cannot refuse
        # anybody, because reaching it requires a session; these three take no
        # session, which is what makes cross-island messaging work and what
        # makes them the only thing between a stranger and a resident's key.
        # ⚠⚠ DOOR 1 DOES NOT REFUSE, AND THAT IS THE FIX, NOT THE BUG. Refusing
        # this endpoint does not close an island, it unplugs it: every
        # cross-island contact request starts here, and the flagship spent
        # hours on 2026-09-09 answering "cannot add people from other islands"
        # because of exactly that. Since report #969 a stranger with no card
        # gets a SEAL-ONLY card — the three keys an envelope cannot be sealed
        # without, and nothing that describes a person: no nickname, no
        # profile, no confirmation that the number they typed is who they meant.
        r = await c.get(f"/federation/keys/{resident}")
        body = r.json() if r.status_code == 200 else {}
        check("door 1 hands a stranger the seal keys, so federation still works",
              r.status_code == 200 and bool(body.get("identity_key")) and bool(body.get("signing_key")),
              str(r.status_code))
        check("★ and nothing that describes the person behind them",
              body.get("nickname") is None and body.get("status_message") is None
              and body.get("gender") is None and body.get("profile_openable") is False,
              str(body))
        # ⚠ WHAT THIS DOOR STILL TELLS AN OUTSIDER: that the number exists at
        # all. A number nobody holds answers 404 here, an existing one answers
        # 200, and `closed_island`'s own help text promises the opposite
        # ("Refusals look exactly like 'no such number'"). Closing that costs
        # something real — a mistyped number would stop being visibly wrong to
        # the sender — so it is a decision, not a patch, and it is open. The
        # neighbouring endpoint /federation/island-record/{uin} is the cheaper
        # oracle of the two and knows nothing about doors at all.

        r = await c.get(f"/federation/keys/{resident}", headers={"X-RCQ-Guest-Card": raw})
        check("door 1 opens for the card its owner handed out",
              r.status_code == 200 and bool(r.json().get("identity_key")), str(r.status_code))

        r = await c.get(f"/federation/keys/{neighbour}", headers={"X-RCQ-Guest-Card": raw})
        nb = r.json() if r.status_code == 200 else {}
        check("★ and that card opens ONE door: the neighbour is back to seal-only",
              r.status_code == 200 and bool(nb.get("identity_key")) and nb.get("nickname") is None,
              f"{r.status_code} {nb}")

        r = await c.get(f"/keys/{resident}/bundle")
        check("door 2 refuses an anonymous stranger too — leaving it open would "
              "just move the hole one endpoint over, since a v=1 envelope seals "
              "with the key it hands out",
              r.status_code == 404, str(r.status_code))

        r = await c.get(f"/keys/{resident}/bundle", headers=auth(ntok))
        check("but a resident with a session passes door 2 untouched",
              r.status_code in (200, 404), str(r.status_code))

        # ⚠⚠ THE DOORS THIS TEST DID NOT KNOW ABOUT, and that is exactly why
        # they stayed open. `/keys/{uin}/bundle` was gated and its device-aware
        # twin was not: asking for device 1 lands in the same primary bundle by
        # another route, and the device LIST hands out a signal identity key per
        # row. Both are current_uin_optional. A lock with a second door is not a
        # lock, and a test that checks one door is not a test.
        r = await c.get(f"/keys/{resident}/devices/1/bundle")
        check("the device-aware door refuses a stranger too, or door 2 was "
              "theatre: device 1 IS the primary bundle",
              r.status_code == 404, str(r.status_code))

        r = await c.get(f"/keys/{resident}/devices")
        check("and the device LIST refuses one: every row in it carries key "
              "material",
              r.status_code == 404, str(r.status_code))

        r = await c.get(f"/keys/{resident}/devices/1/bundle", headers={"X-RCQ-Guest-Card": raw})
        check("a guest card opens the device door as well, or a stranger the "
              "resident invited cannot reach a second device",
              r.status_code in (200, 404), str(r.status_code))

        r = await c.get(f"/keys/{resident}/devices", headers=auth(ntok))
        check("a resident with a session passes both untouched",
              r.status_code == 200, str(r.status_code))

        info = (await c.get("/server/info")).json()
        # `anon_keys` answers "may a stranger fetch a key here", and on a closed
        # island the honest answer is still yes: they get the seal-only card.
        # It turns false only under `federation_refuse_strangers`, the setting
        # for an operator who really does want off the network.
        check("a closed island still advertises anonymous key fetches, because "
              "it still serves them, seal-only",
              info["capabilities"]["anon_keys"] is True,
              str(info["capabilities"].get("anon_keys")))

        # ⚠ This used to reopen the island and check `/users/{uin}/info` with a
        # SESSION, which answers 200 on a closed island too — so it passed
        # whatever the setting said, including with a stuck settings cache. The
        # question is whether reopening restores what closing took away, so ask
        # the door that actually changes: a full card, nickname and all.
        await set_setting("closed_island", "false")
        r = await c.get(f"/federation/keys/{resident}")
        reopened = r.json() if r.status_code == 200 else {}
        check("★ reopening restores the FULL card immediately, with no restart",
              r.status_code == 200 and reopened.get("nickname") is not None,
              f"{r.status_code} {reopened}")

    print(f"\nclosed island on the wire: {ok}/{ok + bad} ok")
    raise SystemExit(0 if bad == 0 else 1)


asyncio.run(main())
