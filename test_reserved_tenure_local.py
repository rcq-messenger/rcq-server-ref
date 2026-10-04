"""Local-only verification that a SCARCE number is not handed to whoever signs
a record naming it (found while investigating report 1069).

`desired_uin` grants a reserved number (short or patterned) only to someone who
already holds it on another island. Until 2026-10-01 "holds it" meant "offers,
or has mirrored here, a home-island record that names it", and such a record
is signed by its own key: any squatter could sign `{homes: [{host: x, uin:
777}]}` and take #777. Now the record only points at an island, the island must
be on `TENURE_TRUSTED_ISLANDS`, and that island itself must serve both the
holder's record and a key card with the same signing key for the number.

The trusted islands are faked with an httpx MockTransport; everything on this
side is the real FastAPI stack. Pins:

  * ★ a self-signed record naming an untrusted island buys nothing, offered
    or planted through the open gossip PUT, and no request leaves for it;
  * ★ a record naming a trusted island buys nothing unless that island
    confirms; ★ a record its holder published for SOMEBODY ELSE's key is not
    enough either, the island's key card must carry the caller's key;
  * the real thing works: a pointer in `home_record`, or (old clients) in the
    gossip mirror, plus a confirming trusted island gives the number;
  * a slow island, a redirect, the island's own name, an empty list and a
    number already taken here all end in a fresh number and a 201, never an
    error, and a slow island costs at most the budget;
  * ★ the lookup takes the same path whether the number is free here or
    taken (by an account, or promised by a live invite): the trusted island is
    asked either way, so the response time says nothing about this island's
    numbers, and that holds behind a closed door too, where it runs before the
    door answers;
  * an invite or paid island with nothing in the invite field asks nobody
    (the door refuses anyway), and an invited newcomer still multihomes;
  * ★ while it waits on the other island the request's own session holds no
    database connection (the 11.09-28.09 pool-stall pattern);
  * ordinary (non-reserved) numbers are untouched and ask nobody.

In-process ASGI against a throwaway SQLite DB, Redis db 15 for the limiter.
NOT deployed.
Run: cd backend && PYTHONPATH=. .venv/bin/python test_reserved_tenure_local.py
"""
import asyncio
import base64
import json
import os
import re
import time

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test_reserved_tenure.db"
os.environ["ENV"] = "dev"
os.environ["RCQ_DB_NESTING_CHECK"] = "1"
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/15")
os.environ.setdefault("JWT_SECRET", "t" * 64)
os.environ.setdefault("REGISTER_CEILING_PER_MINUTE", "5000")
os.environ.setdefault("REGISTER_CEILING_PER_HOUR", "5000")

for f in ("test_reserved_tenure.db",):
    try:
        os.remove(f)
    except FileNotFoundError:
        pass

import secrets  # noqa: E402

import httpx  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from app.core import db_nesting  # noqa: E402
from app.core.config import settings  # noqa: E402
from app.core.db import SessionLocal, init_db  # noqa: E402
from app.core.redis import close_redis  # noqa: E402
from app.main import app  # noqa: E402
from app.models.invite import Invite, hash_invite_code  # noqa: E402
from app.routers.federation import _record_signed_bytes  # noqa: E402
from app.services import reserved_tenure, server_settings  # noqa: E402

fails = 0


def check(name: str, ok: bool, detail: str = "") -> None:
    global fails
    print(f"  {'PASS' if ok else 'FAIL'}  {name}{'' if ok else '  <- ' + detail}")
    if not ok:
        fails += 1


def b64(n=32):
    return base64.b64encode(os.urandom(n)).decode()


def keypair():
    sk = Ed25519PrivateKey.generate()
    pub = sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    return sk, base64.b64encode(pub).decode()


def record(sk, pub, homes):
    """A home-island record exactly as a client signs one."""
    doc = {"v": 1, "ik": b64(), "sk": pub,
           "homes": [{"host": h, "uin": u} for h, u in homes], "ts": int(time.time())}
    doc["sig"] = base64.b64encode(sk.sign(_record_signed_bytes(doc))).decode()
    return doc


# ── The other islands, faked ─────────────────────────────────────────────────
RECORDS: dict = {}   # (host, uin) -> served record
CARDS: dict = {}     # (host, uin) -> signing key on the card
SLOW = {"slow.example"}
BOUNCE = {"bounce.example"}
CALLS: list = []     # (host, path)
HELD: list = []      # did the request session hold a connection at that moment


async def _island(request: httpx.Request) -> httpx.Response:
    host = request.url.host if request.url.port in (None, 443) else f"{request.url.host}:{request.url.port}"
    CALLS.append((host, request.url.path))
    held = db_nesting._REQUEST.get()
    HELD.append(bool(held and held[0].info.get("rcq_holding_connection")))
    if host in SLOW:
        await asyncio.sleep(10)
    if host in BOUNCE:
        return httpx.Response(302, headers={"location": "https://elsewhere.example/federation/keys/1"})
    m = re.fullmatch(r"/federation/(island-record|keys)/(\d+)", request.url.path)
    if not m:
        return httpx.Response(404)
    kind, uin = m.group(1), int(m.group(2))
    if kind == "island-record":
        doc = RECORDS.get((host, uin))
        return httpx.Response(200, json=doc) if doc else httpx.Response(404, json={"detail": "no record"})
    key = CARDS.get((host, uin))
    if not key:
        return httpx.Response(404, json={"detail": "no such user"})
    return httpx.Response(200, json={"uin": uin, "identity_key": b64(), "signing_key": key})


class _HttpxWithFakeIslands:
    """`httpx` as `reserved_tenure` sees it: the same module, except that every
    client it builds talks to the fake islands above."""
    def __getattr__(self, name):
        return getattr(httpx, name)

    def AsyncClient(self, **kw):  # noqa: N802 — mirrors httpx
        kw["transport"] = httpx.MockTransport(_island)
        return httpx.AsyncClient(**kw)


reserved_tenure.httpx = _HttpxWithFakeIslands()

_who = [0]


def client():
    """A fresh caller address per registration: the per-IP limit is 20/hour
    and lives in Redis, which outlives the throwaway database."""
    _who[0] += 1
    pid = os.getpid()
    addr = (f"10.{pid & 0xFF}.{(pid >> 8) & 0xFF}.{_who[0] % 250 + 1}", 44444)
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app, client=addr), base_url="http://t")


async def register(sk, pub, desired, home_record=None, prove=True, invite=None):
    async with client() as c:
        body = {"nickname": "someone", "identity_key": b64(), "signing_key": pub,
                "desired_uin": desired}
        if invite is not None:
            body["invite"] = invite
        if prove:
            ch = (await c.post("/auth/register/challenge", json={"signing_key": pub})).json()["challenge"]
            body["challenge"] = ch
            body["signature"] = base64.b64encode(sk.sign(ch.encode())).decode()
        if home_record is not None:
            body["home_record"] = home_record
        r = await c.post("/auth/register", json=body)
    return r


async def gossip(doc):
    async with client() as c:
        return await c.put("/federation/gossip-record", json=doc)


def asked(host):
    return [p for h, p in CALLS if h == host]


def both(uin):
    return ["/federation/island-record/%d" % uin, "/federation/keys/%d" % uin]


async def set_settings(**values):
    async with SessionLocal() as db:
        await server_settings.apply(db, server_settings.validate(values))
        await db.commit()
    server_settings._cache.at = -1e9


async def make_invite(uin=None) -> str:
    raw = secrets.token_urlsafe(12)
    async with SessionLocal() as db:
        db.add(Invite(code=hash_invite_code(raw), max_uses=1, used_count=0, uin=uin))
        await db.commit()
    return raw


async def main() -> None:
    await init_db()
    settings.TENURE_TRUSTED_ISLANDS = "trusted.example,slow.example,bounce.example,t"
    T = "trusted.example"

    print("\nthe hole: a record signed by its own key names any number")
    m, mp = keypair()
    r = await register(m, mp, 777, record(m, mp, [("evil.example", 777)]))
    check("registration still succeeds", r.status_code == 201, r.text[:200])
    check("★ an offered self-signed record does NOT buy #777", r.json().get("uin") != 777)
    check("★ and nobody was asked about an island off the list", not asked("evil.example"))

    m2, m2p = keypair()
    r = await gossip(record(m2, m2p, [("evil.example", 778)]))
    check("the open gossip PUT still takes a signed record", r.status_code == 200, r.text[:200])
    r = await register(m2, m2p, 778)
    check("★ nor does one planted in the gossip mirror", r.status_code == 201 and r.json()["uin"] != 778)

    m3, m3p = keypair()
    CALLS.clear()
    r = await register(m3, m3p, 779, record(m3, m3p, [(T, 779)]))
    check("★ naming a TRUSTED island is not enough when it does not confirm",
          r.status_code == 201 and r.json()["uin"] != 779)
    check("  (it was asked, both the record and the card)",
          sorted(asked(T)) == ["/federation/island-record/779", "/federation/keys/779"], str(CALLS))

    holder, holder_p = keypair()
    m4, m4p = keypair()
    lent = record(m4, m4p, [(T, 780)])
    RECORDS[(T, 780)] = lent            # the holder of #780 there published M4's record
    CARDS[(T, 780)] = holder_p          # but #780 there is the holder's key
    r = await register(m4, m4p, 780, lent)
    check("★ a record the holder published for SOMEBODY ELSE's key is not enough",
          r.status_code == 201 and r.json()["uin"] != 780)

    print("\nthe real thing")
    p, pp = keypair()
    doc_p = record(p, pp, [(T, 781), ("t", 999_000_111)])
    RECORDS[(T, 781)], CARDS[(T, 781)] = doc_p, pp
    HELD.clear()
    r = await register(p, pp, 781, doc_p)
    check("★ a trusted island that confirms: the number is granted",
          r.status_code == 201 and r.json()["uin"] == 781, r.text[:200])
    check("★ and the request held no DB connection while it waited",
          bool(HELD) and not any(HELD), str(HELD))

    q, qp = keypair()
    doc_q = record(q, qp, [(T, 782)])
    RECORDS[(T, 782)], CARDS[(T, 782)] = doc_q, qp
    await gossip(doc_q)
    r = await register(q, qp, 782)
    check("★ an old client with no home_record: the mirrored record points the way",
          r.status_code == 201 and r.json()["uin"] == 782, r.text[:200])

    w, wp = keypair()
    RECORDS[(T, 783)] = record(w, wp, [("other.example", 783)])
    CARDS[(T, 783)] = wp
    r = await register(w, wp, 783, record(w, wp, [(T, 783)]))
    check("a served record that does not name this island for the number: no",
          r.status_code == 201 and r.json()["uin"] != 783)

    print("\nevery failure is a fresh number, never an error")
    s, sp = keypair()
    RECORDS[("slow.example", 784)], CARDS[("slow.example", 784)] = record(s, sp, [("slow.example", 784)]), sp
    t0 = time.monotonic()
    r = await register(s, sp, 784, record(s, sp, [("slow.example", 784)]))
    took = time.monotonic() - t0
    check("a trusted island that never answers: 201, fresh number",
          r.status_code == 201 and r.json()["uin"] != 784, r.text[:200])
    check("★ and it cost the budget, not the island's patience", took < 7, f"{took:.1f}s")

    b, bp = keypair()
    CALLS.clear()
    r = await register(b, bp, 785, record(b, bp, [("bounce.example", 785)]))
    check("a redirect is not followed and is a no", r.status_code == 201 and r.json()["uin"] != 785)
    check("  nothing went to where it pointed", not asked("elsewhere.example"), str(CALLS))

    o, op = keypair()
    CALLS.clear()
    r = await register(o, op, 786, record(o, op, [("t", 786)]))
    check("★ a record naming THIS island: never asked, never granted",
          r.status_code == 201 and r.json()["uin"] != 786 and not asked("t"), str(CALLS))

    print("\nthe lookup says nothing about this island's own numbers")
    # #781 belongs to P here. Skipping the trip for a taken number made the
    # answer come back a whole TLS round trip faster than for a free one.
    CALLS.clear()
    p2, pp2 = keypair()
    r = await register(p2, pp2, 781, record(p2, pp2, [(T, 781)]))
    check("a number already taken here: fresh number", r.status_code == 201 and r.json()["uin"] != 781)
    check("★ and the trusted island IS asked, exactly as for a free number",
          sorted(asked(T)) == both(781), str(CALLS))

    await make_invite(uin=789)          # promised to whoever redeems the code
    CALLS.clear()
    v, vp = keypair()
    r = await register(v, vp, 789, record(v, vp, [(T, 789)]))
    check("★ a number promised by a live invite: asked about all the same",
          r.status_code == 201 and r.json()["uin"] != 789 and sorted(asked(T)) == both(789), str(CALLS))

    print("\nbehind a closed door")
    await set_settings(registration_policy="invite")
    seen = {}
    for label, n in (("free", 790), ("taken", 781)):
        x, xp = keypair()
        CALLS.clear()
        r = await register(x, xp, n, record(x, xp, [(T, n)]))
        seen[label] = (r.status_code, r.json().get("detail"), list(CALLS))
    check("no invite: refused at the door, and nobody is asked, free or taken",
          seen["free"][:2] == seen["taken"][:2] == (403, {"code": "invite_required"})
          and not seen["free"][2] and not seen["taken"][2], str(seen))

    seen = {}
    for label, n in (("free", 790), ("taken", 781)):
        x, xp = keypair()
        CALLS.clear()
        r = await register(x, xp, n, record(x, xp, [(T, n)]), invite="not-a-code")
        seen[label] = (r.status_code, r.json().get("detail"), sorted(asked(T)))
    check("★ a made-up code gets past the skip, and then free and taken look alike",
          seen["free"][:2] == seen["taken"][:2] == (403, {"code": "invite_invalid"})
          and seen["free"][2] == both(790) and seen["taken"][2] == both(781), str(seen))

    await set_settings(registration_policy="paid")
    x, xp = keypair()
    CALLS.clear()
    r = await register(x, xp, 790, record(x, xp, [(T, 790)]))
    check("a paid island with no voucher: refused, nobody asked",
          r.status_code == 403 and r.json().get("detail") == {"code": "entry_required"} and not CALLS,
          r.text[:200] + str(CALLS))

    await set_settings(registration_policy="invite")
    i, ip = keypair()
    doc_i = record(i, ip, [(T, 791)])
    RECORDS[(T, 791)], CARDS[(T, 791)] = doc_i, ip
    r = await register(i, ip, 791, doc_i, invite=await make_invite())
    check("★ an invited newcomer whose trusted island confirms still gets the number",
          r.status_code == 201 and r.json()["uin"] == 791, r.text[:200])
    await set_settings(registration_policy="open")

    settings.TENURE_TRUSTED_ISLANDS = ""
    e, ep = keypair()
    doc_e = record(e, ep, [(T, 787)])
    RECORDS[(T, 787)], CARDS[(T, 787)] = doc_e, ep
    CALLS.clear()
    r = await register(e, ep, 787, doc_e)
    check("an empty trusted list means never", r.status_code == 201 and r.json()["uin"] != 787 and not CALLS)
    settings.TENURE_TRUSTED_ISLANDS = "trusted.example"

    u, up = keypair()
    CALLS.clear()
    r = await register(u, up, 788, record(u, up, [(T, 788)]), prove=False)
    check("an unproven request asks nobody and gets a fresh number",
          r.status_code == 201 and r.json()["uin"] != 788 and not CALLS)

    print("\nordinary numbers are as before")
    ORDINARY = 27_418_596
    k, kp = keypair()
    CALLS.clear()
    r = await register(k, kp, ORDINARY)
    check("an ordinary number on proof alone is granted",
          r.status_code == 201 and r.json()["uin"] == ORDINARY, r.text[:200])
    check("and nobody is asked about it", not CALLS, str(CALLS))

    await close_redis()
    print("\n" + ("ALL PASS" if fails == 0 else f"{fails} FAILED"))
    raise SystemExit(1 if fails else 0)


asyncio.run(main())
