"""Local-only verification of POST /auth/refresh.

The web client stops keeping a 30-day session token on disk beside the keys
that can mint one, so it needs a way to ask for a token at start-up. That is
this endpoint: same proof as recovery, but the caller names the uin it wants.

What must hold:
  * the owner of the key gets a working token for THEIR uin;
  * naming somebody else's uin does not work, even with a valid signature;
  * an unproven or wrongly-signed request gets nothing;
  * a named install that has no queue cursor gets one at the account
    watermark, never at zero (or its next drain replays the whole queue).

Runs the real FastAPI stack in-process on a throwaway SQLite DB.
NOT part of the prod suite; NOT deployed.
Run: cd backend && PYTHONPATH=. .venv/bin/python test_token_refresh_local.py
"""
import asyncio
import base64
import os

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test_token_refresh.db"
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


for f in ("test_token_refresh.db",):
    try:
        os.remove(f)
    except FileNotFoundError:
        pass

import httpx  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from app.main import app  # noqa: E402
from app.core.db import init_db  # noqa: E402

fails = 0


def check(name, cond):
    global fails
    print(f"  {'PASS' if cond else 'FAIL'}  {name}")
    if not cond:
        fails += 1


def b64(n=32):
    return base64.b64encode(os.urandom(n)).decode()


def keypair():
    sk = Ed25519PrivateKey.generate()
    pub = sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    return sk, base64.b64encode(pub).decode()


def sign(sk, msg: str) -> str:
    return base64.b64encode(sk.sign(msg.encode())).decode()


async def clear_limiter():
    try:
        from app.core.redis import get_redis
        redis = await get_redis()
        for pattern in ("rl:auth_register:*", "rl:auth_register_challenge:*", "rl:auth_refresh:*"):
            keys = [k async for k in redis.scan_iter(match=pattern)]
            if keys:
                await redis.delete(*keys)
    except Exception as exc:  # noqa: BLE001 — no Redis is fine, the limiter opens up
        print(f"  (limiter not cleared: {exc})")


async def register(c, pub):
    r = await c.post(
        "/auth/register",
        json={"nickname": "someone", "identity_key": b64(), "signing_key": pub},
    )
    return r.json()["uin"], r.json()["token"]


async def refresh(c, uin, sk, pub, device_id=None, signer=None):
    r = await c.post("/auth/recover/challenge", json={"signing_key": pub})
    ch = r.json()["challenge"]
    body = {
        "uin": uin,
        "signing_key": pub,
        "challenge": ch,
        "signature": sign(signer or sk, ch),
    }
    if device_id:
        body["device_id"] = device_id
    return await c.post("/auth/refresh", json=body)


async def main():
    await init_db()
    await clear_limiter()
    transport = httpx.ASGITransport(app=app, client=_caller_addr())
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        alice_sk, alice_pub = keypair()
        alice_uin, _ = await register(c, alice_pub)
        bob_sk, bob_pub = keypair()
        bob_uin, _ = await register(c, bob_pub)

        # --- The ordinary case: a start-up with no stored token --------------
        r = await refresh(c, alice_uin, alice_sk, alice_pub, device_id="web-install-1")
        check("★ the key's owner gets a token for their own uin", r.status_code == 200)
        check("and it is that uin", r.json().get("uin") == alice_uin)
        token = r.json().get("token", "")
        me = await c.get("/contacts", headers={"Authorization": f"Bearer {token}"})
        check("★ the token actually authenticates", me.status_code == 200)
        anon = await c.get("/contacts")
        check("and the same call without it does not", anon.status_code in (401, 403))

        # --- Naming somebody else's uin --------------------------------------
        # The whole reason this endpoint exists rather than reusing /auth/recover.
        r = await refresh(c, bob_uin, alice_sk, alice_pub)
        check("★ a valid proof for the WRONG uin is refused", r.status_code == 404)

        # --- A signature by another key ---------------------------------------
        r = await refresh(c, alice_uin, alice_sk, alice_pub, signer=bob_sk)
        check("★ a signature by the wrong key is refused", r.status_code == 401)

        # --- No proof at all ---------------------------------------------------
        r = await c.post(
            "/auth/refresh",
            json={"uin": alice_uin, "signing_key": alice_pub, "challenge": "nope", "signature": "x"},
        )
        check("a junk challenge is refused", r.status_code == 400)

        # --- A REGISTER challenge must not be spendable here -------------------
        r = await c.post("/auth/register/challenge", json={"signing_key": alice_pub})
        reg_ch = r.json()["challenge"]
        r = await c.post(
            "/auth/refresh",
            json={
                "uin": alice_uin,
                "signing_key": alice_pub,
                "challenge": reg_ch,
                "signature": sign(alice_sk, reg_ch),
            },
        )
        check("a registration challenge is not spendable at /auth/refresh", r.status_code == 400)

        # --- The queue-cursor floor -------------------------------------------
        # An install refreshing under a device id the account has never seen
        # must not start at zero: that is the 2026-08-13 drain-floor bug, which
        # notified a fresh device for every message the account ever queued.
        from app.core.db import SessionLocal
        from app.models.queue_cursor import QueueCursor
        async with SessionLocal() as db:
            row = await db.get(QueueCursor, (alice_uin, "web-install-1"))
            check("★ refresh created a cursor for the named install", row is not None)
            floor_ok = row is not None and row.last_direct_id >= 0
            check("and it is a real floor, not a missing row", floor_ok)

    print("\n" + ("ALL PASS" if fails == 0 else f"{fails} FAILED"))
    raise SystemExit(1 if fails else 0)


asyncio.run(main())
