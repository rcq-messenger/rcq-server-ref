"""Local-only verification that a UnifiedPush endpoint fits in the column it
is stored in, and that one too long is refused instead of crashing.

The bug this pins, live on the flagship from 2026-09-01 20:28 to 2026-09-02:
`device_tokens.token` was `VARCHAR(255)`, a width chosen when the column held
an APNs hex token. UnifiedPush put a whole endpoint URL there instead, and
Conversations' distributor mints 344-character ones
(`up.conversations.im/push/v2.local.<paseto>`). Postgres refused the row with
StringDataRightTruncationError, FastAPI turned that into a 500, and the phone
re-registered on every launch: 342 failures in twenty-four hours, and push
that never worked for that person, with nothing on either side saying why.

Pins:
  * a 344-character endpoint, the exact shape that failed, registers and can
    be read back WHOLE (a silently truncated address is worse than a refusal:
    it would point at nobody and every wake would look delivered);
  * one at the 1024 limit still registers;
  * one over it is a 400 that names the limit, NOT a 500 — the client has to
    be able to tell "your distributor is broken" from "try again later", and
    a 500 is what it retries for ever;
  * an ordinary APNs hex token is unaffected;
  * re-registering the same long endpoint is idempotent (the upsert rides the
    (uin, token) unique constraint, which is the index the 1024 is sized for).

⚠ SQLite enforces no VARCHAR width, so this file cannot prove the Postgres
half. What it proves is that nothing in the app cuts the value and that the
guard answers 400. The width itself is in app/models/device_token.py and, for
islands that created the table at 255, in app/core/db.py's widened-columns
list.

In-process ASGI against a throwaway SQLite DB, Redis db 15 for the rate
limiter. NOT deployed.
Run: PYTHONPATH=. /Users/tager/Documents/RCQ/backend/.venv/bin/python test_push_token_length_local.py
"""
import asyncio
import base64
import os

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test_push_token_length.db"
os.environ["ENV"] = "dev"
os.environ["REDIS_URL"] = "redis://localhost:6379/15"
os.environ.setdefault("JWT_SECRET", "t" * 64)

for f in ("test_push_token_length.db",):
    try:
        os.remove(f)
    except FileNotFoundError:
        pass

import httpx  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from app.core.db import init_db  # noqa: E402
from app.core.redis import close_redis  # noqa: E402
from app.main import app  # noqa: E402
from app.routers.users import MAX_PUSH_TOKEN_LEN  # noqa: E402

fails = 0


def check(name: str, ok: bool, detail: str = "") -> None:
    global fails
    print(f"  {'PASS' if ok else 'FAIL'}  {name}{'' if ok else '  <- ' + detail}")
    if not ok:
        fails += 1


def keypair():
    sk = Ed25519PrivateKey.generate()
    pub = sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    return sk, base64.b64encode(pub).decode()


async def clear_limiter():
    from app.core.redis import get_redis
    try:
        redis = await get_redis()
        for pattern in ("rl:auth_register:*", "rl:auth_register_challenge:*"):
            keys = [k async for k in redis.scan_iter(match=pattern)]
            if keys:
                await redis.delete(*keys)
    except Exception:  # noqa: BLE001 - Redis down is not what this test is about
        pass


async def register(c):
    _, pub = keypair()
    r = await c.post("/auth/register", json={
        "nickname": "pushy", "identity_key": base64.b64encode(os.urandom(32)).decode(),
        "signing_key": pub,
    })
    assert r.status_code in (200, 201), f"register: {r.status_code} {r.text[:200]}"
    return r.json()["uin"], r.json()["token"]


# The exact endpoint the flagship refused, rebuilt to length rather than
# copied: a real person's address does not belong in a test file.
_CONV_PREFIX = "https://up.conversations.im/push/v2.local."
CONVERSATIONS = _CONV_PREFIX + "A" * (344 - len(_CONV_PREFIX))


async def main() -> None:
    await init_db()
    await clear_limiter()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        uin, token = await register(c)
        h = {"Authorization": f"Bearer {token}"}

        print("\nthe endpoint that broke production")
        check("it really is 344 characters", len(CONVERSATIONS) == 344, str(len(CONVERSATIONS)))
        r = await c.post("/users/me/push-token", headers=h,
                         json={"token": CONVERSATIONS, "platform": "android-up",
                               "device_id": "dev-1"})
        check("*** a 344-character UnifiedPush endpoint registers", r.status_code == 204,
              f"got {r.status_code} {r.text[:200]}")

        health = await c.get("/users/me/push-health", headers=h)
        stored = health.json() if health.status_code == 200 else {}
        check("/users/me/push-health answers", health.status_code == 200,
              f"got {health.status_code} {health.text[:150]}")

        print("\nstored whole, not cut")
        from sqlalchemy import select
        from app.core.db import SessionLocal
        from app.models.device_token import DeviceToken
        async with SessionLocal() as s:
            rows = (await s.execute(select(DeviceToken).where(DeviceToken.uin == uin))).scalars().all()
        check("one row for this account", len(rows) == 1, str(len(rows)))
        check("*** the endpoint came back byte for byte",
              bool(rows) and rows[0].token == CONVERSATIONS,
              f"stored {len(rows[0].token) if rows else 0} chars")

        print("\nidempotent, as every launch needs it to be")
        r = await c.post("/users/me/push-token", headers=h,
                         json={"token": CONVERSATIONS, "platform": "android-up",
                               "device_id": "dev-1"})
        check("re-registering the same endpoint is 204", r.status_code == 204,
              f"got {r.status_code} {r.text[:200]}")
        async with SessionLocal() as s:
            rows = (await s.execute(select(DeviceToken).where(DeviceToken.uin == uin))).scalars().all()
        check("...and did not add a second row", len(rows) == 1, str(len(rows)))

        print("\nthe limit")
        at_limit = "https://up.example.org/" + "B" * (MAX_PUSH_TOKEN_LEN - 23)
        check("the at-limit value is exactly the limit", len(at_limit) == MAX_PUSH_TOKEN_LEN,
              str(len(at_limit)))
        r = await c.post("/users/me/push-token", headers=h,
                         json={"token": at_limit, "platform": "android-up", "device_id": "dev-2"})
        check("an endpoint AT the limit registers", r.status_code == 204,
              f"got {r.status_code} {r.text[:200]}")

        over = "https://up.example.org/" + "C" * (MAX_PUSH_TOKEN_LEN + 1 - 23)
        r = await c.post("/users/me/push-token", headers=h,
                         json={"token": over, "platform": "android-up", "device_id": "dev-3"})
        check("*** one character over is 400, not 500", r.status_code == 400,
              f"got {r.status_code} {r.text[:200]}")
        detail = r.json().get("detail") if r.status_code == 400 else {}
        code = detail.get("code") if isinstance(detail, dict) else None
        check("...and it names itself so a client can tell it from a blip",
              code == "token_too_long", str(detail)[:120])

        print("\nan ordinary APNs token is untouched")
        apns = "a1b2c3d4" * 8
        r = await c.post("/users/me/push-token", headers=h,
                         json={"token": apns, "platform": "ios", "device_id": "dev-4"})
        check("64-character hex token registers", r.status_code == 204,
              f"got {r.status_code} {r.text[:200]}")

        print("\nempty is still refused")
        r = await c.post("/users/me/push-token", headers=h,
                         json={"token": "   ", "platform": "ios"})
        check("a blank token is 400", r.status_code == 400, f"got {r.status_code}")

    await close_redis()
    print("\n" + ("ALL PASS" if fails == 0 else f"{fails} FAILED"))
    raise SystemExit(1 if fails else 0)


asyncio.run(main())
