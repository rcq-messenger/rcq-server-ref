"""Local-only verification that an install can shed push rows it no longer
answers for (report 1066).

«Вышел из аккаунта, а уведомления для него приходят». A push row is (number,
the install's endpoint). Deleting an account on the phone threw away the only
credentials that could say DELETE /users/me/push-token, so the row stayed and
woke the phone for an account it no longer held, for good: a live endpoint
never answers 404/410.

Two server halves, pinned here:

  * `POST /users/me/push-token` with `accounts_here`: the install lists every
    account it still holds on this island, and rows of the SAME install (same
    token, same non-empty device id) for any other number go;
      - absent field = the old behaviour, nothing else is touched;
      - ★ only for an install that was already registered under the caller
        with that token and device id (a first registration never prunes),
        so a throwaway account cannot name a stranger's endpoint once and
        silence them;
      - ★ never a row registered within the grace window, so a list that was
        composed before an account was added cannot delete that account;
      - ★ a row of another install (other device id), a row without a device
        id and the same account's row on another endpoint are all left alone;
  * revoking an install (`DELETE /devices/{id}`, which a key-slot revoke also
    goes through) removes that install's push rows for the account, and only
    those.

In-process ASGI against a throwaway SQLite DB, Redis db 15 for the limiter.
NOT deployed.
Run: cd backend && PYTHONPATH=. .venv/bin/python test_push_rows_local.py
"""
import asyncio
import base64
import os
from datetime import datetime, timedelta, timezone

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test_push_rows.db"
os.environ["ENV"] = "dev"
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/15")
os.environ.setdefault("JWT_SECRET", "t" * 64)
os.environ.setdefault("REGISTER_CEILING_PER_MINUTE", "5000")
os.environ.setdefault("REGISTER_CEILING_PER_HOUR", "5000")

for f in ("test_push_rows.db",):
    try:
        os.remove(f)
    except FileNotFoundError:
        pass

import httpx  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from sqlalchemy import select, update  # noqa: E402

from app.core.db import SessionLocal, init_db  # noqa: E402
from app.core.redis import close_redis  # noqa: E402
from app.main import app  # noqa: E402
from app.models.device_token import DeviceToken  # noqa: E402

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


def sign(sk, msg: str) -> str:
    return base64.b64encode(sk.sign(msg.encode())).decode()


def _caller_addr():
    """Fresh per run: the per-IP and per-/24 registration limits live in Redis."""
    who = os.getpid()
    return (f"10.{(who >> 8) & 0xFF}.{who & 0xFF}.{(who >> 16) % 254 + 1}", 44444)


async def clear_limiter():
    from app.core.redis import get_redis
    try:
        redis = await get_redis()
        for pattern in ("rl:auth_register:*", "rl:auth_register_challenge:*", "rl:auth_recover*"):
            keys = [k async for k in redis.scan_iter(match=pattern)]
            if keys:
                await redis.delete(*keys)
    except Exception:  # noqa: BLE001 - Redis down is not what this test is about
        pass


async def register(c, device_id=None):
    sk, pub = keypair()
    body = {"nickname": "pushy", "identity_key": base64.b64encode(os.urandom(32)).decode(),
            "signing_key": pub}
    if device_id:
        body["device_id"] = device_id
    r = await c.post("/auth/register", json=body)
    assert r.status_code == 201, f"register: {r.status_code} {r.text[:200]}"
    return r.json()["uin"], {"Authorization": f"Bearer {r.json()['token']}"}, sk, pub


async def push(c, h, token, device_id, accounts_here=None, platform="android-up"):
    body = {"token": token, "platform": platform}
    if device_id is not None:
        body["device_id"] = device_id
    if accounts_here is not None:
        body["accounts_here"] = accounts_here
    return await c.post("/users/me/push-token", headers=h, json=body)


async def rows():
    """{(uin, token, device_id)} currently stored."""
    async with SessionLocal() as s:
        got = (await s.execute(select(DeviceToken.uin, DeviceToken.token, DeviceToken.device_id))).all()
    return {(u, t, d) for u, t, d in got}


async def age(uins, token, hours=2):
    """Pretend these rows were last registered `hours` ago."""
    async with SessionLocal() as s:
        await s.execute(
            update(DeviceToken)
            .where(DeviceToken.uin.in_(uins), DeviceToken.token == token)
            .values(last_seen=datetime.now(timezone.utc) - timedelta(hours=hours))
        )
        await s.commit()


async def main() -> None:
    await init_db()
    await clear_limiter()
    transport = httpx.ASGITransport(app=app, client=_caller_addr())
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        E = "https://ntfy.example/upTOPIC1066"      # the phone's one endpoint
        E2 = "https://ntfy.example/upOTHERPHONE"    # another phone's
        X, Y = "install-x", "install-y"

        a, ha, _, _ = await register(c, X)
        b, hb, _, _ = await register(c, X)
        cc, hc, _, _ = await register(c, X)
        d, hd, _, _ = await register(c, Y)          # another install claiming E
        n, hn, _, _ = await register(c)             # a pre-device-id client
        f, hf, _, _ = await register(c, X)

        for h in (ha, hb, hc):
            r = await push(c, h, E, X)
            assert r.status_code == 204, r.text
        await push(c, hd, E, Y)
        await push(c, hn, E, None)
        await push(c, hc, E2, "install-z")         # C also lives on another phone

        print("\nwithout the field nothing changes")
        r = await push(c, ha, E, X)
        check("re-registering without accounts_here is 204", r.status_code == 204, r.text[:200])
        have = await rows()
        check("the other accounts' rows on the same endpoint stay",
              {(b, E, X), (cc, E, X), (d, E, Y), (n, E, None)} <= have, str(have))

        await age([b, cc, d, n], E)

        print("\na first registration never prunes")
        r = await push(c, hf, E, X, accounts_here=[f, a])
        check("F's first registration with accounts_here is 204", r.status_code == 204, r.text[:200])
        have = await rows()
        check("★ nothing of anybody else went: F had no row on this install before",
              {(b, E, X), (cc, E, X)} <= have, str(have))

        print("\nthe install says it holds A and B now")
        r = await push(c, ha, E, X, accounts_here=[a, b])
        check("204", r.status_code == 204, r.text[:200])
        have = await rows()
        check("★ C's row on this install is gone", (cc, E, X) not in have, str(have))
        check("B, which is listed, stays", (b, E, X) in have)
        check("A, the caller, stays", (a, E, X) in have)
        check("★ F, registered a moment ago and not listed, is spared by the grace window",
              (f, E, X) in have)
        check("★ another install's row with the same token stays", (d, E, Y) in have)
        check("★ a row without a device id stays", (n, E, None) in have)
        check("★ C's row on its other phone stays", (cc, E2, "install-z") in have)

        print("\nonce the window has passed")
        await age([f], E)
        r = await push(c, ha, E, X, accounts_here=[a, b])
        have = await rows()
        check("★ F's abandoned row goes on the next registration", (f, E, X) not in have, str(have))
        check("and B still stays", (b, E, X) in have)

        print("\nguards on the field itself")
        r = await push(c, ha, E, X, accounts_here=list(range(1, 66)))
        check("65 numbers is refused as malformed (422)", r.status_code == 422, str(r.status_code))
        r = await push(c, ha, E, X, accounts_here=list(range(1, 65)))
        check("64 is fine", r.status_code == 204, str(r.status_code))
        check("and the caller is never pruned by its own list", (a, E, X) in await rows())
        r = await c.request("DELETE", "/users/me/push-token", headers=hb,
                            json={"token": E, "device_id": X, "accounts_here": []})
        have = await rows()
        check("DELETE ignores the field: only B's own row went",
              r.status_code == 204 and (b, E, X) not in have and (a, E, X) in have, str(have))

        print("\nrevoking an install takes its push rows")
        rs, rpub = keypair()
        r = await c.post("/auth/register", json={
            "nickname": "two-phones", "identity_key": base64.b64encode(os.urandom(32)).decode(),
            "signing_key": rpub, "device_id": "phone-1",
        })
        ruin = r.json()["uin"]
        h1 = {"Authorization": f"Bearer {r.json()['token']}"}
        ch = (await c.post("/auth/recover/challenge", json={"signing_key": rpub})).json()["challenge"]
        r = await c.post("/auth/recover", json={
            "signing_key": rpub, "challenge": ch, "signature": sign(rs, ch), "device_id": "phone-2",
        })
        check("the same account signs in on a second phone", r.status_code == 200, r.text[:200])
        h2 = {"Authorization": f"Bearer {r.json()['token']}"}
        P1, P2 = "https://ntfy.example/upPHONE1", "https://ntfy.example/upPHONE2"
        await push(c, h1, P1, "phone-1")
        await push(c, h2, P2, "phone-2")
        s_uin, hs, _, _ = await register(c, "phone-2")   # another account on phone 2
        await push(c, hs, P2, "phone-2")

        r = await c.delete("/devices/phone-2", headers=h1)
        check("phone 1 disconnects phone 2", r.status_code == 200, r.text[:200])
        have = await rows()
        check("★ phone 2's row for this account is gone", (ruin, P2, "phone-2") not in have, str(have))
        check("phone 1's own row stays", (ruin, P1, "phone-1") in have)
        check("★ the other account on phone 2 keeps its row", (s_uin, P2, "phone-2") in have)
        r = await c.get("/contacts", headers=h2)
        check("and phone 2's session is refused, as before", r.status_code == 401, str(r.status_code))

    await close_redis()
    print("\n" + ("ALL PASS" if fails == 0 else f"{fails} FAILED"))
    raise SystemExit(1 if fails else 0)


asyncio.run(main())
