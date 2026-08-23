"""Local-only verification that "disconnect this browser" actually disconnects it.

Report #607: «Отключил в приложении связь с браузером, а веб всё равно
работает. В том числе, после обновления страницы.»

The web keeps no session token on disk any more — it MINTS one at start-up by
proving the account's signing key (`POST /auth/refresh`). Revocation was
enforced only where a token is PRESENTED (`authorize_session`), never where one
is MADE, so the phone's revoke denylisted the token the browser was holding and
the browser was handed a brand-new one on its very next request.

What must hold:
  * a revoked device's existing token stops working (this always did);
  * ★ a revoked device cannot MINT itself a new one — not at /auth/refresh,
    not at /auth/recover, not at /auth/device;
  * the account's OTHER installs (the phone that pressed the button) are
    untouched;
  * ★ re-linking works: the phone can link the same browser again and the new
    session is not tarred by the old one's revocation.

Runs the real FastAPI stack in-process on a throwaway SQLite DB. Needs the
local Redis (the denylist lives there).
NOT part of the prod suite; NOT deployed.
Run: cd backend && PYTHONPATH=. .venv/bin/python test_device_revoke_local.py
"""
import asyncio
import base64
import os

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test_device_revoke.db"
os.environ["ENV"] = "dev"

for f in ("test_device_revoke.db",):
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
    from app.core.redis import get_redis
    redis = await get_redis()
    for pattern in ("rl:auth_register:*", "rl:auth_register_challenge:*", "rl:auth_refresh:*"):
        keys = [k async for k in redis.scan_iter(match=pattern)]
        if keys:
            await redis.delete(*keys)


async def register(c, pub, device_id=None):
    body = {"nickname": "someone", "identity_key": b64(), "signing_key": pub}
    if device_id:
        body["device_id"] = device_id
    r = await c.post("/auth/register", json=body)
    return r.json()["uin"], r.json()["token"]


async def refresh(c, uin, sk, pub, device_id=None):
    """What the web does at every start-up."""
    ch = (await c.post("/auth/recover/challenge", json={"signing_key": pub})).json()["challenge"]
    body = {"uin": uin, "signing_key": pub, "challenge": ch, "signature": sign(sk, ch)}
    if device_id:
        body["device_id"] = device_id
    return await c.post("/auth/refresh", json=body)


async def recover(c, sk, pub, device_id=None):
    ch = (await c.post("/auth/recover/challenge", json={"signing_key": pub})).json()["challenge"]
    body = {"signing_key": pub, "challenge": ch, "signature": sign(sk, ch)}
    if device_id:
        body["device_id"] = device_id
    return await c.post("/auth/recover", json=body)


def auth(token):
    return {"Authorization": f"Bearer {token}"}


async def main():
    await init_db()
    await clear_limiter()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        sk, pub = keypair()
        phone_install = "phone-install-1"
        uin, phone_token = await register(c, pub, device_id=phone_install)

        # --- The phone links a browser ---------------------------------------
        r = await c.post("/devices/link", json={"label": "Web"}, headers=auth(phone_token))
        check("the phone can link a browser", r.status_code == 200)
        dev_id = r.json()["device_id"]
        web_token = r.json()["token"]

        r = await c.get("/contacts", headers=auth(web_token))
        check("the linked session's token works", r.status_code == 200)

        # The browser then does what it does on every start: mints its own
        # token from the keys the link blob handed it.
        r = await refresh(c, uin, sk, pub, device_id=dev_id)
        check("the linked browser can mint a session while linked", r.status_code == 200)
        web_minted = r.json()["token"]
        r = await c.get("/contacts", headers=auth(web_minted))
        check("and the minted token works", r.status_code == 200)

        # --- The user presses "отключить связь с браузером" -------------------
        r = await c.delete(f"/devices/{dev_id}", headers=auth(phone_token))
        check("the phone can disconnect it", r.status_code == 200)

        r = await c.get("/contacts", headers=auth(web_token))
        check("the linked token is refused afterwards", r.status_code == 401)
        r = await c.get("/contacts", headers=auth(web_minted))
        check("the token it minted for itself is refused too", r.status_code == 401)

        # --- ★ The report: can it just mint another one? ----------------------
        r = await refresh(c, uin, sk, pub, device_id=dev_id)
        check("★ a disconnected browser CANNOT mint a new session", r.status_code == 401)
        check("  and is told why", "device_revoked" in r.text)

        r = await recover(c, sk, pub, device_id=dev_id)
        check("★ nor through /auth/recover", r.status_code == 401)

        r = await c.post(
            "/auth/device", json={"device_id": dev_id}, headers=auth(phone_token)
        )
        check("★ nor by claiming that id at /auth/device", r.status_code == 401)

        # --- The phone that pressed the button is untouched -------------------
        r = await c.get("/contacts", headers=auth(phone_token))
        check("the phone's own session still works", r.status_code == 200)
        r = await refresh(c, uin, sk, pub, device_id=phone_install)
        check("★ and the phone can still mint (a revoke is not an account lock)", r.status_code == 200)

        # --- ★ Re-linking -----------------------------------------------------
        # A revoke that could never be undone would be its own bug. /devices/link
        # mints a FRESH id every time, so the new session is not the revoked one.
        r = await c.post("/devices/link", json={"label": "Web"}, headers=auth(phone_token))
        check("★ the browser can be linked again", r.status_code == 200)
        dev2 = r.json()["device_id"]
        check("  under a new id, so the denylist does not follow it", dev2 != dev_id)
        r = await c.get("/contacts", headers=auth(r.json()["token"]))
        check("  and the new linked token works", r.status_code == 200)
        r = await refresh(c, uin, sk, pub, device_id=dev2)
        check("★ the re-linked browser can mint again", r.status_code == 200)

        # --- A linked session may not rename itself out of the registry -------
        relinked = r.json()["token"]
        r = await c.post(
            "/auth/device", json={"device_id": "somewhere-else"}, headers=auth(relinked)
        )
        check("a linked session cannot rename itself off the revocable id", r.status_code == 409)

        # --- A linked token on a RECYCLED number ------------------------------
        # `issue_device_token` was the one minting function that never carried
        # the uin epoch, so on a number that has changed hands (262 of them on
        # the flagship) the linked session's token was rejected as "stale" the
        # instant it was issued. Nobody noticed, because the browser answers a
        # 401 by minting its own — the behaviour this file is about.
        from app.core.db import SessionLocal
        from app.core.security import bump_uin_epoch, cache_uin_epoch
        sk2, pub2 = keypair()
        uin2, phone2 = await register(c, pub2, device_id="phone-install-2")
        async with SessionLocal() as db:
            new_epoch = await bump_uin_epoch(db, uin2)
            await db.commit()
        await cache_uin_epoch(uin2, new_epoch)
        # The phone re-mints under the new epoch, as it does after a takeover.
        phone2 = (await refresh(c, uin2, sk2, pub2, device_id="phone-install-2")).json()["token"]
        r = await c.post("/devices/link", json={"label": "Web"}, headers=auth(phone2))
        check("★ a browser linked to a recycled number gets a token", r.status_code == 200)
        r = await c.get("/contacts", headers=auth(r.json()["token"]))
        check("  and that token actually authenticates", r.status_code == 200)

        # --- ⚠ The residual, stated out loud ----------------------------------
        # The link blob hands the browser the account's PRIVATE KEYS, so it is
        # cryptographically the account. Someone who clears the browser's
        # storage and mints under a name nobody has revoked gets a session, and
        # no server-side check can tell that request apart from a new phone.
        # Locked in as a check so it stays visible rather than being assumed
        # closed: the cure is per-device keys, not another denylist.
        r = await refresh(c, uin, sk, pub, device_id="a-name-nobody-revoked")
        check("⚠ residual: the key holder can still mint under a fresh id", r.status_code == 200)

    print("\n" + ("ALL PASS" if fails == 0 else f"{fails} FAILED"))
    raise SystemExit(1 if fails else 0)


asyncio.run(main())
