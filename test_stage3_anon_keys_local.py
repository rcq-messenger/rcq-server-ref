"""Local-only verification of stage 3 of the metadata plan: key lookup stops
naming the pair.

GET /keys/{uin}/devices and the two bundle lookups take no session token any
more. A one-time prekey is handed out against an anonymous deposit token
(X-Deposit-Token, RFC 9474 blind signature, spent once) or, for a client that
does not mint yet, against the session token as before; a caller with neither
gets the bundle minus the OPK. Pins:
  * anonymous device list works and carries no label;
  * anonymous bundle: signed prekey yes, OPK no, pool untouched;
  * session token: OPK consumed (transition path);
  * deposit token: OPK consumed, the same token again is 403, a garbage token
    is 403 (not a silent downgrade);
  * the per-device bundle path behaves the same.

Runs the real FastAPI stack in-process on a throwaway SQLite DB and a local
Redis db 15 (deposit-auth issuer key + spent set live there). NOT deployed.
Run: PYTHONPATH=. /Users/tager/Documents/RCQ/backend/.venv/bin/python test_stage3_anon_keys_local.py
"""
import asyncio
import base64
import json
import os

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test_stage3.db"
os.environ["ENV"] = "dev"
os.environ["REDIS_URL"] = "redis://localhost:6379/15"
os.environ["DEPOSIT_AUTH_ENABLED"] = "true"
os.environ["DEPOSIT_AUTH_POW_BITS"] = "8"
for f in ("test_stage3.db",):
    try:
        os.remove(f)
    except FileNotFoundError:
        pass

import httpx  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers  # noqa: E402

from app.core import deposit_auth as da  # noqa: E402
from app.core.db import SessionLocal, init_db  # noqa: E402
from app.core.redis import close_redis, get_redis  # noqa: E402
from app.core.security import issue_token  # noqa: E402
from app.main import app  # noqa: E402
from app.models.prekey import OneTimePreKey  # noqa: E402
from app.models.user import User  # noqa: E402
from sqlalchemy import func, select  # noqa: E402

fails = 0


def check(name, cond):
    global fails
    print(f"  {'PASS' if cond else 'FAIL'}  {name}")
    if not cond:
        fails += 1


def b64(n=33):
    return base64.b64encode(os.urandom(n)).decode()


RECIPIENT = 3200
SENDER = 3201


async def free_opks(uin: int) -> int:
    async with SessionLocal() as db:
        return (await db.execute(
            select(func.count()).select_from(OneTimePreKey)
            .where(OneTimePreKey.uin == uin, OneTimePreKey.consumed == False)  # noqa: E712
        )).scalar_one()


async def mint_token(c: httpx.AsyncClient) -> str:
    p = (await c.get("/deposit-auth/params")).json()
    n = int.from_bytes(base64.urlsafe_b64decode(p["pubkey"]["n"] + "=="), "big")
    e = int(p["pubkey"]["e"])
    prepared = da.prepare(da.new_token_msg())
    blinded, inv = da.blind(n, e, prepared)
    blinded_b64 = base64.b64encode(blinded).decode()
    nonce = da.solve_pow(f"{p['epoch_id']}:{blinded_b64}", p["pow"]["difficulty"])
    r = await c.post("/deposit-auth/issue", json={"epoch_id": p["epoch_id"], "blinded": blinded_b64, "pow_nonce": nonce})
    assert r.status_code == 200, r.text
    pub = RSAPublicNumbers(e, n).public_key()
    sig = da.finalize(base64.b64decode(r.json()["blind_sig"]), inv, pub, prepared)
    tok = {"epoch_id": p["epoch_id"], "prepared": base64.b64encode(prepared).decode(), "sig": base64.b64encode(sig).decode()}
    return base64.urlsafe_b64encode(json.dumps(tok).encode()).decode().rstrip("=")


async def main():
    global fails
    await init_db()
    redis = await get_redis()
    async for k in redis.scan_iter(match="depauth:*"):
        await redis.delete(k)
    async with SessionLocal() as db:
        db.add(User(uin=RECIPIENT, nickname="r", identity_key=b64(32), signing_key=b64(32)))
        db.add(User(uin=SENDER, nickname="s", identity_key=b64(32), signing_key=b64(32)))
        await db.commit()
    owner = issue_token(RECIPIENT, 0, "phone")
    sender = issue_token(SENDER, 0, "phone")
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        r = await c.post("/keys/bundle", headers={"Authorization": f"Bearer {owner}"}, json={
            "signal_identity_key": b64(), "registration_id": 1234,
            "signed_prekey": {"id": 1, "public": b64(), "signature": b64(64)},
            "kyber_prekey": {"id": 1, "public": b64(1568), "signature": b64(64)},
            "one_time_prekeys": [{"id": i, "public": b64()} for i in range(1, 6)],
        })
        assert r.status_code == 204, r.text
        check("owner published 5 OPKs", await free_opks(RECIPIENT) == 5)

        print("\nAnonymous:")
        r = await c.get(f"/keys/{RECIPIENT}/devices")
        check("device list without a token is 200", r.status_code == 200)
        devs = r.json()["devices"]
        check("device list names device 1", [d["device_id"] for d in devs] == [1])
        check("device list carries no label", all(not d.get("label") for d in devs))
        r = await c.get(f"/keys/{RECIPIENT}/bundle")
        check("bundle without a token is 200", r.status_code == 200)
        check("  ... with the signed prekey", r.json()["signed_prekey"]["id"] == 1)
        check("  ... without a one-time prekey", r.json()["one_time_prekey"] is None)
        check("  ... and the pool is untouched", await free_opks(RECIPIENT) == 5)
        r = await c.get(f"/keys/{RECIPIENT}/devices/1/bundle")
        check("per-device bundle without a token: 200, no OPK", r.status_code == 200 and r.json()["one_time_prekey"] is None)

        print("\nSession token (transition path):")
        r = await c.get(f"/keys/{RECIPIENT}/bundle", headers={"Authorization": f"Bearer {sender}"})
        check("bundle under a session token carries an OPK", r.status_code == 200 and r.json()["one_time_prekey"] is not None)
        check("  ... and one was consumed", await free_opks(RECIPIENT) == 4)

        print("\nDeposit token:")
        tok = await mint_token(c)
        r = await c.get(f"/keys/{RECIPIENT}/devices/1/bundle", headers={"X-Deposit-Token": tok})
        check("bundle under a deposit token carries an OPK", r.status_code == 200 and r.json()["one_time_prekey"] is not None)
        check("  ... and one was consumed", await free_opks(RECIPIENT) == 3)
        r = await c.get(f"/keys/{RECIPIENT}/bundle", headers={"X-Deposit-Token": tok})
        check("the same token again is 403 (spent)", r.status_code == 403)
        check("  ... and nothing was consumed", await free_opks(RECIPIENT) == 3)
        r = await c.get(f"/keys/{RECIPIENT}/bundle", headers={"X-Deposit-Token": "bm90IGEgdG9rZW4"})
        check("a garbage token is 403, not a silent downgrade", r.status_code == 403)
        tok2 = await mint_token(c)
        r = await c.get(f"/keys/{RECIPIENT}/bundle", headers={"X-Deposit-Token": tok2})
        check("a fresh token works on the legacy bundle path too", r.status_code == 200 and r.json()["one_time_prekey"] is not None)
        check("  ... pool now 2", await free_opks(RECIPIENT) == 2)

        print("\nCapabilities:")
        info = (await c.get("/server/info")).json()["capabilities"]
        check("anon_keys advertised", info.get("anon_keys") is True)
        check("deposit_auth advertised (test env)", info.get("deposit_auth") is True)

    await close_redis()
    print(f"\n{'ALL PASS' if fails == 0 else f'{fails} FAILED'}")
    return fails


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
