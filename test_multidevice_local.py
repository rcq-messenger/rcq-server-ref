"""Local-only verification of the additive multi-device backend slice.
Runs the full FastAPI routing/validation/auth stack in-process via httpx
ASGITransport on a throwaway SQLite DB. NOT part of the prod test suite;
NOT deployed. Run: cd backend && PYTHONPATH=. .venv/bin/python test_multidevice_local.py
"""
import asyncio
import base64
import os

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test_multidevice.db"
os.environ["ENV"] = "dev"

# Fresh DB each run.
for f in ("test_multidevice.db",):
    try:
        os.remove(f)
    except FileNotFoundError:
        pass

import httpx  # noqa: E402
from sqlalchemy import func, select  # noqa: E402
from app.main import app  # noqa: E402
from app.core.db import init_db, SessionLocal  # noqa: E402
from app.core.security import issue_token  # noqa: E402
from app.models.user import User  # noqa: E402
from app.models.prekey import OneTimePreKey  # noqa: E402

fails = 0
def check(name, cond):
    global fails
    print(f"  {'PASS' if cond else 'FAIL'}  {name}")
    if not cond:
        fails += 1

def b64(n=33):
    return base64.b64encode(os.urandom(n)).decode()

def bundle(reg, opk_ids, label=None):
    body = {
        "signal_identity_key": b64(),
        "registration_id": reg,
        "signed_prekey": {"id": 1, "public": b64(), "signature": b64(64)},
        "kyber_prekey": {"id": 1, "public": b64(1568), "signature": b64(64)},
        "one_time_prekeys": [{"id": i, "public": b64()} for i in opk_ids],
        # outer sealed-sender pubkey — required for device registration,
        # ignored by /keys/bundle (BundleIn ignores extras).
        "sealed_sender_pub": b64(32),
    }
    if label is not None:
        body["label"] = label
    return body

async def main():
    await init_db()
    UIN = 1000
    identity_key = b64(32)
    async with SessionLocal() as db:
        db.add(User(uin=UIN, nickname="alice", identity_key=identity_key, signing_key=b64(32)))
        await db.commit()
    tok = issue_token(UIN)
    auth = {"Authorization": f"Bearer {tok}"}

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        # 1. Primary bundle upload (phone) — primary OPK ids 1..3
        r = await c.post("/keys/bundle", json=bundle(111, [1, 2, 3]), headers=auth)
        check("POST /keys/bundle (primary) -> 204", r.status_code == 204)

        # 2. Legacy fetch returns the primary, now tagged device_id=1
        r = await c.get(f"/keys/{UIN}/bundle", headers=auth)
        check("legacy GET /keys/{uin}/bundle -> 200", r.status_code == 200)
        check("legacy bundle device_id == 1 (additive field)", r.json().get("device_id") == 1)
        check("primary outer key == UIN identity_key", r.json().get("sealed_sender_pub") == identity_key)
        check("legacy bundle consumed a PRIMARY opk (id in 1..3)", r.json()["one_time_prekey"]["id"] in (1, 2, 3))

        # 3. Register a secondary device (web) — its own OPK ids 101,102
        r = await c.post("/keys/devices", json=bundle(222, [101, 102], label="Web (Chrome)"), headers=auth)
        check("POST /keys/devices -> 201", r.status_code == 201)
        dev_id = r.json().get("device_id")
        check("server assigned device_id == 2", dev_id == 2)

        # 4. Device list = primary(1) + secondary(2)
        r = await c.get(f"/keys/{UIN}/devices", headers=auth)
        ids = [d["device_id"] for d in r.json()["devices"]]
        check("GET /keys/{uin}/devices lists [1, 2]", ids == [1, 2])
        check("secondary device carries its label", any(d.get("label") == "Web (Chrome)" for d in r.json()["devices"]))

        # 5. Per-device bundle fetch (device 2) consumes a DEVICE-2 opk (101/102), never a primary one
        r = await c.get(f"/keys/{UIN}/devices/2/bundle", headers=auth)
        check("GET device-2 bundle -> 200", r.status_code == 200)
        check("device-2 bundle device_id == 2", r.json().get("device_id") == 2)
        check("device-2 bundle reg id matches (222)", r.json().get("registration_id") == 222)
        check("device-2 bundle consumed a DEVICE-2 opk (id in 101,102)", r.json()["one_time_prekey"]["id"] in (101, 102))

        # 6. Pool independence (direct DB check, avoids the SQLite-only naive-tz
        #    issue in /keys/me/status): after the primary fetch (step 2) and the
        #    device-2 fetch (step 5), each pool consumed exactly ONE of its OWN
        #    OPKs — the primary fetch never touched device-2's pool and vice versa.
        async with SessionLocal() as db:
            prim_consumed = (await db.execute(
                select(func.count()).select_from(OneTimePreKey).where(
                    OneTimePreKey.device_id.is_(None), OneTimePreKey.consumed == True)  # noqa: E712
            )).scalar_one()
            dev2_consumed = (await db.execute(
                select(func.count()).select_from(OneTimePreKey).where(
                    OneTimePreKey.device_id == 2, OneTimePreKey.consumed == True)  # noqa: E712
            )).scalar_one()
        check("pool independence: primary consumed exactly 1", prim_consumed == 1)
        check("pool independence: device-2 consumed exactly 1", dev2_consumed == 1)

        # 7. device_id=1 via the per-device route delegates to the primary path
        r = await c.get(f"/keys/{UIN}/devices/1/bundle", headers=auth)
        check("GET device-1 bundle delegates to primary (device_id==1)", r.status_code == 200 and r.json().get("device_id") == 1)

        # 8. A second secondary device gets device_id 3
        r = await c.post("/keys/devices", json=bundle(333, [201], label="Web (Firefox)"), headers=auth)
        check("second secondary device gets device_id == 3", r.json().get("device_id") == 3)

        # 9. Replenish a secondary device's pool, idempotent on collision
        r = await c.post("/keys/devices/2/prekeys", json={"one_time_prekeys": [{"id": 103, "public": b64()}, {"id": 101, "public": b64()}]}, headers=auth)
        check("POST /keys/devices/2/prekeys -> 204", r.status_code == 204)

        # 10. Unknown device bundle -> 404
        r = await c.get(f"/keys/{UIN}/devices/99/bundle", headers=auth)
        check("unknown device bundle -> 404", r.status_code == 404)

    print("\nALL BACKEND MULTI-DEVICE CHECKS PASSED ✅" if fails == 0 else f"\n{fails} CHECK(S) FAILED ❌")
    raise SystemExit(0 if fails == 0 else 1)

asyncio.run(main())
