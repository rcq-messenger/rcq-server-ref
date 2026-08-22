"""Local-only verification of per-device fan-out addressing.

A Double Ratchet session belongs to one PAIR of devices, so a device-aware
sender encrypts a message once per recipient device and posts each copy with
`to_device_id` set. This pins the delivery half of that: every device must
drain its OWN copy and never another device's, while everything queued before
fan-out existed (`to_device_id IS NULL`) still reaches all of them.

Why it matters: a failed decrypt is deliberately never ACKed, so a copy handed
to the wrong device parks in front of its cursor and the queue stops moving —
which is exactly how "messages from my phone stop arriving on my desktop"
looked in the field (2026-08-19).

Runs the real FastAPI stack in-process via httpx ASGITransport on a throwaway
SQLite DB. NOT part of the prod suite; NOT deployed.
Run: cd backend && PYTHONPATH=. .venv/bin/python test_device_fanout_local.py
"""
import asyncio
import base64
import os

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test_device_fanout.db"
os.environ["ENV"] = "dev"

for f in ("test_device_fanout.db",):
    try:
        os.remove(f)
    except FileNotFoundError:
        pass

import httpx  # noqa: E402
from app.main import app  # noqa: E402
from app.core.db import init_db, SessionLocal  # noqa: E402
from app.core.security import issue_token  # noqa: E402
from app.models.user import User  # noqa: E402
from app.models.message import OfflineMessage  # noqa: E402
from sqlalchemy import select  # noqa: E402

fails = 0


def check(name, cond):
    global fails
    print(f"  {'PASS' if cond else 'FAIL'}  {name}")
    if not cond:
        fails += 1


def b64(n=33):
    return base64.b64encode(os.urandom(n)).decode()


UIN = 3100


async def main():
    global fails
    await init_db()
    async with SessionLocal() as db:
        db.add(User(uin=UIN, nickname="fanout", identity_key=b64(32), signing_key=b64(32)))
        await db.commit()

    phone = issue_token(UIN, 0, "phone-install")
    desktop = issue_token(UIN, 0, "desktop-install")
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        # A fan-out sender: same message, one copy per device.
        for dev in (1, 2):
            r = await c.post("/messages/sealed", json={
                "to_uin": UIN, "envelope_type": "message",
                "payload": b64(), "to_device_id": dev,
            })
            assert r.status_code == 200, r.text
        # A legacy sender that knows nothing about devices.
        r = await c.post("/messages/sealed", json={
            "to_uin": UIN, "envelope_type": "message", "payload": b64(),
        })
        assert r.status_code == 200, r.text

        print("\nDrain, primary device (dev=1):")
        r = await c.get("/messages/queue?ack=1&dev=1", headers={"Authorization": f"Bearer {phone}"})
        rows = r.json()
        got = sorted((row["to_device_id"] if row["to_device_id"] is not None else 0) for row in rows)
        check("primary gets its own copy + the unaddressed one", got == [0, 1])
        check("primary never sees the copy for device 2", all(row["to_device_id"] != 2 for row in rows))

        print("\nDrain, secondary device (dev=2):")
        r = await c.get("/messages/queue?ack=1&dev=2", headers={"Authorization": f"Bearer {desktop}"})
        rows2 = r.json()
        got2 = sorted((row["to_device_id"] if row["to_device_id"] is not None else 0) for row in rows2)
        check("secondary gets its own copy + the unaddressed one", got2 == [0, 2])
        check("secondary never sees the copy for device 1", all(row["to_device_id"] != 1 for row in rows2))

        print("\nBoth devices really got the SAME unaddressed row:")
        legacy_1 = [row["id"] for row in rows if row["to_device_id"] is None]
        legacy_2 = [row["id"] for row in rows2 if row["to_device_id"] is None]
        check("one shared legacy row, delivered to both", legacy_1 == legacy_2 and len(legacy_1) == 1)

        print("\nA device that does not pass `dev` is treated as the primary:")
        phone2 = issue_token(UIN, 0, "phone-install-2")
        r = await c.post("/messages/sealed", json={
            "to_uin": UIN, "envelope_type": "message", "payload": b64(), "to_device_id": 1,
        })
        assert r.status_code == 200
        r = await c.get("/messages/queue?ack=1", headers={"Authorization": f"Bearer {phone2}"})
        check("default dev=1 sees the device-1 copy", any(row["to_device_id"] == 1 for row in r.json()))

        print("\nAcking one device does not consume the other's copy:")
        r = await c.get("/messages/queue?ack=1&dev=2", headers={"Authorization": f"Bearer {desktop}"})
        check("device 2 still has nothing addressed to device 1", all(row["to_device_id"] != 1 for row in r.json()))

    # The legacy bundle path is withheld from a multi-homed account so an
    # old sender falls back to v=1 (which every device of the identity can
    # read). A fan-out sender must NOT be caught by that gate: it asks for
    # device 1 explicitly and encrypts a separate copy per device.
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        me = issue_token(9001, 0, "peer-install")
        async with SessionLocal() as db:
            db.add(User(uin=9001, nickname="peer", identity_key=b64(32), signing_key=b64(32)))
            await db.commit()
        auth = {"Authorization": f"Bearer {me}"}
        bundle = {
            "signal_identity_key": b64(33), "registration_id": 42,
            "signed_prekey": {"id": 1, "public": b64(33), "signature": b64(64)},
            "kyber_prekey": {"id": 1, "public": b64(1568), "signature": b64(64)},
            "one_time_prekeys": [{"id": i, "public": b64(33)} for i in range(1, 4)],
        }
        owner = {"Authorization": f"Bearer {issue_token(UIN, 0, 'phone-install')}"}
        r = await c.post("/keys/bundle", json=bundle, headers=owner)
        assert r.status_code == 204, r.text

        print("\nBefore any secondary device exists:")
        r = await c.get(f"/keys/{UIN}/bundle", headers=auth)
        check("legacy bundle path works for a single-device account", r.status_code == 200)

        r = await c.post("/keys/devices", json={**bundle, "label": "desktop",
                                                "sealed_sender_pub": b64(32)}, headers=owner)
        assert r.status_code == 201, r.text
        assigned = r.json()["device_id"]
        check("server assigns a secondary id >= 2", assigned >= 2)

        print("\nOnce a secondary device is registered:")
        r = await c.get(f"/keys/{UIN}/bundle", headers=auth)
        check("legacy path unaffected by a libsignal device (that gate is the QR registry)",
              r.status_code == 200)
        r = await c.get(f"/keys/{UIN}/devices/1/bundle", headers=auth)
        check("★ fan-out sender CAN still reach device 1", r.status_code == 200)

        # The real gate: a QR-linked web session withholds the v=2 bundle so an
        # old sender falls back to v=1. A fan-out sender must be able to walk
        # past it — that gate exists only because fan-out did not.
        from app.core.redis import get_redis
        # Through the helper, not a literal. The key name stopped spelling out
        # the account on 2026-08-22 (core/redis_keys) and a literal here would
        # write a key the gate no longer reads, i.e. the test would pass while
        # asserting nothing.
        from app.core.redis_keys import DEVICES_PREFIX, account_key
        redis = await get_redis()
        devices_key = account_key(DEVICES_PREFIX, UIN)
        await redis.hset(devices_key, "linked-web", "1")
        try:
            r = await c.get(f"/keys/{UIN}/bundle", headers=auth)
            check("legacy path withheld while a session is QR-linked", r.status_code == 404)
            r = await c.get(f"/keys/{UIN}/devices/1/bundle", headers=auth)
            check("★★ fan-out reaches device 1 even behind that gate", r.status_code == 200)
        finally:
            await redis.delete(devices_key)
        r = await c.get(f"/keys/{UIN}/devices/{assigned}/bundle", headers=auth)
        check("fan-out sender can reach the secondary", r.status_code == 200)
        r = await c.get(f"/keys/{UIN}/devices", headers=auth)
        ids = sorted(d["device_id"] for d in r.json()["devices"])
        check("device list names both", ids == [1, assigned])

    # ★ The ack prefix must be counted over the rows this device is SERVED.
    # A sibling's copy is withheld by the drain, so it can never be acked; if
    # the prefix walk still saw it, it would stop there and the cursor would
    # never move again — the queue grows forever and nothing reaps.
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        U2 = 3200
        async with SessionLocal() as db:
            db.add(User(uin=U2, nickname="prefix", identity_key=b64(32), signing_key=b64(32)))
            await db.commit()
        tok = {"Authorization": f"Bearer {issue_token(U2, 0, 'phone')}"}
        # Interleave: mine, sibling's, mine, sibling's...
        for dev in (1, 2, 1, 2, 1):
            r = await c.post("/messages/sealed", json={
                "to_uin": U2, "envelope_type": "message", "payload": b64(), "to_device_id": dev,
            })
            assert r.status_code == 200

        # Device 2 drains first so it owns a cursor: the reap floor is the
        # MINIMUM cursor across devices, and a device that has never drained is
        # seeded at the account watermark anyway (it was never going to see
        # these rows). The invariant worth pinning is the other one — a sibling
        # that IS keeping up must not have its copies reaped under it.
        tok2 = {"Authorization": f"Bearer {issue_token(U2, 0, 'desktop')}"}
        r = await c.get("/messages/queue?ack=1&dev=2", headers=tok2)
        theirs = [row["id"] for row in r.json()]
        check("drain hands device 2 only its own two", len(theirs) == 2)

        print("\nAck prefix with a sibling's copies interleaved:")
        r = await c.get("/messages/queue?ack=1&dev=1", headers=tok)
        mine = [row["id"] for row in r.json()]
        check("drain hands device 1 only its own three", len(mine) == 3)
        r = await c.post("/messages/queue/ack?dev=1", json={"direct_ids": mine, "group_ids": []}, headers=tok)
        check("ack accepted", r.status_code == 200)
        r = await c.get("/messages/queue?ack=1&dev=1", headers=tok)
        check("★ cursor moved past the sibling's copies (nothing redelivered)", r.json() == [])

        async with SessionLocal() as db:
            from sqlalchemy import func as sqlfunc
            left = (await db.execute(
                select(sqlfunc.count()).select_from(OfflineMessage).where(OfflineMessage.to_uin == U2)
            )).scalar_one()
        print(f"    (rows left for {U2}: {left})")
        check("nothing reaped while the sibling's cursor still lags", left == 5)
        r = await c.get("/messages/queue?ack=1&dev=2", headers=tok2)
        check("★★ device 2 is still served its own copies", [row["id"] for row in r.json()] == theirs)

    print("\nALL FAN-OUT CHECKS PASSED ✅" if fails == 0 else f"\n{fails} CHECK(S) FAILED ❌")
    raise SystemExit(1 if fails else 0)


asyncio.run(main())
