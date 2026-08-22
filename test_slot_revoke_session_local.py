"""Report #695: revoking a key SLOT must also end the auth SESSION that
claimed it. The slot table (Postgres) and the session registry (Redis) were
two disjoint registries with no bridge: deleting an old phone from the device
list stopped senders encrypting to it and nothing else — the phone stayed
signed in, reading and writing.

Run: PYTHONPATH=. .venv/bin/python test_slot_revoke_session_local.py
Needs a local Redis (same as the other _local suites).
"""
import asyncio
import os

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_slot_revoke.db")

from sqlalchemy import select  # noqa: E402

from app.core.db import SessionLocal, init_db  # noqa: E402
from app.core.redis import get_redis  # noqa: E402
from app.core.redis_keys import DEV_REVOKED_PREFIX, account_key  # noqa: E402
from app.core.security import device_is_revoked  # noqa: E402
from app.models.device import Device  # noqa: E402
from app.models.user import User  # noqa: E402
from app.routers.keys import revoke_device_slot  # noqa: E402

PASS: list[str] = []
FAIL: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    print(("  ok   " if ok else "  FAIL ") + name + (f"   <- {detail}" if detail and not ok else ""))
    (PASS if ok else FAIL).append(name)


async def main() -> None:
    await init_db()
    redis = await get_redis()
    uin = 460001
    old_install = "aaaa1111bbbb2222cccc3333dddd4444"
    await redis.delete(account_key(DEV_REVOKED_PREFIX, uin))

    async with SessionLocal() as db:
        db.add(User(uin=uin, nickname="probe-695", identity_key="ik", signing_key="sk-695"))
        # The old phone's slot, claimed by a session whose token names
        # `old_install` in its dev claim.
        db.add(Device(
            uin=uin, device_id=2, label="Old phone", auth_device_id=old_install,
            sealed_sender_pub="ss", signal_identity_key="sid", signal_registration_id=1,
            signed_prekey_id=1, signed_prekey_public="sp", signed_prekey_signature="ss",
            kyber_prekey_id=1, kyber_prekey_public="kp", kyber_prekey_signature="ks",
        ))
        # A slot from before the bridge existed: no auth link.
        db.add(Device(
            uin=uin, device_id=3, label="Ancient tablet", auth_device_id=None,
            sealed_sender_pub="ss", signal_identity_key="sid", signal_registration_id=1,
            signed_prekey_id=1, signed_prekey_public="sp", signed_prekey_signature="ss",
            kyber_prekey_id=1, kyber_prekey_public="kp", kyber_prekey_signature="ks",
        ))
        await db.commit()

    check("the session is not revoked beforehand",
          not await device_is_revoked(uin, old_install))

    # The new phone (its own install id) revokes the old phone's slot.
    async with SessionLocal() as db:
        await revoke_device_slot(2, uin=uin, caller_device="new-phone-install", db=db)

    check("★ revoking the slot denylists the session that claimed it",
          await device_is_revoked(uin, old_install))

    async with SessionLocal() as db:
        row = (await db.execute(
            select(Device).where(Device.uin == uin, Device.device_id == 2)
        )).scalar_one()
        check("the slot is tombstoned", row.revoked_at is not None)
        check("the auth link is blanked with the rest of the row",
              row.auth_device_id is None)

    # The unlinked slot keeps the old retire-only behaviour and does not blow up.
    async with SessionLocal() as db:
        await revoke_device_slot(3, uin=uin, caller_device="new-phone-install", db=db)
        row = (await db.execute(
            select(Device).where(Device.uin == uin, Device.device_id == 3)
        )).scalar_one()
        check("a pre-bridge slot still revokes cleanly", row.revoked_at is not None)

    await redis.delete(account_key(DEV_REVOKED_PREFIX, uin))
    print(f"\n{len(PASS)}/{len(PASS) + len(FAIL)} pass")
    if FAIL:
        raise SystemExit("FAILED: " + ", ".join(FAIL))


asyncio.run(main())
