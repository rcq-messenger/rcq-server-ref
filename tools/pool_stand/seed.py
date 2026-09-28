"""Seed the local pool stand (README.md): 3000 accounts, room 21 with 2271
members, settings that differ from every env default (as the flagship's do),
262 epoch rows and two guests. Idempotent: a seeded database is left alone.

Run by up.sh, with PYTHONPATH=<repo root> and DATABASE_URL pointing DIRECTLY
at Postgres (the DDL in init_db must not go through the transaction pool).
"""
import asyncio
import base64
import os
import secrets

from sqlalchemy import text

from app.core.db import SessionLocal, init_db
from app.models.group import Group, GroupMember
from app.models.server_setting import ServerSetting
from app.models.uin_epoch import UinEpoch
from app.models.user import User

N_USERS = 3000
ROOM_ID = 21
ROOM_MEMBERS = 2271
BASE_UIN = 500_000


def b64() -> str:
    return base64.b64encode(secrets.token_bytes(32)).decode()


async def main() -> None:
    await init_db()
    async with SessionLocal() as db:
        if (await db.execute(text("select count(*) from users"))).scalar() >= N_USERS:
            print("already seeded")
            return
        users = [
            User(uin=BASE_UIN + i, nickname=f"user{i}", identity_key=b64(), signing_key=b64())
            for i in range(N_USERS)
        ]
        # Two guest copies, like the flagship.
        users[-1].guest_status = "proven"
        users[-2].guest_status = "added"
        db.add_all(users)
        await db.flush()
        db.add(Group(id=ROOM_ID, name="big room", owner_uin=BASE_UIN))
        await db.flush()
        db.add_all(
            GroupMember(group_id=ROOM_ID, uin=BASE_UIN + i, role="owner" if i == 0 else "member")
            for i in range(ROOM_MEMBERS)
        )
        # Numbers that changed hands (262 on the flagship): high uins only, so
        # the callers the load uses carry epoch 0.
        db.add_all(UinEpoch(uin=BASE_UIN + N_USERS - 300 + i, epoch=1) for i in range(262))
        # The flagship's own answers, which differ from every env default.
        for k, v in {
            "registration_policy": "paid",
            "entry_price_cents": "1500",
            "island_name": "RCQ Flagship",
            "island_host": "api.rcq.app",
        }.items():
            db.add(ServerSetting(key=k, value=v))
        await db.commit()
        await db.execute(text(f"select setval(pg_get_serial_sequence('groups','id'), {ROOM_ID})"))
        await db.commit()
    print("seeded", N_USERS, "users, room", ROOM_ID, "with", ROOM_MEMBERS, "members")


asyncio.run(main())
