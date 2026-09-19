"""Local-only verification that uin-for-key and recover pick the same row (15.09.2026).

§5c cross-island groups rely on two endpoints agreeing. A group owner calls
`GET /federation/uin-for-key` to find the member's existing copy on this island
and ADDS that uin to the room; the member's own client later calls
`POST /auth/recover` on the same island and reads the room as whatever uin
comes back. When a key has two rows here, those have to be the same row, or the
member lands in an account that is not in the group.

They were not: recover ordered by first claim (coalesce(identity_created_at,
created_at), then uin) and uin-for-key ordered by uin alone. So the cases
below are built to make those two orders DISAGREE; a fixture where the oldest
row also has the lowest number would pass against the old code and prove
nothing.

1. two rows, the OLDER one has the HIGHER uin     -> both endpoints return it
2. a moved row: fresh created_at, old identity_created_at, higher uin
                                                  -> both return the moved row
3. legacy rows with NULL identity_created_at      -> both fall back to created_at
4. a key with no row                              -> both say not found

Recover is exercised for real: a challenge is issued and signed with a freshly
generated Ed25519 key, so the ordering is checked through the endpoint function
and not through a copy of its query.

Direct calls into the router functions against a throwaway SQLite DB, no HTTP.
Redis db 15 is only touched by `uin_epoch`, which degrades to the DB without it.
Run: PYTHONPATH=. PYTHONPATH=. .venv/bin/python test_uin_for_key_order_local.py
"""
import asyncio
import base64
import os
from datetime import datetime, timedelta, timezone

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test_uin_for_key_order.db"
os.environ["ENV"] = "dev"
os.environ["REDIS_URL"] = "redis://localhost:6379/15"
os.environ.setdefault("RCQ_JWT_SECRET", "test-secret-for-uin-for-key-order")

for leftover in ("./test_uin_for_key_order.db",):
    if os.path.exists(leftover):
        os.remove(leftover)

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat  # noqa: E402
from fastapi import HTTPException  # noqa: E402

from app.core.db import Base, SessionLocal, engine  # noqa: E402
from app.core.security import issue_recover_challenge  # noqa: E402
from app.models.user import User  # noqa: E402

# ⚠ The metadata is only complete once every model module has been imported,
# and the list is hand-maintained inside init_db (core/db.py). A missing import
# makes create_all fail on a foreign key to a table nobody registered.
import app.models.user, app.models.contact, app.models.message, app.models.group  # noqa: E402,F401
import app.models.device_token, app.models.prekey, app.models.device  # noqa: E402,F401
import app.models.audio_room, app.models.report, app.models.news, app.models.invite  # noqa: E402,F401
import app.models.queue_cursor, app.models.federation, app.models.capability  # noqa: E402,F401
import app.models.broker, app.models.access_token, app.models.server_setting  # noqa: E402,F401
import app.models.uin_epoch, app.models.owned_uin, app.models.relay_inquiry  # noqa: E402,F401
import app.models.mailbox_seq, app.models.group_log, app.models.vault  # noqa: E402,F401
import app.models.island_logo, app.models.site, app.models.uin_sale  # noqa: E402,F401
import app.models.uin_listing, app.models.guest_card  # noqa: E402,F401

from app.routers.auth import RecoverIn, recover  # noqa: E402
from app.routers.federation import uin_for_key  # noqa: E402

NOW = datetime.now(timezone.utc)

ok = True


def check(name: str, got, want) -> None:
    global ok
    if got == want:
        print(f"  ok   {name}")
    else:
        ok = False
        print(f"  FAIL {name}: got {got!r}, want {want!r}")


def new_key() -> tuple[Ed25519PrivateKey, str]:
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return priv, base64.b64encode(pub).decode()


def b64(n: int = 32) -> str:
    return base64.b64encode(os.urandom(n)).decode()


async def reset() -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)


async def seed(sk: str, rows) -> None:
    """rows: (uin, created_at, identity_created_at)"""
    async with SessionLocal() as db:
        for uin, created, identity_created in rows:
            db.add(User(
                uin=uin,
                nickname=f"u{uin}",
                identity_key=b64(),
                signing_key=sk,
                created_at=created,
                identity_created_at=identity_created,
            ))
        await db.commit()


async def via_uin_for_key(sk: str) -> int | None:
    async with SessionLocal() as db:
        try:
            # A padded key, as a client pasting it might send: both endpoints
            # strip, so the lookup has to survive it.
            return (await uin_for_key(signing_key=f" {sk}\n", db=db)).uin
        except HTTPException as e:
            if e.status_code == 404:
                return None
            raise


async def via_recover(priv: Ed25519PrivateKey, sk: str) -> int | None:
    challenge = issue_recover_challenge(sk)
    signature = base64.b64encode(priv.sign(challenge.encode())).decode()
    async with SessionLocal() as db:
        try:
            out = await recover(
                RecoverIn(signing_key=sk, challenge=challenge, signature=signature),
                db=db,
            )
            return out.uin
        except HTTPException as e:
            if e.status_code == 404:
                return None
            raise


async def main() -> None:
    print("uin-for-key agrees with /auth/recover")
    await reset()

    # ── 1: the older row carries the higher number ──────────────────────────
    # Old code: uin-for-key said 500100001, recover said 500100009.
    priv1, sk1 = new_key()
    await seed(sk1, [
        (500100001, NOW - timedelta(days=3), NOW - timedelta(days=3)),    # newer copy, low uin
        (500100009, NOW - timedelta(days=60), NOW - timedelta(days=60)),  # first claim, high uin
    ])
    r1, k1 = await via_recover(priv1, sk1), await via_uin_for_key(sk1)
    check("recover lands on the first claim, not the lowest number", r1, 500100009)
    check("uin-for-key returns the same row", k1, r1)

    # ── 2: a moved row, whose created_at is the NUMBER's (now) ──────────────
    # identity_created_at rode across the move, so the person still wins; an
    # order by created_at alone would pick 500200001, one by uin also 500200001.
    priv2, sk2 = new_key()
    await seed(sk2, [
        (500200001, NOW - timedelta(days=10), NOW - timedelta(days=10)),  # a later copy
        (500200777, NOW - timedelta(minutes=1), NOW - timedelta(days=90)),  # moved owner
    ])
    r2, k2 = await via_recover(priv2, sk2), await via_uin_for_key(sk2)
    check("recover lands on the person who moved", r2, 500200777)
    check("uin-for-key follows identity_created_at too", k2, r2)

    # ── 3: legacy rows from before identity_created_at existed ──────────────
    # ⚠ Passing None to the constructor does NOT store NULL: the column has a
    # Python-side default (models/user.py), and the ORM fills it in for a None
    # attribute, so both rows got now() and the tie-break by uin decided the
    # case. The first run of this file failed exactly that way. The NULL is
    # written with an UPDATE after the insert, and then checked, so the fixture
    # cannot quietly stop being the legacy shape it claims to be.
    priv3, sk3 = new_key()
    await seed(sk3, [
        (500300002, NOW - timedelta(days=50), None),
        (500300008, NOW - timedelta(days=100), None),  # older, higher uin
    ])
    from sqlalchemy import select, update
    async with SessionLocal() as db:
        await db.execute(
            update(User).where(User.signing_key == sk3).values(identity_created_at=None)
        )
        await db.commit()
        nulls = (await db.execute(
            select(User.identity_created_at).where(User.signing_key == sk3)
        )).scalars().all()
    check("fixture: both legacy rows really hold NULL", nulls, [None, None])
    r3, k3 = await via_recover(priv3, sk3), await via_uin_for_key(sk3)
    check("recover falls back to created_at on NULL", r3, 500300008)
    check("uin-for-key falls back the same way", k3, r3)

    # ── 4: nobody holds the key ─────────────────────────────────────────────
    priv4, sk4 = new_key()
    check("recover: no account for an unknown key", await via_recover(priv4, sk4), None)
    check("uin-for-key: no account for an unknown key", await via_uin_for_key(sk4), None)

    await engine.dispose()
    if os.path.exists("./test_uin_for_key_order.db"):
        os.remove("./test_uin_for_key_order.db")
    print("\nuin-for-key order:", "ALL PASS" if ok else "FAILURES ABOVE")
    raise SystemExit(0 if ok else 1)


asyncio.run(main())
