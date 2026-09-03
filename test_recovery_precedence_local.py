"""Local-only verification that a move does not cost you your way back in.

⚠⚠ `/auth/recover` mints a session from a signing key alone, so when two
accounts carry the same key it must pick one, and it picks whoever claimed the
key FIRST. That order is what stops somebody who learned a public key (they are
public - `/users/{uin}/info` hands them out) from registering an account with it
and inheriting the owner's only way back into an account that has no email and
no phone.

The order was read off `created_at`, and `_perform_migration` deliberately does
not copy it: it is a fact about the NUMBER, and the number is new. So every move
put the person BEHIND any other row holding their key, and on the flagship seven
keys are already held by more than one account, one of them by twelve.

`identity_created_at` follows the person across a move and recovery orders by
it, falling back to `created_at` for rows written before the column existed.

Checks:
  * a fresh account recovers to itself;
  * an older row carrying the same key wins, which is the anti-hijack rule and
    must not change;
  * ⚠ after a migration the person still wins against a row created AFTER them,
    which is the bug: before this, moving handed that row the recovery;
  * a row that predates the column (NULL) still resolves by `created_at`.

Runs the real FastAPI stack in-process on a throwaway SQLite DB with Redis
db 15. NOT deployed.
Run: PYTHONPATH=. /Users/tager/Documents/RCQ/backend/.venv/bin/python test_recovery_precedence_local.py
"""
import asyncio
import base64
import os
from datetime import datetime, timedelta, timezone

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test_recovery_precedence.db"
os.environ["ENV"] = "dev"
os.environ["REDIS_URL"] = "redis://localhost:6379/15"
os.environ.setdefault("ADMIN_USERNAME", "admin")
os.environ.setdefault("ADMIN_PASSWORD", "adminpw")
for f in ("test_recovery_precedence.db",):
    try:
        os.remove(f)
    except FileNotFoundError:
        pass

from sqlalchemy import func, select  # noqa: E402

from app.core.db import SessionLocal, init_db  # noqa: E402
from app.core.redis import close_redis, get_redis  # noqa: E402
from app.models.user import User  # noqa: E402
from app.routers.migrate import _perform_migration  # noqa: E402

fails = 0


def check(name, cond):
    global fails
    print(f"  {'PASS' if cond else 'FAIL'}  {name}")
    if not cond:
        fails += 1


def b64(n=32):
    return base64.b64encode(os.urandom(n)).decode()


def aware(dt):
    """SQLite hands back naive datetimes; the column is tz-aware on Postgres.

    The test compares against `now`, so it has to speak one dialect.
    """
    if dt is None:
        return None
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


async def resolves_to(db, sk: str) -> int | None:
    """The account `/auth/recover` would land on, by the same order it uses."""
    first_claim = func.coalesce(User.identity_created_at, User.created_at)
    return (
        await db.execute(
            select(User.uin)
            .where(User.signing_key == sk)
            .order_by(first_claim.asc(), User.uin.asc())
            .limit(1)
        )
    ).scalar_one_or_none()


async def main() -> int:
    await init_db()
    await (await get_redis()).flushdb()
    now = datetime.now(timezone.utc)
    KEY = b64()

    async with SessionLocal() as db:
        # The owner, who claimed the key a month ago.
        db.add(User(uin=700300001, nickname="owner", identity_key=b64(), signing_key=KEY,
                    created_at=now - timedelta(days=30),
                    identity_created_at=now - timedelta(days=30)))
        # Somebody who registered with the same key a week ago, back when that
        # was possible without proving the private half.
        db.add(User(uin=700300002, nickname="later", identity_key=b64(), signing_key=KEY,
                    created_at=now - timedelta(days=7),
                    identity_created_at=now - timedelta(days=7)))
        # An older row from before the column existed: NULL, resolved by created_at.
        OLD_KEY = b64()
        db.add(User(uin=700300003, nickname="legacy", identity_key=b64(), signing_key=OLD_KEY,
                    created_at=now - timedelta(days=100), identity_created_at=None))
        db.add(User(uin=700300004, nickname="legacy2", identity_key=b64(), signing_key=OLD_KEY,
                    created_at=now - timedelta(days=50), identity_created_at=None))
        await db.commit()

        print("\nBefore anybody moves:")
        check("the owner, who claimed the key first, gets the recovery",
              await resolves_to(db, KEY) == 700300001)
        check("a legacy pair with no identity date still resolves by created_at",
              await resolves_to(db, OLD_KEY) == 700300003)

        print("\nThe owner moves to a new number:")
        owner = await db.get(User, 700300001)
        new_uin = await _perform_migration(db, owner, target_uin=700300777)
        await db.commit()
        check(f"the move landed on {new_uin}", new_uin == 700300777)
        moved = await db.get(User, 700300777)
        check("the new row's created_at is the NUMBER's, i.e. now",
              moved is not None and (now - aware(moved.created_at)) < timedelta(minutes=5))
        check("  ... and identity_created_at is the PERSON's, i.e. a month ago",
              moved.identity_created_at is not None
              and (now - aware(moved.identity_created_at)) > timedelta(days=29))
        check("⚠ the recovery still lands on the person who moved, not on the "
              "younger row holding their key",
              await resolves_to(db, KEY) == 700300777)

        print("\nA second move does not erode it either:")
        moved = await db.get(User, 700300777)
        again = await _perform_migration(db, moved, target_uin=700300778)
        await db.commit()
        check(f"moved again to {again}", again == 700300778)
        check("the person still wins their own key",
              await resolves_to(db, KEY) == 700300778)
        twice = await db.get(User, 700300778)
        check("  ... because the identity date rode across both moves",
              twice.identity_created_at is not None
              and (now - aware(twice.identity_created_at)) > timedelta(days=29))

    await close_redis()
    try:
        os.remove("test_recovery_precedence.db")
    except FileNotFoundError:
        pass
    print("\n" + ("ALL PASS" if fails == 0 else f"{fails} FAILED"))
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
