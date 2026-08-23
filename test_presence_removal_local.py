"""Local-only verification of the 2026-08-23 removal of "visibility after
leaving" (`users.presence_persistent` + `users.presence_ttl_minutes`).

The feature is gone, but the CLIENTS that drive it are still in the field, so
what has to be pinned is a removal that does not break them:

1. Presence is now ONE rule for every account: `last_seen` freshness. A user
   whose heartbeat stopped reads offline no matter what their stored `status`
   says, and no column can opt them out of that any more.
2. A shipped iOS / Android build still PUTs `presence_persistent` (and, from
   the TTL picker, `presence_ttl_minutes`) from its Privacy screen. That
   request must still be a 200 and must still apply the REST of its body: the
   toggle travels in the same PUT as the nickname, the avatar and every other
   privacy tri-state, so a 400 would fail the whole profile save. The value
   itself goes nowhere.
3. The two keys are still ON the profile response, pinned to a constant off
   (`false` / `null`). Absent is NOT the same message: the shipped iOS Privacy
   screen only writes its cached toggle from `if let v = p.presencePersistent`,
   so a missing key leaves the switch reading ON forever on every phone that
   had the feature enabled. An explicit `false` is what turns it off.
4. On SQLite the physical column has to GO, not merely stop being mapped:
   `create_all` built `presence_persistent` as NOT NULL with no default, and
   SQLite cannot drop a NOT NULL constraint, so an unmapped-but-present column
   would kill the next /auth/register. (On Postgres the column deliberately
   stays for one release, see the note in core/db.py.)

Runs the real FastAPI stack in-process on a throwaway SQLite DB with Redis
db 15. NOT deployed.
Run: cd backend && PYTHONPATH=. .venv/bin/python test_presence_removal_local.py
"""
import asyncio
import base64
import os
from datetime import datetime, timedelta, timezone

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test_presence_removal.db"
os.environ["ENV"] = "dev"
os.environ["REDIS_URL"] = "redis://localhost:6379/15"
os.environ.setdefault("JWT_SECRET", "t" * 64)

for f in ("test_presence_removal.db",):
    try:
        os.remove(f)
    except FileNotFoundError:
        pass

import httpx  # noqa: E402
from sqlalchemy import text  # noqa: E402

from app.core.db import Base, SessionLocal, engine, init_db  # noqa: E402
from app.core.redis import close_redis  # noqa: E402
from app.core.security import issue_token  # noqa: E402
from app.main import app  # noqa: E402
from app.models.user import User, effective_status, visible_status  # noqa: E402

PASS, FAIL = [], []

A = 7301
DEAD = ("presence_persistent", "presence_ttl_minutes")


def check(name: str, ok: bool, detail: str = "") -> None:
    (PASS if ok else FAIL).append(name)
    print(f"  {'ok  ' if ok else 'FAIL'} {name}{'' if ok else '  <- ' + detail}")


def b64(n=32):
    return base64.b64encode(os.urandom(n)).decode()


def H(tok):
    return {"Authorization": f"Bearer {tok}"}


async def users_columns() -> set[str]:
    async with engine.begin() as conn:
        rows = (await conn.execute(text("PRAGMA table_info(users)"))).all()
    return {r[1] for r in rows}


async def main() -> None:
    print("Schema:")
    await init_db()
    # Put the pre-cut shape in front of the migration. A real pre-cut island
    # has `presence_persistent` NOT NULL with NO default (that is what
    # `create_all` wrote from the old model), and SQLite refuses to ADD a
    # NOT NULL column without one, so the constraint is what we cannot
    # reproduce by ALTER here. The column's PRESENCE is, and that is what the
    # drop loop keys off.
    async with engine.begin() as conn:
        await conn.execute(text(
            "ALTER TABLE users ADD COLUMN presence_persistent BOOLEAN NOT NULL DEFAULT 0"
        ))
        await conn.execute(text("ALTER TABLE users ADD COLUMN presence_ttl_minutes INTEGER"))
    check("the pre-cut island really has both columns", DEAD[0] in await users_columns())

    await init_db()
    left = sorted(set(DEAD) & await users_columns())
    check("init_db drops both columns off a SQLite island that has them",
          not left, f"still there: {left}")

    mapped = {c.name for c in Base.metadata.tables["users"].columns}
    check("neither column is an ORM column any more",
          not (set(DEAD) & mapped), f"still mapped: {sorted(set(DEAD) & mapped)}")

    # A fresh island never had them, and the drop loop must not log its way
    # through every boot: re-running is a no-op, not an error.
    await init_db()
    check("a second boot of the reduced schema is clean",
          not (set(DEAD) & await users_columns()))

    from app.core.redis import get_redis  # noqa: PLC0415
    await (await get_redis()).flushdb()
    async with SessionLocal() as db:
        db.add(User(uin=A, nickname="pres", identity_key=b64(), signing_key=b64(),
                    about="before"))
        await db.commit()
    tok = issue_token(A, 0, "phone")

    print("\nThe shipped client's body:")
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        # Exactly what an 0.146 Android / a shipped iOS build sends when the
        # user flips the toggle, TTL picker and all.
        r = await c.put("/users/me", headers=H(tok),
                        json={"presence_persistent": True, "presence_ttl_minutes": 1440})
        check(f"a legacy presence PUT is still a 200 ({r.status_code})", r.status_code == 200)
        # An old build that was poked, or one whose picker we no longer know
        # about. There is no allow-list left to violate, so this is a 200 too.
        r = await c.put("/users/me", headers=H(tok),
                        json={"presence_persistent": True, "presence_ttl_minutes": 999999})
        check(f"an out-of-range TTL is ignored rather than 400'd ({r.status_code})",
              r.status_code == 200)

        # The toggle rides in the same request as everything else on the
        # Privacy screen. Ignoring it must not cost the rest of the body.
        r = await c.put("/users/me", headers=H(tok), json={
            "presence_persistent": False,
            "about": "after",
            "last_seen_visibility": "nobody",
        })
        body = r.json()
        check("the rest of a mixed body still applies",
              r.status_code == 200
              and body.get("about") == "after"
              and body.get("last_seen_visibility") == "nobody",
              f"{r.status_code} {body}")

        print("\nWhat comes back:")
        # The body PUT `presence_persistent: false` above, but that is not why
        # it reads false: nothing stored it. Both keys are constants on the
        # response model now.
        check("the PUT response pins the toggle off",
              set(DEAD) <= set(body)
              and body["presence_persistent"] is False
              and body["presence_ttl_minutes"] is None,
              f"{ {k: body.get(k) for k in DEAD} }")
        r = await c.get(f"/users/{A}/info", headers=H(tok))
        info = r.json()
        check("the owner's own /info pins the toggle off",
              r.status_code == 200 and set(DEAD) <= set(info)
              and info["presence_persistent"] is False
              and info["presence_ttl_minutes"] is None,
              f"{r.status_code} { {k: info.get(k) for k in DEAD} }")
        # The one that actually matters for a phone in the field: a PUT that
        # turns it ON must still come back off, or the client caches ON again.
        r = await c.put("/users/me", headers=H(tok),
                        json={"presence_persistent": True, "presence_ttl_minutes": 480})
        back = r.json()
        check("a PUT that turns it ON still answers off",
              r.status_code == 200
              and back.get("presence_persistent") is False
              and back.get("presence_ttl_minutes") is None,
              f"{r.status_code} { {k: back.get(k) for k in DEAD} }")

        # The one thing a validation change could break by accident: a real
        # tri-state next to the dead one is still validated.
        r = await c.put("/users/me", headers=H(tok), json={"last_seen_visibility": "sometimes"})
        check(f"a bad tri-state is still a 400 ({r.status_code})", r.status_code == 400)

    print("\nPresence is last_seen freshness, for everyone:")
    now = datetime.now(timezone.utc)
    u = User(uin=A, nickname="pres", identity_key="k", signing_key="s")

    u.status, u.last_seen = "online", now - timedelta(seconds=5)
    check("a fresh heartbeat reads online", effective_status(u) == "online")
    u.last_seen = now - timedelta(seconds=59)
    check("still online at 59s, one heartbeat short of the window",
          effective_status(u) == "online")
    u.last_seen = now - timedelta(seconds=61)
    check("offline at 61s, whatever `status` says", effective_status(u) == "offline")
    # The case the removed setting existed to break: the app is gone, the
    # column that used to keep them "around" is gone with it.
    u.status, u.last_seen = "away", now - timedelta(hours=5)
    check("a five-hour-old heartbeat is offline, not away",
          effective_status(u) == "offline")
    u.status, u.last_seen = "away", now - timedelta(seconds=5)
    check("a chosen sub-state is still honoured while fresh",
          effective_status(u) == "away")
    u.status = "invisible"
    check("invisible still reads offline to other viewers",
          effective_status(u) == "invisible" and visible_status(u) == "offline")

    await close_redis()
    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    for f in FAIL:
        print(f"  FAILED: {f}")
    raise SystemExit(1 if FAIL else 0)


if __name__ == "__main__":
    asyncio.run(main())
