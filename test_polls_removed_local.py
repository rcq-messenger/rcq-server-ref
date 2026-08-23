"""Local-only verification that polls are gone AND that a shipped client
degrades instead of breaking (2026-08-23, founder item 14a).

The removal is protocol-visible in two ways and both are easy to get wrong:

  1. Every build in the field still has the poll composer and none of them
     gate it on a capability, so all of them will keep calling these paths for
     weeks. They must get a clean, decodable 410 with `feature_removed`, never
     a routing 404 (indistinguishable from "no such poll id") and never a 500.
     A browser must see the CORS header on it too, or web reports the failure
     as a phantom CORS error instead of the real one.
  2. `GET /server/info` must ANSWER `polls: false` rather than drop the key.
     Clients default an ABSENT capability to True on purpose, so a missing key
     means "show the composer". That is the Nearby mistake, written down in
     routers/server.py.

Plus the point of the whole exercise: no model, and `init_db` on a fresh
island does not create `polls` / `poll_votes` at all.

And the half that is NOT visible on the wire but is the reason the feature had
to go: on an island that already HAS the two tables (prod and is2 keep them
until an operator runs the DROP by hand), `DELETE /auth/account` still has to
reach the rows that name the burning account. There is no model left to point
at, so `services/uin_rows.purge_uin_rows` deletes from them by name, and only
from the ones `core/db.init_db` actually found at boot.

In-process ASGI against a throwaway SQLite DB, no lifespan, no Redis.
Run: cd backend && PYTHONPATH=. .venv/bin/python test_polls_removed_local.py
"""
import asyncio
import os

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test_polls_removed.db"
os.environ["ENV"] = "dev"
os.environ.setdefault("JWT_SECRET", "t" * 64)

for f in ("test_polls_removed.db",):
    try:
        os.remove(f)
    except FileNotFoundError:
        pass

import httpx  # noqa: E402
from sqlalchemy import text  # noqa: E402

from app.core.db import (  # noqa: E402
    LEGACY_POLL_TABLES,
    Base,
    SessionLocal,
    engine,
    init_db,
)
from app.main import app  # noqa: E402
from app.services.uin_rows import purge_uin_rows  # noqa: E402

fails = 0


def check(name: str, ok: bool, detail: str = "") -> None:
    global fails
    print(f"  {'PASS' if ok else 'FAIL'}  {name}{'' if ok else '  <- ' + detail}")
    if not ok:
        fails += 1


# Exactly the paths PollService.swift calls, in the order the bubble hits them.
DEAD_PATHS = [
    ("POST", "/groups/77/polls"),
    ("POST", "/polls/7/vote"),
    ("POST", "/polls/7/close"),
    ("GET", "/polls/7"),
    ("GET", "/polls/by_message/2B0A9C1E-0000-4000-8000-000000000001"),
]


async def main() -> None:
    await init_db()

    print("\nschema")
    check("no `polls` table in the ORM metadata", "polls" not in Base.metadata.tables)
    check("no `poll_votes` table in the ORM metadata",
          "poll_votes" not in Base.metadata.tables)
    async with SessionLocal() as db:
        names = {r[0] for r in (await db.execute(
            text("SELECT name FROM sqlite_master WHERE type = 'table'")
        )).all()}
    check("a fresh island does not create either table",
          not ({"polls", "poll_votes"} & names), str(sorted(names & {"polls", "poll_votes"})))

    print("\nthe endpoints a shipped composer still calls")
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        for method, path in DEAD_PATHS:
            r = await c.request(method, path, json={"option_index": 0},
                                headers={"Origin": "https://chat.rcq.app"})
            check(f"{method} {path} is 410", r.status_code == 410, f"got {r.status_code}")
            body = r.json() if r.headers.get("content-type", "").startswith(
                "application/json") else {}
            check(f"{method} {path} says feature_removed",
                  (body.get("detail") or {}).get("code") == "feature_removed", str(body))
            check(f"{method} {path} carries the CORS header",
                  r.headers.get("access-control-allow-origin") == "*",
                  str(dict(r.headers)))

        # No token was sent above. The old routes were all authenticated, so
        # this pins that the tombstone answers "gone" before it answers
        # "unauthorised": a client with a stale token must not be sent off to
        # refresh it for a feature that no longer exists.
        r = await c.get("/polls/7")
        check("no session token still gets 410, not 401", r.status_code == 410,
              f"got {r.status_code}")

        # A path the old router never served. The catch-all has to cover it too,
        # or the next client typo becomes a 404 that reads like a live feature
        # with a bad id.
        r = await c.get("/polls/7/results")
        check("an unknown /polls/* subpath is 410 as well", r.status_code == 410,
              f"got {r.status_code}")

        print("\nthe capability")
        r = await c.get("/server/info")
        caps = r.json().get("capabilities", {})
        check("/server/info answers", r.status_code == 200, f"got {r.status_code}")
        check("`polls` is PRESENT in capabilities (absent means 'show it')",
              "polls" in caps, str(sorted(caps)))
        check("`polls` is false", caps.get("polls") is False, str(caps.get("polls")))

    print("\nthe burn still reaches an island that kept the tables")
    # A fresh island has neither table, so nothing is detected and nothing is
    # deleted. Pin that first: the raw-SQL tail must be a no-op here, or every
    # burn on a new island fails on a missing table.
    check("a fresh island detects no leftover poll tables", not LEGACY_POLL_TABLES,
          str(sorted(LEGACY_POLL_TABLES)))
    async with SessionLocal() as db:
        await purge_uin_rows(db, 4242)
        await db.commit()
    check("...so a burn there is untroubled by them", True)

    # Now the shape prod is in: the tables are physically present, with rows.
    async with engine.begin() as conn:
        await conn.execute(text(
            "CREATE TABLE polls (id INTEGER PRIMARY KEY, group_id INTEGER, "
            "creator_uin BIGINT, message_id TEXT)"
        ))
        await conn.execute(text(
            "CREATE TABLE poll_votes (id INTEGER PRIMARY KEY, poll_id INTEGER, "
            "voter_uin BIGINT, option_index INTEGER)"
        ))
    await init_db()
    check("a pre-cut island detects both tables",
          set(LEGACY_POLL_TABLES) == {"polls", "poll_votes"}, str(sorted(LEGACY_POLL_TABLES)))

    burned, bystander = 4242, 4343
    async with SessionLocal() as db:
        await db.execute(text(
            "INSERT INTO polls (id, group_id, creator_uin, message_id) "
            "VALUES (1, 9, :a, 'm1'), (2, 9, :b, 'm2')"), {"a": burned, "b": bystander})
        # The row the removal was argued over: a ballot in somebody ELSE'S poll,
        # in the clear, anonymous flag or not.
        await db.execute(text(
            "INSERT INTO poll_votes (id, poll_id, voter_uin, option_index) "
            "VALUES (1, 2, :a, 0), (2, 2, :b, 1)"), {"a": burned, "b": bystander})
        await db.commit()
        await purge_uin_rows(db, burned)
        await db.commit()
        votes = {r[0] for r in (await db.execute(text("SELECT voter_uin FROM poll_votes"))).all()}
        creators = {r[0] for r in (await db.execute(text("SELECT creator_uin FROM polls"))).all()}
    check("*** a burn clears the burned account's ballots", burned not in votes, str(votes))
    check("*** and the polls it created", burned not in creators, str(creators))
    check("...and touches nobody else's rows",
          votes == {bystander} and creators == {bystander}, f"{votes} {creators}")

    print(f"\n{'ALL PASS' if not fails else str(fails) + ' FAILED'}")
    raise SystemExit(1 if fails else 0)


asyncio.run(main())
