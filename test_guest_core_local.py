"""Local-only verification of the guest-copy foundations (spec 2026-09-15,
sections 2, 2.4, 3 and the `fail_closed` half of 13).

Nothing here mints a guest through an endpoint: those routes are later steps.
This pins what they stand on, and each item is something a later step would
otherwise have to discover the hard way:

  * the columns exist on a fresh island (create_all) and come back on an old
    one through the additive migration, with existing rows native and existing
    rooms open to guests (no backfill);
  * the six settings, their defaults, and that a bad `guest_admission` is
    refused;
  * `admission_open` across the whole matrix (open, invite, paid, closed,
    refuse strangers, auto/on/off) and `/server/info guest_accounts_v1`
    agreeing with it in every case;
  * `get_strict` refuses on a cold worker where `get` would quietly serve the
    code default, keeps serving the last-known rows through a later DB blip,
    and `admission_open` fails closed in that window;
  * `enforce_rate_limit(fail_closed=True)` keeps a cap with Redis gone, and the
    default still fails soft;
  * the guest cache: rebuild from the table, mark and unmark, a rebuild racing
    a mark that has not committed yet, Redis down (the row is read, never
    "native"), Redis AND the database down (raises), `mark_guest` raising;
  * `shares_room`;
  * roster `guest` / `invited`, `GroupOut.allow_guests` (owner-only PATCH, a
    NULL column served as True), `PublicUser.guest` for self and co-members
    only, `RegisterOut.guest`;
  * `_perform_migration` carries both guest columns.

Runs the real FastAPI stack in-process on a throwaway SQLite DB with Redis
db 15. NOT deployed.
Run: PYTHONPATH=. /Users/tager/Documents/RCQ/backend/.venv/bin/python test_guest_core_local.py
"""
import asyncio
import base64
import os
import random
import secrets
from datetime import datetime, timezone

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test_guest_core.db"
os.environ["ENV"] = "dev"
os.environ["REDIS_URL"] = "redis://localhost:6379/15"
os.environ.pop("RCQ_GUEST_ADMISSION", None)
for f in ("test_guest_core.db",):
    try:
        os.remove(f)
    except FileNotFoundError:
        pass

import httpx  # noqa: E402
from fastapi import HTTPException  # noqa: E402
from sqlalchemy import select, text  # noqa: E402

import app.core.db as db_mod  # noqa: E402
import app.core.redis as redis_mod  # noqa: E402
from app.core import guest_policy as gp  # noqa: E402
from app.core import rate_limit as rl  # noqa: E402
from app.core.db import SessionLocal, engine, init_db  # noqa: E402
from app.core.redis import close_redis, get_redis  # noqa: E402
from app.core.security import issue_token, uin_epoch  # noqa: E402
from app.main import app  # noqa: E402
from app.models.group import Group, GroupMember  # noqa: E402
from app.models.user import User  # noqa: E402
from app.routers.migrate import _perform_migration  # noqa: E402
from app.services import server_settings  # noqa: E402
from app.services.connection_manager import manager  # noqa: E402

fails = 0


def check(name, cond):
    global fails
    print(f"  {'PASS' if cond else 'FAIL'}  {name}")
    if not cond:
        fails += 1


def b64(n=32):
    return base64.b64encode(os.urandom(n)).decode()


def H(tok):
    return {"Authorization": f"Bearer {tok}"}


async def clear(*patterns):
    redis = await get_redis()
    for pattern in patterns:
        keys = [k async for k in redis.scan_iter(match=pattern)]
        if keys:
            await redis.delete(*keys)


async def set_settings(**values):
    async with SessionLocal() as db:
        await server_settings.apply(db, server_settings.validate(values))
        await db.commit()
    server_settings._cache.at = -1e9


async def unused_uin() -> int:
    async with SessionLocal() as db:
        while True:
            u = random.randint(800_000_000, 899_999_999)
            if await db.get(User, u) is None:
                return u


async def make_row(status: str | None, nick: str) -> int:
    uin = await unused_uin()
    async with SessionLocal() as db:
        db.add(User(
            uin=uin, nickname=nick, identity_key=b64(), signing_key=b64(),
            guest_status=status,
            guest_since=datetime.now(timezone.utc) if status else None,
            entered_via="guest" if status else None,
        ))
        await db.commit()
    return uin


async def columns(table: str) -> set[str]:
    async with engine.connect() as conn:
        rows = (await conn.execute(text(f"PRAGMA table_info({table})"))).all()
    return {r[1] for r in rows}


async def main() -> int:
    await init_db()
    await clear("guest_uins*", "rl:auth_register*", "rl:ceiling:*", "rl:groups_create*",
                "rl:users_info*", "rl:gcore_*")
    transport = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t")
    async with transport as c:

        async def register(nick):
            r = await c.post("/auth/register", json={"nickname": nick, "identity_key": b64(), "signing_key": b64()})
            assert r.status_code == 201, r.text
            return r.json()

        async def cap():
            r = await c.get("/server/info")
            return r.json()["capabilities"].get("guest_accounts_v1")

        # ── 1. schema on a fresh island ───────────────────────────────────
        print("Schema (create_all):")
        ucols, gcols = await columns("users"), await columns("groups")
        check("users.guest_status and users.guest_since exist", {"guest_status", "guest_since"} <= ucols)
        check("groups.allow_guests exists", "allow_guests" in gcols)

        # ── 2. settings ───────────────────────────────────────────────────
        print("\nSettings:")
        check("guest_admission defaults to auto", await server_settings.get("guest_admission") == "auto")
        check("room joins/day 200, ceiling 3500, max groups 50, seat TTL 7, idle 60",
              [await server_settings.get(k) for k in (
                  "guest_room_joins_per_day", "guest_room_member_ceiling", "guest_max_groups",
                  "guest_added_ttl_days", "guest_idle_days")] == [200, 3500, 50, 7, 60])
        try:
            server_settings.validate({"guest_admission": "maybe"})
            refused = False
        except ValueError:
            refused = True
        check("guest_admission refuses a word outside auto/on/off", refused)
        try:
            server_settings.validate({"guest_room_member_ceiling": 5000})
            refused = False
        except ValueError:
            refused = True
        check("the member ceiling cannot be set past the 4096 payload cap", refused)
        os.environ["RCQ_GUEST_ADMISSION"] = "ON "
        check("RCQ_GUEST_ADMISSION is read (trimmed, any case)", server_settings.REGISTRY["guest_admission"].default() == "on")
        os.environ["RCQ_GUEST_ADMISSION"] = "yes please"
        check("  ... and a typo there reads as auto, never as on", server_settings.REGISTRY["guest_admission"].default() == "auto")
        os.environ.pop("RCQ_GUEST_ADMISSION", None)

        # Accounts are made while the island is still open.
        a = await register("owner")
        b = await register("member")
        cc = await register("stranger")
        check("RegisterOut carries guest:false for a native registration", a.get("guest") is False)
        A, B, C = a["uin"], b["uin"], cc["uin"]

        # ── 3. admission matrix ───────────────────────────────────────────
        print("\nAdmission (admission_open == /server/info guest_accounts_v1):")
        matrix = [
            # policy, closed, refuse, mode, expected, label
            ("open", False, False, "auto", False, "open island, auto"),
            ("open", False, False, "on", False, "open island, on (guest mode means nothing there)"),
            ("paid", False, False, "auto", True, "paid island, auto"),
            ("paid", False, True, "auto", True, "paid island, refuse-strangers WITHOUT closed changes nothing"),
            ("paid", False, False, "off", False, "paid island, off (the brake)"),
            ("paid", True, False, "auto", False, "paid closed island, auto"),
            ("paid", True, False, "on", True, "paid closed island, on"),
            ("invite", False, False, "auto", False, "invite island, auto (founder: only with on)"),
            ("invite", False, False, "on", True, "invite island, on"),
            ("invite", True, False, "on", True, "invite closed island, on"),
            ("paid", True, True, "on", False, "closed + refuse strangers beats on"),
        ]
        for policy, closed, refuse, mode, expected, label in matrix:
            await set_settings(registration_policy=policy, closed_island=closed,
                               federation_refuse_strangers=refuse, guest_admission=mode)
            got = await gp.admission_open()
            served = await cap()
            check(f"{label} -> {expected}", got is expected and served is expected)

        # ── 4. cold settings cache ────────────────────────────────────────
        print("\nget_strict and a cold worker:")
        await set_settings(registration_policy="paid", closed_island=True,
                           federation_refuse_strangers=False, guest_admission="auto")
        check("warm: a paid CLOSED island on auto admits nobody", await gp.admission_open() is False)
        cache = server_settings._cache
        saved_session = server_settings.SessionLocal
        saved_env = server_settings._env.REGISTRATION_POLICY

        def db_down():
            raise RuntimeError("database unreachable")

        cache.rows, cache.at, cache.loaded = {}, -1e9, False
        server_settings.SessionLocal = db_down
        env_patched = True
        try:
            server_settings._env.REGISTRATION_POLICY = "paid"
        except Exception:  # noqa: BLE001
            env_patched = False
        try:
            if env_patched:
                check("cold + DB down: plain get serves the env default 'paid' and closed=False "
                      "(defaults alone would say guests are welcome)",
                      await server_settings.get("registration_policy") == "paid"
                      and await server_settings.get("closed_island") is False)
            try:
                await server_settings.get_strict("registration_policy")
                raised = False
            except server_settings.SettingsUnavailable:
                raised = True
            check("★ get_strict raises SettingsUnavailable instead", raised)
            check("★ admission_open fails closed in that window", await gp.admission_open() is False)
            check("  ... and /server/info still answers, with the capability false",
                  await cap() is False)
        finally:
            server_settings.SessionLocal = saved_session
            server_settings._env.REGISTRATION_POLICY = saved_env
        cache.at = -1e9
        check("once the DB answers, get_strict reads the real override",
              await server_settings.get_strict("registration_policy") == "paid" and cache.loaded is True)
        cache.at = -1e9
        server_settings.SessionLocal = db_down
        try:
            check("a DB blip AFTER a successful read keeps the last-known rows (no raise)",
                  await server_settings.get_strict("closed_island") is True)
        finally:
            server_settings.SessionLocal = saved_session
        cache.at = -1e9
        await set_settings(registration_policy="open", closed_island=False,
                           federation_refuse_strangers=False, guest_admission="auto")

        # ── 5. enforce_rate_limit(fail_closed) ────────────────────────────
        print("\nenforce_rate_limit:")
        saved_rl_redis = rl.get_redis

        async def redis_down():
            raise ConnectionError("redis unreachable")

        tag = secrets.token_hex(4)
        rl.get_redis = redis_down
        try:
            soft_raised = False
            for _ in range(5):
                try:
                    await rl.enforce_rate_limit("uin:1", f"gcore_soft_{tag}", 2, 60)
                except HTTPException:
                    soft_raised = True
            check("default stays fail-soft with Redis gone (5 calls past a limit of 2)", not soft_raised)
            outcomes = []
            for _ in range(3):
                try:
                    await rl.enforce_rate_limit("uin:1", f"gcore_hard_{tag}", 2, 60, fail_closed=True)
                    outcomes.append(None)
                except HTTPException as exc:
                    outcomes.append(exc)
            third = outcomes[2]
            check("★ fail_closed=True keeps the cap in this process: two pass, the third is 429",
                  outcomes[0] is None and outcomes[1] is None and third is not None and third.status_code == 429)
            check("  ... with the same shape as the dependency (rate_limited, Retry-After)",
                  third is not None and isinstance(third.detail, dict)
                  and third.detail.get("code") == "rate_limited"
                  and int((third.headers or {}).get("Retry-After", "0")) >= 1)
        finally:
            rl.get_redis = saved_rl_redis
        outcomes = []
        for _ in range(3):
            try:
                await rl.enforce_rate_limit("uin:1", f"gcore_up_{tag}", 2, 60, fail_closed=True)
                outcomes.append(200)
            except HTTPException as exc:
                outcomes.append(exc.status_code)
        check("with Redis up, fail_closed changes nothing: 200, 200, 429", outcomes == [200, 200, 429])

        # ── 6. guest cache ────────────────────────────────────────────────
        print("\nGuest cache:")
        G = await make_row("proven", "guest")
        S = await make_row("added", "seat")
        redis = await get_redis()
        await clear("guest_uins*")
        check("a native account is not a guest", await gp.is_guest(A) is False)
        check("a proven row is a guest (the set rebuilt itself from the table)", await gp.is_guest(G) is True)
        check("an unclaimed seat is a guest", await gp.is_guest(S) is True)
        ttl = await redis.ttl(gp.GUEST_LOADED_KEY)
        check("the marker is armed for at most 300 s", 0 < ttl <= 300)

        X = await unused_uin()
        await gp.mark_guest(X)
        await redis.delete(gp.GUEST_LOADED_KEY)
        check("★ a rebuild racing a mark whose row is not committed yet keeps the mark",
              await gp.is_guest(X) is True)
        await redis.delete(gp.GUEST_PENDING_KEY, gp.GUEST_LOADED_KEY)
        check("  ... which is the pending set's doing: without it the same rebuild drops it",
              await gp.is_guest(X) is False)
        await gp.mark_guest(X)
        await gp.unmark_guest(X)
        await redis.delete(gp.GUEST_LOADED_KEY)
        check("a mark whose commit failed is gone after unmark, rebuild included", await gp.is_guest(X) is False)

        async with SessionLocal() as db:
            await db.execute(text("UPDATE users SET guest_status=NULL, guest_since=NULL WHERE uin=:u"), {"u": G})
            await db.commit()
        await gp.unmark_guest(G)
        check("a conversion committed then unmarked reads native at once", await gp.is_guest(G) is False)
        async with SessionLocal() as db:
            await db.execute(text("UPDATE users SET guest_status='proven' WHERE uin=:u"), {"u": G})
            await db.commit()
        await gp.mark_guest(G)

        saved_get_redis = redis_mod.get_redis

        async def cache_down():
            raise ConnectionError("redis unreachable")

        redis_mod.get_redis = cache_down
        try:
            check("★ Redis down: a guest is still a guest (the row is read)", await gp.is_guest(G) is True)
            check("  ... and a native is still native", await gp.is_guest(A) is False)
            try:
                await gp.mark_guest(X)
                mark_raised = False
            except gp.GuestCacheUnavailable:
                mark_raised = True
            check("★ mark_guest raises when it cannot write, so the caller can roll back", mark_raised)
            try:
                await gp.unmark_guest(G)
                unmark_ok = True
            except Exception:  # noqa: BLE001
                unmark_ok = False
            check("unmark_guest is best effort and never raises", unmark_ok)
            saved_db_session = db_mod.SessionLocal
            db_mod.SessionLocal = db_down
            try:
                try:
                    answer = await gp.is_guest(G)
                    check("Redis AND the database down: is_guest raises, never answers", False)
                    print(f"         (answered {answer})")
                except Exception:  # noqa: BLE001
                    check("Redis AND the database down: is_guest raises, never answers", True)
            finally:
                db_mod.SessionLocal = saved_db_session
        finally:
            redis_mod.get_redis = saved_get_redis
        err = gp.guest_unavailable_error()
        check("guest_unavailable_error is 503 guest_unavailable",
              err.status_code == 503 and err.detail == {"code": "guest_unavailable"})

        # ── 7. rooms, rosters, profiles ───────────────────────────────────
        print("\nRooms and rosters:")
        r = await c.post("/groups", headers=H(a["token"]), json={"name": "core", "member_uins": []})
        check(f"owner creates a room ({r.status_code})", r.status_code == 201)
        gid = r.json()["id"]
        check("a new room lets guests in by default", r.json().get("allow_guests") is True)
        async with SessionLocal() as db:
            for u in (B, G, S):
                db.add(GroupMember(group_id=gid, uin=u, role="member"))
            await db.commit()

        async with SessionLocal() as db:
            check("shares_room: owner and guest share the room", await gp.shares_room(db, A, G) is True)
            check("shares_room: owner and a non-member do not", await gp.shares_room(db, A, C) is False)

        r = await c.get(f"/groups/{gid}", headers=H(a["token"]))
        rows = {m["uin"]: m for m in r.json()["members"]}
        check("roster: native owner guest:false invited:false",
              rows[A]["guest"] is False and rows[A]["invited"] is False)
        check("roster: native member guest:false invited:false",
              rows[B]["guest"] is False and rows[B]["invited"] is False)
        check("roster: proven guest guest:true invited:false",
              rows[G]["guest"] is True and rows[G]["invited"] is False)
        check("roster: unclaimed seat guest:true invited:true",
              rows[S]["guest"] is True and rows[S]["invited"] is True)
        check("roster rows name no island", not any(k in rows[G] for k in ("host", "home", "island")))

        r = await c.patch(f"/groups/{gid}", headers=H(b["token"]), json={"allow_guests": False})
        check(f"a plain member cannot close the room to guests ({r.status_code})", r.status_code == 403)
        r = await c.patch(f"/groups/{gid}", headers=H(a["token"]), json={"allow_guests": False})
        check(f"the owner can ({r.status_code})", r.status_code == 200 and r.json().get("allow_guests") is False)
        async with SessionLocal() as db:
            check("  ... and it is stored", (await db.get(Group, gid)).allow_guests is False)
        r = await c.patch(f"/groups/{gid}", headers=H(a["token"]), json={"name": "renamed"})
        check("a PATCH that does not mention it leaves it alone", r.json().get("allow_guests") is False)
        r = await c.patch(f"/groups/{gid}", headers=H(a["token"]), json={"allow_guests": True})
        check("and back on", r.json().get("allow_guests") is True)
        async with SessionLocal() as db:
            await db.execute(text("UPDATE groups SET allow_guests=NULL WHERE id=:g"), {"g": gid})
            await db.commit()
        r = await c.get(f"/groups/{gid}", headers=H(a["token"]))
        check("a NULL column is served as true", r.json().get("allow_guests") is True)

        print("\nProfiles:")
        tok_g = issue_token(G, await uin_epoch(G))
        r = await c.get(f"/users/{G}/info", headers=H(tok_g))
        check(f"a guest's own view says guest:true ({r.status_code})", r.status_code == 200 and r.json().get("guest") is True)
        r = await c.get(f"/users/{G}/info", headers=H(a["token"]))
        check("a co-member sees guest:true", r.status_code == 200 and r.json().get("guest") is True)
        r = await c.get(f"/users/{G}/info", headers=H(cc["token"]))
        check(f"★ somebody sharing no room gets guest:false ({r.status_code})",
              r.status_code != 200 or r.json().get("guest") is False)
        r = await c.get(f"/users/{B}/info", headers=H(a["token"]))
        check("a native co-member is guest:false", r.json().get("guest") is False)
        r = await c.get(f"/users/{A}/info", headers=H(a["token"]))
        check("a native's own view is guest:false", r.json().get("guest") is False)

        # ── 8. a number move carries the columns ──────────────────────────
        print("\nMigration:")
        M = await make_row("proven", "mover")
        target = await unused_uin()
        async with SessionLocal() as db:
            await _perform_migration(db, await db.get(User, M), target_uin=target)
            await db.commit()
        async with SessionLocal() as db:
            moved = await db.get(User, target)
        check("★ _perform_migration carries guest_status and guest_since",
              moved is not None and moved.guest_status == "proven" and moved.guest_since is not None)

    # ── 9. the additive migration on an island older than the columns ─────
    print("\nAdditive migration (an island booting this code over an old schema):")
    try:
        async with engine.begin() as conn:
            await conn.execute(text("ALTER TABLE users DROP COLUMN guest_status"))
            await conn.execute(text("ALTER TABLE users DROP COLUMN guest_since"))
            await conn.execute(text("ALTER TABLE groups DROP COLUMN allow_guests"))
        dropped = True
    except Exception as exc:  # noqa: BLE001
        dropped = False
        print(f"  SKIP  this SQLite cannot drop columns ({exc})")
    if dropped:
        check("the columns really were gone", "guest_status" not in await columns("users"))
        await init_db()
        check("init_db adds users.guest_status and guest_since back",
              {"guest_status", "guest_since"} <= await columns("users"))
        check("init_db adds groups.allow_guests back", "allow_guests" in await columns("groups"))
        async with engine.connect() as conn:
            allow = (await conn.execute(text("SELECT allow_guests FROM groups WHERE id=:g"), {"g": gid})).scalar()
            guests = (await conn.execute(text("SELECT count(*) FROM users WHERE guest_status IS NOT NULL"))).scalar()
        check("an existing room reads allow_guests true (the DEFAULT, no backfill)", bool(allow) is True)
        check("every existing account comes back native", guests == 0)
        await init_db()
        check("a second boot is a no-op", {"guest_status", "guest_since"} <= await columns("users"))

    await manager.shutdown()
    await clear("guest_uins*", "rl:gcore_*")
    await close_redis()
    try:
        os.remove("test_guest_core.db")
    except FileNotFoundError:
        pass
    print("\n" + ("ALL PASS" if fails == 0 else f"{fails} FAILED"))
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
