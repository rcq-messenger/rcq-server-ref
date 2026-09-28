"""Local-only verification of the fix for the 11.09-28.09 pool stalls.

The mechanism (core/single_flight.py has the long version): request handlers
held their session's connection and then let a cached helper reload itself on
a SECOND session, every concurrent request at once, so a burst of ~30
requests against a stale cache filled the pool with holders waiting on each
other. This pins what replaced that:

  * settings: a stale cache is served at once and refreshed ONCE behind 20
    concurrent readers; rows past the hard age cap are NOT served before one
    refresh is given a moment (a worker idle for an hour sees a write made on
    another worker); a hung refresh costs everybody together one bounded
    wait, not one per read; a failed refresh backs off, counted from the
    FAILURE; a refresh that read the table before an admin write cannot
    publish the old value over it, `apply()` no longer makes readers wait,
    and `reload()` after the commit shows the write (and on failure leaves
    the back-off, not an invalidation); a cold worker's failed first read
    does not make the defaults look fresh; a task left over from another
    event loop is not waited on;
  * the lifespan ticker refreshes a due cache with nobody reading it;
  * the decisions whose default is the dangerous answer read strictly on a
    cold worker: the door fails closed, registration answers 503;
  * /server/info on a warm worker answers while every refresh behind it is
    blocked (it waits on nothing); a COLD worker answers 503 island_busy with
    Retry-After instead of publishing the env defaults, within ONE shared
    budget for settings, logo and headcount; /server/logo waits for the first
    read the same way, and 404 means "no logo", never "not read yet";
  * the headcount caches a 0, serves a stale count while recounting, and
    backs off from the failure;
  * the uin-epoch and suspended mirrors, like the guest set in
    test_guest_core_local.py: a lapsed marker is answered from the mirror and
    rebuilt once, in the background, with the next kick counted from the end
    of the attempt; the Redis-down fallbacks of `uin_epoch` and `is_guest`
    read a REAL row on the caller's session;
  * `_warm_caches` (the lifespan, which no ASGITransport test runs) loads
    everything and primes the mirrors, and with the database down returns
    at its deadline instead of failing the boot;
  * GET /health/db: `{"ok": true}`, or 503 `{"ok": false}`, nothing else;
  * a pool timeout is a 503 island_busy handled INSIDE the app (it does not
    reach ServerErrorMiddleware, which re-raised it and made uvicorn print a
    ~100-line traceback per refusal), logged once with the route template and
    not the account number in the path; on a WEBSOCKET it is one line and a
    1013 close, not an AttributeError;
  * the nesting tripwire (core/db_nesting.py) warns for a second session
    opened while the request's session holds a connection and for a wait on
    a cache in that state, and stays quiet for one opened before the first
    query, for a task the handler spawned, and for the background refresh;
  * ★ and the REAL hot handlers of the stalls (/users/{uin}/info,
    /users/search, /contacts/outgoing, POST /contacts/request, the key
    bundle and device list, POST /groups/{id}/join, /auth/refresh) run with
    the tripwire on and produce no warning with stale, over-age and
    invalidated settings, lapsed markers, and mirrors never built.

The burst reproduction (Postgres + PgBouncer in transaction mode, four
workers) cannot run in-process; it lives in tools/pool_stand/ with its pass
thresholds.

Runs the real FastAPI stack in-process on a throwaway SQLite DB with Redis
db 15. NOT deployed.
Run: PYTHONPATH=. .venv/bin/python test_pool_nesting_local.py
"""
import asyncio
import base64
import logging
import os
import time

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test_pool_nesting.db"
os.environ["ENV"] = "dev"
os.environ["REDIS_URL"] = "redis://localhost:6379/15"
os.environ.pop("RCQ_DB_NESTING_CHECK", None)
for f in ("test_pool_nesting.db",):
    try:
        os.remove(f)
    except FileNotFoundError:
        pass

import httpx  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from fastapi import Depends, WebSocket  # noqa: E402
from sqlalchemy import delete, select, text  # noqa: E402
from sqlalchemy.exc import TimeoutError as SQLAlchemyTimeoutError  # noqa: E402

import app.core.db as db_mod  # noqa: E402
import app.core.redis as redis_mod  # noqa: E402
import app.main as main_mod  # noqa: E402
from app.core import db_nesting, guest_policy, security  # noqa: E402
from app.core.db import SessionLocal, get_db, init_db  # noqa: E402
from app.core.redis import close_redis, get_redis  # noqa: E402
from app.core.security import issue_token  # noqa: E402
from app.core.single_flight import SingleFlight  # noqa: E402
from app.main import app  # noqa: E402
from app.models.group import Group, GroupMember  # noqa: E402
from app.models.server_setting import ServerSetting  # noqa: E402
from app.models.uin_epoch import UinEpoch  # noqa: E402
from app.models.user import User  # noqa: E402
from app.routers import server as server_mod  # noqa: E402
from app.services import door, island_logo, server_settings  # noqa: E402

fails = 0


def check(name, cond):
    global fails
    print(f"  {'PASS' if cond else 'FAIL'}  {name}")
    if not cond:
        fails += 1


def b64(n=32):
    return base64.b64encode(os.urandom(n)).decode()


def keypair():
    sk = Ed25519PrivateKey.generate()
    pub = sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    return sk, base64.b64encode(pub).decode()


class Capture(logging.Handler):
    def __init__(self):
        super().__init__(logging.DEBUG)
        self.lines: list[str] = []

    def emit(self, record):
        self.lines.append(record.getMessage())


async def clear(*patterns):
    redis = await get_redis()
    for pattern in patterns:
        keys = [k async for k in redis.scan_iter(match=pattern)]
        if keys:
            await redis.delete(*keys)


async def wait_until(pred, seconds=2.0):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if pred():
            return True
        await asyncio.sleep(0.01)
    return pred()


async def settle():
    """Let every refresh in flight finish, so one check does not leak into
    the next."""
    for flight in (server_settings._flight, island_logo._flight, server_mod._user_count_flight):
        task = flight.current()
        if task is not None:
            await asyncio.wait({task}, timeout=3.0)


def aged(seconds: float) -> float:
    """An `at` reading for rows that are `seconds` old now."""
    return time.monotonic() - seconds


async def set_setting(**values):
    async with SessionLocal() as db:
        await server_settings.apply(db, server_settings.validate(values))
        await db.commit()
    await server_settings.reload()


async def write_behind_our_back(key: str, raw: str):
    """A write made on ANOTHER worker: it reaches the table, and nothing on
    this worker hears of it (no `apply`, no `reload`, no `gen`)."""
    async with SessionLocal() as db:
        row = await db.get(ServerSetting, key)
        if row is None:
            db.add(ServerSetting(key=key, value=raw))
        else:
            row.value = raw
        await db.commit()


# ── routes the detector and the 503 path are exercised through ────────────
@app.get("/__t/pool-timeout/{uin}")
async def _t_pool_timeout(uin: int):
    raise SQLAlchemyTimeoutError("QueuePool limit of size 5 overflow 5 reached, connection timed out, timeout 20.00")


@app.websocket("/__t/ws-pool-timeout/{uin}")
async def _t_ws_pool_timeout(ws: WebSocket, uin: int):
    await ws.accept()
    raise SQLAlchemyTimeoutError("QueuePool limit of size 5 overflow 5 reached, connection timed out, timeout 20.00")


@app.get("/__t/nest-after-query")
async def _t_nest_after(db=Depends(get_db)):
    await db.execute(select(1))
    async with SessionLocal() as other:
        await other.execute(select(1))
    return {}


@app.get("/__t/nest-before-query")
async def _t_nest_before(db=Depends(get_db)):
    async with SessionLocal() as other:
        await other.execute(select(1))
    await db.execute(select(1))
    return {}


@app.get("/__t/nest-after-commit")
async def _t_nest_after_commit(db=Depends(get_db)):
    await db.execute(select(1))
    await db.commit()
    async with SessionLocal() as other:
        await other.execute(select(1))
    return {}


_spawned: list[asyncio.Task] = []


@app.get("/__t/spawn-after-query")
async def _t_spawn(db=Depends(get_db)):
    await db.execute(select(1))

    async def side():
        async with SessionLocal() as other:
            await other.execute(select(1))

    _spawned.append(asyncio.create_task(side()))
    await asyncio.sleep(0.05)
    return {}


@app.get("/__t/settings-after-query")
async def _t_settings_after_query(db=Depends(get_db)):
    await db.execute(select(1))
    return {"name": await server_settings.island_name()}


def loop_binding_checks():
    print("SingleFlight and event loops:")
    flight = SingleFlight("t")
    gate = {}

    async def first():
        gate["ev"] = asyncio.Event()

        async def never():
            await gate["ev"].wait()
            return True

        flight.start(never)
        await asyncio.sleep(0)
        return flight.current() is not None

    # A loop closed WITHOUT cancelling its tasks (a tool's own loop, a test
    # harness with a loop per test): the refresh it started stays pending for
    # ever, which is the case a module-level "one in flight" check has to
    # survive. `asyncio.run` would cancel it and hide the problem.
    loop = asyncio.new_event_loop()
    started = loop.run_until_complete(first())
    leftover = flight._task
    loop.close()

    async def second():
        stale = flight.current()

        async def quick():
            return True

        task = flight.start(quick)
        ok = await flight.wait(task, 1.0)
        return stale is None, ok

    stale_ignored, ran = asyncio.run(second())
    check("a refresh task is visible on the loop that started it", started)
    check("★ a task left pending on ANOTHER (closed) loop is not waited on; a new one runs",
          leftover is not None and not leftover.done() and stale_ignored and ran)
    leftover._log_destroy_pending = False  # it is the point of the check, not a leak


def websocket_pool_timeout_check():
    """Outside the main loop: the TestClient drives the app from a thread of
    its own, which is the only way to open a websocket against it."""
    from starlette.testclient import TestClient
    from starlette.websockets import WebSocketDisconnect

    print("\nPool timeout on a websocket:")
    cap = Capture()
    logging.getLogger("rcq").addHandler(cap)
    code = None
    other: Exception | None = None
    try:
        with TestClient(app).websocket_connect("/__t/ws-pool-timeout/995814918") as ws:
            ws.receive_text()
    except WebSocketDisconnect as exc:
        code = exc.code
    except Exception as exc:  # noqa: BLE001 - what the check is about
        other = exc
    finally:
        logging.getLogger("rcq").removeHandler(cap)
    lines = [ln for ln in cap.lines if "Pool exhausted" in ln]
    check(f"★ the handler does not crash on a WebSocket (no AttributeError): the socket is closed "
          f"with 1013 ({code}, {type(other).__name__ if other else None})",
          other is None and code == 1013)
    check(f"  ... one log line, WS, route template, no account number ({lines})",
          len(lines) == 1 and "WS /__t/ws-pool-timeout/{uin}" in lines[0] and "995814918" not in lines[0])


async def main() -> int:
    await init_db()
    await clear("guest_uins*", "uin_epochs*", "suspended_uins*", "rl:*")
    cap = Capture()
    # "rcq" covers "rcq.db_nesting" by propagation; "app" the modules.
    logging.getLogger("rcq").addHandler(cap)
    logging.getLogger("app").addHandler(cap)
    refresh_sk, refresh_pub = keypair()
    async with SessionLocal() as db:
        for i in range(41):
            db.add(User(
                uin=700_000 + i, nickname=f"n{i}", identity_key=b64(),
                signing_key=refresh_pub if i == 40 else b64(),
            ))
        await db.flush()
        db.add(Group(id=21, name="room", owner_uin=700_000))
        await db.flush()
        db.add(GroupMember(group_id=21, uin=700_000, role="owner"))
        await db.commit()
    await server_settings.reload()
    real_read = server_settings._read_rows

    async def failing_read():
        raise RuntimeError("database unreachable")

    transport = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t")
    async with transport as c:
        # ── settings ─────────────────────────────────────────────────────
        print("\nSettings cache:")
        await set_setting(island_name="Before")
        check("reload() after the commit shows the write at once",
              await server_settings.get("island_name") == "Before")

        reads: list[int] = []
        gate = asyncio.Event()

        async def gated_read():
            reads.append(1)
            await gate.wait()
            return await real_read()

        server_settings._read_rows = gated_read
        try:
            server_settings._cache.at = aged(server_settings._TTL + 1)  # stale, inside the cap
            t0 = time.monotonic()
            try:
                got = await asyncio.wait_for(
                    asyncio.gather(*[server_settings.get("island_name") for _ in range(20)]), 2.0
                )
            except asyncio.TimeoutError:  # a regression that waits must fail, not hang
                got = []
            spent = time.monotonic() - t0
            check(f"★ 20 concurrent readers of a STALE cache answer at once from it ({spent*1000:.1f} ms)",
                  len(got) == 20 and all(g == "Before" for g in got) and spent < 0.5 and not gate.is_set())
            await asyncio.sleep(0)
            check(f"  ... and exactly ONE refresh is running behind them ({len(reads)})", len(reads) == 1)
            gate.set()
            await settle()
            check("  ... which publishes and makes the cache fresh",
                  time.monotonic() - server_settings._cache.at < server_settings._TTL)
        finally:
            server_settings._read_rows = real_read

        # ★ The blocker of the review: a worker that sat idle for an hour.
        await write_behind_our_back("island_name", "Written elsewhere")
        server_settings._cache.at = aged(3600)
        t0 = time.monotonic()
        got = await server_settings.get("island_name")
        spent = time.monotonic() - t0
        check(f"★ rows an HOUR old are not served: the first read after the idle hour already sees "
              f"the write another worker made ({got!r}, {spent*1000:.1f} ms)",
              got == "Written elsewhere" and spent < server_settings._STALE_WAIT)
        await set_setting(island_name="Before")

        # Past the cap with a refresh that hangs: ONE bounded wait for all.
        hang = asyncio.Event()

        async def hung_read():
            await hang.wait()
            return await real_read()

        saved_stale_wait = server_settings._STALE_WAIT
        server_settings._STALE_WAIT = 0.3
        server_settings._read_rows = hung_read
        try:
            server_settings._cache.at = aged(3600)
            t0 = time.monotonic()
            got = [await server_settings.get("island_name") for _ in range(5)]
            spent = time.monotonic() - t0
            check(f"★ past the cap with a HUNG refresh: five reads in a row cost one bounded wait "
                  f"together, not one each ({spent:.2f} s for a {server_settings._STALE_WAIT} s budget)",
                  all(g == "Before" for g in got) and 0.25 <= spent < 0.55)
        finally:
            hang.set()
            server_settings._read_rows = real_read
            server_settings._STALE_WAIT = saved_stale_wait
        await settle()

        # Past the cap with a database that is failing: no wait at all.
        attempts: list[int] = []

        async def counted_failing_read():
            attempts.append(1)
            raise RuntimeError("database unreachable")

        await server_settings.reload()
        server_settings._read_rows = counted_failing_read
        try:
            server_settings._cache.at = aged(3600)
            await server_settings.get("island_name")  # the one attempt, and it fails
            t0 = time.monotonic()
            for _ in range(10):
                v = await server_settings.get("island_name")
            spent = time.monotonic() - t0
            check(f"★ past the cap with the database *failing*: served at once, no wait and no new "
                  f"attempt per read ({len(attempts)} attempt(s), {spent*1000:.1f} ms for 10 reads)",
                  len(attempts) == 1 and v == "Before" and spent < 0.1)
        finally:
            server_settings._read_rows = real_read
        await server_settings.reload()

        # A failed refresh backs off (a stale cache inside the cap).
        attempts.clear()
        server_settings._read_rows = counted_failing_read
        try:
            server_settings._cache.at = aged(server_settings._TTL + 1)
            for _ in range(10):
                v = await server_settings.get("island_name")
                await asyncio.sleep(0.01)
            check(f"★ a failed refresh is not retried by every call ({len(attempts)} attempt(s) in 10 calls)",
                  len(attempts) == 1 and v == "Before")
            await asyncio.sleep(server_settings._RETRY_AFTER + 0.1)
            await server_settings.get("island_name")
            await wait_until(lambda: len(attempts) >= 2)
            check(f"  ... and is retried once the back-off has passed ({len(attempts)})", len(attempts) == 2)
        finally:
            server_settings._read_rows = real_read
        await server_settings.reload()

        # The back-off is counted from the FAILURE, not from the attempt's start.
        async def slow_failing_read():
            await asyncio.sleep(0.4)
            raise RuntimeError("QueuePool limit ... timeout 20.00")

        server_settings._read_rows = slow_failing_read
        try:
            t0 = time.monotonic()
            await server_settings._flight.wait(server_settings._flight.start(server_settings._refresh), 2.0)
            check(f"★ the back-off runs from the moment the refresh *failed* "
                  f"(next attempt {server_settings._cache.retry_at - t0:.2f} s after the start, "
                  f">= 0.4 s of failing + {server_settings._RETRY_AFTER} s)",
                  server_settings._cache.retry_at - t0 >= 0.4 + server_settings._RETRY_AFTER - 0.05)
        finally:
            server_settings._read_rows = real_read
        await server_settings.reload()

        # A refresh that read the table before an admin write is discarded.
        gate2 = asyncio.Event()

        async def old_read():
            rows = await real_read()
            await gate2.wait()
            return rows

        server_settings._read_rows = old_read
        try:
            server_settings._cache.at = aged(server_settings._TTL + 1)
            await server_settings.get("island_name")  # kicks the slow refresh
            await asyncio.sleep(0.05)
        finally:
            server_settings._read_rows = real_read
        await set_setting(island_name="After")
        gate2.set()
        await asyncio.sleep(0.05)
        check("★ a refresh that started before the write cannot put the old value back (gen)",
              await server_settings.get("island_name") == "After"
              and server_settings._cache.rows.get("island_name") == "After")

        # apply() no longer makes readers wait. The table read is gated, so
        # a reader that did wait for one would show it.
        at0 = server_settings._cache.at
        gate3 = asyncio.Event()

        async def gated_read3():
            await gate3.wait()
            return await real_read()

        server_settings._read_rows = gated_read3
        try:
            async with SessionLocal() as admin_db:
                await server_settings.apply(admin_db, server_settings.validate({"island_name": "Pending"}))
                t0 = time.monotonic()
                during = await asyncio.wait_for(server_settings.get("island_name"), 3.0)
                spent = time.monotonic() - t0
                at_during = server_settings._cache.at
                await admin_db.commit()
        finally:
            gate3.set()
            server_settings._read_rows = real_read
        await settle()
        await server_settings.reload()
        check(f"★ between apply() and the commit a reader on the admin's worker is not held up "
              f"({during!r}, {spent*1000:.1f} ms, cache untouched: {at_during == at0})",
              during == "After" and spent < 0.05 and at_during == at0)
        check("  ... and reload() after the commit publishes the write",
              await server_settings.get("island_name") == "Pending")

        # A failed reload() leaves the back-off, not an invalidation.
        at_before = server_settings._cache.at
        server_settings._read_rows = failing_read
        try:
            ok = await server_settings.reload()
            t0 = time.monotonic()
            v = await server_settings.get("island_name")
            spent = time.monotonic() - t0
        finally:
            server_settings._read_rows = real_read
        check(f"★ a failed reload() keeps the rows valid and backs off, so readers do not wait "
              f"({ok}, {spent*1000:.1f} ms)",
              ok is False and server_settings._cache.at == at_before
              and server_settings._cache.retry_at > time.monotonic() and v == "Pending" and spent < 0.05)
        await server_settings.reload()

        # Invalidated (tests only) with a hung read: bounded per attempt.
        cache = server_settings._cache
        saved_cold_wait = server_settings._COLD_WAIT
        server_settings._COLD_WAIT = 0.3
        hang2 = asyncio.Event()

        async def hung_read2():
            await hang2.wait()
            return await real_read()

        server_settings._read_rows = hung_read2
        try:
            cache.at = -1e9
            t0 = time.monotonic()
            got = [await server_settings.get("island_name") for _ in range(5)]
            spent = time.monotonic() - t0
            check(f"★ an invalidated cache with a hung read: five reads cost one bounded wait "
                  f"together and serve the rows ({spent:.2f} s for a {server_settings._COLD_WAIT} s budget)",
                  all(g == "Pending" for g in got) and 0.25 <= spent < 0.55)
        finally:
            hang2.set()
            server_settings._read_rows = real_read
        await settle()

        # Cold with a hung read: bounded too, and strict readers refuse.
        hang3 = asyncio.Event()

        async def hung_read3():
            await hang3.wait()
            return await real_read()

        saved = (dict(cache.rows), cache.at, cache.loaded)
        server_settings._read_rows = hung_read3
        try:
            cache.rows, cache.at, cache.loaded = {}, -1e9, False
            t0 = time.monotonic()
            got = [await server_settings.get("island_name") for _ in range(5)]
            try:
                await server_settings.get_strict("registration_policy")
                strict_refused = False
            except server_settings.SettingsUnavailable:
                strict_refused = True
            spent = time.monotonic() - t0
            check(f"★ COLD with a hung read: bounded the same way, and get_strict refuses "
                  f"({spent:.2f} s, strict refused: {strict_refused})",
                  0.25 <= spent < 0.55 and strict_refused and all(g != "Pending" for g in got))
        finally:
            hang3.set()
            server_settings._read_rows = real_read
            server_settings._COLD_WAIT = saved_cold_wait
        await settle()
        cache.rows, cache.at, cache.loaded = saved
        await server_settings.reload()

        # Cold: a failed first read must not make the defaults look fresh.
        await set_setting(closed_island=False)
        saved = (dict(cache.rows), cache.at, cache.loaded)
        server_settings._read_rows = failing_read
        try:
            cache.rows, cache.at, cache.loaded = {}, -1e9, False
            v_cold = await server_settings.get("island_name")
            closed_cold = await door.island_is_closed()
            r_reg = await c.post(
                "/auth/register",
                json={"nickname": "walk-in", "identity_key": b64(), "signing_key": b64()},
            )
        finally:
            server_settings._read_rows = real_read
        t0 = time.monotonic()
        v_back = await server_settings.get("island_name")
        spent = time.monotonic() - t0
        check(f"★ cold, a failed first read does not make the defaults 'fresh': a reader a moment "
              f"later, inside the back-off, reads the table ({v_cold!r} -> {v_back!r}, {spent*1000:.1f} ms)",
              v_cold != "Pending" and v_back == "Pending" and cache.loaded)
        check("★ the door fails CLOSED on a worker that has never read the settings (the island is open)",
              closed_cold is True and await door.island_is_closed() is False)
        check(f"★ /auth/register on that worker is a 503 island_busy, not a registration under the "
              f"default policy ({r_reg.status_code} {r_reg.text[:60]})",
              r_reg.status_code == 503 and r_reg.json().get("detail") == "island_busy"
              and int(r_reg.headers.get("Retry-After", "0")) >= 1)
        cache.rows, cache.at, cache.loaded = saved
        await server_settings.reload()

        # ── the ticker ──────────────────────────────────────────────────
        print("\nLifespan ticker:")
        saved_tick = main_mod._TICK_SECONDS
        main_mod._TICK_SECONDS = 0.05
        ticker = asyncio.create_task(main_mod._cache_ticker())
        try:
            await write_behind_our_back("island_name", "Seen by the clock")
            server_settings._cache.at = aged(server_settings._TTL + 0.01)
            server_mod._USER_COUNT = (1.0, 0)
            server_mod._user_count_retry_at = 0.0
            ticked = await wait_until(
                lambda: server_settings._cache.rows.get("island_name") == "Seen by the clock"
                and server_mod._USER_COUNT[1] == 41, 2.0,
            )
            check("★ a due cache is refreshed with NOBODY reading it (settings, headcount)", ticked)
            t0 = time.monotonic()
            got = await server_settings.get("island_name")
            spent = time.monotonic() - t0
            check(f"  ... so the idle worker's next request is served the write, at once "
                  f"({got!r}, {spent*1000:.1f} ms)",
                  got == "Seen by the clock" and spent < 0.05 and server_settings._flight.current() is None)
        finally:
            ticker.cancel()
            await asyncio.gather(ticker, return_exceptions=True)
            main_mod._TICK_SECONDS = saved_tick
        check("  ... and the ticker stops when cancelled (the lifespan's shutdown)", ticker.cancelled())
        await settle()
        await set_setting(island_name="After")

        # ── /server/info ────────────────────────────────────────────────
        print("\n/server/info:")
        r = await c.get("/server/info")
        check(f"warm: 200 with the island's own name ({r.status_code} {r.json().get('name')})",
              r.status_code == 200 and r.json().get("name") == "After")

        blocked = asyncio.Event()
        calls: list[str] = []

        async def blocked_settings():
            calls.append("settings")
            await blocked.wait()
            return await real_read()

        real_logo_read = island_logo._read_row

        async def blocked_logo(known):
            calls.append("logo")
            await blocked.wait()
            return await real_logo_read(known)

        real_count = server_mod._count_users

        async def blocked_count():
            calls.append("count")
            await blocked.wait()
            return await real_count()

        server_settings._read_rows = blocked_settings
        island_logo._read_row = blocked_logo
        server_mod._count_users = blocked_count
        try:
            server_settings._cache.at = aged(server_settings._TTL + 1)
            island_logo._cache.at = aged(3600)
            server_mod._USER_COUNT = (1.0, server_mod._USER_COUNT[1])
            server_mod._user_count_retry_at = 0.0
            t0 = time.monotonic()
            try:
                status_code = (await asyncio.wait_for(c.get("/server/info"), 2.0)).status_code
            except asyncio.TimeoutError:  # a regression that waits must fail, not hang
                status_code = None
            spent = time.monotonic() - t0
            check(f"★ warm and stale: answers while EVERY refresh behind it is blocked "
                  f"({status_code}, {spent*1000:.1f} ms, refreshes started: {sorted(calls)})",
                  status_code == 200 and spent < 0.5
                  and sorted(calls) == ["count", "logo", "settings"])
        finally:
            blocked.set()
            server_settings._read_rows = real_read
            island_logo._read_row = real_logo_read
            server_mod._count_users = real_count
        await settle()

        # Cold: never the defaults.
        saved = (dict(cache.rows), cache.at, cache.loaded)
        server_settings._read_rows = failing_read
        try:
            cache.rows, cache.at, cache.loaded = {}, -1e9, False
            r = await c.get("/server/info")
            check(f"★ cold worker, database down: 503 island_busy with Retry-After, no defaults "
                  f"({r.status_code} {r.text[:60]})",
                  r.status_code == 503 and r.json() == {"detail": "island_busy"}
                  and int(r.headers.get("Retry-After", "0")) >= 1)
        finally:
            server_settings._read_rows = real_read
            cache.rows, cache.at, cache.loaded = saved
        await server_settings.reload()

        # Cold with settings, logo AND headcount all hanging: one budget.
        lc = island_logo._cache
        hang4 = asyncio.Event()

        async def hung_settings():
            await hang4.wait()
            return await real_read()

        async def hung_logo(known):
            await hang4.wait()
            return await real_logo_read(known)

        async def hung_count():
            await hang4.wait()
            return await real_count()

        saved = (dict(cache.rows), cache.at, cache.loaded)
        lsaved = (lc.row, lc.at, lc.loaded)
        csaved = server_mod._USER_COUNT
        saved_budget = server_mod._COLD_WAIT_SECONDS
        server_mod._COLD_WAIT_SECONDS = 0.4
        server_settings._read_rows = hung_settings
        island_logo._read_row = hung_logo
        server_mod._count_users = hung_count
        try:
            cache.rows, cache.at, cache.loaded = {}, -1e9, False
            lc.row, lc.at, lc.loaded = None, -1e9, False
            server_mod._USER_COUNT = (0.0, 0)
            server_mod._user_count_retry_at = 0.0
            t0 = time.monotonic()
            r = await c.get("/server/info")
            spent = time.monotonic() - t0
            check(f"★ cold with settings, logo and headcount all hanging: ONE shared budget, then 503 "
                  f"({r.status_code}, {spent:.2f} s for a {server_mod._COLD_WAIT_SECONDS} s budget)",
                  r.status_code == 503 and spent < server_mod._COLD_WAIT_SECONDS * 1.6)
        finally:
            hang4.set()
            server_settings._read_rows = real_read
            island_logo._read_row = real_logo_read
            server_mod._count_users = real_count
            server_mod._COLD_WAIT_SECONDS = saved_budget
        await settle()
        cache.rows, cache.at, cache.loaded = saved
        lc.row, lc.at, lc.loaded = lsaved
        server_mod._USER_COUNT = csaved
        await server_settings.reload()
        await island_logo.reload()

        async def failing_logo(known):
            raise RuntimeError("database unreachable")

        lsaved = (lc.row, lc.at, lc.loaded)
        island_logo._read_row = failing_logo
        try:
            lc.row, lc.at, lc.loaded = None, -1e9, False
            r1 = await c.get("/server/info")
            r2 = await c.get("/server/logo")
            check(f"★ logo never read (not the same as 'no logo'): /server/info 503, /server/logo 503 "
                  f"({r1.status_code}, {r2.status_code})", r1.status_code == 503 and r2.status_code == 503)
        finally:
            island_logo._read_row = real_logo_read
        lc.row, lc.at, lc.loaded = None, -1e9, False
        r = await c.get("/server/logo")
        check(f"★ /server/logo on a cold worker whose database answers waits for the read and says "
              f"'no logo' (404), not 503 ({r.status_code})", r.status_code == 404 and lc.loaded)
        r = await c.get("/server/logo")
        check(f"  ... and once read, an island with no logo is a plain 404 ({r.status_code})", r.status_code == 404)
        lc.row, lc.at, lc.loaded = lsaved
        await island_logo.reload()

        # ── headcount ───────────────────────────────────────────────────
        print("\nHeadcount:")
        server_mod._USER_COUNT = (time.monotonic(), 0)
        server_mod._user_count_retry_at = 0.0
        n = await server_mod._user_count()
        check("a fresh count of 0 is cached, not recounted",
              n == 0 and server_mod._user_count_flight.current() is None)
        server_mod._USER_COUNT = (1.0, 0)
        n = await server_mod._user_count()
        await wait_until(lambda: server_mod._USER_COUNT[1] > 0)
        check(f"a stale count is served and recounted behind ({n} -> {server_mod._USER_COUNT[1]})",
              n == 0 and server_mod._USER_COUNT[1] == 41)

        class SlowFailingSession:
            async def __aenter__(self):
                await asyncio.sleep(0.4)
                raise RuntimeError("QueuePool limit ... timeout 20.00")

            async def __aexit__(self, *exc):
                return False

        real_server_session = server_mod.SessionLocal
        server_mod.SessionLocal = lambda: SlowFailingSession()
        try:
            t0 = time.monotonic()
            await server_mod._user_count_flight.wait(
                server_mod._user_count_flight.start(server_mod._count_users), 2.0
            )
            check(f"★ a failed count backs off from the *failure* "
                  f"({server_mod._user_count_retry_at - t0:.2f} s after the start)",
                  server_mod._user_count_retry_at - t0 >= 0.4 + server_mod._USER_COUNT_RETRY_AFTER - 0.05)
        finally:
            server_mod.SessionLocal = real_server_session
        server_mod._user_count_retry_at = 0.0

        # ── mirrors ─────────────────────────────────────────────────────
        print("\nEpoch and suspended mirrors:")
        redis = await get_redis()
        for mirror, getter, label in (
            (security._EPOCH_MIRROR, lambda: security.uin_epoch(700_001), "uin epochs"),
            (security._SUSPENDED_MIRROR, lambda: security.is_suspended(700_001), "suspended set"),
        ):
            await getter()  # builds it (never built -> inline)
            check(f"{label}: the first read builds it and records `built`",
                  await redis.exists(mirror.built) == 1 and await redis.exists(mirror.marker) == 1)
            await redis.delete(mirror.marker)
            real_rebuild = mirror._rebuild
            seen: list[bool] = []
            g = asyncio.Event()

            async def slow(redis_, db_, _real=real_rebuild, _seen=seen, _g=g):
                _seen.append(db_ is None)
                await _g.wait()
                await _real(redis_, db_)

            mirror._rebuild = slow
            mirror._next_kick = 0.0
            try:
                t0 = time.monotonic()
                try:
                    # Bounded: a regression that rebuilds inline would wait on
                    # the gate below for ever, and must fail, not hang.
                    await asyncio.wait_for(asyncio.gather(*[getter() for _ in range(20)]), 2.0)
                except asyncio.TimeoutError:
                    pass
                spent = time.monotonic() - t0
                await wait_until(lambda: bool(seen))
                check(f"★ {label}: marker lapsed, 20 readers answer without waiting "
                      f"({spent*1000:.1f} ms) and ONE background rebuild runs ({seen})",
                      spent < 0.5 and seen == [True] and not g.is_set())
            finally:
                g.set()
                mirror._rebuild = real_rebuild
            await wait_until(lambda: False, 0.1)
            check(f"  ... {label}: which re-arms the marker", await redis.exists(mirror.marker) == 1)

        # The next kick is counted from the END of a failed rebuild.
        mirror = security._EPOCH_MIRROR
        real_rebuild = mirror._rebuild

        async def slow_failing_rebuild(redis_, db_):
            await asyncio.sleep(0.4)
            raise RuntimeError("QueuePool limit ... timeout 20.00")

        await redis.delete(mirror.marker)
        mirror._rebuild = slow_failing_rebuild
        mirror._next_kick = 0.0
        try:
            t0 = time.monotonic()
            await security.uin_epoch(700_001)
            task = mirror._flight.current()
            if task is not None:
                await asyncio.wait({task}, timeout=2.0)
            check(f"★ a failed background rebuild backs off from its END "
                  f"(next kick {mirror._next_kick - t0:.2f} s after the kick)",
                  mirror._next_kick - t0 >= 0.4 + mirror.retry_after - 0.05)
            await security.uin_epoch(700_001)
            check("  ... and a reader inside that pause starts no new one",
                  mirror._flight.current() is None)
        finally:
            mirror._rebuild = real_rebuild
            mirror._next_kick = 0.0
            await redis.delete(mirror.lock)
        await security.uin_epoch(700_001)
        await wait_until(lambda: False, 0.1)

        opened: list[int] = []
        real_factory = db_mod.SessionLocal

        def counting(*a, **kw):
            opened.append(1)
            return real_factory(*a, **kw)

        async def redis_gone():
            raise ConnectionError("redis unreachable")

        # A REAL row, so a fallback that failed (and answered its default)
        # cannot pass for one that read it.
        async with SessionLocal() as db:
            db.add(UinEpoch(uin=700_001, epoch=3))
            await db.execute(text("UPDATE users SET guest_status='proven' WHERE uin=700004"))
            await db.commit()
        try:
            async with SessionLocal() as caller_db:
                await caller_db.execute(select(1))
                db_mod.SessionLocal = counting
                real_get_redis = redis_mod.get_redis
                redis_mod.get_redis = redis_gone
                try:
                    ep = await security.uin_epoch(700_001, caller_db)
                    try:
                        guest = await guest_policy.is_guest(700_004, caller_db)
                    except Exception as exc:  # noqa: BLE001 - it raises when the row read fails
                        guest = exc
                finally:
                    redis_mod.get_redis = real_get_redis
                    db_mod.SessionLocal = real_factory
            check(f"★ uin_epoch with Redis down reads the row on the CALLER'S session, no second one "
                  f"(epoch {ep}, opened {len(opened)})", ep == 3 and not opened)
            check(f"★ is_guest with Redis down reads the row on the CALLER'S session, no second one "
                  f"({guest}, opened {len(opened)})", guest is True and not opened)
        finally:
            async with SessionLocal() as db:
                await db.execute(delete(UinEpoch).where(UinEpoch.uin == 700_001))
                await db.execute(text("UPDATE users SET guest_status=NULL WHERE uin=700004"))
                await db.commit()
            await clear("guest_uins*", "uin_epochs*", "suspended_uins*")

        # ── boot warm-up ────────────────────────────────────────────────
        print("\nBoot warm-up (_warm_caches, which no ASGITransport test runs):")
        cache.rows, cache.at, cache.loaded = {}, -1e9, False
        lc.row, lc.at, lc.loaded = None, -1e9, False
        server_mod._USER_COUNT = (0.0, 0)
        await clear("guest_uins*", "uin_epochs*", "suspended_uins*")
        t0 = time.monotonic()
        await main_mod._warm_caches()
        spent = time.monotonic() - t0
        built = [
            await redis.exists(m.built)
            for m in (guest_policy._mirror, security._EPOCH_MIRROR, security._SUSPENDED_MIRROR)
        ]
        check(f"★ loads settings, logo and headcount and primes the three mirrors ({spent*1000:.0f} ms, "
              f"count {server_mod._USER_COUNT[1]}, built {built})",
              server_settings.is_loaded() and island_logo.is_loaded()
              and server_mod._USER_COUNT[1] == 41 and built == [1, 1, 1])

        cache.rows, cache.at, cache.loaded = {}, -1e9, False
        saved_deadline = main_mod._WARM_DEADLINE_SECONDS
        main_mod._WARM_DEADLINE_SECONDS = 0.5
        server_settings._read_rows = failing_read
        cap.lines.clear()
        raised = None
        try:
            t0 = time.monotonic()
            try:
                await main_mod._warm_caches()
            except Exception as exc:  # noqa: BLE001 - what the check is about
                raised = exc
            spent = time.monotonic() - t0
        finally:
            server_settings._read_rows = real_read
            main_mod._WARM_DEADLINE_SECONDS = saved_deadline
        warned = [ln for ln in cap.lines if "[boot] serving with cold caches" in ln]
        check(f"★ with the database down it returns at its deadline instead of failing the boot "
              f"({spent:.2f} s for 0.5 s, raised {raised!r}, warned {len(warned)})",
              raised is None and 0.4 <= spent < 1.5 and len(warned) == 1 and not server_settings.is_loaded())
        await server_settings.reload()

        # ── /health/db ──────────────────────────────────────────────────
        print("\n/health/db:")
        main_mod._DB_PROBE_LAST = (-1e9, False)
        r = await c.get("/health/db")
        check(f"200 {{\"ok\": true}} and nothing else ({r.status_code} {r.text})",
              r.status_code == 200 and r.json() == {"ok": True})

        class DeadEngine:
            def connect(self):
                raise RuntimeError("connection refused to 10.0.0.1:25061 user=doadmin")

        real_engine = main_mod.engine
        main_mod.engine = DeadEngine()
        main_mod._DB_PROBE_LAST = (-1e9, False)
        try:
            r = await c.get("/health/db")
        finally:
            main_mod.engine = real_engine
        check(f"★ database down: 503 {{\"ok\": false}}, no error text, host or counters ({r.status_code} {r.text})",
              r.status_code == 503 and r.json() == {"ok": False})
        main_mod._DB_PROBE_LAST = (-1e9, False)

        # ── the 503 on a pool timeout ───────────────────────────────────
        print("\nPool timeout:")
        cap.lines.clear()
        try:
            r = await c.get("/__t/pool-timeout/995814918")
            propagated = False
        except Exception:  # noqa: BLE001
            propagated = True
        check("★ handled inside the app: it does not reach ServerErrorMiddleware (no re-raise, "
              "so no uvicorn traceback)", not propagated)
        check(f"  ... 503 island_busy with Retry-After ({r.status_code})",
              not propagated and r.status_code == 503 and r.json() == {"detail": "island_busy"}
              and int(r.headers.get("Retry-After", "0")) >= 1)
        line = [ln for ln in cap.lines if "Pool exhausted" in ln]
        check(f"  ... one log line, with the route TEMPLATE and no account number ({line})",
              len(line) == 1 and "/__t/pool-timeout/{uin}" in line[0] and "995814918" not in line[0])

        # ── the nesting tripwire ────────────────────────────────────────
        print("\nNesting tripwire:")
        check("on in ENV=dev", db_nesting.enabled())

        def nest_lines():
            return [ln for ln in cap.lines if "[db-nesting]" in ln]

        cap.lines.clear()
        await c.get("/__t/nest-after-query")
        got = nest_lines()
        check(f"★ a second session after the request's first query is reported, with the call site ({got})",
              len(got) == 1 and "_t_nest_after" in got[0])
        for path, what in (
            ("/__t/nest-before-query", "a second session BEFORE the first query (nothing held yet)"),
            ("/__t/nest-after-commit", "a second session after the commit gave the connection back"),
            ("/__t/spawn-after-query", "a task the handler spawned (it does not make the request wait)"),
        ):
            cap.lines.clear()
            await c.get(path)
            if _spawned:
                await asyncio.gather(*_spawned)
                _spawned.clear()
            check(f"no warning for {what} ({nest_lines()})", not nest_lines())
        cap.lines.clear()
        server_settings._cache.at = aged(server_settings._TTL + 1)
        r = await c.get("/__t/settings-after-query")
        await asyncio.sleep(0.1)
        check(f"no warning for the background refresh a stale cache starts mid-request "
              f"({r.json()}, {nest_lines()})", r.json() == {"name": "After"} and not nest_lines())
        cap.lines.clear()
        db_nesting._last_logged.clear()
        server_settings._cache.at = aged(3600)
        r = await c.get("/__t/settings-after-query")
        got = nest_lines()
        check(f"★ but a wait on an over-age cache while holding a connection IS reported ({got})",
              r.status_code == 200 and len(got) == 1 and "waiting on server_settings" in got[0]
              and "_t_settings_after_query" in got[0])
        await settle()

        # ── the real hot handlers, with the tripwire on ─────────────────
        print("\nThe handlers of the stalls, tripwire on:")
        await set_setting(closed_island=True)  # so the door runs all the way
        caller = 700_001
        auth = {"Authorization": f"Bearer {issue_token(caller, await security.uin_epoch(caller))}"}

        async def st_stale():
            server_settings._cache.at = aged(server_settings._TTL + 1)
            island_logo._cache.at = aged(3600)
            await redis.delete(guest_policy.GUEST_LOADED_KEY, security._EPOCH_LOADED_KEY,
                               security._SUSPENDED_LOADED_KEY)

        async def st_over_age():
            server_settings._cache.at = aged(3600)

        async def st_invalidated():
            server_settings._cache.at = -1e9

        async def st_never_built():
            await redis.delete(
                guest_policy.GUEST_LOADED_KEY, guest_policy.GUEST_BUILT_KEY,
                security._EPOCH_LOADED_KEY, security._EPOCH_BUILT_KEY,
                security._SUSPENDED_LOADED_KEY, security._SUSPENDED_BUILT_KEY,
            )

        async def do_refresh():
            await clear("rl:*")
            r = await c.post("/auth/recover/challenge", json={"signing_key": refresh_pub})
            ch = r.json()["challenge"]
            sig = base64.b64encode(refresh_sk.sign(ch.encode())).decode()
            return await c.post("/auth/refresh", json={
                "uin": 700_040, "signing_key": refresh_pub, "challenge": ch, "signature": sig,
            })

        states = (
            ("stale settings and logo, lapsed markers", st_stale),
            ("settings past the hard age cap", st_over_age),
            ("settings invalidated", st_invalidated),
            ("mirrors never built (a flushed Redis)", st_never_built),
        )
        for idx, (state, setup) in enumerate(states):
            routes = (
                ("GET /users/{uin}/info", {200},
                 lambda: c.get("/users/700002/info", headers=auth)),
                ("GET /users/search", {200},
                 lambda: c.get("/users/search", params={"q": "n3"}, headers=auth)),
                ("GET /contacts/outgoing", {200},
                 lambda: c.get("/contacts/outgoing", headers=auth)),
                ("POST /contacts/request", {202},
                 lambda: c.post("/contacts/request", json={"to_uin": 700_030 + idx}, headers=auth)),
                ("GET /keys/{uin}/bundle (resident)", {200, 404},
                 lambda: c.get("/keys/700003/bundle", headers=auth)),
                ("GET /keys/{uin}/bundle (anonymous)", {200, 404},
                 lambda: c.get("/keys/700003/bundle")),
                ("GET /keys/{uin}/devices (anonymous)", {200, 404},
                 lambda: c.get("/keys/700003/devices")),
                ("POST /groups/{id}/join", {200},
                 lambda: c.post("/groups/21/join", headers={
                     "Authorization": f"Bearer {issue_token(700_020 + idx, 0)}"})),
                ("POST /auth/refresh", {200},
                 do_refresh),
            )
            bad: list[str] = []
            for name, ok_codes, call in routes:
                await setup()
                await clear("rl:*")
                cap.lines.clear()
                db_nesting._last_logged.clear()
                resp = await call()
                await settle()
                await asyncio.sleep(0.05)
                nest = nest_lines()
                if resp.status_code not in ok_codes or nest:
                    bad.append(f"{name}: {resp.status_code} {resp.text[:80]} {nest}")
            check(f"★ {state}: every handler answers and none nests or waits holding a connection "
                  f"({bad or 'all clean'})", not bad)
            await server_settings.reload()
            await island_logo.reload()

        await set_setting(closed_island=False, island_name="")

    await clear("guest_uins*", "uin_epochs*", "suspended_uins*", "rl:*")
    await close_redis()
    print(f"\n{'ALL PASS' if fails == 0 else f'{fails} FAILED'}")
    return 1 if fails else 0


if __name__ == "__main__":
    loop_binding_checks()
    websocket_pool_timeout_check()
    rc = asyncio.run(main())
    raise SystemExit(rc)
