import asyncio
import logging
import re
import secrets
import time

from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
from sqlalchemy import text
from sqlalchemy.exc import TimeoutError as SQLAlchemyTimeoutError

from app.core.config import settings
from app.core.db import engine, init_db
from app.core import metrics
from app.core.single_flight import SingleFlight
from app.core.feature_gate import require_feature
from app.core.rate_limit import _client_ip
from app.core.redis import close_redis, get_redis
from app.core.transport import classify as transport_of
from app.routers import admin, audio_rooms, auth, broker, contacts, deposit_auth, devices, entry, federation, gate, groups, keys, link, media, messages, migrate, news, polls, presence, public, reports, server, sites, uin_shop, users, vault, ws, guest_cards, invites, residency
from app.routers import random as random_chat
from app.services.connection_manager import manager
from app.services.evidence_sweep import evidence_sweep_loop
from app.services.inquiry_sweep import inquiry_sweep_loop
from app.services.dead_account_sweep import dead_account_sweep_loop
from app.services.offline_queue_sweep import offline_queue_sweep_loop
from app.services.stale_reader_sweep import stale_reader_sweep_loop


class _RedactSecretsInLogs(logging.Filter):
    """Strip session tokens out of anything we log.

    A websocket cannot carry an Authorization header, so `/ws/{uin}` takes the
    token in the query string, and uvicorn's access logger prints the request
    line verbatim:

        INFO: ('62.182.70.125', 0) - "WebSocket /ws/695744503?token=eyJhbGci…"

    journald then puts that in /var/log/syslog, where the audit found 816
    distinct tokens over 449 accounts, 815 of which would still have been
    accepted. Our tokens have no working expiry, so a leaked one is good until
    the number changes hands — a log file is effectively a file of passwords.

    Caddy's access log was filtered back in August and stopped being a source;
    this is the channel that was left, and it is the one closest to the leak,
    so it covers whatever else ends up logging a URL later. The substring test
    runs before the regex so the ordinary line costs one `in`.
    """

    _RE = re.compile(r"(?i)\b(token|access_token|invite)=[A-Za-z0-9._\-]+")

    # ⚠ The token was only half of it. The same access line carries the client's
    # FULL address next to an account number in the path:
    #
    #     INFO: ('185.102.11.202', 0) - "WebSocket /ws/68650924?token=<redacted>"
    #     INFO: ('185.102.11.202', 0) - "GET /users/68650924/info HTTP/1.1" 200
    #
    # so the journal was an IP-to-account map plus a per-second activity feed
    # for every account, about 1.2 million lines a day over the 2.4 days the
    # 1G cap holds. The metadata audit of 22.08 closed the application's own
    # `uin=` log lines and left this one, which is larger than all of them
    # together. Caddy has masked its own copy to /24 since 11.08; this is the
    # same masking arriving at the channel that still had the raw value.
    #
    # Both halves are rewritten rather than the line dropped: an access log
    # with no addresses and no account numbers still answers "is it serving,
    # what is it answering, how fast", which is what it is read for.
    _RE_ADDR = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}\b")
    # Any long-ish number that is a whole path segment: account numbers, and
    # group ids too, which name a room and are metadata in their own right. A
    # device id or an API version is one or two digits and survives, so the
    # line still says which endpoint was called and how it answered.
    _RE_ID_PATH = re.compile(r"/(\d{3,10})(?=[/?\s\"]|$)")
    # A vault slot name (stage 4a) is 32 hex characters the client derives from
    # its identity: not an account number, but a stable per-account pseudonym
    # all the same, and one line per read or write would make the access log
    # an activity feed per account again. Same treatment as the number.
    _RE_VAULT_PATH = re.compile(r"/vault/[0-9a-f]{32}(?=[/?\s\"]|$)")

    def _scrub(self, text: str, paths: bool) -> str:
        out = text
        if "token=" in out or "invite=" in out:
            out = self._RE.sub(r"\1=<redacted>", out)
        if paths:
            out = self._RE_ADDR.sub(r"\1.0", out)
            out = self._RE_ID_PATH.sub("/<id>", out)
            if "/vault/" in out:
                out = self._RE_VAULT_PATH.sub("/vault/<slot>", out)
        return out

    def _scrub_arg(self, value: object, paths: bool) -> object:
        """One positional arg, rewritten without changing its type.

        ⚠⚠ NOT EVERY ARG IS A STRING, and the first version of this filter
        assumed one. uvicorn's HTTP access line passes the client address as
        the already-formatted `"ip:port"` string, so it came out masked. Its
        WEBSOCKET lines pass `scope["client"]`, the raw `(host, port)` TUPLE,
        which `%s` renders in full, so `/ws/<id>` had its path masked and the
        address next to it did not:

            INFO: ('77.110.109.154', 0) - "WebSocket /ws/<id>?token=<redacted>"

        That is one line per connect per device, measured at ~1760 lines and
        182 distinct full addresses per half hour on the flagship, which is the
        larger half of what the 22.08 access-log work was for. Walk into the
        container and rewrite the strings inside it instead of skipping it.
        """
        if isinstance(value, str):
            return self._scrub(value, paths=paths)
        if isinstance(value, tuple):
            return tuple(self._scrub_arg(v, paths) for v in value)
        if isinstance(value, list):
            return [self._scrub_arg(v, paths) for v in value]
        return value

    def filter(self, record: logging.LogRecord) -> bool:
        # ⚠⚠ NEVER blank `record.args` on a uvicorn record. Its access formatter
        # unpacks them itself (`uvicorn/logging.py`: `(client_addr, method,
        # full_path, http_version, status_code) = recordcopy.args`), so an empty
        # tuple raises inside the formatter, and Python's logging then prints a
        # full traceback AND an `Arguments:` line holding the untouched original
        # values. Rewriting the message and dropping the args therefore turned
        # one clean line into a traceback that leaked exactly what the rewrite
        # was hiding, on every single request. Rewrite the ARGS in place and
        # leave the shape alone.
        uvicorn_record = record.name.startswith("uvicorn")
        if uvicorn_record and isinstance(record.args, tuple) and record.args:
            scrubbed = tuple(self._scrub_arg(a, True) for a in record.args)
            if scrubbed != record.args:
                record.args = scrubbed
            return True
        try:
            msg = record.getMessage()
        except Exception:  # noqa: BLE001 — a broken record must not kill logging
            return True
        cleaned = self._scrub(msg, paths=uvicorn_record)
        if cleaned != msg:
            record.msg = cleaned
            record.args = ()
        return True


def _install_log_redaction() -> None:
    # Attached to the loggers that see request lines AND to the root, because
    # the point is to be the last thing between a secret and a disk, not to
    # enumerate every logger that might one day print a URL.
    f = _RedactSecretsInLogs()
    for name in ("uvicorn.access", "uvicorn.error", "uvicorn", "rcq", ""):
        logging.getLogger(name).addFilter(f)


#: How long boot waits for the per-worker caches before taking traffic anyway.
_WARM_DEADLINE_SECONDS = 10.0


async def _warm_caches() -> None:
    """Read the settings, the logo and the headcount before this worker
    serves its first request.

    ⚠ Why it matters now: those caches serve stale values and refresh behind
    the request, so a request never waits on the pool for them (the 28.09
    stalls, core/single_flight.py) -- EXCEPT on a worker that has never read
    them, where there is no value to serve. Warming here makes that window
    boot-only instead of "the first burst after a restart".

    ⚠ Bounded, and never fatal. `init_db` has already talked to the database,
    so this normally takes milliseconds; if the database went away since, a
    worker that refuses to start is worse than one that starts cold. Cold,
    /server/info answers 503 until the settings load (never the defaults),
    `get_strict` refuses (the door reads as closed, registration answers
    503), and `_cache_ticker` retries each cache every couple of seconds.
    """
    from app.core import guest_policy, security
    from app.routers.server import warm_user_count
    from app.services import island_logo, server_settings

    deadline = time.monotonic() + _WARM_DEADLINE_SECONDS
    # The Redis mirrors (guest set, uin epochs, suspended set): built here if
    # this Redis has never held them, so no request is the one that does it.
    try:
        redis = await get_redis()
        for mirror in (guest_policy._mirror, security._EPOCH_MIRROR, security._SUSPENDED_MIRROR):
            await asyncio.wait_for(mirror.prime(redis), max(0.1, deadline - time.monotonic()))
    except Exception as exc:  # noqa: BLE001 - the request path still builds them if this fails
        _log.warning("[boot] Redis mirrors not primed (%s: %s)", type(exc).__name__, exc)
    status: tuple = ()
    while True:
        left = deadline - time.monotonic()
        if left <= 0:
            break
        status = tuple(
            await asyncio.gather(
                server_settings.warm(timeout=left),
                island_logo.warm(timeout=left),
                warm_user_count(timeout=left),
            )
        )
        if all(status):
            return
        await asyncio.sleep(min(1.0, max(0.0, deadline - time.monotonic())))
    _log.warning(
        "[boot] serving with cold caches (settings, logo, count loaded: %s); "
        "they retry in the background",
        status,
    )


#: How often the ticker below looks at the per-worker caches. It reads the
#: database only for a cache that is due (settings and logo every `_TTL`, 5 s;
#: the headcount every minute), so a second here costs nothing but a glance.
_TICK_SECONDS = 1.0


async def _cache_ticker() -> None:
    """Keep this worker's settings, logo and headcount fresh ON A CLOCK.

    ⚠⚠ Why this exists. Those caches serve a stale value and refresh behind
    the request (core/single_flight.py: a request that reloaded them inline
    was the 28.09 stalls). Left at that, how old a served value can be
    depended on traffic: a worker nobody asked for an hour answered its next
    request with the settings of an hour ago, so a paid island's quiet worker
    let the first walk-in register for free, and the till handed out the
    wallet the operator had just replaced. With this loop a running worker's
    settings are never much older than `_TTL` plus one read, idle or not,
    and no request waits for them. Every worker runs one; each costs one
    small read per cache per `_TTL`.

    Never raises out of the loop: a tick that fails is logged once a minute
    at most, and the caches' own back-off decides when the next read goes.
    """
    from app.routers.server import tick_user_count
    from app.services import island_logo, server_settings

    last_log = 0.0
    while True:
        await asyncio.sleep(_TICK_SECONDS)
        try:
            server_settings.tick()
            island_logo.tick()
            tick_user_count()
        except Exception as exc:  # noqa: BLE001 - the loop outlives any one tick
            now = time.monotonic()
            if now - last_log >= 60.0:
                last_log = now
                _log.warning("[cache-ticker] tick failed: %s: %s", type(exc).__name__, exc)


@asynccontextmanager
async def lifespan(_: FastAPI):
    _install_log_redaction()
    # Fail-closed on misconfigured JWT_SECRET. Issuing tokens signed with
    # the placeholder default would let anyone who reads the public repo
    # forge a JWT for any UIN on this server. Equally, an empty secret
    # means HS256 signs with the empty key — also forgeable. The `dev`
    # escape hatch keeps local development + the test suite ergonomic;
    # production / TestFlight / self-host operators must set a real
    # secret in .env before the first boot.
    if settings.ENV != "dev" and settings.JWT_SECRET in ("", "change-me-in-prod"):
        raise RuntimeError(
            "JWT_SECRET is unset or still the placeholder default. "
            "Set JWT_SECRET in .env to a long random string "
            "(e.g. `openssl rand -hex 32`), or set ENV=dev to allow "
            "boot with the placeholder secret for local development."
        )
    await init_db()
    # Warm the Redis client + ping the server. With multi-worker uvicorn
    # the main shared state (random-chat queue, audio-room rosters, WS
    # pub/sub fanout, rate-limit buckets) all rides on Redis — so a
    # missing Redis is a hard error we want to surface at boot, not on
    # the first user request.
    await get_redis()
    # One-shot, idempotent, before anything is served: the linked-web-session
    # registry and its revocation denylist move off key names that spelled out
    # the account number. Folding them in rather than renaming is what makes
    # this safe with four workers booting at once. See the module.
    from app.core.redis_keys import migrate_legacy_account_keys

    try:
        await migrate_legacy_account_keys()
    except Exception:  # noqa: BLE001, a key migration must never block boot
        _log.exception("[boot] legacy per-account key migration failed")
    # Teach the transport classifier which addresses are broker relays, so a
    # request from one is not filed as `direct` (the panel and the hourly log
    # disagreed by exactly this traffic). Best-effort: an island with no
    # broker rows just gets an empty set, which is what it had before.
    try:
        from app.core.db import SessionLocal
        from app.routers.broker import refresh_broker_transport_set

        async with SessionLocal() as _db:
            n = await refresh_broker_transport_set(_db)
        _log.info("[boot] transport knows %d broker relay address(es)", n)
    except Exception:  # noqa: BLE001 - never block boot on a counter
        _log.exception("[boot] broker transport set unavailable")
    await _warm_caches()
    cache_ticker_task = asyncio.create_task(_cache_ticker())
    expire_task = asyncio.create_task(random_chat.expire_loop())
    offline_queue_sweep_task = asyncio.create_task(offline_queue_sweep_loop())
    # Accounts minted and never used — see dead_account_sweep's docstring.
    dead_account_sweep_task = asyncio.create_task(dead_account_sweep_loop())
    # Retention for decrypted report evidence — see evidence_sweep's docstring.
    evidence_sweep_task = asyncio.create_task(evidence_sweep_loop())
    # A device that read the group log once and then stopped used to keep its
    # whole account off the legacy queue for ever, which on 13.09 was nine
    # people between 41 and 2011 messages behind their rooms while online. See
    # stale_reader_sweep's docstring.
    stale_reader_sweep_task = asyncio.create_task(stale_reader_sweep_loop())
    # The two website forms are the only place we hold a way to reach a
    # person, and until 07.09 they were held for ever. The privacy policy
    # now says a year; this is what makes that true.
    inquiry_sweep_task = asyncio.create_task(inquiry_sweep_loop())
    # Five-minute online samples for the hourly activity history. Every worker
    # runs one; the write is a max() into a shared Redis hash, so the extras
    # cost a SCARD each and change nothing.
    from app.services.activity_rollup import activity_sampler_loop

    activity_sampler_task = asyncio.create_task(activity_sampler_loop())
    # Retention for accepted contact requests — the relationship lives in
    # `contacts`, the request row does not need to outlive it.
    from app.services.contact_request_sweep import contact_request_sweep_loop

    contact_request_sweep_task = asyncio.create_task(contact_request_sweep_loop())
    # Retention for the `identity_rotated` markers /auth/reissue leaves behind.
    # See retired_key_sweep's docstring for the horizon and what shortening it
    # costs.
    from app.services.retired_key_sweep import retired_key_sweep_loop

    retired_key_sweep_task = asyncio.create_task(retired_key_sweep_loop())
    # Lifetimes of guest copies from other islands: unclaimed seats after a
    # week, guests that never polled after a week, idle guests after 60 days.
    # See guest_sweep's docstring (spec 2026-09-15, 8.4).
    from app.services.guest_sweep import guest_sweep_loop

    guest_sweep_task = asyncio.create_task(guest_sweep_loop())
    # Retention for the encrypted media store — see media_sweep's docstring
    # (30-day age sweep that spares avatars and report evidence).
    from app.services.media_sweep import media_sweep_loop

    media_sweep_task = asyncio.create_task(media_sweep_loop())
    # ── Retention, stage 1b (2026-08-22) ────────────────────────────────────
    # The metadata map's recurring finding was rows outliving the thing they
    # describe. Each loop below closes one of those; each module's docstring
    # carries the horizon and the reasoning for it, and each takes a
    # RCQ_*_SWEEP_DRY_RUN=1 env switch. All are leader-elected, so only one of
    # the four workers does the work in any cycle.
    from app.services.credential_sweep import credential_sweep_loop
    from app.services.device_sweep import device_sweep_loop
    from app.services.gossip_sweep import gossip_sweep_loop
    from app.services.prekey_sweep import prekey_sweep_loop
    from app.services.presence_sweep import presence_sweep_loop
    from app.services.report_sweep import report_sweep_loop

    retention_tasks = [
        # Consumed one-time prekeys: a dated per-account count of how many
        # strangers opened a session toward you.
        asyncio.create_task(prekey_sweep_loop()),
        # Closed reports: operator notes about named people, attachment AES
        # keys, and the plaintext support thread.
        asyncio.create_task(report_sweep_loop()),
        # Revoked device slots, once the id is safe to hand out again.
        asyncio.create_task(device_sweep_loop()),
        # (The poll sweep was here. Polls were removed whole on 2026-08-23, so
        # there is nothing left to age out: no writer, no model, and the two
        # orphaned tables are frozen until the operator drops them by hand.
        # See routers/polls.py and the block in core/db.py.)
        # Spent invites and dead network-gate tokens.
        asyncio.create_task(credential_sweep_loop()),
        # Ghosts in the cluster-wide online set, which had no TTL at all.
        asyncio.create_task(presence_sweep_loop()),
        # Federation gossip mirrors nobody resolves any more. The last of the
        # map's section-2 items, and the only one that needed a design rather
        # than a horizon: the row is keyed by a signing key, so the burn path
        # could not see it, and it is a mirror other islands read, so a plain
        # age cutoff would break the fallback it exists to serve.
        asyncio.create_task(gossip_sweep_loop()),
    ]
    try:
        yield
    finally:
        cache_ticker_task.cancel()
        expire_task.cancel()
        offline_queue_sweep_task.cancel()
        dead_account_sweep_task.cancel()
        evidence_sweep_task.cancel()
        stale_reader_sweep_task.cancel()
        inquiry_sweep_task.cancel()
        activity_sampler_task.cancel()
        contact_request_sweep_task.cancel()
        retired_key_sweep_task.cancel()
        guest_sweep_task.cancel()
        media_sweep_task.cancel()
        for task in retention_tasks:
            task.cancel()
        # The fanout subscriber first, while Redis is still there to say
        # goodbye to; closing the client under it logged a traceback per
        # worker on every deploy.
        await manager.shutdown()
        await close_redis()


# A masquerade/closed island disables /docs + /openapi.json — they're the
# loudest "this is RCQ" fingerprint behind the gate.
_docs_kwargs = (
    {"docs_url": None, "redoc_url": None, "openapi_url": None}
    if settings.RCQ_DOCS_DISABLED else {}
)
app = FastAPI(title=settings.APP_NAME, lifespan=lifespan, **_docs_kwargs)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
    # The roster's validator: a browser cannot read a response header that is
    # not listed here, and without it the web client can never ask "still the
    # same?" (GET /contacts answers 304 to If-None-Match).
    expose_headers=["ETag"],
    allow_credentials=False,
)

_log = logging.getLogger("rcq")


def _pool_gauge() -> tuple[int | None, int | None]:
    """(connections handed out, the wall) for the database pool.

    The ceiling is `pool_size + max_overflow` — the configured maximum. NOT
    `overflow()`, which is how far past the size we are right now and goes
    negative while idle, so using it made the ceiling move under the reading.
    """
    pool = getattr(engine, "pool", None)
    if pool is None:
        return None, None
    try:
        in_use = pool.checkedout() if callable(getattr(pool, "checkedout", None)) else None
        size = pool.size() if callable(getattr(pool, "size", None)) else None
        extra = getattr(pool, "_max_overflow", None)
        ceiling = size + extra if size is not None and isinstance(extra, int) and extra >= 0 else None
        return in_use, ceiling
    except Exception:
        return None, None


class _BodyClock:
    """Outermost ASGI wrapper: clocks how long `receive()` spends waiting for
    the request BODY's chunks, so the timing middleware below can subtract
    the client's half of the wire from what it reports as server work. An
    endpoint with no body never awaits receive, so GETs cost nothing here.
    Stored on the scope: the Request object the inner middleware sees is a
    different instance, but the scope dict is the same one."""

    def __init__(self, app):  # noqa: ANN001 - ASGI app
        self.app = app

    async def __call__(self, scope, receive, send):  # noqa: ANN001
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        waited = {"s": 0.0}
        scope["rcq_body_wait"] = waited

        async def timed_receive():
            t0 = time.perf_counter()
            msg = await receive()
            waited["s"] += time.perf_counter() - t0
            return msg

        await self.app(scope, timed_receive, send)


app.add_middleware(_BodyClock)


@app.middleware("http")
async def record_metrics(request: Request, call_next):
    """Time every request into the in-memory minute buckets.

    The template, not the URL: `/groups/{group_id}` and not `/groups/21`, so a
    thousand group ids stay one row and no id ends up in a counter key.

    The uin comes from whatever the endpoint already resolved onto the request
    state — this does not decode a token of its own. Sealed-sender endpoints
    are unauthenticated by design and so are simply anonymous here, which is
    the honest answer: we genuinely do not know who sent them.
    """
    started = time.perf_counter()
    status_code = 500
    try:
        response = await call_next(request)
        status_code = response.status_code
        return response
    finally:
        route = request.scope.get("route")
        path = getattr(route, "path", None) or "(unmatched)"
        in_use, ceiling = _pool_gauge()
        # The client's half of the clock (waiting for its body chunks),
        # measured by _BodyClock outside us. Subtracted so the path rows
        # say what the SERVER did; a stalled upload is counted separately.
        body_s = float(request.scope.get("rcq_body_wait", {}).get("s", 0.0))
        metrics.record_request(
            path=path,
            seconds=max(0.0, time.perf_counter() - started - body_s),
            body_seconds=body_s,
            status_code=status_code,
            uin=getattr(request.state, "uin", None),
            pool_in_use=in_use,
            pool_ceiling=ceiling,
            # Classified here, where the address is still whole, and counted
            # rather than stored — Caddy's log masks it now, and the exact
            # relay match this needs cannot survive that (see core/transport).
            transport=transport_of(_client_ip(request)),
        )


@app.exception_handler(Exception)
async def cors_aware_internal_error(request: Request, exc: Exception):
    """Return unhandled 500s WITH a CORS header.

    Starlette produces a bare 500 from ServerErrorMiddleware, which sits OUTSIDE
    CORSMiddleware — so without this the response carries no
    Access-Control-Allow-Origin and a browser reports the failure as a phantom
    "CORS error" instead of the real server error. HTTPExceptions (401/403/404/…)
    already get CORS via the inner handler; this only covers true unhandled
    exceptions. We still log the traceback so it stays visible in the logs.
    Mirrors CORSMiddleware's allow_origins=["*"].

    ⚠⚠ One exception is answered differently, and the difference is the whole
    point: running out of POOLED CONNECTIONS is not a bug in this request, it is
    the island being too busy to take it right now. On 13.09.2026 that arrived as
    `QueuePool limit of size 5 overflow 5 reached, connection timed out, timeout
    20.00` and every one of them became a 500 — which every client read as "the
    server is broken", retried immediately, and so made the queue longer. Peak
    was 435 of them in a minute while the box itself was 86% idle.

    A 503 with Retry-After says the true thing, and it says it in the one
    vocabulary every HTTP client already understands: come back, not "give up"
    and not "hammer me". The twenty seconds the request already spent waiting is
    not charged to the person again; the header asks for a short, jittered wait,
    and the jitter is deliberate, because a fixed number turns a crowd into a
    metronome and brings the same wave back in unison.
    """
    if isinstance(exc, SQLAlchemyTimeoutError):
        return await pool_exhausted(request, exc)
    _log.exception("Unhandled error on %s %s", request.method, _route_template(request))
    return JSONResponse(
        {"detail": "internal_error"},
        status_code=500,
        headers={"Access-Control-Allow-Origin": "*"},
    )


def _route_template(request: Request) -> str:
    """`/users/{uin}/info`, never `/users/995814918/info`.

    ⚠ The raw path put account numbers into the journal: the 503 line below
    wrote one per refused request, 1,797 of them on 28.09 alone, while the
    access log and Caddy both mask the same numbers. The template says which
    endpoint was refused, which is all the line is read for."""
    route = request.scope.get("route")
    return getattr(route, "path", None) or "(unmatched)"


@app.exception_handler(SQLAlchemyTimeoutError)
async def pool_exhausted(request: Request, exc: Exception):
    """503 island_busy for a pool checkout that timed out. See the handler
    above for why a 503 and not a 500.

    ⚠⚠ REGISTERED FOR THE EXCEPTION CLASS, not only caught in the catch-all
    above, and that is the log fix. A handler for `Exception` runs in
    Starlette's ServerErrorMiddleware, which sends the response and then
    RE-RAISES, so uvicorn printed "Exception in ASGI application" and a ~100
    line ExceptionGroup traceback after every one of these warnings. On 28.09
    journald dropped ~171k lines in three minutes of a stall, and with them
    most of the evidence. A handler for the class itself runs in
    ExceptionMiddleware, which answers and stops: one line per refusal.
    """
    # Not `exception`: a busy minute would write hundreds of identical
    # tracebacks, and the one that matters is the pool gauge, not the stack.
    in_use, ceiling = _pool_gauge()
    if request.scope.get("type") != "http":
        # ⚠ A WEBSOCKET lands here too: a handler registered for an exception
        # class runs for every scope, and Starlette hands it the WebSocket.
        # That has no `.method` and takes no JSONResponse, so the HTTP branch
        # below crashed with AttributeError and uvicorn printed two chained
        # tracebacks per socket, the very noise this handler removes. During
        # a stall ws.py raises the pool timeout out of the connect, ping and
        # disconnect paths. One line, and the socket is closed with 1013 "try
        # again later". The web and iOS clients redial on their ordinary
        # backoff for any code but 4000/4401/4403 (web-chat lib/ws.tsx,
        # iOS WebSocketService); Android was not checked.
        _log.warning(
            "Pool exhausted on WS %s (%s/%s checked out)",
            _route_template(request), in_use, ceiling,
        )
        try:
            await request.close(code=1013)
        except Exception:  # noqa: BLE001 - already closed by the client or by ws.py
            pass
        return None
    _log.warning(
        "Pool exhausted on %s %s (%s/%s checked out)",
        request.method, _route_template(request), in_use, ceiling,
    )
    return JSONResponse(
        {"detail": "island_busy"},
        status_code=503,
        headers={
            "Retry-After": str(2 + secrets.randbelow(6)),
            "Access-Control-Allow-Origin": "*",
        },
    )


app.include_router(auth.router)
app.include_router(users.router)
app.include_router(contacts.router)
app.include_router(federation.router)
app.include_router(broker.router)
app.include_router(deposit_auth.router)
app.include_router(groups.router)
app.include_router(messages.router)
app.include_router(keys.router)
app.include_router(guest_cards.router)
app.include_router(invites.router)
app.include_router(residency.router)
app.include_router(media.router)
app.include_router(presence.router)
app.include_router(random_chat.router, dependencies=[Depends(require_feature("random_enabled"))])
app.include_router(audio_rooms.router)
app.include_router(reports.router)
# Polls were removed on 2026-08-23. These two routers are the 410 tombstone
# that keeps a shipped composer from meeting a bare routing 404, NOT a feature.
# routers/polls.py carries the reasoning and the condition for deleting them.
app.include_router(polls.router)
app.include_router(polls.group_polls_router)
app.include_router(news.public_router)
app.include_router(news.admin_router)
# `.rcq` sites (docs/rcq-sites-design.md). Reads are unauthenticated by design:
# the island must not be able to build a record of who read what.
app.include_router(sites.router)
app.include_router(sites.admin_router)
app.include_router(admin.router)
app.include_router(migrate.router)
app.include_router(uin_shop.router)
# The till's one question about entry (price + wallets), signed. Not gated on
# the number shop: residency sells with the shop closed (routers/entry.py).
app.include_router(entry.router)
app.include_router(public.router)
app.include_router(server.router)
app.include_router(link.router)
app.include_router(devices.router)
app.include_router(vault.router)
app.include_router(gate.router)
app.include_router(ws.router)


@app.get("/health")
async def health() -> dict:
    return {"ok": True, "app": settings.APP_NAME, "version": settings.SERVER_VERSION}


#: The probe below, at most one in flight per worker, and its last answer.
_DB_PROBE = SingleFlight("health-db")
_DB_PROBE_LAST: tuple[float, bool] = (-1e9, False)
_DB_PROBE_TIMEOUT = 3.0
#: A flood of /health/db is answered from the last probe for this long, so
#: the endpoint costs the pool at most one checkout per worker per second
#: whoever calls it.
_DB_PROBE_REUSE = 1.0


async def _probe_db() -> bool:
    global _DB_PROBE_LAST

    async def _checkout_and_select() -> None:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))

    try:
        await asyncio.wait_for(_checkout_and_select(), _DB_PROBE_TIMEOUT)
        ok = True
    except Exception:  # noqa: BLE001 - any failure is "not ok", and says nothing more
        ok = False
    _DB_PROBE_LAST = (time.monotonic(), ok)
    return ok


@app.get("/health/db")
async def health_db():
    """Can this worker get a pooled connection and run a query, within 3 s?

    ⚠ The probe for the database, and the only one. `/health` never touches
    it, and `/server/info` no longer does on a warm worker (it serves from
    memory), so after the 28.09 fix a stalled pool would be invisible to the
    monitor without this.

    ⚠ The body is `{"ok": true}` or a 503 `{"ok": false}` and nothing else.
    It is unauthenticated, and pool counters or error text would tell anybody
    who asks how loaded the island is and when a push would hurt it.

    One checkout plus `SELECT 1` under a 3 s timeout, shared by concurrent
    callers on the worker, and reused for a second, so this endpoint cannot
    itself become the load it measures. It answers for ONE worker, whichever
    the request lands on; a stall on one worker of four may take a few probes
    to be seen.
    """
    at, ok = _DB_PROBE_LAST
    if time.monotonic() - at >= _DB_PROBE_REUSE:
        # The caller's own wait is bounded too: a probe cancelled mid-query
        # can take a while to hand its connection back (the reset on return
        # waits for the database it just gave up on), and a caller that
        # joined it must still get its answer within the 3 s.
        ok = await _DB_PROBE.wait(_DB_PROBE.start(_probe_db), _DB_PROBE_TIMEOUT)
    if ok:
        return JSONResponse({"ok": True}, headers={"Cache-Control": "no-store"})
    return JSONResponse(
        {"ok": False},
        status_code=503,
        headers={"Retry-After": "5", "Cache-Control": "no-store"},
    )


# Nothing on an island is for a search engine. `.rcq` sites are served without
# a login on purpose (the island must not be able to log who read what), which
# means anyone holding the address can fetch one — and without this file that
# "anyone" quietly included crawlers, so a page somebody published for the
# people in one chat was on its way into a web index (report #976, 12.09).
# A single Disallow keeps the design and removes the surprise. The same answer
# for every path: an API host has no page that wants indexing.
@app.get("/robots.txt", include_in_schema=False)
async def robots() -> PlainTextResponse:
    return PlainTextResponse("User-agent: *\nDisallow: /\n")
