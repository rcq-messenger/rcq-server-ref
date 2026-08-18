import asyncio
import logging
import re
import time
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.core.config import settings
from app.core.db import engine, init_db
from app.core import metrics
from app.core.feature_gate import require_feature
from app.core.rate_limit import _client_ip
from app.core.redis import close_redis, get_redis
from app.core.transport import classify as transport_of
from app.routers import admin, audio_rooms, auth, broker, contacts, deposit_auth, devices, federation, gate, groups, hood, keys, link, media, messages, migrate, nearby, news, polls, presence, public, referrals, reports, server, stories, uin_shop, users, ws
from app.routers import random as random_chat
from app.services.evidence_sweep import evidence_sweep_loop
from app.services.nearby_sweep import nearby_sweep_loop
from app.services.offline_queue_sweep import offline_queue_sweep_loop
from app.services.story_sweep import story_sweep_loop


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

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            msg = record.getMessage()
        except Exception:  # noqa: BLE001 — a broken record must not kill logging
            return True
        if "token=" in msg or "invite=" in msg:
            record.msg = self._RE.sub(r"\1=<redacted>", msg)
            record.args = ()
        return True


def _install_log_redaction() -> None:
    # Attached to the loggers that see request lines AND to the root, because
    # the point is to be the last thing between a secret and a disk, not to
    # enumerate every logger that might one day print a URL.
    f = _RedactSecretsInLogs()
    for name in ("uvicorn.access", "uvicorn.error", "uvicorn", "rcq", ""):
        logging.getLogger(name).addFilter(f)


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
    expire_task = asyncio.create_task(random_chat.expire_loop())
    story_sweep_task = asyncio.create_task(story_sweep_loop())
    offline_queue_sweep_task = asyncio.create_task(offline_queue_sweep_loop())
    # Retention for decrypted report evidence — see evidence_sweep's docstring.
    evidence_sweep_task = asyncio.create_task(evidence_sweep_loop())
    # Retention for expired People-Nearby check-ins (geohash buckets tied to a
    # UIN were previously filtered on read but never deleted).
    nearby_sweep_task = asyncio.create_task(nearby_sweep_loop())
    # Five-minute online samples for the hourly activity history. Every worker
    # runs one; the write is a max() into a shared Redis hash, so the extras
    # cost a SCARD each and change nothing.
    from app.services.activity_rollup import activity_sampler_loop

    activity_sampler_task = asyncio.create_task(activity_sampler_loop())
    try:
        yield
    finally:
        expire_task.cancel()
        story_sweep_task.cancel()
        offline_queue_sweep_task.cancel()
        evidence_sweep_task.cancel()
        nearby_sweep_task.cancel()
        activity_sampler_task.cancel()
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
        metrics.record_request(
            path=path,
            seconds=time.perf_counter() - started,
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
    """
    _log.exception("Unhandled error on %s %s", request.method, request.url.path)
    return JSONResponse(
        {"detail": "internal_error"},
        status_code=500,
        headers={"Access-Control-Allow-Origin": "*"},
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
app.include_router(media.router)
app.include_router(nearby.router, dependencies=[Depends(require_feature("nearby_enabled"))])
app.include_router(presence.router)
app.include_router(random_chat.router, dependencies=[Depends(require_feature("random_enabled"))])
app.include_router(audio_rooms.router)
app.include_router(hood.router, dependencies=[Depends(require_feature("hood_enabled"))])
app.include_router(reports.router)
app.include_router(polls.router)
app.include_router(polls.group_polls_router)
app.include_router(news.public_router)
app.include_router(news.admin_router)
app.include_router(admin.router)
app.include_router(stories.router, dependencies=[Depends(require_feature("stories_enabled"))])
app.include_router(migrate.router)
app.include_router(uin_shop.router)
app.include_router(referrals.router)
app.include_router(public.router)
app.include_router(server.router)
app.include_router(link.router)
app.include_router(devices.router)
app.include_router(gate.router)
app.include_router(ws.router)


@app.get("/health")
async def health() -> dict:
    return {"ok": True, "app": settings.APP_NAME, "version": settings.SERVER_VERSION}
