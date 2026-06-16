import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.core.config import settings
from app.core.db import init_db
from app.core.feature_gate import require_feature
from app.core.redis import close_redis, get_redis
from app.routers import admin, audio_rooms, auth, broker, contacts, deposit_auth, devices, federation, gate, groups, hood, hood_banners, keys, link, media, messages, migrate, nearby, news, polls, presence, public, referrals, reports, server, stories, uin_shop, users, ws
from app.routers import random as random_chat
from app.services.fake_users import seed_fake_users
from app.services.offline_queue_sweep import offline_queue_sweep_loop
from app.services.story_sweep import story_sweep_loop


@asynccontextmanager
async def lifespan(_: FastAPI):
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
    # Demo fakes are opt-in (default off) so self-hosted islands never seed
    # phantom accounts. The flagship keeps its long-ago-seeded fakes regardless
    # (seeding is idempotent); this just stops new islands from getting any.
    if settings.SEED_FAKE_USERS:
        await seed_fake_users()
    expire_task = asyncio.create_task(random_chat.expire_loop())
    story_sweep_task = asyncio.create_task(story_sweep_loop())
    offline_queue_sweep_task = asyncio.create_task(offline_queue_sweep_loop())
    try:
        yield
    finally:
        expire_task.cancel()
        story_sweep_task.cancel()
        offline_queue_sweep_task.cancel()
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
app.include_router(hood_banners.router, dependencies=[Depends(require_feature("hood_enabled"))])
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
