import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.core.db import init_db
from app.core.redis import close_redis, get_redis
from app.routers import admin, audio_rooms, auth, contacts, groups, hood, hood_banners, keys, media, messages, migrate, nearby, news, polls, presence, public, referrals, reports, stories, uin_shop, users, ws
from app.routers import random as random_chat
from app.services.fake_users import seed_fake_users
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
    await seed_fake_users()
    expire_task = asyncio.create_task(random_chat.expire_loop())
    story_sweep_task = asyncio.create_task(story_sweep_loop())
    try:
        yield
    finally:
        expire_task.cancel()
        story_sweep_task.cancel()
        await close_redis()


app = FastAPI(title=settings.APP_NAME, lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=False,
)

app.include_router(auth.router)
app.include_router(users.router)
app.include_router(contacts.router)
app.include_router(groups.router)
app.include_router(messages.router)
app.include_router(keys.router)
app.include_router(media.router)
app.include_router(nearby.router)
app.include_router(presence.router)
app.include_router(random_chat.router)
app.include_router(audio_rooms.router)
app.include_router(hood.router)
app.include_router(hood_banners.router)
app.include_router(reports.router)
app.include_router(polls.router)
app.include_router(polls.group_polls_router)
app.include_router(news.public_router)
app.include_router(news.admin_router)
app.include_router(admin.router)
app.include_router(stories.router)
app.include_router(migrate.router)
app.include_router(uin_shop.router)
app.include_router(referrals.router)
app.include_router(public.router)
app.include_router(ws.router)


@app.get("/health")
async def health() -> dict:
    return {"ok": True, "app": settings.APP_NAME}
