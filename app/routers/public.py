"""Unauthenticated landing-page endpoints."""

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Response
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import get_db
from app.models.user import User

router = APIRouter(prefix="/public", tags=["public"])


class ActiveTesterOut(BaseModel):
    nickname: str


class ActiveTestersResponse(BaseModel):
    testers: list[ActiveTesterOut]


# Users who came back to the app at least an hour after registering
# (filters out the bot-registered-and-bounced cohort) AND have been
# online within the active window. last_seen is bumped on every WS
# (re)connect, so this maps to "opened the app recently".
RETURN_THRESHOLD = timedelta(hours=1)
ACTIVE_WINDOW = timedelta(days=14)
TESTER_LIMIT = 50


@router.get("/active-testers", response_model=ActiveTestersResponse)
async def active_testers(
    response: Response,
    db: AsyncSession = Depends(get_db),
) -> ActiveTestersResponse:
    now = datetime.now(timezone.utc)
    active_since = now - ACTIVE_WINDOW
    stmt = (
        select(User.nickname)
        .where(
            User.is_fake.is_(False),
            User.is_suspended.is_(False),
            User.last_seen >= active_since,
            User.last_seen >= User.created_at + RETURN_THRESHOLD,
        )
        .order_by(User.last_seen.desc())
        .limit(TESTER_LIMIT)
    )
    rows = (await db.execute(stmt)).scalars().all()
    response.headers["Cache-Control"] = "public, max-age=60"
    return ActiveTestersResponse(
        testers=[ActiveTesterOut(nickname=nick) for nick in rows]
    )


class HofEntry(BaseModel):
    uin: int
    nickname: str


class HofResponse(BaseModel):
    members: list[HofEntry]


@router.get("/hof", response_model=HofResponse)
async def hall_of_fame(
    response: Response,
    db: AsyncSession = Depends(get_db),
) -> HofResponse:
    """Public Hall of Fame wall. A member shows here only when BOTH the user
    opted in (`hof_opt_in`, set from their client) AND the founder approved
    them (`hof_approved`, set from the admin console). Nickname + uin only —
    the same always-public identity fields the contact card already exposes.
    Cached 5 min."""
    stmt = (
        select(User.uin, User.nickname)
        .where(
            User.hof_approved.is_(True),
            User.hof_opt_in.is_(True),
            User.is_fake.is_(False),
            User.is_suspended.is_(False),
        )
        .order_by(User.nickname.asc())
    )
    rows = (await db.execute(stmt)).all()
    response.headers["Cache-Control"] = "public, max-age=300"
    return HofResponse(members=[HofEntry(uin=r.uin, nickname=r.nickname) for r in rows])


class StatsResponse(BaseModel):
    user_count: int


@router.get("/stats", response_model=StatsResponse)
async def stats(
    response: Response,
    db: AsyncSession = Depends(get_db),
) -> StatsResponse:
    """Public headline stats. `user_count` = real (non-fake) registered
    accounts — surfaced in the iOS About sheet as a "X people on RCQ"
    badge. Cached 2 min; the number moves slowly enough."""
    count = await db.scalar(
        select(func.count(User.uin)).where(User.is_fake.is_(False))
    )
    response.headers["Cache-Control"] = "public, max-age=120"
    return StatsResponse(user_count=int(count or 0))
