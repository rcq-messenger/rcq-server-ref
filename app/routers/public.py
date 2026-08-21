"""Unauthenticated landing-page endpoints."""

from datetime import datetime, timedelta, timezone

import logging

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import get_db
from app.core.rate_limit import rate_limit
from app.models.relay_inquiry import RelayInquiry
from app.models.user import User
from app.services.hof_stats import bug_report_stats, effort_score, podium_score

log = logging.getLogger(__name__)

router = APIRouter(prefix="/public", tags=["public"])

# Wall ordering — gold flowers first, then silver, then bronze, alphabetical
# within a tier. A curated wall, not a leaderboard, so the only signal in the
# order is the founder's rating; report counts never reorder anyone.
# Ruby sits ABOVE gold (founder, 21.08): the fourth, rarest grade, for a
# contribution the wall's other three don't reach.
_TIER_RANK = {"ruby": -1, "gold": 0, "silver": 1, "bronze": 2}


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
    # True when this member uploaded an avatar; the wall then loads it from
    # GET /public/hof/{uin}/avatar (kept out of the list to keep it small).
    has_avatar: bool = False
    # Founder-assigned rating → which flower the wall draws (bronze/silver/gold).
    tier: str = "gold"
    # Bug-bounty effort. `reports` is the count the wall shows in the center of
    # the ring; `confirmed` is how many were real bugs; `effort` (0..1) is the
    # ring fill, red→amber→green. Members who never reported bugs are (0, 0, 0)
    # and the wall draws a neutral ring — they earn their place via `tier`.
    reports: int = 0
    confirmed: int = 0
    effort: float = 0.0
    # 1, 2 or 3 for the podium, null for everyone else. The wall draws the top
    # three separately; the rest of the list is unchanged. Only gold-flower
    # members are eligible, so the podium is never something a person can climb
    # onto by volume alone without the founder's own judgement first.
    rank: int | None = None


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
        select(User.uin, User.nickname, User.hof_avatar, User.hof_tier)
        .where(
            User.hof_approved.is_(True),
            User.hof_opt_in.is_(True),
            User.is_suspended.is_(False),
        )
    )
    rows = (await db.execute(stmt)).all()
    stats = await bug_report_stats(db, [r.uin for r in rows])
    members = []
    for r in rows:
        total, confirmed = stats.get(r.uin, (0, 0))
        members.append(
            HofEntry(
                uin=r.uin,
                nickname=r.nickname,
                has_avatar=bool(r.hof_avatar),
                tier=(r.hof_tier or "gold"),
                reports=total,
                confirmed=confirmed,
                effort=effort_score(confirmed),
            )
        )
    # Podium: the three highest-scoring GOLD members who have had at least one
    # bug confirmed. Gold is a prerequisite rather than a tiebreak — the flower
    # is the founder's call, and the score only ranks people he already vouched
    # for. Ruby counts too: it sits above gold, and a promotion must never
    # cost somebody their podium place. Ties fall back to confirmed count,
    # then nickname, so the order is stable between requests instead of
    # wobbling with dict order.
    contenders = sorted(
        (m for m in members if m.tier in ("gold", "ruby") and m.confirmed > 0),
        key=lambda m: (-podium_score(m.reports, m.confirmed), -m.confirmed, m.nickname.lower()),
    )
    for place, m in enumerate(contenders[:3], start=1):
        m.rank = place
    # Podium first in the order it was earned, then the wall as it always was.
    members.sort(key=lambda m: (
        m.rank if m.rank is not None else 99,
        _TIER_RANK.get(m.tier, 0),
        m.nickname.lower(),
    ))
    response.headers["Cache-Control"] = "public, max-age=300"
    return HofResponse(members=members)


@router.get("/hof/{uin}/avatar")
async def hall_of_fame_avatar(
    uin: int,
    response: Response,
    db: AsyncSession = Depends(get_db),
) -> Response:
    """Serve an APPROVED member's HoF avatar image. The stored value is a
    `data:<mime>;base64,<b64>` URI; we decode it and return the raw image bytes
    so the wall can use a plain <img>. 404 unless the uin is an approved,
    opted-in, non-suspended member WITH an avatar — so an avatar is never
    public before the founder approves. Cached 5 min."""
    from base64 import b64decode

    row = (
        await db.execute(
            select(User.hof_avatar).where(
                User.uin == uin,
                User.hof_approved.is_(True),
                User.hof_opt_in.is_(True),
                User.is_suspended.is_(False),
            )
        )
    ).first()
    data_uri = row[0] if row else None
    if not data_uri or not data_uri.startswith("data:") or ";base64," not in data_uri:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no avatar")
    header, b64 = data_uri.split(";base64,", 1)
    mime = header[len("data:"):].strip().lower() or "application/octet-stream"
    try:
        blob = b64decode(b64, validate=True)
    except Exception:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no avatar")
    return Response(content=blob, media_type=mime, headers={"Cache-Control": "public, max-age=300"})


class StatsResponse(BaseModel):
    user_count: int


@router.get("/stats", response_model=StatsResponse)
async def stats(
    response: Response,
    db: AsyncSession = Depends(get_db),
) -> StatsResponse:
    """Public headline stats. `user_count` = registered
    accounts — surfaced in the iOS About sheet as a "X people on RCQ"
    badge. Cached 2 min; the number moves slowly enough."""
    count = await db.scalar(
        select(func.count(User.uin))
    )
    response.headers["Cache-Control"] = "public, max-age=120"
    return StatsResponse(user_count=int(count or 0))


# ── private-relay inquiries (the /organizations form) ──────────────────────
#
# The page's submit button used to be a mock: it slept 700ms and said thank
# you, storing nothing. Someone asking to pay us was answered by an animation.
# This lands the request in a queue an operator actually reads (admin.rcq.app
# → Inquiries), which is step one of `docs/private-relays-design.md` and the
# step that does not need a payment rail to be worth anything.
#
# Unauthenticated on purpose: the audience is organisations that do not have
# an account yet. That is spammable, so the route is rate limited per IP,
# every field is capped by the schema, and the queue can dismiss in one click.


class RelayInquiryIn(BaseModel):
    tier: str = Field(default="team", max_length=32)
    contact: str = Field(min_length=3, max_length=200)
    about: str = Field(default="", max_length=4000)
    lang: str = Field(default="", max_length=8)


class RelayInquiryOut(BaseModel):
    ok: bool


@router.post(
    "/relay-inquiry",
    response_model=RelayInquiryOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(rate_limit("relay_inquiry", 5, 3600))],
)
async def relay_inquiry(
    body: RelayInquiryIn,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> RelayInquiryOut:
    contact = body.contact.strip()
    if len(contact) < 3:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail={"code": "contact_required"})
    row = RelayInquiry(
        tier=body.tier.strip()[:32] or "team",
        contact=contact,
        about=body.about.strip(),
        lang=body.lang.strip()[:8],
        # Cloudflare gives us a country on the edge; it is a spam-triage hint,
        # not a record of the person. No IP is stored.
        country=(request.headers.get("cf-ipcountry") or "")[:8],
    )
    db.add(row)
    await db.commit()
    log.warning("[relay-inquiry] tier=%s country=%s", row.tier, row.country)
    return RelayInquiryOut(ok=True)
