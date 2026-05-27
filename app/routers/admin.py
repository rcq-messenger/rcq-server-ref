"""Admin endpoints — gated by HTTP Basic against `ADMIN_USERNAME` /
`ADMIN_PASSWORD` from `.env`. Consumed by the static SPA at
`admin.rcq.app`.

Surfaces:
  • Reports queue: list / resolve, see who filed against whom
  • Users: search by uin/nickname, view summary, ban / unban
  • Stats: signups, DAU, total users, open-reports
  • Activity feed: recent admin actions
  • Live presence: who's connected right now
"""

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import desc, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import get_db
from app.core.security import require_admin
from app.models.report import Report
from app.models.user import User, effective_status

router = APIRouter(
    prefix="/admin",
    tags=["admin"],
    dependencies=[Depends(require_admin)],
)


# ── DTOs ────────────────────────────────────────────────────────────


class ReportAttachmentOut(BaseModel):
    media_id: str
    key: str
    mime: str
    size: int = 0


class ReportOut(BaseModel):
    id: int
    reporter_uin: int
    reporter_nickname: str | None
    target_uin: int
    target_nickname: str | None
    reason: str
    context: str
    status: str
    resolution_action: str
    resolution_notes: str
    created_at: datetime
    resolved_at: datetime | None
    attachments: list[ReportAttachmentOut] = []


class ReportsListOut(BaseModel):
    items: list[ReportOut]
    open_count: int


class ResolveReportIn(BaseModel):
    action: str = Field(..., min_length=1, max_length=32)
    notes: str = Field(default="", max_length=2000)
    ban_target: bool = False


class UserSummary(BaseModel):
    uin: int
    nickname: str
    is_suspended: bool
    is_fake: bool
    status: str
    last_seen: datetime
    created_at: datetime
    reports_against: int


class UserSearchOut(BaseModel):
    items: list[UserSummary]


class BanIn(BaseModel):
    suspended: bool


class StatsOut(BaseModel):
    total_users: int
    fake_users: int
    suspended_users: int
    new_users_24h: int
    new_users_7d: int
    open_reports: int
    resolved_reports_7d: int


# ── Reports ─────────────────────────────────────────────────────────


@router.get("/reports", response_model=ReportsListOut)
async def list_reports(
    status_filter: str = Query("open", alias="status"),
    limit: int = Query(50, le=200),
    db: AsyncSession = Depends(get_db),
) -> ReportsListOut:
    """`status` accepts: open | resolved | dismissed | duplicate | all."""
    query = select(Report).order_by(desc(Report.created_at)).limit(limit)
    if status_filter != "all":
        query = query.where(Report.status == status_filter)
    rows = (await db.execute(query)).scalars().all()

    uins: set[int] = set()
    for r in rows:
        uins.add(r.reporter_uin)
        uins.add(r.target_uin)
    nicks: dict[int, str] = {}
    if uins:
        for u in (await db.execute(select(User).where(User.uin.in_(uins)))).scalars().all():
            nicks[u.uin] = u.nickname

    open_count = await db.scalar(
        select(func.count(Report.id)).where(Report.status == "open")
    ) or 0

    items = [
        ReportOut(
            id=r.id,
            reporter_uin=r.reporter_uin,
            reporter_nickname=nicks.get(r.reporter_uin),
            target_uin=r.target_uin,
            target_nickname=nicks.get(r.target_uin),
            reason=r.reason,
            context=r.context,
            status=r.status,
            resolution_action=r.resolution_action,
            resolution_notes=r.resolution_notes,
            created_at=r.created_at,
            resolved_at=r.resolved_at,
            attachments=_coerce_attachments(r.attachments),
        )
        for r in rows
    ]
    return ReportsListOut(items=items, open_count=int(open_count))


def _coerce_attachments(raw) -> list[ReportAttachmentOut]:
    """Defensive coercion — the JSON column may have older entries with
    missing fields. Drop malformed rows rather than 500 the queue."""
    if not raw or not isinstance(raw, list):
        return []
    out: list[ReportAttachmentOut] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        media_id = item.get("media_id")
        key = item.get("key")
        mime = item.get("mime")
        if not (isinstance(media_id, str) and isinstance(key, str) and isinstance(mime, str)):
            continue
        out.append(ReportAttachmentOut(
            media_id=media_id,
            key=key,
            mime=mime,
            size=int(item.get("size") or 0),
        ))
    return out


@router.post("/reports/{report_id}/resolve", response_model=ReportOut)
async def resolve_report(
    report_id: int,
    body: ResolveReportIn,
    db: AsyncSession = Depends(get_db),
) -> ReportOut:
    report = await db.get(Report, report_id)
    if report is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such report")

    action = body.action.strip().lower()
    if action == "duplicate":
        new_status = "duplicate"
    elif action in {"no_action", "rejected"}:
        new_status = "dismissed"
    else:
        new_status = "resolved"

    report.resolution_action = action
    report.resolution_notes = body.notes.strip()
    report.status = new_status
    report.resolved_at = datetime.now(timezone.utc)

    if body.ban_target and action == "ban":
        target = await db.get(User, report.target_uin)
        if target is not None:
            target.is_suspended = True

    await db.commit()
    await db.refresh(report)

    target_user = await db.get(User, report.target_uin)
    reporter_user = await db.get(User, report.reporter_uin)
    return ReportOut(
        id=report.id,
        reporter_uin=report.reporter_uin,
        reporter_nickname=reporter_user.nickname if reporter_user else None,
        target_uin=report.target_uin,
        target_nickname=target_user.nickname if target_user else None,
        reason=report.reason,
        context=report.context,
        status=report.status,
        resolution_action=report.resolution_action,
        resolution_notes=report.resolution_notes,
        created_at=report.created_at,
        resolved_at=report.resolved_at,
        attachments=_coerce_attachments(report.attachments),
    )


# ── Users ───────────────────────────────────────────────────────────


@router.get("/users", response_model=UserSearchOut)
async def search_users(
    q: str = Query(..., min_length=1, max_length=64),
    limit: int = Query(20, le=100),
    db: AsyncSession = Depends(get_db),
) -> UserSearchOut:
    """`q` matches uin (when digits) OR nickname (case-insensitive)."""
    needle = q.strip()
    query = select(User).limit(limit)
    if needle.isdigit():
        try:
            uin_val = int(needle)
            query = query.where(or_(User.uin == uin_val, User.nickname.ilike(f"%{needle}%")))
        except ValueError:
            query = query.where(User.nickname.ilike(f"%{needle}%"))
    else:
        query = query.where(User.nickname.ilike(f"%{needle}%"))
    users = (await db.execute(query)).scalars().all()

    out: list[UserSummary] = []
    for u in users:
        out.append(await _summarize(db, u))
    return UserSearchOut(items=out)


@router.get("/users/{uin}", response_model=UserSummary)
async def get_user(uin: int, db: AsyncSession = Depends(get_db)) -> UserSummary:
    user = await db.get(User, uin)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such user")
    return await _summarize(db, user)


@router.post("/users/{uin}/ban", response_model=UserSummary)
async def set_ban(uin: int, body: BanIn, db: AsyncSession = Depends(get_db)) -> UserSummary:
    user = await db.get(User, uin)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such user")
    user.is_suspended = body.suspended
    await db.commit()
    await db.refresh(user)
    return await _summarize(db, user)


async def _summarize(db: AsyncSession, user: User) -> UserSummary:
    reports_against = await db.scalar(
        select(func.count(Report.id)).where(Report.target_uin == user.uin)
    ) or 0
    return UserSummary(
        uin=user.uin,
        nickname=user.nickname,
        is_suspended=user.is_suspended,
        is_fake=user.is_fake,
        status=effective_status(user),
        last_seen=user.last_seen,
        created_at=user.created_at,
        reports_against=int(reports_against),
    )


# ── Stats ───────────────────────────────────────────────────────────


@router.get("/stats", response_model=StatsOut)
async def stats(db: AsyncSession = Depends(get_db)) -> StatsOut:
    now = datetime.now(timezone.utc)
    day_ago = now - timedelta(days=1)
    week_ago = now - timedelta(days=7)

    total_users = await db.scalar(select(func.count(User.uin))) or 0
    fake_users = await db.scalar(
        select(func.count(User.uin)).where(User.is_fake == True)  # noqa: E712
    ) or 0
    suspended_users = await db.scalar(
        select(func.count(User.uin)).where(User.is_suspended == True)  # noqa: E712
    ) or 0
    new_users_24h = await db.scalar(
        select(func.count(User.uin)).where(User.created_at >= day_ago)
    ) or 0
    new_users_7d = await db.scalar(
        select(func.count(User.uin)).where(User.created_at >= week_ago)
    ) or 0
    open_reports = await db.scalar(
        select(func.count(Report.id)).where(Report.status == "open")
    ) or 0
    resolved_reports_7d = await db.scalar(
        select(func.count(Report.id)).where(
            Report.status != "open", Report.resolved_at >= week_ago
        )
    ) or 0

    return StatsOut(
        total_users=int(total_users),
        fake_users=int(fake_users),
        suspended_users=int(suspended_users),
        new_users_24h=int(new_users_24h),
        new_users_7d=int(new_users_7d),
        open_reports=int(open_reports),
        resolved_reports_7d=int(resolved_reports_7d),
    )


# ── Timeseries (charts) ─────────────────────────────────────────────


class DayPoint(BaseModel):
    date: str
    count: int


class TimeseriesOut(BaseModel):
    points: list[DayPoint]


@router.get("/timeseries/signups", response_model=TimeseriesOut)
async def signups_timeseries(
    days: int = Query(30, ge=1, le=180),
    db: AsyncSession = Depends(get_db),
) -> TimeseriesOut:
    now = datetime.now(timezone.utc)
    start = (now - timedelta(days=days - 1)).replace(hour=0, minute=0, second=0, microsecond=0)

    rows = (await db.execute(
        select(
            func.date(User.created_at).label("d"),
            func.count(User.uin).label("c"),
        )
        .where(User.created_at >= start, User.is_fake == False)  # noqa: E712
        .group_by("d")
        .order_by("d")
    )).all()

    by_day: dict[str, int] = {str(r.d): int(r.c) for r in rows}
    out: list[DayPoint] = []
    for i in range(days):
        d = (start + timedelta(days=i)).date().isoformat()
        out.append(DayPoint(date=d, count=by_day.get(d, 0)))
    return TimeseriesOut(points=out)


@router.get("/timeseries/dau", response_model=TimeseriesOut)
async def dau_timeseries(
    days: int = Query(30, ge=1, le=180),
    db: AsyncSession = Depends(get_db),
) -> TimeseriesOut:
    now = datetime.now(timezone.utc)
    start = (now - timedelta(days=days - 1)).replace(hour=0, minute=0, second=0, microsecond=0)

    rows = (await db.execute(
        select(
            func.date(User.last_seen).label("d"),
            func.count(User.uin).label("c"),
        )
        .where(User.last_seen >= start, User.is_fake == False)  # noqa: E712
        .group_by("d")
        .order_by("d")
    )).all()

    by_day: dict[str, int] = {str(r.d): int(r.c) for r in rows}
    out: list[DayPoint] = []
    for i in range(days):
        d = (start + timedelta(days=i)).date().isoformat()
        out.append(DayPoint(date=d, count=by_day.get(d, 0)))
    return TimeseriesOut(points=out)


# ── Activity feed (recent admin actions) ────────────────────────────


class ActivityEvent(BaseModel):
    kind: str  # "report_resolved"
    uin: int
    nickname: str | None
    summary: str
    occurred_at: datetime


@router.get("/activity", response_model=list[ActivityEvent])
async def recent_activity(
    limit: int = Query(40, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
) -> list[ActivityEvent]:
    """Recent resolved reports, newest first."""
    resolved = (await db.execute(
        select(Report)
        .where(Report.status != "open")
        .order_by(Report.resolved_at.desc().nulls_last())
        .limit(limit)
    )).scalars().all()

    report_uins = {r.target_uin for r in resolved if r.target_uin}
    nick_lookup: dict[int, str] = {}
    if report_uins:
        users = (await db.execute(
            select(User.uin, User.nickname).where(User.uin.in_(list(report_uins)))
        )).all()
        nick_lookup = {int(u.uin): u.nickname for u in users}

    events: list[ActivityEvent] = []
    for r in resolved:
        if r.resolved_at is None:
            continue
        verb = "report dismissed" if r.status == "dismissed" else f"report {r.status}"
        events.append(ActivityEvent(
            kind="report_resolved",
            uin=r.target_uin,
            nickname=nick_lookup.get(r.target_uin),
            summary=f"{verb} · {r.resolution_action or 'no action'}",
            occurred_at=r.resolved_at,
        ))

    events.sort(key=lambda e: e.occurred_at, reverse=True)
    return events[:limit]


# ── Live presence ───────────────────────────────────────────────────


@router.get("/presence/online-count")
async def online_count() -> dict[str, int]:
    """Cluster-wide count of currently-connected UINs."""
    from app.core.redis import get_redis
    try:
        redis = await get_redis()
        n = await redis.scard("ws:online_uins")
        return {"online": int(n or 0)}
    except Exception:
        return {"online": 0}


class OnlineUser(BaseModel):
    uin: int
    nickname: str
    status: str
    last_seen: datetime
    is_fake: bool


@router.get("/presence/online", response_model=list[OnlineUser])
async def online_users(
    db: AsyncSession = Depends(get_db),
) -> list[OnlineUser]:
    from app.core.redis import get_redis
    try:
        redis = await get_redis()
        members = await redis.smembers("ws:online_uins")
    except Exception:
        return []
    uins: list[int] = []
    for m in members or []:
        try:
            uins.append(int(m))
        except (ValueError, TypeError):
            continue
    if not uins:
        return []
    rows = (await db.execute(
        select(User)
        .where(User.uin.in_(uins))
        .order_by(User.last_seen.desc())
    )).scalars().all()
    return [
        OnlineUser(
            uin=int(u.uin),
            nickname=u.nickname,
            status=effective_status(u),
            last_seen=u.last_seen,
            is_fake=bool(u.is_fake),
        )
        for u in rows
    ]
