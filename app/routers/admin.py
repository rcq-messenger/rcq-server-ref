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

import json
import logging
import os
from pathlib import Path

import httpx
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field
from sqlalchemy import delete, desc, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core import metrics
from app.core.db import engine, get_db
from app.core.security import mark_suspended, require_admin
from app.models.invite import Invite
from app.models.owned_uin import OwnedUin
from app.models.report import Report
from app.models.user import User, effective_status
from app.services import server_settings
from app.services.apns import send_to_user as apns_send
from app.services.unifiedpush import send_to_user as up_send
from app.services.hof_stats import bug_report_stats

import time as _time

log = logging.getLogger(__name__)

# In-memory TTL cache for the read-heavy analytics endpoints. The admin
# dashboard polls these on a short interval; without caching, each poll
# (signups/DAU date aggregations, activity feed, online roster) checks out one
# of the deliberately tiny pooled DB connections (pool_size=2 + overflow 1 per
# worker), and a few concurrent polls starve everything else — users'
# /contacts and the background story_sweep started returning 500 (QueuePool
# timeout). In the browser that 500 looks like a CORS error, because an
# unhandled 500 is produced above CORSMiddleware and so carries no
# Access-Control-Allow-Origin header. Per-worker cache is fine: each worker
# collapses its own repeated polls into one DB hit per TTL window, and admin
# analytics tolerate a few seconds of staleness.
_ANALYTICS_TTL = 15.0
_analytics_cache: dict[str, tuple[float, object]] = {}


def _cache_get(key: str):
    hit = _analytics_cache.get(key)
    if hit is not None and hit[0] > _time.monotonic():
        return hit[1]
    return None


def _cache_put(key: str, value: object) -> None:
    _analytics_cache[key] = (_time.monotonic() + _ANALYTICS_TTL, value)


router = APIRouter(
    prefix="/admin",
    tags=["admin"],
    dependencies=[Depends(require_admin)],
)


@router.get("/console", response_class=HTMLResponse, include_in_schema=False)
async def admin_console() -> HTMLResponse:
    """Self-host admin UI — a single self-contained page that drives this same
    /admin API. Open `https://<server>/admin/console`; the browser prompts for
    the ADMIN_USERNAME / ADMIN_PASSWORD set in .env (the page is Basic-gated by
    the router dependency above), then replays those credentials for its calls.
    The managed counterpart is console.rcq.app; this gives self-hosters parity
    with zero extra hosting."""
    from app.admin_console import ADMIN_CONSOLE_HTML

    return HTMLResponse(ADMIN_CONSOLE_HTML)


# ── operator settings (Features tab) ────────────────────────────────
# Runtime overrides over the .env baseline so an operator can toggle optional
# features / limits / branding live without editing .env + restarting (which
# would kill the worker serving this console). Source of truth =
# app/services/server_settings (typed registry + DB-backed overrides);
# /server/info and the feature routers consult the same effective values.
@router.get("/settings", include_in_schema=False)
async def get_settings() -> dict[str, Any]:
    return {"settings": await server_settings.describe()}


@router.patch("/settings", include_in_schema=False)
async def patch_settings(
    body: dict[str, Any],
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    try:
        serialized = server_settings.validate(body)
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail={"code": "bad_setting", "message": str(exc)})
    if serialized:
        await server_settings.apply(db, serialized)
        await db.commit()
    return {"settings": await server_settings.describe()}


# ── self-host update check ──────────────────────────────────────────
# Compares this server's VERSION against the VERSION on the repo's main branch
# so the admin console can show an "update available" banner. Cached 6h,
# fail-silent (never blocks the console), and skipped entirely when
# RCQ_UPDATE_CHECK=false (air-gapped installs).
_UPDATE_TTL = 6 * 3600.0
_update_cache: tuple[float, dict] | None = None


@router.get("/update-check", include_in_schema=False)
async def update_check() -> dict:
    current = settings.SERVER_VERSION
    base = {"current": current, "repo_url": settings.REPO_URL}
    if not settings.RCQ_UPDATE_CHECK:
        return {**base, "latest": None, "update_available": False, "disabled": True}
    global _update_cache
    now = _time.monotonic()
    if _update_cache is not None and _update_cache[0] > now:
        return _update_cache[1]
    latest: str | None = None
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.get(settings.UPDATE_CHECK_URL)
        if r.status_code == 200:
            latest = (r.text.strip().splitlines() or [""])[0].strip()[:32] or None
    except (httpx.HTTPError, OSError):
        latest = None
    result = {
        **base,
        "latest": latest,
        # Any difference means "behind": a self-hoster tracking main is never
        # ahead of it. A blank/unknown latest → no nag.
        "update_available": bool(latest) and latest != current,
    }
    _update_cache = (now + _UPDATE_TTL, result)
    return result


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
    # What was said back to the reporter, so the queue shows at a glance
    # which reports have been answered and which are still silent.
    reply_text: str = ""
    replied_at: datetime | None = None
    created_at: datetime
    resolved_at: datetime | None
    attachments: list[ReportAttachmentOut] = []
    # True when this report carries DECRYPTED media the reporter consented to
    # share. The file itself is fetched separately from
    # `GET /admin/reports/{id}/evidence` so it is never inlined into a list
    # response (and so every view of it is logged individually).
    has_evidence: bool = False
    evidence_mime: str | None = None


class ReportsListOut(BaseModel):
    items: list[ReportOut]
    open_count: int
    # Open auto-crash reports (reason carries the [CRASH] marker), counted
    # separately so the admin UI can badge its Crashes tab. Additive with a
    # default so older admin SPAs keep parsing.
    open_crash_count: int = 0


class ResolveReportIn(BaseModel):
    action: str = Field(..., min_length=1, max_length=32)
    notes: str = Field(default="", max_length=2000)
    ban_target: bool = False


class ReplyReportIn(BaseModel):
    # Kept short on purpose: this is an answer to a reporter, not a chat.
    text: str = Field(..., min_length=1, max_length=4000)


class UserSummary(BaseModel):
    uin: int
    nickname: str
    is_suspended: bool
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
    suspended_users: int
    new_users_24h: int
    new_users_7d: int
    # Human reports only — auto crash reports are counted in open_crashes
    # (additive default so older admin SPAs keep parsing).
    open_reports: int
    open_crashes: int = 0
    resolved_reports_7d: int


# ── Reports ─────────────────────────────────────────────────────────


# Auto-submitted crash reports carry this marker in `reason` (clients prefix
# "[<platform> <version>] [CRASH]"). They ride the same /reports channel but
# clutter human triage, so the admin UI splits them into their own tab.
CRASH_MARKER = "[CRASH]"


@router.get("/reports", response_model=ReportsListOut)
async def list_reports(
    status_filter: str = Query("open", alias="status"),
    kind: str = Query("all"),
    limit: int = Query(50, le=200),
    db: AsyncSession = Depends(get_db),
) -> ReportsListOut:
    """`status` accepts: open | resolved | dismissed | duplicate | all.
    `kind` accepts: all | crash (auto crash reports) | user (everything else)."""
    query = select(Report).order_by(desc(Report.created_at)).limit(limit)
    if status_filter != "all":
        query = query.where(Report.status == status_filter)
    if kind == "crash":
        query = query.where(Report.reason.contains(CRASH_MARKER))
    elif kind == "user":
        query = query.where(~Report.reason.contains(CRASH_MARKER))
    rows = (await db.execute(query)).scalars().all()

    uins: set[int] = set()
    for r in rows:
        uins.add(r.reporter_uin)
        uins.add(r.target_uin)
    nicks: dict[int, str] = {}
    if uins:
        for u in (await db.execute(select(User).where(User.uin.in_(uins)))).scalars().all():
            nicks[u.uin] = u.nickname

    open_crash_count = await db.scalar(
        select(func.count(Report.id)).where(
            Report.status == "open", Report.reason.contains(CRASH_MARKER)
        )
    ) or 0
    open_count = (await db.scalar(
        select(func.count(Report.id)).where(Report.status == "open")
    ) or 0) - int(open_crash_count)

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
            reply_text=r.reply_text or "",
            replied_at=r.replied_at,
            created_at=r.created_at,
            resolved_at=r.resolved_at,
            attachments=_coerce_attachments(r.attachments),
            has_evidence=bool(r.evidence_path),
            evidence_mime=r.evidence_mime,
        )
        for r in rows
    ]
    return ReportsListOut(
        items=items,
        open_count=int(open_count),
        open_crash_count=int(open_crash_count),
    )


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

    # Accept both vocabularies: the admin console posts "banned"/"dismissed"
    # (admin_console.py), older/API callers post "ban"/"no_action"/"rejected".
    # "dismissed" was missing from the dismissal set, so pressing Dismiss filed
    # the report as `resolved` and inflated the resolved-reports stat with
    # reports nobody acted on.
    action = body.action.strip().lower()
    if action == "duplicate":
        new_status = "duplicate"
    elif action in {"no_action", "rejected", "dismissed"}:
        new_status = "dismissed"
    else:
        new_status = "resolved"

    report.resolution_action = action
    report.resolution_notes = body.notes.strip()
    report.status = new_status
    report.resolved_at = datetime.now(timezone.utc)

    # `ban_target` is the caller's explicit intent and is the only thing that
    # gates the suspend. It used to ALSO require `action == "ban"`, but the
    # admin console sends `action: "banned"` (admin_console.py, resolve()), so
    # the two never matched: pressing Ban suspended nobody while still moving
    # the report to `resolved` and dropping it out of the open queue. The
    # operator got no error and every ban silently no-opped — on the one
    # workflow that is used under time pressure.
    banned_uin: int | None = None
    if body.ban_target:
        target = await db.get(User, report.target_uin)
        if target is not None:
            target.is_suspended = True
            banned_uin = target.uin

    await db.commit()
    if banned_uin is not None:
        await mark_suspended(banned_uin, True)
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
        reply_text=report.reply_text or "",
        replied_at=report.replied_at,
        created_at=report.created_at,
        resolved_at=report.resolved_at,
        attachments=_coerce_attachments(report.attachments),
        has_evidence=bool(report.evidence_path),
        evidence_mime=report.evidence_mime,
    )


@router.post("/reports/{report_id}/reply", response_model=ReportOut)
async def reply_to_report(
    report_id: int,
    body: ReplyReportIn,
    db: AsyncSession = Depends(get_db),
) -> ReportOut:
    """Answer the person who filed the report.

    Separate from /resolve on purpose: most thoughtful reports deserve an
    answer BEFORE anyone decides whether to ban, dismiss or ship a fix, and
    tying the two together would mean an operator has to pick a verdict just
    to say "we read this, here is what we think".

    Delivery: the text is stored on the report and the reporter reads it back
    through GET /reports/mine on their own session. It is deliberately NOT a
    chat message. Chats are sealed on the sending device and this server holds
    no keys, so putting an answer into a conversation would require giving the
    server the ability to write into one, which is the exact capability the
    project promises it lacks. The push below is only a doorbell: it carries
    no part of the answer, because a push traverses APNs and our push host in
    the clear. The client fetches the text over its authenticated session.
    """
    report = await db.get(Report, report_id)
    if report is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such report")

    report.reply_text = body.text.strip()
    report.replied_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(report)

    push_args = dict(
        alert_title="RCQ",
        alert_body="We answered your report",
        thread_id="reports",
        notif_kind="report_reply",
    )
    await apns_send(report.reporter_uin, **push_args)
    await up_send(report.reporter_uin, **push_args)

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
        reply_text=report.reply_text or "",
        replied_at=report.replied_at,
        created_at=report.created_at,
        resolved_at=report.resolved_at,
        attachments=_coerce_attachments(report.attachments),
        has_evidence=bool(report.evidence_path),
        evidence_mime=report.evidence_mime,
    )


# ── Report evidence (decrypted media) ───────────────────────────────


@router.get("/reports/{report_id}/evidence", include_in_schema=False)
async def get_report_evidence(
    report_id: int,
    admin: str = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Serve the decrypted media a reporter consented to attach.

    This is the read half that `POST /reports/with_evidence` was written
    against and that never existed: the upload path stored files under
    `evidence/` and recorded the path, but nothing could open them, so the
    feature collected other people's decrypted pictures and gave moderators
    nothing. Retention is handled by `services/evidence_sweep`.

    Every fetch is logged with the admin username. Looking at content a user
    surrendered under a consent prompt should leave a trace naming who looked,
    and it is the difference between 'we hold evidence' and 'we hold evidence
    with an access record' in any conversation where that distinction matters.
    """
    from fastapi.responses import FileResponse

    report = await db.get(Report, report_id)
    if report is None or not report.evidence_path:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no evidence for this report")

    # `evidence_path` is written as a bare UUID filename, but resolve and
    # re-anchor it anyway so a malformed/legacy row can never walk out of the
    # directory.
    base = Path(os.environ.get("RCQ_EVIDENCE_DIR", "evidence")).resolve()
    target = (base / Path(report.evidence_path).name).resolve()
    if not target.is_relative_to(base) or not target.exists():
        raise HTTPException(status.HTTP_404_NOT_FOUND, "evidence file is gone")

    log.warning(
        "[evidence-access] admin=%s report=%s target_uin=%s reporter_uin=%s mime=%s",
        admin, report.id, report.target_uin, report.reporter_uin, report.evidence_mime,
    )
    return FileResponse(
        target,
        media_type=report.evidence_mime or "application/octet-stream",
        # inline so the console can render it in an <img>/<video> rather than
        # forcing a download onto the moderator's disk.
        content_disposition_type="inline",
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
    # Mirror into the Redis set `current_uin` consults, so the ban takes effect
    # on the REST surface immediately instead of at the next cache refresh.
    await mark_suspended(uin, body.suspended)
    return await _summarize(db, user)


async def _summarize(db: AsyncSession, user: User) -> UserSummary:
    reports_against = await db.scalar(
        select(func.count(Report.id)).where(Report.target_uin == user.uin)
    ) or 0
    return UserSummary(
        uin=user.uin,
        nickname=user.nickname,
        is_suspended=user.is_suspended,
        status=effective_status(user),
        last_seen=user.last_seen,
        created_at=user.created_at,
        reports_against=int(reports_against),
    )


# ── Hall of Fame ────────────────────────────────────────────────────


class HofRow(BaseModel):
    uin: int
    nickname: str
    opt_in: bool
    approved: bool
    created_at: datetime
    last_seen: datetime
    # The member's uploaded HoF avatar as a data-URI (so the founder sees what
    # he's approving), or null. Inline is fine — the admin list is small and
    # founder-only.
    avatar: str | None = None
    # Founder-assigned wall rating (bronze/silver/gold) — drives the flower.
    tier: str = "gold"
    # Bug-bounty effort, so the founder can see contribution before grading.
    # `reports` = total bug reports filed; `bugs_confirmed` = of those, how
    # many were confirmed as real bugs (status=resolved). Both INCLUDE the
    # founder-granted off-form credit below, i.e. they are what the wall shows.
    reports: int = 0
    bugs_confirmed: int = 0
    # The granted part of those two, so the console can show what was typed in
    # rather than making the founder subtract to find it.
    bonus_reports: int = 0
    bonus_confirmed: int = 0


class HofListOut(BaseModel):
    items: list[HofRow]
    approved_count: int


# Valid founder ratings. Anything else on POST is a 400.
_HOF_TIERS = {"bronze", "silver", "gold"}


class HofApproveIn(BaseModel):
    # All optional so the founder can toggle wall membership, set the rating and
    # grant off-form report credit independently through the same endpoint. A
    # request sets whatever it sends.
    approved: bool | None = None
    tier: str | None = None
    # Credit for bug reports filed outside the in-app form (closed tester chat,
    # comments). ADDED to the counts computed from real report rows, so a
    # contributor who also uses the form keeps earning on top of the grant.
    bonus_reports: int | None = Field(default=None, ge=0, le=10_000)
    bonus_confirmed: int | None = Field(default=None, ge=0, le=10_000)


@router.get("/hof", response_model=HofListOut)
async def hof_candidates(db: AsyncSession = Depends(get_db)) -> HofListOut:
    """Everyone who opted into the Hall of Fame, newest opt-ins implicitly
    surfaced by the approved-last ordering. The founder flips `approved` per
    row; only approved+opted-in users reach the public /public/hof wall."""
    rows = (
        await db.execute(
            select(User)
            .where(User.hof_opt_in.is_(True), User.is_fake.is_(False))
            .order_by(User.hof_approved.desc(), User.last_seen.desc())
        )
    ).scalars().all()
    approved = sum(1 for u in rows if u.hof_approved)
    stats = await bug_report_stats(db, [u.uin for u in rows])
    return HofListOut(
        items=[
            HofRow(
                uin=u.uin,
                nickname=u.nickname,
                opt_in=u.hof_opt_in,
                approved=u.hof_approved,
                created_at=u.created_at,
                last_seen=u.last_seen,
                avatar=u.hof_avatar,
                tier=(u.hof_tier or "gold"),
                reports=stats.get(u.uin, (0, 0))[0],
                bugs_confirmed=stats.get(u.uin, (0, 0))[1],
                bonus_reports=u.hof_bonus_reports or 0,
                bonus_confirmed=u.hof_bonus_confirmed or 0,
            )
            for u in rows
        ],
        approved_count=approved,
    )


@router.post("/hof/{uin}", response_model=HofRow)
async def hof_set_approved(uin: int, body: HofApproveIn, db: AsyncSession = Depends(get_db)) -> HofRow:
    """Founder controls for one member: flip wall membership (`approved`), set
    the rating tier (`tier`), and grant credit for reports filed off the in-app
    form (`bonus_*`). All optional — a request changes only what it sends. Does
    not touch the user's own opt-in consent.

    `bonus_confirmed` above `bonus_reports` would draw a ring claiming more
    confirmed bugs than reports filed, so it is rejected rather than clamped —
    a typo in the console should not silently become a wrong number on a public
    wall."""
    if body.tier is not None and body.tier not in _HOF_TIERS:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"invalid tier (expected one of {sorted(_HOF_TIERS)})",
        )
    user = await db.get(User, uin)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such user")
    new_bonus_reports = (
        body.bonus_reports if body.bonus_reports is not None else user.hof_bonus_reports
    )
    new_bonus_confirmed = (
        body.bonus_confirmed if body.bonus_confirmed is not None else user.hof_bonus_confirmed
    )
    if (new_bonus_confirmed or 0) > (new_bonus_reports or 0):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "bonus_confirmed cannot exceed bonus_reports",
        )
    if body.approved is not None:
        user.hof_approved = body.approved
    if body.tier is not None:
        user.hof_tier = body.tier
    user.hof_bonus_reports = new_bonus_reports
    user.hof_bonus_confirmed = new_bonus_confirmed
    await db.commit()
    await db.refresh(user)
    stats = await bug_report_stats(db, [user.uin])
    total, confirmed = stats.get(user.uin, (0, 0))
    return HofRow(
        uin=user.uin,
        nickname=user.nickname,
        opt_in=user.hof_opt_in,
        approved=user.hof_approved,
        created_at=user.created_at,
        last_seen=user.last_seen,
        avatar=user.hof_avatar,
        tier=(user.hof_tier or "gold"),
        reports=total,
        bugs_confirmed=confirmed,
        bonus_reports=user.hof_bonus_reports or 0,
        bonus_confirmed=user.hof_bonus_confirmed or 0,
    )


# ── Stats ───────────────────────────────────────────────────────────


# ── Transport mix ───────────────────────────────────────────────────
#
# How people actually reach the island: direct, through the Cloudflare front,
# or out of one of our relays. The numbers come from Caddy's own access log,
# which this process cannot read (caddy-owned, mode 600) — so a root timer
# (rcq-telemetry.timer) runs scripts/transport-mix.py hourly and leaves a
# readable JSONL snapshot behind. Serving the file rather than recomputing also
# means the admin view is instant and the log parse happens once an hour.
TRANSPORT_SNAPSHOTS = os.getenv("TRANSPORT_SNAPSHOTS", "/var/lib/rcq-telemetry/transport.jsonl")


@router.get("/transport-mix")
async def transport_mix(limit: int = Query(48, le=720)) -> dict:
    """Recent snapshots, newest last. Empty list when the timer has not run yet
    or the file is missing — the panel says so rather than showing zeros, which
    would read as "nobody is using relays"."""
    try:
        with open(TRANSPORT_SNAPSHOTS) as fh:
            lines = fh.read().splitlines()
    except OSError:
        return {"snapshots": [], "available": False}
    out = []
    for line in lines[-limit:]:
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return {"snapshots": out, "available": True}


@router.get("/metrics")
async def instrument_panel(minutes: int = Query(60, ge=5, le=60)) -> dict:
    """What this island is doing right now, minute by minute.

    In-memory and per-process, which is the one thing to know before reading
    it: with more than one uvicorn worker these are the numbers for whichever
    worker answered, not the island total, so read shapes and ratios rather
    than absolutes. It is still the only place that can answer half of these —
    Caddy's log sees a request and a duration to the client, not our own work,
    not the database pool, and not who was asking.

    Everything resets on deploy. That is a feature for a panel meant to answer
    "what is happening now"; the long view lives in the Transport tab, which
    is written to disk by the hourly timer.
    """
    snap = metrics.snapshot(minutes=minutes)
    pool = getattr(engine, "pool", None)
    # `size()` is the configured pool_size and `_max_overflow` the configured
    # headroom above it, so their sum is the real ceiling a request can hit.
    # ⚠ NOT `overflow()`: that is how far past pool_size we are RIGHT NOW, and
    # it goes negative while the pool is idle — adding it to the size gave a
    # "peak / ceiling" reading whose ceiling moved around under the peak.
    pool_info: dict = {"configured": None, "in_use": None, "ceiling": None}
    if pool is not None:
        try:
            if callable(getattr(pool, "size", None)):
                pool_info["configured"] = pool.size()
            if callable(getattr(pool, "checkedout", None)):
                pool_info["in_use"] = pool.checkedout()
            size = pool_info["configured"]
            extra = getattr(pool, "_max_overflow", None)
            if size is not None and isinstance(extra, int) and extra >= 0:
                pool_info["ceiling"] = size + extra
        except Exception:
            pass
    snap["pool"] = pool_info
    snap["workers_note"] = "per-process; multiple uvicorn workers each keep their own"
    return snap


@router.get("/stats", response_model=StatsOut)
async def stats(db: AsyncSession = Depends(get_db)) -> StatsOut:
    now = datetime.now(timezone.utc)
    day_ago = now - timedelta(days=1)
    week_ago = now - timedelta(days=7)

    total_users = await db.scalar(select(func.count(User.uin))) or 0
    suspended_users = await db.scalar(
        select(func.count(User.uin)).where(User.is_suspended == True)  # noqa: E712
    ) or 0
    new_users_24h = await db.scalar(
        select(func.count(User.uin)).where(User.created_at >= day_ago)
    ) or 0
    new_users_7d = await db.scalar(
        select(func.count(User.uin)).where(User.created_at >= week_ago)
    ) or 0
    open_crashes = await db.scalar(
        select(func.count(Report.id)).where(
            Report.status == "open", Report.reason.contains(CRASH_MARKER)
        )
    ) or 0
    open_reports = (await db.scalar(
        select(func.count(Report.id)).where(Report.status == "open")
    ) or 0) - int(open_crashes)
    resolved_reports_7d = await db.scalar(
        select(func.count(Report.id)).where(
            Report.status != "open", Report.resolved_at >= week_ago
        )
    ) or 0

    return StatsOut(
        total_users=int(total_users),
        suspended_users=int(suspended_users),
        new_users_24h=int(new_users_24h),
        new_users_7d=int(new_users_7d),
        open_reports=int(open_reports),
        open_crashes=int(open_crashes),
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
    ck = f"signups:{days}"
    cached = _cache_get(ck)
    if cached is not None:
        return cached
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
    result = TimeseriesOut(points=out)
    _cache_put(ck, result)
    return result


@router.get("/timeseries/dau", response_model=TimeseriesOut)
async def dau_timeseries(
    days: int = Query(30, ge=1, le=180),
    db: AsyncSession = Depends(get_db),
) -> TimeseriesOut:
    ck = f"dau:{days}"
    cached = _cache_get(ck)
    if cached is not None:
        return cached
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
    result = TimeseriesOut(points=out)
    _cache_put(ck, result)
    return result


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
    ck = f"activity:{limit}"
    cached = _cache_get(ck)
    if cached is not None:
        return cached
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
    result = events[:limit]
    _cache_put(ck, result)
    return result


# ── Live presence ───────────────────────────────────────────────────


@router.get("/presence/online-count")
async def online_count(db: AsyncSession = Depends(get_db)) -> dict[str, int]:
    """Cluster-wide count of currently-connected UINs.

    Deliberately the LENGTH of the same list `/presence/online` returns, not a
    separate SCARD. The two used to disagree in the console for two reasons and
    both were real: the list is cached for a few seconds while the raw count was
    not, and the count included set members with no `users` row at all, which
    the list quietly dropped when it joined. Ghost members happen because the
    SREM on disconnect is best-effort (see connection_manager) — a worker that
    dies mid-flight leaves its UINs behind.

    One source, one number. `_online_users` also prunes the ghosts it finds, so
    the set heals instead of drifting upward forever.
    """
    return {"online": len(await _online_users(db))}


class OnlineUser(BaseModel):
    uin: int
    nickname: str
    status: str
    last_seen: datetime


async def _online_users(db: AsyncSession) -> list[OnlineUser]:
    """Everyone with a live socket somewhere in the cluster, as rows.

    Shared by the list endpoint and the count so the console cannot show two
    different numbers for the same thing.
    """
    cached = _cache_get("online_users")
    if cached is not None:
        return cached
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
    # Members of the set with no account behind them: burned accounts, or a
    # worker that went away without running its SREM. Drop them so the set
    # stops counting people who are not there. Best-effort — a failure here
    # must not turn the console blank.
    ghosts = set(uins) - {int(u.uin) for u in rows}
    if ghosts:
        try:
            await redis.srem("ws:online_uins", *[str(g) for g in ghosts])
            log.warning("[presence] pruned %d stale online member(s)", len(ghosts))
        except Exception:  # noqa: BLE001
            pass
    result = [
        OnlineUser(
            uin=int(u.uin),
            nickname=u.nickname,
            status=effective_status(u),
            last_seen=u.last_seen,
        )
        for u in rows
    ]
    _cache_put("online_users", result)
    return result


@router.get("/presence/online", response_model=list[OnlineUser])
async def online_users(db: AsyncSession = Depends(get_db)) -> list[OnlineUser]:
    return await _online_users(db)


# ── Handing out numbers by arrangement ──────────────────────────────
# Self-hosted islands have no shop (the storefront is flagship-only), so an
# operator who agrees to give someone a number needs a way to do it. An invite
# with a reserved `uin` already covers a NEW member, but there was nothing at
# all for an EXISTING one — which is the normal case, because the arrangement
# usually happens after somebody has been on the island a while.


class GrantUinIn(BaseModel):
    # The number to hand over.
    uin: int = Field(gt=0)
    # Who gets it, by their current number.
    to_uin: int = Field(gt=0)


class GrantUinOut(BaseModel):
    uin: int
    to_uin: int
    owned: list[int]


@router.post("/uin/grant", response_model=GrantUinOut)
async def grant_uin(
    body: GrantUinIn,
    db: AsyncSession = Depends(get_db),
) -> GrantUinOut:
    """Put a number into an existing member's collection.

    It lands in the collection, NOT on their account: the operator decides who
    gets a number, the person decides when (and whether) to answer as it. That
    also means this can never yank somebody's identity out from under them
    mid-conversation.

    Works whether or not the shop is enabled — this is the operator acting
    directly, which is the whole point on an island with no storefront.
    """
    if await db.scalar(select(User.uin).where(User.uin == body.uin)) is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, detail={"code": "in_use"})
    if await db.scalar(select(OwnedUin.uin).where(OwnedUin.uin == body.uin)) is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, detail={"code": "already_held"})
    if await db.get(User, body.to_uin) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail={"code": "no_such_user"})

    db.add(OwnedUin(uin=body.uin, owner_uin=body.to_uin, source="granted"))
    await db.commit()
    owned = (
        await db.execute(
            select(OwnedUin.uin).where(OwnedUin.owner_uin == body.to_uin).order_by(OwnedUin.uin)
        )
    ).scalars().all()
    log.warning("[uin-grant] %s -> %s", body.uin, body.to_uin)
    return GrantUinOut(uin=body.uin, to_uin=body.to_uin, owned=[int(u) for u in owned])


# ── Server-join invites ─────────────────────────────────────────────
# Minted here (web-admin / console.rcq.app); self-host operators can also
# mint via the `app.tools.mint_invite` CLI. Only meaningful when the server
# runs REGISTRATION_POLICY=invite — an open server never checks them.


class MintInviteIn(BaseModel):
    label: str | None = Field(default=None, max_length=120)
    max_uses: int = Field(default=1, ge=1, le=100_000)
    ttl_hours: int | None = Field(default=None, ge=1)  # null = never expires
    # Optional reserved (vanity) UIN this invite grants at registration. When
    # set, the user who redeems this code gets exactly this number. Must be free
    # and in [UIN_MIN, UIN_MAX]; pair with max_uses=1 so it isn't claimed twice.
    uin: int | None = Field(default=None)


class InviteOut(BaseModel):
    code: str
    label: str | None
    max_uses: int
    used_count: int
    uin: int | None = None
    expires_at: datetime | None
    created_at: datetime
    join_url: str


def _join_url(request: Request, code: str) -> str:
    host = request.headers.get("x-forwarded-host") or (request.url.hostname or "")
    return f"rcq://server/{host}?invite={code}"


def _invite_out(request: Request, inv: Invite) -> InviteOut:
    return InviteOut(
        code=inv.code,
        label=inv.label,
        max_uses=inv.max_uses,
        used_count=inv.used_count,
        uin=inv.uin,
        expires_at=inv.expires_at,
        created_at=inv.created_at,
        join_url=_join_url(request, inv.code),
    )


@router.post("/invites", response_model=InviteOut, status_code=status.HTTP_201_CREATED)
async def mint_invite(
    body: MintInviteIn, request: Request, db: AsyncSession = Depends(get_db)
) -> InviteOut:
    # A reserved (vanity) UIN must be in range, not already registered, and not
    # already reserved by another live invite — otherwise two people could be
    # promised the same number.
    reserved_uin = body.uin
    if reserved_uin is not None:
        if not (settings.UIN_MIN <= reserved_uin <= settings.UIN_MAX):
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                detail={"code": "uin_out_of_range", "min": settings.UIN_MIN, "max": settings.UIN_MAX},
            )
        if await db.scalar(select(User.uin).where(User.uin == reserved_uin)) is not None:
            raise HTTPException(status.HTTP_409_CONFLICT, detail={"code": "uin_taken"})
        already = await db.scalar(
            select(Invite.code).where(
                Invite.uin == reserved_uin,
                Invite.used_count < Invite.max_uses,
                or_(Invite.expires_at.is_(None), Invite.expires_at > datetime.now(timezone.utc)),
            )
        )
        if already is not None:
            raise HTTPException(status.HTTP_409_CONFLICT, detail={"code": "uin_reserved"})
    code = secrets.token_urlsafe(16)
    expires_at = (
        datetime.now(timezone.utc) + timedelta(hours=body.ttl_hours)
        if body.ttl_hours
        else None
    )
    inv = Invite(
        code=code, label=body.label, max_uses=body.max_uses,
        expires_at=expires_at, uin=reserved_uin,
    )
    db.add(inv)
    await db.commit()
    await db.refresh(inv)
    return _invite_out(request, inv)


@router.get("/invites", response_model=list[InviteOut])
async def list_invites(
    request: Request, db: AsyncSession = Depends(get_db)
) -> list[InviteOut]:
    rows = (
        await db.execute(select(Invite).order_by(desc(Invite.created_at)))
    ).scalars().all()
    return [_invite_out(request, inv) for inv in rows]


@router.delete("/invites/{code}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_invite(code: str, db: AsyncSession = Depends(get_db)) -> None:
    await db.execute(delete(Invite).where(Invite.code == code))
    await db.commit()
