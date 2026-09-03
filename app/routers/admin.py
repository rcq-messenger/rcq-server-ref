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

from app.core.config import log_identity, settings
from app.core import metrics
from app.core.db import engine, get_db
from app.core.security import mark_suspended, require_admin
from app.models.invite import Invite, hash_invite_code
from app.models.owned_uin import OwnedUin
from app.models.uin_sale import UinHold
from app.models.relay_inquiry import RelayInquiry
from app.models.report import Report
from app.models.report_message import ReportMessage
from app.models.user import User, effective_status
from app.services import island_logo, server_settings
from app.services.apns import send_to_user as apns_send
from app.services.unifiedpush import send_to_user as up_send
from app.services.hof_stats import bug_report_stats
# Shared with `services/uin.uin_is_taken`, which now asks the same question of
# every number it hands out. Three readers of one predicate; when they drift a
# number gets promised twice and neither side is told (see the docstring).
from app.services.uin import invite_is_live, uin_is_taken

import time as _time

log = logging.getLogger(__name__)

# In-memory TTL cache for the read-heavy analytics endpoints. The admin
# dashboard polls these on a short interval; without caching, each poll
# (signups/DAU date aggregations, activity feed, online roster) checks out one
# of the deliberately tiny pooled DB connections (pool_size=2 + overflow 1 per
# worker), and a few concurrent polls starve everything else — users'
# /contacts and the background sweeps started returning 500 (QueuePool
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

    # ⚠ no-store, and it is not paranoia. The page IS the app: its whole client
    # is inlined in this HTML, so a browser holding yesterday's copy runs
    # yesterday's logic against today's API and the operator has no way to see
    # that. It cost a real afternoon: the console was flattening a transparent
    # island logo onto white, the fix shipped, the operator re-uploaded, and
    # the cached page produced the identical flattened JPEG down to the byte,
    # so even the version digest did not move and the upload looked ignored.
    return HTMLResponse(
        ADMIN_CONSOLE_HTML,
        headers={"Cache-Control": "no-store, must-revalidate", "Pragma": "no-cache"},
    )


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


# ── the island's logo (Features tab -> Branding) ─────────────────────
# Sits next to the island NAME and the welcome text, which are ordinary
# settings-registry strings. The logo is not one: the registry stores strings in
# a VARCHAR(2048) and silently truncates to it, which for a data URI means an
# image that cannot be opened. It gets its own endpoints and its own single-row
# table (models/island_logo.py explains why not a file and why not the settings
# row); what reaches the clients is a 12-character version on /server/info plus
# the public GET /server/logo.
class IslandLogoState(BaseModel):
    """What the console needs to draw the control. Deliberately WITHOUT the
    picture: the console renders the public `/server/logo?v=<version>` in a
    plain <img>, which is the same URL every client uses, so the preview cannot
    disagree with what members see."""

    has_logo: bool
    version: str
    #: The cap, so the console can state it BEFORE the operator picks a file
    #: rather than after they have waited for an upload to be refused.
    max_bytes: int
    mimes: list[str]


def _logo_state(version: str) -> IslandLogoState:
    return IslandLogoState(
        has_logo=bool(version),
        version=version,
        max_bytes=island_logo.MAX_LOGO_BYTES,
        mimes=list(island_logo.ALLOWED_MIMES),
    )


@router.get("/server/logo", include_in_schema=False)
async def get_island_logo() -> IslandLogoState:
    return _logo_state(await island_logo.version())


class IslandLogoIn(BaseModel):
    #: `data:image/png;base64,...`. A data URI rather than a multipart upload
    #: because the console is a single static page with no upload form, and
    #: because it is the shape a browser FileReader / canvas already produces
    #: after the client-side downscale. Same shape as the HoF avatar
    #: (routers/users.py).
    data_uri: str


@router.put("/server/logo", include_in_schema=False)
async def put_island_logo(
    body: IslandLogoIn,
    db: AsyncSession = Depends(get_db),
) -> IslandLogoState:
    """Set the island's logo. Refuses, and changes nothing, on anything the
    clients could not draw: a non-image, a type outside the allow-list, base64
    that does not decode, or an image over the cap. Never scales, never crops,
    never truncates. An island keeps the logo it had rather than gaining a
    broken one."""
    try:
        mime, blob = island_logo.parse_data_uri(body.data_uri)
    except island_logo.LogoTooLarge as exc:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            detail={"code": "logo_too_large", "message": str(exc), "max_bytes": island_logo.MAX_LOGO_BYTES},
        )
    except ValueError as exc:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            detail={"code": "bad_logo", "message": str(exc)},
        )
    version = await island_logo.store(db, mime, blob)
    await db.commit()
    return _logo_state(version)


@router.delete("/server/logo", include_in_schema=False)
async def delete_island_logo(
    db: AsyncSession = Depends(get_db),
) -> IslandLogoState:
    """Drop the logo. Every client falls back to the lettered tile it drew
    before one was set. Idempotent."""
    await island_logo.clear(db)
    await db.commit()
    return _logo_state("")


# ── self-host update check ──────────────────────────────────────────
# Compares this server's VERSION against the VERSION on the repo's main branch
# so the admin console can show an "update available" banner. Cached 6h,
# fail-silent (never blocks the console), and skipped entirely when
# RCQ_UPDATE_CHECK=false (air-gapped installs).
_UPDATE_TTL = 6 * 3600.0
_update_cache: tuple[float, dict] | None = None


def _version_tuple(v: str) -> tuple[int, ...] | None:
    """`2026.08.13.5` → (2026, 8, 13, 5). None when it is not dotted numbers."""
    parts = v.strip().split(".")
    if not parts or not all(p.isdigit() for p in parts):
        return None
    return tuple(int(p) for p in parts)


def _is_newer(latest: str, current: str) -> bool:
    a, b = _version_tuple(latest), _version_tuple(current)
    if a is None or b is None:
        return latest != current
    return a > b


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
        # ⚠ NEWER than published is not "behind". This used to be `latest !=
        # current`, on the theory that a self-hoster tracking main is never
        # ahead of it — which is false for anyone who builds before the tag
        # lands, us included: the flagship ran 2026.08.13.5 while the repo said
        # .4 and its own console nagged the author to update TO AN OLDER
        # BUILD. Compare as version numbers and nag only when the published one
        # is genuinely higher; fall back to plain inequality for anything that
        # does not parse as dotted numbers.
        "update_available": bool(latest) and _is_newer(latest, current),
    }
    _update_cache = (now + _UPDATE_TTL, result)
    return result


# ── DTOs ────────────────────────────────────────────────────────────


class ReportAttachmentOut(BaseModel):
    media_id: str
    key: str
    mime: str
    size: int = 0


class ReportTurnOut(BaseModel):
    id: int
    from_admin: bool
    author_uin: int
    body: str
    created_at: datetime


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
    # The exchange so far, oldest first. The operator needs the reporter's
    # follow-ups in the queue itself — that is the whole point of letting them
    # write back, and an answer written without reading "it still happens after
    # the update" is worse than no answer.
    thread: list[ReportTurnOut] = []


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
    # The human queue split the way the console shows it: complaints about a
    # person vs bugs filed about the island. Additive defaults so an older SPA
    # (and the self-host console) keeps parsing this response.
    open_abuse: int = 0
    open_bugs: int = 0
    # Organisations waiting for an answer on /organizations. The sidebar had a
    # badge for reports and for crashes and none for the one queue where the
    # person on the other end is trying to give us money.
    open_inquiries: int = 0
    resolved_reports_7d: int
    # ⚠⚠ The number of relays a BLOCKED stranger can actually be handed.
    #
    # `/broker/bridges` is the last path left when a user's whole bundled pool
    # is unreachable: the signed config is the same addresses they already
    # cannot reach, and onion rides those same addresses too. It is therefore
    # the one figure that says whether someone who has just been cut off has
    # anywhere to go.
    #
    # It read ZERO for an unknown length of time and nothing said so, because
    # this panel never showed it. Every relay registered with the broker was
    # bound to a tenant, and a tenant's endpoint is deliberately never in the
    # public answer (broker.py) — so the pool was empty by construction while
    # the admin page looked healthy. Surfaced here so it cannot happen quietly
    # again: if this is 0, the bypass has no fallback at all.
    broker_public_relays: int = 0
    # Of those, how many the liveness gate would actually serve right now.
    broker_public_live: int = 0


# ── Reports ─────────────────────────────────────────────────────────


# Auto-submitted crash reports carry this marker in `reason` (clients prefix
# "[<platform> <version>] [CRASH]"). They ride the same /reports channel but
# clutter human triage, so the admin UI splits them into their own tab.
CRASH_MARKER = "[CRASH]"

# What separates "a user told us about a bug" from "a user complained about
# somebody". Every client sends context="bug_bounty" on the bug-report form;
# an abuse report carries the surface it was filed from ("contact", "hood",
# "group:<id>", …) or, for the oldest rows, nothing at all. A row with no
# context is therefore NOT a bug report, and the negation spells that out
# rather than letting SQL's NULL comparison drop it from both lists.
_IS_BUG = Report.context == "bug_bounty"
_IS_NOT_BUG = or_(Report.context.is_(None), Report.context != "bug_bounty")


@router.get("/reports", response_model=ReportsListOut)
async def list_reports(
    status_filter: str = Query("open", alias="status"),
    kind: str = Query("all"),
    limit: int = Query(50, le=200),
    db: AsyncSession = Depends(get_db),
) -> ReportsListOut:
    """`status` accepts: open | resolved | dismissed | duplicate | all.

    `kind` accepts:
      all   — everything
      crash — auto-submitted crash dumps ([CRASH] in `reason`)
      bug   — bug reports a user filed about the island itself
      abuse — a complaint ABOUT somebody: a user or one of their messages
      user  — legacy: bug + abuse together (what the old SPA asks for)

    bug and abuse are the same queue split by `context`, and they are three
    different jobs: an abuse report is triaged by deciding what happens to the
    reported account, a bug report by deciding whether it is a bug. Mixed in one
    list they read as one queue with the wrong buttons on two thirds of it."""
    query = select(Report).order_by(desc(Report.created_at)).limit(limit)
    if status_filter != "all":
        query = query.where(Report.status == status_filter)
    # Crash first: a crash row also carries context="bug_bounty", so the marker
    # has to be tested before the context is.
    if kind == "crash":
        query = query.where(Report.reason.contains(CRASH_MARKER))
    elif kind == "bug":
        query = query.where(~Report.reason.contains(CRASH_MARKER), _IS_BUG)
    elif kind == "abuse":
        query = query.where(~Report.reason.contains(CRASH_MARKER), _IS_NOT_BUG)
    elif kind == "user":
        query = query.where(~Report.reason.contains(CRASH_MARKER))
    elif kind != "all":
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, f"unknown kind: {kind}"
        )
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

    # One query for every turn on the page, not one per report.
    turns: dict[int, list[ReportTurnOut]] = {}
    if rows:
        for m in (await db.execute(
            select(ReportMessage)
            .where(ReportMessage.report_id.in_([r.id for r in rows]))
            .order_by(ReportMessage.created_at.asc())
        )).scalars().all():
            turns.setdefault(m.report_id, []).append(ReportTurnOut(
                id=m.id, from_admin=m.from_admin, author_uin=m.author_uin,
                body=m.body, created_at=m.created_at,
            ))

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
            thread=turns.get(r.id, []),
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


async def _report_out(db: AsyncSession, report: Report) -> ReportOut:
    """One place that turns a Report row into the queue's shape. Three handlers
    used to build it inline, which is how `thread` ended up on some responses
    and not others."""
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
        # The thread rides along, so a queue that just replied or reopened
        # repaints from the response instead of refetching the list.
        thread=[
            ReportTurnOut(
                id=m.id, from_admin=m.from_admin, author_uin=m.author_uin,
                body=m.body, created_at=m.created_at,
            )
            for m in (await db.execute(
                select(ReportMessage)
                .where(ReportMessage.report_id == report.id)
                .order_by(ReportMessage.created_at.asc())
            )).scalars().all()
        ],
    )


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
    # Reopening is a verdict like any other, and the queue needs it: a ticket
    # closed by mistake, or one the reporter answered after it was closed, has
    # to come back to the open list. Without it the only way back was a manual
    # UPDATE on the database, which is not a workflow.
    if action in {"reopen", "open", "reopened"}:
        report.status = "open"
        report.resolution_action = ""
        report.resolution_notes = body.notes.strip()
        report.resolved_at = None
        await db.commit()
        await db.refresh(report)
        return await _report_out(db, report)

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
    # The same text also becomes a turn in the report's conversation. Both,
    # not one or the other: `reply_text` is what every already-installed client
    # reads, and the thread is what a client with a ticket screen renders. When
    # the fleet has turned over, `reply_text` becomes a mirror of the last
    # operator turn and nothing more.
    db.add(ReportMessage(
        report_id=report.id, from_admin=True, author_uin=0, body=report.reply_text
    ))
    await db.commit()
    await db.refresh(report)

    push_args = dict(
        alert_body="We answered your report",
        thread_id="reports",
        notif_kind="report_reply",
    )
    await apns_send(report.reporter_uin, **push_args)
    await up_send(report.reporter_uin, **push_args)

    return await _report_out(db, report)


class EditTurnIn(BaseModel):
    body: str = Field(..., min_length=1, max_length=4000)


@router.patch("/reports/{report_id}/messages/{message_id}", response_model=ReportOut)
async def edit_admin_turn(
    report_id: int,
    message_id: int,
    body: EditTurnIn,
    db: AsyncSession = Depends(get_db),
) -> ReportOut:
    """Fix an operator's own turn in a ticket.

    Answers get typed under time pressure and sometimes carry the wrong version
    number or the wrong link. Before this the only options were to send a second
    turn correcting the first, or to leave it. Only OUR side is editable: the
    reporter's words are theirs, and an operator quietly rewriting them would
    make the whole thread worthless as a record.

    `reply_text` mirrors the LAST operator turn for clients that predate the
    thread, so editing that turn updates it too — otherwise an old build would
    keep showing the sentence we just corrected.
    """
    report = await db.get(Report, report_id)
    if report is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such report")
    turn = await db.get(ReportMessage, message_id)
    if turn is None or turn.report_id != report_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such message")
    if not turn.from_admin:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            detail={"code": "not_ours", "message": "only operator turns can be edited"},
        )
    turn.body = body.body.strip()
    last_admin = (
        await db.execute(
            select(ReportMessage)
            .where(ReportMessage.report_id == report_id, ReportMessage.from_admin.is_(True))
            .order_by(ReportMessage.created_at.desc())
            .limit(1)
        )
    ).scalars().first()
    if last_admin is not None and last_admin.id == turn.id:
        report.reply_text = turn.body
    await db.commit()
    await db.refresh(report)
    return await _report_out(db, report)


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
_HOF_TIERS = {"bronze", "silver", "gold", "ruby"}


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
            .where(User.hof_opt_in.is_(True))
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
    from app.main import _pool_gauge  # local: app.main imports this router

    in_use, ceiling = _pool_gauge()
    snap["pool"] = {"in_use": in_use, "ceiling": ceiling}
    snap["workers_note"] = "per-process; multiple uvicorn workers each keep their own"
    # ⚠ Unlike everything above, calls are ISLAND-WIDE and survive a deploy:
    # they live in Redis, not in this process. They are here because both
    # numbers were invisible until 2026-08-12, when calls stopped working for
    # everyone and it took a day to find out why — see the field notes on each.
    snap["calls"] = await _call_health()
    return snap


async def _call_health() -> dict:
    """Two things that silently break calls, neither of which shows up
    anywhere else.

    `stuck` — active-call registrations older than a call could plausibly be.
    Nothing expires that hash: it is cleared by call_end or by the socket-close
    handler, so a worker that dies mid-call leaves its two participants marked
    busy for ever, and every call they try afterwards is refused instantly with
    "busy". Fifteen such entries were found on prod, two of them real accounts
    stuck since June.

    `relay_ports` — how much of the TURN media-port range is spoken for. Every
    call here is relay-only by default, so it costs two allocations plus a
    probe, and coturn holds each for ten minutes. The range had been
    hand-narrowed to 49 ports, i.e. about a dozen concurrent calls for the whole
    service; past that the client gathers no candidates at all and the call dies
    on its connect timeout with nothing logged anywhere.
    """
    from app.routers.ws import _CALLS_KEY, _CALL_REGISTRATION_STALE_S, _get_redis

    out: dict = {"active": 0, "stuck": 0, "stale_after_s": _CALL_REGISTRATION_STALE_S}
    try:
        redis = await _get_redis()
        entries = await redis.hgetall(_CALLS_KEY)
    except Exception:  # noqa: BLE001 — a panel must never be the thing that breaks
        out["error"] = "redis unavailable"
        return out
    now = int(_time.time())
    for raw in (entries or {}).values():
        parts = str(raw).split("|")
        started = int(parts[2]) if len(parts) >= 3 and parts[2].isdigit() else None
        # No timestamp means it predates the field, which means it predates the
        # last deploy, which means it is not a live call.
        if started is None or (now - started) > _CALL_REGISTRATION_STALE_S:
            out["stuck"] += 1
        else:
            out["active"] += 1
    # Registrations are per participant; a call holds two.
    out["active_calls"] = out["active"] // 2
    return out


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
    from app.models.relay_inquiry import RelayInquiry
    open_inquiries = await db.scalar(
        select(func.count()).select_from(RelayInquiry).where(RelayInquiry.status == "open")
    ) or 0
    open_reports = (await db.scalar(
        select(func.count(Report.id)).where(Report.status == "open")
    ) or 0) - int(open_crashes)
    open_bugs = await db.scalar(
        select(func.count(Report.id)).where(
            Report.status == "open",
            ~Report.reason.contains(CRASH_MARKER),
            _IS_BUG,
        )
    ) or 0
    open_abuse = await db.scalar(
        select(func.count(Report.id)).where(
            Report.status == "open",
            ~Report.reason.contains(CRASH_MARKER),
            _IS_NOT_BUG,
        )
    ) or 0
    resolved_reports_7d = await db.scalar(
        select(func.count(Report.id)).where(
            Report.status != "open", Report.resolved_at >= week_ago
        )
    ) or 0

    # The public bridge pool, counted the way `/broker/bridges` itself filters:
    # enabled, and NOT bound to a tenant (a tenant's node is never disclosed
    # publicly). `live` additionally applies the canary liveness window, which
    # is what actually gates a community relay from being served.
    from app.models.broker import BrokerRelay
    from app.routers.broker import _LIVENESS_WINDOW

    public_rows = (
        await db.execute(
            select(BrokerRelay).where(
                BrokerRelay.enabled.is_(True),
                BrokerRelay.tenant_id.is_(None),
            )
        )
    ).scalars().all()
    now_epoch = int(now.timestamp())
    broker_public_live = sum(
        1
        for r in public_rows
        if r.tier == "trusted"
        or (r.last_ok is not None and now_epoch - r.last_ok <= _LIVENESS_WINDOW)
    )

    return StatsOut(
        broker_public_relays=len(public_rows),
        broker_public_live=int(broker_public_live),
        total_users=int(total_users),
        suspended_users=int(suspended_users),
        new_users_24h=int(new_users_24h),
        new_users_7d=int(new_users_7d),
        open_reports=int(open_reports),
        open_crashes=int(open_crashes),
        open_abuse=int(open_abuse),
        open_bugs=int(open_bugs),
        open_inquiries=int(open_inquiries),
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
        .where(User.created_at >= start)
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
        .where(User.last_seen >= start)
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


class HourPoint(BaseModel):
    hour: str
    msg: int
    gmsg: int
    reg: int
    ws: int
    call: int
    online_max: int


class ActivityHourlyOut(BaseModel):
    points: list[HourPoint]
    # When the counters first existed — hours before this are "no data yet",
    # not "the island was silent", and the panel draws them differently.
    since: str | None


@router.get("/activity-hourly", response_model=ActivityHourlyOut)
async def activity_hourly(hours: int = Query(168, ge=24, le=720)) -> ActivityHourlyOut:
    """Island-wide hourly activity with the sampled online peak.

    This is the long-memory counterpart to /admin/metrics: island-wide (the
    ring is per worker) and deploy-proof (the ring resets). Counted in Redis
    at the hot paths; see services/activity_rollup.py.
    """
    from app.services.activity_rollup import read_hours

    points, since = await read_hours(hours)
    return ActivityHourlyOut(points=[HourPoint(**p) for p in points], since=since)


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


class HoldUinIn(BaseModel):
    uin: int = Field(gt=0)
    #: The till's own handle for this hold, so it can release what it placed.
    hold_id: str = Field(min_length=8, max_length=64)
    #: Minutes to keep the number off the shelf. Deliberately allowed to be far
    #: longer than an invoice: a payment that lands late should find the number
    #: still there, and a number nobody paid for costs nothing to hold.
    minutes: int = Field(default=1440, ge=5, le=10080)


class HoldUinOut(BaseModel):
    uin: int
    hold_id: str
    expires_at: datetime


@router.post("/uin/hold", response_model=HoldUinOut)
async def hold_uin(body: HoldUinIn, db: AsyncSession = Depends(get_db)) -> HoldUinOut:
    """Keep a number off the shelf while somebody pays for it.

    This is the OPERATOR's door, for holding a number by hand. The till uses
    `POST /uin/hold`, which proves itself with the same signing key its
    vouchers carry: a machine that only needs to reserve numbers has no
    business holding the credentials that can also read the member list.

    Either way the hold carries no buyer and no price: the island's whole share
    of a sale is "this number is spoken for until this moment".

    ⚠ The hold is what stops two people paying for one number. With the money
    watched outside this island there is no automatic refund, so a number sold
    twice has no clean ending; a number held for a day and not paid for costs
    nothing at all. That asymmetry is why the default window is generous.
    """
    if await uin_is_taken(db, body.uin):
        raise HTTPException(status.HTTP_409_CONFLICT, detail={"code": "taken"})
    expires = datetime.now(timezone.utc) + timedelta(minutes=int(body.minutes))
    existing = await db.get(UinHold, body.uin)
    if existing is not None:
        existing.hold_id = body.hold_id
        existing.expires_at = expires
    else:
        db.add(UinHold(uin=body.uin, hold_id=body.hold_id, expires_at=expires))
    await db.commit()
    return HoldUinOut(uin=body.uin, hold_id=body.hold_id, expires_at=expires)


@router.delete("/uin/hold/{uin}", response_model=dict)
async def release_hold(uin: int, db: AsyncSession = Depends(get_db)) -> dict:
    """Let a number go before its hold expires: the buyer walked away, or the
    invoice was cancelled. Idempotent - releasing a hold that is already gone is
    the same outcome the caller wanted."""
    hold = await db.get(UinHold, uin)
    if hold is not None:
        await db.delete(hold)
        await db.commit()
    return {"ok": True}


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
    # PROMISED is as unavailable as held, and this is the other direction of the
    # check `POST /admin/invites` already makes (it answers `uin_held`). A live
    # invite reserving this number has no `users` row and no `owned_uins` row,
    # so both checks above see free space and the operator ends up having
    # promised the same number twice. It fails on the redeemer's side and
    # silently: `auth.register` spends the invite use in the atomic UPDATE
    # BEFORE it tests availability, so the newcomer gets an unrelated random
    # number, the single-use code is burnt, and nobody is told anything.
    reserved = await db.scalar(
        select(Invite.code).where(Invite.uin == body.uin, *invite_is_live())
    )
    if reserved is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, detail={"code": "uin_reserved"})
    if await db.get(User, body.to_uin) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail={"code": "no_such_user"})

    db.add(OwnedUin(uin=body.uin, owner_uin=body.to_uin, source="granted"))
    await db.commit()
    owned = (
        await db.execute(
            select(OwnedUin.uin).where(OwnedUin.owner_uin == body.to_uin).order_by(OwnedUin.uin)
        )
    ).scalars().all()
    # ⚠ Two accounts in the clear, at WARNING, on a line whose whole content
    # was "this number now belongs to that person". The durable record of the
    # grant is the `owned_uins` row with `source="granted"`, which is where an
    # operator should read it; the journal only needs to know a grant happened
    # and when. Both fields go behind the flag, the vanity number included:
    # it is one lookup away from naming its new holder.
    log.warning("[uin-grant] %s -> %s", log_identity(body.uin), log_identity(body.to_uin))
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
    # ⚠ The sha256-hex, not the token: `invites.code` stopped holding the raw
    # credential on 2026-08-22. Kept in the payload because it is this row's id
    # everywhere else in the panel: the list keys on it and DELETE /invites/{code}
    # revokes by it. Publishing a hash to an authenticated admin costs nothing.
    code: str
    label: str | None
    max_uses: int
    used_count: int
    uin: int | None = None
    expires_at: datetime | None
    created_at: datetime
    # The raw token and its join URL, present ONLY in the response to the mint
    # that created it. The island cannot reproduce either afterwards, which is
    # the entire point of hashing: a dump of this table no longer mints access.
    # Both panels render the QR from the mint response and show
    # "code shown once" on every older row.
    raw_code: str | None = None
    join_url: str | None = None


def _join_url(request: Request, raw_code: str) -> str:
    host = request.headers.get("x-forwarded-host") or (request.url.hostname or "")
    return f"rcq://server/{host}?invite={raw_code}"


def _invite_out(request: Request, inv: Invite, raw_code: str | None = None) -> InviteOut:
    return InviteOut(
        code=inv.code,
        label=inv.label,
        max_uses=inv.max_uses,
        used_count=inv.used_count,
        uin=inv.uin,
        expires_at=inv.expires_at,
        created_at=inv.created_at,
        raw_code=raw_code,
        join_url=_join_url(request, raw_code) if raw_code else None,
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
        # Held is as unavailable as registered. A number in somebody's
        # collection has no `users` row, so the check above sees nothing and
        # the operator would be promising the same number twice: once to the
        # holder (who was told nobody else could take it) and once to whoever
        # redeems this code. Same rule `POST /admin/uin/grant` already applies
        # in the other direction, where it answers "already_held".
        if await db.scalar(
            select(OwnedUin.uin).where(OwnedUin.uin == reserved_uin)
        ) is not None:
            raise HTTPException(status.HTTP_409_CONFLICT, detail={"code": "uin_held"})
        already = await db.scalar(
            select(Invite.code).where(Invite.uin == reserved_uin, *invite_is_live())
        )
        if already is not None:
            raise HTTPException(status.HTTP_409_CONFLICT, detail={"code": "uin_reserved"})
    raw_code = secrets.token_urlsafe(16)
    expires_at = (
        datetime.now(timezone.utc) + timedelta(hours=body.ttl_hours)
        if body.ttl_hours
        else None
    )
    inv = Invite(
        code=hash_invite_code(raw_code), label=body.label, max_uses=body.max_uses,
        expires_at=expires_at, uin=reserved_uin,
    )
    db.add(inv)
    await db.commit()
    await db.refresh(inv)
    # The one and only time the raw token leaves this process.
    return _invite_out(request, inv, raw_code=raw_code)


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


# ── private-relay inquiries ────────────────────────────────────────────────
#
# The queue behind the `/organizations` form. Until this existed the form
# stored nothing, so "довести заявку до админки" is the whole point: an
# organisation asking to pay for private relays now reaches a human. Payment
# is deliberately NOT here — the first customers are handled by hand (phase 0
# in docs/private-relays-design.md), and a queue is what makes that possible.


class RelayInquiryOut(BaseModel):
    id: int
    tier: str
    contact: str
    about: str
    status: str
    note: str
    country: str
    lang: str
    created_at: datetime


class RelayInquiriesListOut(BaseModel):
    inquiries: list[RelayInquiryOut]
    open_count: int


@router.get("/relay-inquiries", response_model=RelayInquiriesListOut)
async def list_relay_inquiries(
    status_filter: str = Query("open", alias="status"),
    limit: int = Query(100, le=500),
    db: AsyncSession = Depends(get_db),
) -> RelayInquiriesListOut:
    """`status` accepts: open | contacted | closed | all."""
    query = select(RelayInquiry).order_by(desc(RelayInquiry.created_at)).limit(limit)
    if status_filter != "all":
        query = query.where(RelayInquiry.status == status_filter)
    rows = (await db.execute(query)).scalars().all()
    open_count = (
        await db.execute(
            select(func.count()).select_from(RelayInquiry).where(RelayInquiry.status == "open")
        )
    ).scalar_one()
    return RelayInquiriesListOut(
        inquiries=[
            RelayInquiryOut(
                id=r.id, tier=r.tier, contact=r.contact, about=r.about or "",
                status=r.status, note=r.note or "", country=r.country or "",
                lang=r.lang or "", created_at=r.created_at,
            )
            for r in rows
        ],
        open_count=int(open_count),
    )


class RelayInquiryPatch(BaseModel):
    status: str | None = None
    note: str | None = None


@router.patch("/relay-inquiries/{inquiry_id}", response_model=RelayInquiryOut)
async def update_relay_inquiry(
    inquiry_id: int,
    body: RelayInquiryPatch,
    db: AsyncSession = Depends(get_db),
) -> RelayInquiryOut:
    row = await db.get(RelayInquiry, inquiry_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "inquiry not found")
    if body.status is not None:
        if body.status not in {"open", "contacted", "closed"}:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "bad status")
        row.status = body.status
    if body.note is not None:
        row.note = body.note[:4000]
    await db.commit()
    return RelayInquiryOut(
        id=row.id, tier=row.tier, contact=row.contact, about=row.about or "",
        status=row.status, note=row.note or "", country=row.country or "",
        lang=row.lang or "", created_at=row.created_at,
    )
