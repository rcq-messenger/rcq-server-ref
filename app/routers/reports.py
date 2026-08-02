"""User-side abuse reports.

iOS surfaces a `Report` action on a contact (and on the contact's
preview overlay). Tap → sheet → reason text → POST /reports.

Sealed-sender means the report can only be tied to a UIN, not to a
specific message — the reporter knows the sender of THEIR copy of a
message, but the server cannot verify that mapping. We accept the
report as filed and let the admin triage the queue manually.

Media evidence flow
-------------------
For end-to-end-encrypted media the server can never decrypt the
bytes. Without an evidence path that's a moderation black hole. The
`POST /reports/with_evidence` endpoint plugs that gap: the reporter,
after explicit consent, uploads the DECRYPTED media along with the
reason text. The server stores it under `evidence/<uuid>.<ext>`
(admin-only path) and records the path on the Report row.
"""

import contextlib
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import get_db
from app.core.rate_limit import enforce_rate_limit, rate_limit
from app.core.security import current_uin
from app.models.report import Report
from app.services import server_settings

router = APIRouter(prefix="/reports", tags=["reports"])


async def require_reports_open() -> None:
    """Reject new submissions when the operator has switched reports off
    (admin console → Features, advertised as `reports` on /server/info).

    Only INTAKE is gated. `GET /reports/mine` stays open on purpose: someone
    who filed a report before the operator closed the desk must still be able
    to read the answer, and taking that away would make the off switch a way
    to silently drop a conversation already in progress.
    """
    if not await server_settings.get_bool("reports_enabled"):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            detail={"code": "reports_disabled",
                    "message": "this island does not accept reports"},
        )

# Anti-spam guard rails. Reasons are short user-typed text — caps
# keep the queue readable + bound disk usage. The context tag is
# even shorter (it's a surface code like "contact" or "hood").
MAX_REASON_LEN: int = 1000
MAX_CONTEXT_LEN: int = 64

# Per-hour submission budgets, per UIN. Reports ABOUT another member are
# rate-limited as a harassment guard (see create_report). Bug reports are
# limited only so a broken client can't loop forever.
ABUSE_REPORTS_PER_HOUR: int = 5
BUG_REPORTS_PER_HOUR: int = 20

# Evidence file caps. 25 MB matches the in-app media size limit;
# larger files would exceed both a sane memory budget for the upload
# and what a reporter would reasonably attach as evidence (a single
# photo or short video).
MAX_EVIDENCE_BYTES: int = 25 * 1024 * 1024
ALLOWED_EVIDENCE_MIMES: set[str] = {
    "image/jpeg", "image/png", "image/heic", "image/heif", "image/webp",
    "video/mp4", "video/quicktime", "video/x-m4v",
}

# Filesystem location for stored evidence. Lives next to the regular
# `media/` dir but is admin-only — Caddy doesn't expose it; the only
# read path is through admin endpoints (future: /admin/reports/<id>/
# evidence). Created at module-import time so the first report on a
# fresh deploy doesn't crash on the missing directory.
_EVIDENCE_DIR = Path(os.environ.get("RCQ_EVIDENCE_DIR", "evidence")).resolve()
_EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)


# Bug-bounty attachment caps. Each row references a previously
# uploaded /media blob; we never hold plaintext. Three attachments per
# report is comfortably more than the typical "one screenshot, one
# screen recording" pattern testers send, and bounds the JSON column
# size so it can't be used as a smuggling channel.
MAX_ATTACHMENTS_PER_REPORT: int = 3


class ReportAttachmentIn(BaseModel):
    """One encrypted blob attached to a bug-bounty report. The reporter
    uploads the bytes through the standard /media/upload encrypted lane
    and ships the resulting (media_id, AES key) tuple here. Server
    stores both opaquely — the admin client decrypts the blob on
    inspection using `key`."""

    media_id: str = Field(..., min_length=1, max_length=64)
    key: str = Field(..., min_length=1, max_length=96)
    mime: str = Field(..., min_length=1, max_length=64)
    size: int = Field(default=0, ge=0)


class CreateReportIn(BaseModel):
    target_uin: int = Field(gt=0)
    reason: str = Field(min_length=1, max_length=MAX_REASON_LEN)
    context: str = Field(default="", max_length=MAX_CONTEXT_LEN)
    attachments: list[ReportAttachmentIn] = Field(default_factory=list)


class CreateReportOut(BaseModel):
    id: int
    created_at: datetime


@router.post(
    "",
    response_model=CreateReportOut,
    status_code=status.HTTP_201_CREATED,
    # The per-hour budget is applied INSIDE the handler, because it depends on
    # what kind of report this is and that only exists in the body. See
    # BUG_REPORTS_PER_HOUR.
    dependencies=[Depends(require_reports_open)],
)
async def create_report(
    body: CreateReportIn,
    uin: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> CreateReportOut:
    # Two different things ride this endpoint and they deserve different caps.
    # Flagging OTHER PEOPLE is a harassment vector: mass-flagging drowns the
    # queue and can be used against someone, so it stays tight. Writing to the
    # maintainers about the app is the opposite — it is the thing we ask people
    # to do, and 5/hour punished exactly the person who takes it seriously.
    # user-9547 sent 24 reports in five days; on 2026-08-02 the access log
    # shows 26 rejections against 8 accepted, i.e. he spent a quarter of an
    # hour retrying a button that told him nothing.
    is_bug_report = body.context == "bug_bounty"
    await enforce_rate_limit(
        f"uin:{uin}",
        "reports_bug" if is_bug_report else "reports_create",
        BUG_REPORTS_PER_HOUR if is_bug_report else ABUSE_REPORTS_PER_HOUR,
        3600,
    )
    # Self-target is rejected for normal abuse reports (no meaningful
    # action an admin can take) but PERMITTED for bug-bounty
    # submissions, which ride this same endpoint with `context =
    # "bug_bounty"` and use target_uin == self as a "submitter is
    # also the subject" stand-in (the real signal is the body text).
    if body.target_uin == uin and body.context != "bug_bounty":
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "cannot report yourself",
        )

    # Attachments are only meaningful on bug-bounty submissions today.
    # Quietly drop them for plain abuse reports rather than 400ing —
    # that path is owned by older clients and shouldn't break if some
    # future build mis-tags. Bug-bounty path caps the count.
    attachments_payload: list[dict] | None = None
    if body.context == "bug_bounty" and body.attachments:
        if len(body.attachments) > MAX_ATTACHMENTS_PER_REPORT:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                detail={
                    "code": "too_many_attachments",
                    "max": MAX_ATTACHMENTS_PER_REPORT,
                },
            )
        attachments_payload = [
            {
                "media_id": a.media_id,
                "key": a.key,
                "mime": a.mime,
                "size": a.size,
            }
            for a in body.attachments
        ]

    report = Report(
        reporter_uin=uin,
        target_uin=body.target_uin,
        reason=body.reason.strip(),
        context=body.context.strip(),
        attachments=attachments_payload,
    )
    db.add(report)
    await db.commit()
    await db.refresh(report)
    return CreateReportOut(id=report.id, created_at=report.created_at)


@router.post(
    "/with_evidence",
    response_model=CreateReportOut,
    status_code=status.HTTP_201_CREATED,
    # Same per-hour cap as the reason-only flow — both routes share
    # the same admin-queue scarcity. A single user mass-uploading
    # spurious evidence files would otherwise drain disk; the cap
    # bounds that.
    dependencies=[
        Depends(require_reports_open),
        Depends(rate_limit("reports_create", ABUSE_REPORTS_PER_HOUR, 3600)),
    ],
)
async def create_report_with_evidence(
    target_uin: int = Form(...),
    reason: str = Form(...),
    context: str = Form(""),
    message_id: str = Form(""),
    consent_acknowledged: bool = Form(...),
    evidence: UploadFile = File(...),
    uin: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> CreateReportOut:
    """Report with attached decrypted media as evidence.

    Reporter consents (via the `consent_acknowledged` form field —
    the iOS sheet shows an explicit "I authorize RCQ moderators to
    review this content" toggle) and the device uploads the
    DECRYPTED bytes. Server stores under `evidence/<uuid>.<ext>`
    with admin-only access; never re-encrypts (the whole point is
    that the moderator can read it).
    """
    if target_uin == uin:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "cannot report yourself")
    if not consent_acknowledged:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            detail={"code": "consent_required"},
        )
    if not reason.strip() or len(reason) > MAX_REASON_LEN:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid reason length")
    if len(context) > MAX_CONTEXT_LEN:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "context too long")
    if len(message_id) > 36:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid message_id")

    # Mime gate. Reject anything we don't have a clear policy for —
    # the admin queue is meant for media + photos, not arbitrary
    # binary blobs that could carry malware.
    mime = evidence.content_type or "application/octet-stream"
    if mime not in ALLOWED_EVIDENCE_MIMES:
        raise HTTPException(
            status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail={"code": "unsupported_evidence_type", "mime": mime},
        )

    # Read with a hard byte cap. `UploadFile.read()` happily slurps
    # multi-GB into memory if you let it; we read in chunks and
    # short-circuit at the cap.
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = await evidence.read(64 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > MAX_EVIDENCE_BYTES:
            raise HTTPException(
                status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail={"code": "evidence_too_large", "max_bytes": MAX_EVIDENCE_BYTES},
            )
        chunks.append(chunk)
    payload = b"".join(chunks)
    if not payload:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "empty evidence")

    # Store under a fresh UUID so a malicious uploader can't probe
    # other reports' files by guessing names. Extension comes from
    # the mime — never trusted from `evidence.filename` (that's
    # client-controlled and could carry path-traversal payload).
    ext = {
        "image/jpeg": ".jpg",
        "image/png": ".png",
        "image/heic": ".heic",
        "image/heif": ".heif",
        "image/webp": ".webp",
        "video/mp4": ".mp4",
        "video/quicktime": ".mov",
        "video/x-m4v": ".m4v",
    }.get(mime, ".bin")
    file_id = str(uuid.uuid4())
    file_path = _EVIDENCE_DIR / f"{file_id}{ext}"
    try:
        file_path.write_bytes(payload)
    except OSError as exc:
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"code": "evidence_write_failed", "error": str(exc)},
        )

    # Relative path stored in DB so the admin endpoint can serve it
    # regardless of where the evidence dir is mounted.
    relative_path = f"{file_id}{ext}"
    report = Report(
        reporter_uin=uin,
        target_uin=target_uin,
        reason=reason.strip(),
        context=context.strip() or "premium_media",
        evidence_path=relative_path,
        evidence_mime=mime,
        message_id=message_id or None,
    )
    db.add(report)
    await db.commit()
    await db.refresh(report)
    return CreateReportOut(id=report.id, created_at=report.created_at)


class MyReportOut(BaseModel):
    id: int
    reason: str
    status: str
    created_at: datetime
    # The operator's answer, empty until one is written. This is the whole
    # point of the endpoint: before it existed a report was a one-way box.
    reply: str
    replied_at: datetime | None


@router.get("/mine", response_model=list[MyReportOut])
async def my_reports(
    uin: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> list[MyReportOut]:
    """The reporter's own reports, with the operator's answer when there is one.

    Why a fetch and not a message: a reply cannot be delivered into a chat.
    Chats are sealed on the sending device and the server holds no keys, so
    the only way for the server to put text in front of a user would be a
    channel that lets it write into conversations — exactly the capability
    this project promises it does not have. Instead the answer stays server
    data, attached to the report, and the reporter reads it back over their
    own authenticated session. Nothing here claims to be an encrypted
    message, and a compromised server gains no ability to impersonate anyone.

    Only the reporter's own rows, and only the reader-safe columns:
    `resolution_notes` is the operator's internal reasoning and never leaves
    the admin side.
    """
    rows = (
        await db.execute(
            select(Report)
            .where(Report.reporter_uin == uin)
            .order_by(Report.created_at.desc())
            .limit(50)
        )
    ).scalars().all()
    return [
        MyReportOut(
            id=r.id,
            reason=r.reason,
            status=r.status,
            created_at=r.created_at,
            reply=r.reply_text or "",
            replied_at=r.replied_at,
        )
        for r in rows
    ]


@router.delete("/mine/{report_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_my_report(
    report_id: int,
    uin: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Let a reporter drop their own report.

    A tester asked for this the obvious way: the list shows a stale piece of
    feedback from weeks ago and there is no way to be rid of it. The text is
    theirs, so they may take it back.

    One exception, and it is not a technicality: a still-open report ABOUT
    ANOTHER user is the only record moderation has of that complaint, and a
    "delete" button over it would let someone file an accusation, watch the
    consequences land, and then erase the evidence. Those wait for a verdict;
    everything else (feedback, bug reports, anything already resolved) goes.
    Deleting is a real DELETE — no tombstone, nothing kept "just in case".
    """
    report = await db.get(Report, report_id)
    if report is None or report.reporter_uin != uin:
        # Same answer either way: a wrong id must not confirm that some other
        # user's report exists.
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail={"code": "not_found"})
    if report.target_uin != uin and report.status == "open":
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail={"code": "under_review"},
        )
    if report.evidence_path:
        # The decrypted evidence blob outlives the row otherwise: the sweep
        # only ever looked at expiry, never at deletions. Resolve by NAME under
        # the evidence dir, the way the sweep does — `evidence_path` is stored
        # relative and must never be able to point outside it.
        target = (_EVIDENCE_DIR / Path(report.evidence_path).name).resolve()
        if target.parent == _EVIDENCE_DIR:
            with contextlib.suppress(OSError):
                target.unlink()
    await db.delete(report)
    await db.commit()
