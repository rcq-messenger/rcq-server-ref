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

import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import get_db
from app.core.rate_limit import rate_limit
from app.core.security import current_uin
from app.models.report import Report

router = APIRouter(prefix="/reports", tags=["reports"])

# Anti-spam guard rails. Reasons are short user-typed text — caps
# keep the queue readable + bound disk usage. The context tag is
# even shorter (it's a surface code like "contact" or "hood").
MAX_REASON_LEN: int = 1000
MAX_CONTEXT_LEN: int = 64

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
    # Reports queue is admin-managed; a single user mass-flagging
    # innocent people would drown the queue and become a
    # harassment vector. 5/hr per UIN is plenty for a real user
    # who hits a bad day on Hood.
    dependencies=[Depends(rate_limit("reports_create", 5, 3600))],
)
async def create_report(
    body: CreateReportIn,
    uin: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> CreateReportOut:
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
    dependencies=[Depends(rate_limit("reports_create", 5, 3600))],
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
