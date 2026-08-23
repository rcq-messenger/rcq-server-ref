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

The number, and why deleting is a hide
--------------------------------------
Every user-facing response here carries `number`, and it is `reports.id`, the
same integer the founder triages by. There is exactly one number for a report,
because he answers people by quoting it (see _report_number).

Dropping a report from your own list is a SOFT delete (`hidden_at`), which is
not tidiness: the Hall of Fame counts these rows live, so a hard DELETE let a
contributor erase the reports that came back dismissed and rank as somebody who
is never wrong. See delete_my_report for the rule and what it costs.
"""

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
from app.models.report_message import ReportMessage
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


# Auto-submitted crash reports ride this same channel: clients prefix `reason`
# with "[<platform> <version>] [CRASH]". Mirrors CRASH_MARKER in
# app/routers/admin.py and _CRASH_MARKER in app/services/hof_stats.py, which is
# where it does the real work (a crash dump is not a contributor's effort and is
# kept out of the Hall of Fame counts). Kept as a literal here rather than
# imported from the admin router, so this module stays free of it. Keep the
# three in sync.
CRASH_MARKER = "[CRASH]"


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


# The number a person can quote when they write "обращение #123", and the
# number the operator answers by. It is `reports.id` verbatim, on purpose.
#
# The alternative was a per-account counter (your first report is #1), which
# hides how many reports the whole island has taken. That privacy is worth
# less than it looks: the founder triages from /admin/reports, which lists the
# primary key, and the reply channel refers to reports by that number. A second
# numbering would mean the person and the person answering them are looking at
# two different numbers for the same report, and the first time that goes wrong
# is the first time somebody quotes a number in a support thread. So: ONE
# number, and it is the admin's.
#
# What it leaks is the row id, i.e. roughly how many reports have ever been
# filed on this island, to anyone who files one. It is already leaked by the
# `id` field these responses have always carried; naming it does not widen
# anything, it only tells the client which integer to print.
def _report_number(report: Report) -> int:
    return report.id


class CreateReportOut(BaseModel):
    id: int
    # Same integer as `id`. Present as its own field so clients render the
    # number instead of guessing whether `id` is an internal key they should
    # keep out of the UI. See _report_number.
    number: int
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
    return CreateReportOut(
        id=report.id, number=_report_number(report), created_at=report.created_at
    )


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
    return CreateReportOut(
        id=report.id, number=_report_number(report), created_at=report.created_at
    )


class ReportTurnOut(BaseModel):
    id: int
    from_admin: bool
    body: str
    created_at: datetime


class MyReportOut(BaseModel):
    id: int
    # The number to print: "обращение #123". Same integer as `id` and the same
    # one the operator sees in the queue, which is the point. See
    # _report_number.
    number: int
    reason: str
    status: str
    created_at: datetime
    # Set once the reporter has rewritten their own text (PATCH below). NULL on
    # every report nobody edited, which is all of them before 2026-08-23.
    edited_at: datetime | None = None
    # The operator's answer, empty until one is written. This is the whole
    # point of the endpoint: before it existed a report was a one-way box.
    #
    # ⚠ Kept for clients that predate the thread below. It mirrors the LAST
    # operator turn, so an old build shows the newest answer instead of
    # silently showing nothing.
    reply: str
    replied_at: datetime | None
    # The whole exchange, oldest first — what a client with a ticket screen
    # renders. Empty on a report nobody has answered and nobody has added to.
    thread: list[ReportTurnOut] = []


async def _thread_of(db: AsyncSession, report_ids: list[int]) -> dict[int, list[ReportTurnOut]]:
    """Every turn for these reports, grouped. One query, because the list
    screen asks for fifty reports at once and a query per report is how a
    screen that used to be instant becomes a spinner."""
    if not report_ids:
        return {}
    rows = (
        await db.execute(
            select(ReportMessage)
            .where(ReportMessage.report_id.in_(report_ids))
            .order_by(ReportMessage.created_at.asc())
        )
    ).scalars().all()
    out: dict[int, list[ReportTurnOut]] = {}
    for m in rows:
        out.setdefault(m.report_id, []).append(
            ReportTurnOut(id=m.id, from_admin=m.from_admin, body=m.body, created_at=m.created_at)
        )
    return out


def _mine_out(report: Report, thread: list[ReportTurnOut]) -> MyReportOut:
    """One place that shapes a report for its own author. The list and the edit
    endpoint both return it, and building it twice by hand is how two callers
    end up disagreeing about which fields a report has."""
    return MyReportOut(
        id=report.id,
        number=_report_number(report),
        reason=report.reason,
        status=report.status,
        created_at=report.created_at,
        edited_at=report.edited_at,
        reply=report.reply_text or "",
        replied_at=report.replied_at,
        thread=thread,
    )


class AddTurnIn(BaseModel):
    body: str = Field(..., min_length=1, max_length=4000)


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
    the admin side. Rows the reporter dropped (`hidden_at`) are gone from here
    and from nowhere else, which is the whole of what dropping one means.
    """
    rows = (
        await db.execute(
            select(Report)
            .where(Report.reporter_uin == uin, Report.hidden_at.is_(None))
            .order_by(Report.created_at.desc())
            .limit(50)
        )
    ).scalars().all()
    threads = await _thread_of(db, [r.id for r in rows])
    return [_mine_out(r, threads.get(r.id, [])) for r in rows]


@router.post(
    "/mine/{report_id}/messages",
    response_model=ReportTurnOut,
    status_code=status.HTTP_201_CREATED,
    # A conversation, not a firehose: enough to answer a question and add the
    # log line you forgot, not enough to turn the queue into a chat room.
    dependencies=[Depends(rate_limit("report_reply", 20, 3600))],
)
async def add_to_my_report(
    report_id: int,
    body: AddTurnIn,
    uin: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> ReportTurnOut:
    """Write back on your own report.

    This is the half that was missing. An operator could answer, but the person
    who filed it could not say "still happens" or hand over the diagnostic line
    they were asked for — so they filed a second report instead, and the queue
    filled with the same issue three times over.

    ⚠ Deliberately NOT gated on the island's "reports open" switch, same as
    reading: intake can be closed while a conversation that is already open
    must still be finishable.

    Only your own report, and only while it is open — a closed one that starts
    receiving text again is a ticket nobody is watching. A report you dropped
    from your list answers 404 like any other id you cannot see: it is not on
    your screen, so there is nothing there to write on.
    """
    report = await db.get(Report, report_id)
    if report is None or report.reporter_uin != uin or report.hidden_at is not None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such report")
    if report.status != "open":
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail={"code": "closed", "message": "this report is closed"},
        )
    turn = ReportMessage(report_id=report.id, from_admin=False, author_uin=uin, body=body.body.strip())
    db.add(turn)
    await db.commit()
    await db.refresh(turn)
    return ReportTurnOut(
        id=turn.id, from_admin=turn.from_admin, body=turn.body, created_at=turn.created_at
    )


@router.delete("/mine/{report_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_my_report(
    report_id: int,
    uin: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Let a reporter drop their own report from their own list.

    A tester asked for this the obvious way: the list shows a stale piece of
    feedback from weeks ago and there is no way to be rid of it.

    ⚠⚠ IT IS A HIDE, NOT A DELETE, AND THAT IS THE BUG THIS FIXES. This used to
    be a real DELETE with no tombstone, which sounded principled and was in fact
    a scoreboard exploit: `services/hof_stats` counts a contributor's bug-bounty
    reports (how many filed, how many confirmed) live over these rows, so
    deleting the ones that came back `dismissed` or `duplicate` raised the
    confirmed-to-filed ratio the public wall ranks people by. File thirty, keep
    the four that were real, and the wall shows a contributor who is never
    wrong. So the row stays and only leaves the reporter's screen.

    THE RULE, and it has no exceptions because every exception is a loophole:
    once filed, a report counts as filed forever. Not "unless it was still
    pending": the operator says "это не баг" in the thread before he flips the
    status, so a pending carve-out would just move the exploit to the window
    between the answer and the verdict, and someone watching for it would never
    have a rejected report on their record at all. You cannot edit the number of
    times you asked, only what happened next, and `confirmed` never falls, so
    nobody is punished for filing (see hof_stats.podium_score).

    Still refused: a still-open report ABOUT ANOTHER user. Not for the evidence
    any more (the row survives now either way) but because the reporter is a
    live party to that case, and the operator's only way to ask them anything is
    the thread they would be hiding. It waits for a verdict; everything else
    (feedback, bug reports, anything already closed) goes off the list at once.

    What is deliberately NOT done here:
      * the thread is kept, because it is the operator's record of the exchange
        he is being asked to remember having had;
      * the evidence blob is kept, because deleting it is exactly how the
        founder loses the proof behind a report he rejected. It is not kept
        forever: `services/evidence_sweep` unlinks every evidence file 48h after
        the report closes and 30 days after it was filed regardless;
      * the horizon does not move. An abuse report is still deleted outright
        and a bug report still redacted down to its tally 90 days after the
        operator closes it, hidden or not (`services/report_sweep`).

    What DID have to change with the soft delete: a report withdrawn while it is
    still OPEN has no `resolved_at`, so on the resolution clock alone it had no
    clock at all, and the free text would have stayed on the island forever
    unless an operator happened to close a report nobody was asking about any
    more. The reporter cannot get at it either: it is off their list, and the
    edit and turn paths 404 on a hidden row, so they cannot even ask for it to
    be closed. `report_sweep` therefore also measures 90 days from `hidden_at`.
    Same length, different starting gun, and one that only ever applies to a row
    the reporter has already walked away from.
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
    # Idempotent: hiding an already-hidden report is a no-op, not a second
    # timestamp. A client retrying a 204 it never saw must not rewrite when.
    if report.hidden_at is None:
        report.hidden_at = datetime.now(timezone.utc)
        await db.commit()


class EditReportIn(BaseModel):
    reason: str = Field(..., min_length=1, max_length=MAX_REASON_LEN)


@router.patch(
    "/mine/{report_id}",
    response_model=MyReportOut,
    # Same budget as writing a turn: rewording your own question a few times is
    # normal, rewriting it in a loop is a client bug.
    dependencies=[Depends(rate_limit("report_edit", 20, 3600))],
)
async def edit_my_report(
    report_id: int,
    body: EditReportIn,
    uin: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> MyReportOut:
    """Rewrite your own report while nobody has answered it yet.

    People send the report and immediately notice the typo, the missing version
    number, or that they described the wrong screen. Until now the only fix was
    a second report saying "sorry, I meant", which is how the queue collected
    the same issue three times.

    ⚠ Deliberately NOT gated on the island's "reports open" switch, same as
    reading and writing back: intake can be closed while a report already in
    the queue must still be correctable.

    The rules, and each one is load-bearing:

      only your own, and not one you dropped from your list (404 either way, a
        wrong id must not confirm somebody else's report exists);

      only while `status == "open"`. Editing a closed report is editing the
        thing a verdict was written about;

      only while nothing has been said back. If the operator has replied, the
        text he replied to cannot change under him, or the thread reads as an
        answer to a question nobody asked;

      never on a crash dump, and the new text may not carry the [CRASH] marker.
        That marker is what `services/hof_stats` uses to keep auto-submitted
        crashes out of a contributor's count, so letting a person put it into
        their own text by hand would hand them a switch that takes a report out
        of the tally: file, wait, and mark as crash whatever looks like it is
        heading for a dismissal. Clients generate that prefix, people do not.

    The trail is `edited_at` and nothing more, on purpose: see Report.edited_at.
    """
    report = await db.get(Report, report_id)
    if report is None or report.reporter_uin != uin or report.hidden_at is not None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail={"code": "not_found"})
    if report.status != "open":
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail={"code": "closed", "message": "this report is closed"},
        )
    # `or ""` like every other read of this column: a row that predates the
    # column's DEFAULT can still hold NULL on an island that upgraded across it.
    if (report.reply_text or "").strip():
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail={"code": "already_answered"},
        )
    answered = await db.scalar(
        select(ReportMessage.id)
        .where(ReportMessage.report_id == report.id, ReportMessage.from_admin.is_(True))
        .limit(1)
    )
    if answered is not None:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail={"code": "already_answered"},
        )
    reason = body.reason.strip()
    if not reason:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid reason length")
    if CRASH_MARKER in reason or CRASH_MARKER in (report.reason or ""):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            detail={"code": "not_editable"},
        )
    report.reason = reason
    report.edited_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(report)
    return _mine_out(report, (await _thread_of(db, [report.id])).get(report.id, []))
