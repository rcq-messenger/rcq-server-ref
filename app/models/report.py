from datetime import datetime, timezone

from sqlalchemy import JSON, BigInteger, DateTime, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class Report(Base):
    """User-submitted abuse report. Triaged by an admin via
    `admin.rcq.app` → /admin/reports queue. Required for App Store
    Review Guideline 1.2 ("the developer must take action on
    objectionable content within 24 hours").

    Reports are always against a UIN (the only globally-addressable
    identity in RCQ). Sealed-sender means we cannot tie a report to
    a specific MESSAGE — only to a sender's UIN as known to the
    reporter. The free-text `reason` is what the reporter typed in
    the iOS Report sheet.
    """

    __tablename__ = "reports"
    __table_args__ = (
        Index("ix_reports_status_created", "status", "created_at"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    # Who filed the report. Authenticated via the reporter's bearer
    # token; never anonymous. Lets the admin spot abuse-reporter
    # patterns (one user mass-reporting innocents to spam the queue).
    reporter_uin: Mapped[int] = mapped_column(BigInteger, index=True)
    # The UIN being reported. Could be a contact, a stranger from a
    # search result, a hood-chat poster, etc. Indexed for the admin's
    # "show me all reports filed against UIN X" view.
    target_uin: Mapped[int] = mapped_column(BigInteger, index=True)
    # Free-text body the reporter typed. Capped to keep the queue
    # readable + bound disk usage; users are expected to be terse,
    # not write essays.
    reason: Mapped[str] = mapped_column(Text)
    # Optional surface where the reporter encountered the target —
    # "contact", "hood", "search", "group:<id>", etc. Lets the
    # admin understand context without asking. Empty string for
    # legacy / unspecified.
    context: Mapped[str] = mapped_column(String(64), default="")
    # Lifecycle: open → resolved (action taken) | dismissed (no
    # action) | duplicate. Default open.
    status: Mapped[str] = mapped_column(String(16), default="open", index=True)
    # Premium-content / media evidence support. The reporter consents
    # to upload the decrypted media (only available client-side after
    # they've paid + unlocked, for premium content) so an admin can
    # actually review what they're reporting. Sealed-sender + E2EE
    # otherwise leaves the admin staring at "user X says Y did
    # something bad" with no way to verify.
    #
    # Apple App Review specifically calls out paid user-generated
    # content as a moderation hazard — without this evidence path,
    # premium media looks like a perfect channel for prohibited
    # content with no oversight. With it, every report carries the
    # actual content for review.
    #
    # `evidence_path` — relative path under `evidence/` on the server
    # filesystem. Admin-only access. NULL for non-evidence reports.
    evidence_path: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # Mime type of the uploaded evidence — drives how the admin UI
    # renders it (image preview vs video player vs file download).
    evidence_mime: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # Original `Message.id` (UUID) so the admin can cross-reference
    # against a specific bubble in the chat history. Stored even when
    # there's no evidence file attached (a plain reason-only report
    # against a known message).
    message_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    # Bug-bounty attachments — JSON array of
    # {media_id, key, mime, size} dicts. Reporter (iOS) uploads each
    # screenshot / video through the standard encrypted /media/upload
    # lane and pipes the (media_id, AES key) tuple to the report. The
    # admin client decrypts client-side using the keys shipped here;
    # server stores opaque ciphertext + keys, never plaintext. Empty /
    # NULL for the historical reason-only flow + for plain abuse
    # reports.
    attachments: Mapped[list | None] = mapped_column(JSON, nullable=True)
    # Admin's action when resolving: "ban", "warn", "no_action",
    # "duplicate". Empty until resolved. Surfaced in the queue's
    # closed-tab so the admin can see what was done historically.
    resolution_action: Mapped[str] = mapped_column(String(32), default="")
    # Free-text admin notes — why the decision was made. Internal
    # only, never surfaced back to the reporter or the target.
    resolution_notes: Mapped[str] = mapped_column(Text, default="")
    # The one field on this table the REPORTER is allowed to read back.
    # Reports were a one-way box: people wrote careful, hour-long feedback
    # and could not be answered at all, because a reply cannot go into a
    # chat (the server holds no keys and must never be able to write into
    # a conversation). So the answer lives here, next to the report, and
    # the reporter fetches it over their own authenticated session via
    # GET /reports/mine. Empty = not answered yet.
    reply_text: Mapped[str] = mapped_column(Text, default="")
    replied_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # Set when the REPORTER dropped this report from their own list. It is a
    # soft delete and the row is deliberately kept, because a hard DELETE here
    # rewrote history: `services/hof_stats` counts a contributor's bug-bounty
    # reports (filed, and how many were confirmed) live over this table, so the
    # way to improve your standing on the wall was to file everything you could
    # think of and then delete whatever came back dismissed. The number of
    # reports you filed is not yours to revise after the fact.
    #
    # What it changes: the row disappears from GET /reports/mine and stops
    # accepting turns. What it does NOT change: the admin queue (the operator
    # keeps the evidence of the report he rejected) or the Hall of Fame counts.
    #
    # It is also a RETENTION timestamp, and has to be. A closed report is swept
    # 90 days after `resolved_at` whether it is hidden or not, but a report
    # withdrawn while still OPEN has no `resolved_at` and would then have no
    # clock at all: its free text would outlive every other report on the island
    # because the one person who would have chased it to a verdict is the one
    # who dropped it. So `services/report_sweep` measures the same 90 days from
    # here when that is the only stamp there is.
    hidden_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # Last time the reporter rewrote `reason` through PATCH /reports/mine/{id}.
    # NULL = never edited, which is every row that predates the endpoint.
    #
    # This is the whole edit trail on purpose. Keeping the superseded drafts
    # would mean storing MORE user free text per report, permanently, which is
    # the exact thing `services/report_sweep` exists to stop; and an edit is
    # only allowed before anyone has answered, so there is no operator reply
    # left standing next to text that has since changed. The stamp is what the
    # queue needs: "this is not what I read yesterday".
    edited_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True
    )
    resolved_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
