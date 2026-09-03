from datetime import datetime, timezone

from sqlalchemy import BigInteger, Boolean, DateTime, ForeignKey, Index, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class ReportMessage(Base):
    """One turn in the conversation attached to a report.

    A report used to be a box with a lid: the person wrote once, an operator
    wrote back once, and that was the whole channel. Every real exchange needs
    more than that — "which version?", "here is the log line", "still happens
    after the update" — and without it people re-filed the same thing three
    times, which is what the queue actually looked like.

    ⚠ This is NOT a chat, and the distinction is load-bearing. Chats are sealed
    on the sending device and the server holds no keys; a channel where the
    server can put text in front of a user must therefore be something else,
    plainly server-side, or the project's central claim stops being true. So:
    these rows are ordinary server data on the report, read back over the
    reporter's own authenticated session, and nothing in the UI calls them
    messages from a person.
    """

    __tablename__ = "report_messages"
    __table_args__ = (
        # The only query there is: one report's turns, oldest first.
        Index("ix_report_messages_report_created", "report_id", "created_at"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    report_id: Mapped[int] = mapped_column(
        ForeignKey("reports.id", ondelete="CASCADE"), index=True
    )
    # True when an operator wrote it. Deliberately a flag rather than a uin:
    # the operator's own number is not the reporter's business, and there is
    # exactly one side on each end of this conversation.
    from_admin: Mapped[bool] = mapped_column(Boolean, default=False)
    # Who wrote it, for the admin side's benefit. 0 for an operator.
    author_uin: Mapped[int] = mapped_column(BigInteger, default=0)
    body: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
