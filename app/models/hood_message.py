from datetime import datetime, timezone

from sqlalchemy import BigInteger, Boolean, DateTime, Index, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class HoodMessage(Base):
    """One message in a geohash-level-6 bucket. Anonymous by the
    sender's choice — anonymous=True hides `owner_uin` from the
    response payload (still stored server-side for moderation).

    NOT end-to-end encrypted: bucket-local chat is a public surface,
    iOS surfaces a permanent "unencrypted" banner in HoodChatView.
    """

    __tablename__ = "hood_messages"
    __table_args__ = (
        Index("ix_hood_messages_bucket_created", "bucket_id", "created_at"),
        Index("ix_hood_messages_owner", "owner_uin"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    bucket_id: Mapped[str] = mapped_column(String(64), nullable=False)
    owner_uin: Mapped[int] = mapped_column(BigInteger, nullable=False)
    nickname: Mapped[str] = mapped_column(String(64), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    anonymous: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    # Optional reply target. Stored verbatim (sender-supplied
    # nickname + snippet) so old replies render even if the parent
    # message is deleted later.
    reply_to_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    reply_to_nickname: Mapped[str | None] = mapped_column(String(64), nullable=True)
    reply_to_body: Mapped[str | None] = mapped_column(String(160), nullable=True)
    # Soft-delete: row stays for moderation, body collapses in the
    # API response. Non-null = deleted.
    deleted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # `{ "❤️": "uin1,uin2", "🔥": "uin3" }` — emoji → comma-separated
    # UIN list. JSONB on PG. Used by the optimistic reaction toggle
    # on iOS.
    reactions: Mapped[dict | None] = mapped_column(JSON, nullable=True, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
