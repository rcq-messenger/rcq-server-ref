from datetime import datetime, timezone

from sqlalchemy import JSON, DateTime, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class NewsPost(Base):
    """Admin-authored broadcast post. Surfaced to every iOS client via
    the news sheet in the main contacts menu.

    Unlike chat / story media which is end-to-end encrypted per-
    recipient, news media is a public broadcast — the admin uploads
    plaintext files into `news_media/` and the server serves them at
    `/news/media/{id}`. No per-user encryption: it's a public
    channel and every user is supposed to see the same bytes.
    """

    __tablename__ = "news_posts"
    __table_args__ = (
        Index("ix_news_posts_published", "published_at"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    # JSON array of {media_id, mime, kind}. `kind` ∈ {"image", "video", "gif"}
    # so iOS can route to the right renderer without sniffing bytes.
    attachments: Mapped[list | None] = mapped_column(JSON, nullable=True)
    # Author label shown to readers — typically "RCQ Team" but
    # admin can override per-post for guest-author drops.
    author_label: Mapped[str] = mapped_column(String(64), nullable=False, default="RCQ Team")
    published_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
