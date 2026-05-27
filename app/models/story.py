"""24h ephemeral stories.

The flow:
- A user posts a story via `POST /stories` — uploads media (photo/video)
  through the existing `/media/upload` pipeline first, then references the
  resulting `media_id` here. Caption + anonymous flag + duration_sec are
  metadata-only.
- Stories are visible to **contacts** of the poster — readers see them in
  the feed at the top of their contact list (one circular ring per
  contact who has active stories).
- Anonymous stories still belong to a UIN (so the poster can delete them
  and see view counts), but the byline is suppressed when shown to
  viewers — they read "Аноним" / "Anonymous" instead of the nickname.
- Each view is recorded once per `(story_id, viewer_uin)` so the poster
  can see who watched. The denormalised `view_count` on the Story row
  is the cheap read for display in feeds.
- `expires_at = posted_at + 24h`. A background sweeper deletes expired
  stories + their `story_views` rows + the underlying media blob.

Media is stored on the same blob backend as chat photos / videos —
clients encrypt the media client-side with a per-story AES-GCM key and
ship the key inside the story record. Server never sees plaintext.
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import BigInteger, Boolean, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Story(Base):
    """One posted story."""

    __tablename__ = "stories"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)  # uuid hex
    owner_uin: Mapped[int] = mapped_column(
        BigInteger,
        ForeignKey("users.uin", ondelete="CASCADE"),
        index=True,
    )
    # photo | video
    media_kind: Mapped[str] = mapped_column(String(8), nullable=False)
    # `media_id` is the uuid hex returned by `/media/upload`. The blob is
    # AES-GCM-encrypted client-side; the key is in `media_key_b64` so any
    # contact who fetches this row can decrypt the blob locally. Server
    # itself only sees opaque bytes — same posture as chat media.
    media_id: Mapped[str] = mapped_column(String(64), nullable=False)
    media_key_b64: Mapped[str] = mapped_column(String(96), nullable=False)
    # Optional plaintext-on-server caption. Acceptable: the caption is
    # not as sensitive as message bodies, and we want server-side
    # full-text moderation hooks to be possible later (abuse reports,
    # rate-limit on link-spam, etc.). Keep short.
    caption: Mapped[str | None] = mapped_column(String(280), nullable=True)
    # When true, the byline in the viewer reads "Anonymous" — the UIN
    # still owns the row server-side for delete + view-count purposes,
    # but the wire format hides it from non-owner viewers (see the
    # router's response shaping).
    is_anonymous: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    duration_sec: Mapped[int | None] = mapped_column(Integer, nullable=True)
    posted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_now,
    )
    # Denormalised count for cheap feed reads. Authoritative source is
    # the `story_views` table — count(*) where story_id = this.
    view_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    # 24h window. Server cron sweep deletes rows where expires_at < now.
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True,
    )


class StoryView(Base):
    """One viewer-watched-story event. Idempotent on `(story_id, viewer_uin)`
    so re-fetching a story doesn't double-count."""

    __tablename__ = "story_views"

    story_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("stories.id", ondelete="CASCADE"),
        primary_key=True,
    )
    viewer_uin: Mapped[int] = mapped_column(
        BigInteger,
        primary_key=True,
        index=True,
    )
    viewed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_now,
    )


__all__ = ["Story", "StoryView"]
