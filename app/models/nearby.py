from datetime import datetime, timezone

from sqlalchemy import BigInteger, DateTime, ForeignKey, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class NearbyCheckin(Base):
    """Active People Nearby check-in. Each user gets at most one row at
    a time — re-checkin replaces the prior — keyed by `uin` so the
    pool stays bounded. Expired rows are filtered on read; an
    occasional sweeper would be nice-to-have once the table grows.

    Bucket id is an opaque string the client computed from its
    geohash (level-6, ~1km × ~0.6km tile depending on latitude). The
    server never sees raw coordinates — only the precomputed bucket
    string. Two users in the same bucket are roughly within 1.5km
    of each other; clients in adjacent buckets the server doesn't
    surface together for v1 (single-bucket lookups only)."""

    __tablename__ = "nearby_checkins"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    uin: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("users.uin", ondelete="CASCADE"), unique=True
    )
    bucket_id: Mapped[str] = mapped_column(String(16))
    # Anonymous display name the client picked for this check-in
    # (e.g. "Wandering Stranger #4982"). Surfaced through
    # `/nearby/list` and `/hood/messages` instead of the real user
    # nickname so Nearby and Hood Chat are anonymous by default.
    # Nullable for backwards compat with rows written before the
    # column was added — the read path falls back to the real
    # nickname in that case.
    display_name: Mapped[str | None] = mapped_column(String(64), nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    __table_args__ = (
        Index("ix_nearby_checkins_bucket_expires", "bucket_id", "expires_at"),
    )
