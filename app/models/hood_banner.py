from datetime import datetime, timezone

from sqlalchemy import BigInteger, Boolean, DateTime, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class HoodBanner(Base):
    """One paid district-banner placement. Lives in a geohash-level-6
    bucket (same key the /nearby surface uses); auto-expires when
    `expires_at` passes.

    Pricing is enforced on the create endpoint: a mock IAP receipt
    is currently accepted blindly, real StoreKit verification slots
    in there later.
    """

    __tablename__ = "hood_banners"
    __table_args__ = (
        Index("ix_hood_banners_bucket_expires", "bucket_id", "expires_at"),
        Index("ix_hood_banners_owner", "owner_uin"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    bucket_id: Mapped[str] = mapped_column(String(64), nullable=False)
    owner_uin: Mapped[int] = mapped_column(BigInteger, nullable=False)
    text: Mapped[str] = mapped_column(Text, nullable=False)
    image_url: Mapped[str | None] = mapped_column(String(255), nullable=True)
    image_thumb_url: Mapped[str | None] = mapped_column(String(255), nullable=True)
    is_anonymous: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    duration: Mapped[str] = mapped_column(String(8), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    # Mock placeholder while StoreKit isn't wired. NOT NULL on the
    # column so a future migration to real receipt-validation has a
    # column to inspect; a literal "mock-iap-…" string is what /uin
    # purchase + this endpoint accept today.
    iap_receipt: Mapped[str] = mapped_column(String(500), nullable=False, default="")
