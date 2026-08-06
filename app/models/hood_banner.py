from datetime import datetime, timezone

from sqlalchemy import BigInteger, Boolean, DateTime, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class HoodBanner(Base):
    """Rows of a district banner board that no longer exists.

    ⚠ The surface and its endpoints were removed: in three months the board
    took eight posts from seven people, every one of them a test, and none was
    alive at the end. It also showed dollar prices while the purchase check
    accepted any non-empty string, so the price was a fiction the screen told
    with a straight face.

    The table stays for one reason: burning an account has to delete what that
    account left behind, and `services/uin_rows.py` sweeps these rows by
    `owner_uin`. Dropping the model would quietly leave someone's rows behind
    after they asked to be erased.
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
