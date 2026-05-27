from datetime import datetime, timezone

from sqlalchemy import BigInteger, DateTime, Index
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class Referral(Base):
    """One row per referred account.

    `invitee_uin` is unique: an account can only ever be referred
    once, and only at signup. The row is created pending; once the
    invitee reaches the activation bar (3 distinct active days)
    `activated_at` is stamped and both sides are paid via a
    `BountyCredit` row (source="referral"), the same launch-redeemed
    pipeline bug-bounty rewards use.
    """

    __tablename__ = "referrals"
    __table_args__ = (
        Index("ix_referrals_inviter", "inviter_uin"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    inviter_uin: Mapped[int] = mapped_column(BigInteger, nullable=False)
    invitee_uin: Mapped[int] = mapped_column(BigInteger, nullable=False, unique=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    activated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
