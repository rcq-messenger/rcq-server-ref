from datetime import datetime, timezone

from sqlalchemy import BigInteger, Boolean, DateTime, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class Contact(Base):
    __tablename__ = "contacts"
    __table_args__ = (UniqueConstraint("owner_uin", "contact_uin", name="uq_owner_contact"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    owner_uin: Mapped[int] = mapped_column(BigInteger, index=True)
    contact_uin: Mapped[int] = mapped_column(BigInteger, index=True)
    blocked: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )


class ContactRequest(Base):
    __tablename__ = "contact_requests"
    __table_args__ = (UniqueConstraint("from_uin", "to_uin", name="uq_request_pair"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    from_uin: Mapped[int] = mapped_column(BigInteger, index=True)
    to_uin: Mapped[int] = mapped_column(BigInteger, index=True)
    state: Mapped[str] = mapped_column(String(16), default="pending")  # pending|accepted|declined
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
