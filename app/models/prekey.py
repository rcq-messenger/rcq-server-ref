from datetime import datetime, timezone

from sqlalchemy import BigInteger, Boolean, DateTime, ForeignKey, Index, Integer, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class OneTimePreKey(Base):
    """A libsignal one-time prekey (OPK), uploaded by the owner, consumed
    once by another client when initiating an X3DH session.

    Each X3DH initiation pulls (and consumes) exactly one row. When the pool
    runs low the owner replenishes via POST /keys/prekeys. Consumed rows
    stick around briefly so a re-fetch with an in-flight matching `prekey_id`
    can still succeed under retry — actual deletion is left to a periodic
    sweeper (TBD; for now `consumed=True` rows just hang)."""

    __tablename__ = "one_time_prekeys"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    uin: Mapped[int] = mapped_column(BigInteger, ForeignKey("users.uin", ondelete="CASCADE"), index=True)
    # Whatever id the client picked (libsignal-side `PreKeyRecord.id`). Carried
    # back inside the PreKeySignalMessage so the recipient knows which OPK
    # to feed into X3DH on their side.
    prekey_id: Mapped[int] = mapped_column(Integer)
    # Base64 of the 33-byte serialized libsignal `PublicKey`.
    public_key: Mapped[str] = mapped_column(Text)
    consumed: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    __table_args__ = (
        Index("ix_one_time_prekeys_uin_consumed", "uin", "consumed"),
    )
