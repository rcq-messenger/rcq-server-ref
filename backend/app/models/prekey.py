from datetime import datetime, timezone

from sqlalchemy import BigInteger, Boolean, DateTime, ForeignKey, Index, Integer, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class OneTimePreKey(Base):
    """A libsignal one-time prekey (OPK), uploaded by the owner, consumed
    once by another client when initiating an X3DH session.

    Each X3DH initiation pulls (and consumes) exactly one row. When the pool
    runs low the owner replenishes via POST /keys/prekeys.

    A CONSUMED row is kept as a tombstone and then deleted by
    `services/prekey_sweep` (the "TBD sweeper" this docstring promised until
    2026-08-22). What the tombstone is for, precisely, because the horizon
    depends on it. No read path ever serves a consumed row again, since
    `_claim_opk` filters `consumed == False`. But BOTH replenish endpoints dedupe an
    incoming batch against every row of the pool, consumed ones included. That
    dedupe is what stops an owner re-publishing a `prekey_id` whose private
    half their libsignal store has already dropped, which is the exact shape of
    the handed-out-twice bug documented in `_claim_opk`. See the sweep for how
    long that has to last."""

    __tablename__ = "one_time_prekeys"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    uin: Mapped[int] = mapped_column(BigInteger, ForeignKey("users.uin", ondelete="CASCADE"), index=True)
    # Multi-device: which device's pool this OPK belongs to. NULL = the PRIMARY
    # device (the phone, libsignal deviceId 1). Every pre-multi-device row is
    # NULL, so the primary fetch/replenish/upload paths scope to `device_id IS
    # NULL` and stay byte-for-byte back-compatible. A secondary device (web,
    # deviceId >= 2) tags its pool with its device_id.
    device_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # Whatever id the client picked (libsignal-side `PreKeyRecord.id`). Carried
    # back inside the PreKeySignalMessage so the recipient knows which OPK
    # to feed into X3DH on their side.
    prekey_id: Mapped[int] = mapped_column(Integer)
    # Base64 of the 33-byte serialized libsignal `PublicKey`.
    public_key: Mapped[str] = mapped_column(Text)
    consumed: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    # When the key was handed to a sender. A DIFFERENT clock from `created_at`,
    # which is the upload, and the sweep needs this one: a key uploaded in June
    # and claimed yesterday is a live tombstone, and measuring its retention
    # from the upload would delete it while the message it protects is still in
    # somebody's queue. NULL on every row consumed before this column existed;
    # the sweep says what it does with those.
    consumed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, default=None
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    __table_args__ = (
        Index("ix_one_time_prekeys_uin_consumed", "uin", "consumed"),
        # The sweep's only query: consumed rows past their horizon. Without it
        # a pass seq-scans a quarter of a million rows to find the 7% that are
        # tombstones.
        Index("ix_one_time_prekeys_consumed_at", "consumed", "consumed_at"),
    )
