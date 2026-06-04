from datetime import datetime, timezone

from sqlalchemy import BigInteger, DateTime, ForeignKey, Integer, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class Device(Base):
    """A SECONDARY libsignal device linked to a UIN (the web client today).

    Multi-device model: the PRIMARY device (the phone, libsignal `deviceId` 1)
    keeps its bundle on the `User` row exactly as before — this table is purely
    additive and the single-device path is untouched. Each secondary device
    (deviceId >= 2) registers its OWN independent libsignal identity + prekey
    bundle here. Senders fetch `GET /keys/{uin}/devices`, then one bundle per
    device, and fan out one ciphertext per device; each device runs its own
    Double Ratchet (a session is per-(identity, state), so it cannot be shared
    across devices — see docs/web-multidevice-plan.md).

    One-time prekeys for a secondary device live in `one_time_prekeys` rows
    tagged with `device_id`; the primary device's pool has `device_id IS NULL`.
    """

    __tablename__ = "devices"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    uin: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("users.uin", ondelete="CASCADE"), index=True
    )
    # libsignal deviceId, server-assigned, 2..127. The phone is deviceId 1 and
    # never appears here. Clients never self-assert this — the server allocates
    # it on registration so two devices can't collide.
    device_id: Mapped[int] = mapped_column(Integer)
    label: Mapped[str | None] = mapped_column(Text, nullable=True)  # e.g. "Web (Chrome)"

    # Per-device X25519 sealed-sender (OUTER ECIES) public key, raw-32 b64.
    # A sender fanning out to this device encrypts the v=1/v=2 OUTER envelope
    # to THIS key (not the UIN's shared identity_key) — so a secondary device
    # (web) holds only its own keys and never the account master key
    # (multi-device security, decision #2). The primary device keeps using the
    # UIN's identity_key as its outer key (back-compat), so this column is
    # secondary-only.
    sealed_sender_pub: Mapped[str] = mapped_column(Text)

    # Per-device libsignal bundle — same shape as the User Stage-3 columns.
    signal_identity_key: Mapped[str] = mapped_column(Text)
    signal_registration_id: Mapped[int] = mapped_column(Integer)
    signed_prekey_id: Mapped[int] = mapped_column(Integer)
    signed_prekey_public: Mapped[str] = mapped_column(Text)
    signed_prekey_signature: Mapped[str] = mapped_column(Text)
    signed_prekey_uploaded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    kyber_prekey_id: Mapped[int] = mapped_column(Integer)
    kyber_prekey_public: Mapped[str] = mapped_column(Text)
    kyber_prekey_signature: Mapped[str] = mapped_column(Text)
    kyber_prekey_uploaded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    # Set when the device is unlinked/revoked. Revoked devices are excluded
    # from the device list + bundle fetch so senders stop fanning out to them.
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (UniqueConstraint("uin", "device_id", name="uq_devices_uin_device"),)
