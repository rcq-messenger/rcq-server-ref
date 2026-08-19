from datetime import datetime, timezone

from sqlalchemy import BigInteger, DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class OfflineMessage(Base):
    """Encrypted blobs queued for offline recipients.

    The server never sees plaintext: `payload` is a base64 LibSignal ciphertext envelope.
    Sealed sender means the `from_uin` field is hidden inside the envelope; we only need
    the recipient address to deliver, plus a server-side timestamp for ordering.
    """

    __tablename__ = "offline_messages"

    id: Mapped[int] = mapped_column(primary_key=True)
    to_uin: Mapped[int] = mapped_column(BigInteger, index=True)
    envelope_type: Mapped[str] = mapped_column(String(16))  # "message" | "nudge" | "typing"
    payload: Mapped[str] = mapped_column(Text)  # base64 ciphertext
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    # Which of the recipient's libsignal devices this ciphertext is FOR.
    #
    # A Double Ratchet session belongs to one pair of devices, so a sender with a
    # device-aware client encrypts the same message once per recipient device and
    # posts each copy separately. Without this column every device drains every
    # copy, can decrypt exactly one, and — because a failed decrypt is never
    # ACKed — wedges its cursor in front of the others forever.
    #
    # NULL = "for whichever device can read it": what every client sent before
    # fan-out existed, and still the shape of a legacy sender's message. A
    # secondary device that meets a NULL row it cannot read must ACK and drop it
    # rather than stall (the row belongs to the primary).
    to_device_id: Mapped[int | None] = mapped_column(Integer, nullable=True, default=None)
