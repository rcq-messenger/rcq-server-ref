from datetime import datetime, timezone

from sqlalchemy import BigInteger, DateTime, String, Text
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
