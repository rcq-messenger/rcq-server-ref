from datetime import datetime, timezone

from sqlalchemy import BigInteger, DateTime, Index, Integer, SmallInteger, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class OfflineMessage(Base):
    """Encrypted blobs queued for offline recipients.

    The server never sees plaintext: `payload` is a base64 LibSignal ciphertext envelope.
    Sealed sender means the `from_uin` field is hidden inside the envelope; we only need
    the recipient address to deliver, plus a server-side timestamp for ordering.
    """

    __tablename__ = "offline_messages"

    # ⚠ (to_uin, seq) is unique: a drifted per-mailbox counter must raise, never
    # overwrite a queued envelope (see `seq` below and routers/messages.py). It
    # is a UNIQUE index rather than a table constraint so init_db can add it to
    # the live table idempotently; the rows that predate `seq` all carry NULL,
    # and NULLs are distinct in a unique index on both Postgres and SQLite, so
    # the legacy rows never collide with each other.
    __table_args__ = (
        Index("ix_offline_messages_to_uin_seq", "to_uin", "seq", unique=True),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    to_uin: Mapped[int] = mapped_column(BigInteger, index=True)
    envelope_type: Mapped[str] = mapped_column(String(16))  # "message" | "nudge" | "typing"
    payload: Mapped[str] = mapped_column(Text)  # base64 ciphertext
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    # Stage 2a: the 3-value STORAGE CLASS the server actually branches on
    # (0 ephemeral | 1 content | 2 critical), recorded ALONGSIDE envelope_type,
    # not instead of it. envelope_type stays the ingest alias that old clients
    # and the federation wire keep sending; this is derived from it on the way
    # in (routers/messages.py `_cls_for`) or taken directly when a new client
    # sends it. NULL on every row written before the column, read back through
    # the envelope_type fallback, so a mixed table branches correctly.
    cls: Mapped[int | None] = mapped_column(SmallInteger, nullable=True, default=None)
    # Stage 2b: a DURABLE per-mailbox sequence, counting only within this
    # recipient's mailbox. Served beside `id` so a client can move off the
    # global bigserial (which bounds the island's total message volume between
    # any two of your own rows) without ?after= changing meaning yet.
    #
    # ⚠ NOT derived from MAX(seq): a MAX-seeded counter reseeds to 0 once the
    # sweep empties a quiet mailbox, and the fresh rows then land BELOW every
    # device's stored cursor where ?after= can never reach them — silent
    # permanent loss. Allocated from a durable `mailbox_seq.next_seq` row the
    # queue sweep never touches. NULL on legacy rows (clients fall back to id).
    seq: Mapped[int | None] = mapped_column(BigInteger, nullable=True, default=None)
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
