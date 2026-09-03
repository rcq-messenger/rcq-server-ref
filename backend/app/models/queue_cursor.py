from datetime import datetime

from sqlalchemy import BigInteger, DateTime, String, func
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class QueueCursor(Base):
    """Per-device drain cursor for the offline message queue.

    The offline queue (`OfflineMessage` / `OfflineGroupMessage`) is keyed by
    `to_uin`, i.e. shared across a user's devices (their phone + a connect-to-web
    browser). Without a per-device cursor, whichever device drains the queue
    first deletes the rows and the other device never sees those messages
    (founder report: "received on web → missing on the phone").

    Each device instead records the highest queue id it has ACKed. `/messages/
    queue?ack=1` returns only rows above that device's cursor; `/messages/queue/
    ack` advances it. A queued row is reaped only once EVERY device's cursor has
    passed it (delete-below-the-min-cursor), with the existing TTL sweep as a
    backstop for cursors left behind by an abandoned/removed device.
    """

    __tablename__ = "queue_cursors"

    uin: Mapped[int] = mapped_column(BigInteger, primary_key=True, index=True)
    device_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    # Highest acked OfflineMessage.id / OfflineGroupMessage.id for this device.
    last_direct_id: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    last_group_id: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    # Last time this device drained. Reinstalling an app mints a NEW device id
    # (the old one is gone with its keys), so without this the abandoned cursor
    # would sit at its old id forever and hold the whole account's queue above
    # the reap floor. Nullable because rows written before this column existed
    # have no stamp; those are treated as "seen just now" until they next ack.
    updated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, server_default=func.now()
    )
