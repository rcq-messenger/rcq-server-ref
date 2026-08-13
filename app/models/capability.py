from datetime import datetime, timezone

from sqlalchemy import BigInteger, Boolean, DateTime
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class UserCapability(Base):
    """Per-account client-capability flags, advertised by the apps themselves.

    Deliberately a separate table (not columns on `users`) so it rides
    `create_all` on every island — flagship, is2 and self-hosters pick it up
    on a plain restart, no hand-rolled ALTER.

    `sender_keys` — the account's client(s) understand the sender-keys group
    path (`gmsg` broadcast envelopes + `skdm` distributions). The
    /messages/group-broadcast fan-out targets ONLY capable members, so an old
    client never sees envelopes it can't parse, and senders read the flag off
    the group member list to decide who still needs the legacy per-member
    fan-out (dual-send migration). An updated client advertises once on start;
    the flag is per-ACCOUNT, so an account that still signs in from one old
    device may miss sender-keys group messages on that stale device only —
    accepted v1 trade-off (web auto-updates; native updaters converge fast).
    """

    __tablename__ = "user_capabilities"

    # See the note in models/user.py: an integer PK without this becomes a
    # BIGSERIAL, and a forgotten column then mints a trophy number silently.
    uin: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=False)
    sender_keys: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False,
    )
