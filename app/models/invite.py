from datetime import datetime, timezone

from sqlalchemy import BigInteger, DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class Invite(Base):
    """A server-join invite token.

    When `REGISTRATION_POLICY=invite`, `/auth/register` requires a valid invite
    (exists, not expired, `used_count < max_uses`) and atomically consumes one
    use. Minted by an admin: the web-admin panel / console.rcq.app (managed
    orgs) or the `app.tools.mint_invite` CLI (self-host operators). Registration
    policy defaults to `open`, so a server that never sets the env keeps the
    current behaviour and this table simply stays empty.
    """

    __tablename__ = "invites"

    # The token itself — what rides in the QR / `rcq://server/<host>?invite=<code>`.
    code: Mapped[str] = mapped_column(String(64), primary_key=True)
    # Human label so an admin can tell invites apart in the list (e.g. "Acme HR").
    label: Mapped[str | None] = mapped_column(String(120), nullable=True)
    max_uses: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    used_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    # Admin uin that minted it (nullable — CLI mints have no admin session).
    created_by: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
