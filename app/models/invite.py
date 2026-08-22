import hashlib
from datetime import datetime, timezone

from sqlalchemy import BigInteger, DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


def hash_invite_code(raw: str) -> str:
    """sha256-hex of a raw invite token: what actually goes in `Invite.code`.

    Same construction as `routers/gate._hash` for `access_tokens.token_hash`,
    deliberately: two credential tables on one island should not be two
    different schemes. Plain sha256 rather than a KDF because the token is 128
    bits of `secrets.token_urlsafe(16)`, not a password. There is nothing to
    brute force, and the cost of a KDF would land on `/auth/register`.
    """
    return hashlib.sha256(raw.strip().encode("utf-8")).hexdigest()


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

    # ⚠ THE SHA256-HEX OF THE TOKEN, NOT THE TOKEN. Since 2026-08-22, and the
    # column keeps its name because it is the primary key and renaming a PK is
    # not something this schema layer can do safely (app/core/db.py is
    # create_all plus additive ALTERs, no Alembic).
    #
    # Until then the live entry credential to an invite-gated island sat here
    # in the clear, so a database read (a dump, a backup, a compromise) MINTED
    # ACCESS, and linked a QR handed to a person to the account that redeemed
    # it. `access_tokens.token_hash` had already solved exactly this problem in
    # the next file over, three months earlier.
    #
    # The raw token is returned ONCE, by the mint endpoint and the CLI, and is
    # not recoverable afterwards. `/auth/register` hashes what the client
    # presents and looks up by that, so every code already handed out kept
    # working across the migration.
    code: Mapped[str] = mapped_column(String(64), primary_key=True)
    # Human label so an admin can tell invites apart in the list (e.g. "Acme HR").
    label: Mapped[str | None] = mapped_column(String(120), nullable=True)
    max_uses: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    used_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    # Optional reserved UIN: when set, `/auth/register` granting THIS invite
    # assigns exactly this UIN (vanity / hand-picked) instead of a random one,
    # provided it's still free at registration time. Lets a self-host operator
    # hand out specific numbers ("your code -> UIN 777777"). NULL = normal
    # random allocation. Pair with max_uses=1 so a number can't be claimed twice.
    uin: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    # Admin uin that minted it (nullable, since CLI mints have no admin session).
    created_by: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    # When the invite stopped being usable, for `services/credential_sweep`.
    # Stamped when the last use is spent; an expiry needs no stamp because
    # `expires_at` is already its own clock. NULL on a live invite and on every
    # row spent before this column existed.
    spent_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, default=None
    )
