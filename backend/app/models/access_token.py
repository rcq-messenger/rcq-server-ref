from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Index, Integer, String, text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class AccessToken(Base):
    """Network-gate access token for a CLOSED (masquerade) island.

    Only relevant when the operator runs the masquerade Caddyfile, which asks
    `/gate/check` on every request and serves a decoy on anything but a 2xx.
    These rows let the operator hand out per-person, revocable tokens instead of
    one shared secret. We store ONLY the sha256-hex of the raw token — the raw is
    shown once at creation and never persisted or logged.

    Kinds:
      * `invite`   — one-time (max_uses=1). Redeemed on first connect into a
                     `device` token, then exhausted; a re-posted invite works
                     only once.
      * `device`   — durable, minted by `/gate/redeem` from an invite, bound to a
                     client-chosen `device_id`, revocable. Stamped on every later
                     request.
      * `standing` — durable admin token for a known person/bot/relay
                     (max_uses NULL = unlimited), used directly (no redeem).
    The legacy single `RCQ_AUTH_TOKEN` env var is matched in-process by
    /gate/check and has NO row here.
    """

    __tablename__ = "access_tokens"
    __table_args__ = (
        # The gate credential is looked up by hash on every request.
        Index("ix_access_tokens_token_hash", "token_hash", unique=True),
        # Idempotency key for /gate/redeem's INSERT ... ON CONFLICT. Partial so
        # multiple invite/standing rows (device_id NULL) don't collide.
        Index(
            "uq_access_tokens_device_id", "device_id", unique=True,
            postgresql_where=text("device_id IS NOT NULL"),
            sqlite_where=text("device_id IS NOT NULL"),
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    # sha256-hex of the raw token. Raw is never stored.
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    kind: Mapped[str] = mapped_column(String(16), nullable=False)  # invite|device|standing
    label: Mapped[str | None] = mapped_column(String(128), nullable=True)
    # Set on `device` rows — the client-chosen random per-install id.
    device_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # The invite a `device` row was minted from (for the revocation cascade).
    parent_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # invite = 1; standing = NULL (unlimited); device = NULL (not use-limited).
    max_uses: Mapped[int | None] = mapped_column(Integer, nullable=True)
    uses: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False,
    )
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
