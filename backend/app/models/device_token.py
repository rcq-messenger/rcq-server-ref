from datetime import datetime, timezone

from sqlalchemy import BigInteger, DateTime, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class DeviceToken(Base):
    """One row per (UIN, APNs device token). Devices register their token via
    `POST /users/me/push-token` after iOS finishes
    `registerForRemoteNotifications`. The same UIN may appear multiple times
    if the user is signed in on multiple devices (multi-device path is not
    yet wired client-side, but the schema doesn't block it).

    Tokens get pruned in three places:
      * `DELETE /users/me/push-token` when the iOS client logs out / burns
      * Cascade from `User` row deletion (account burn)
      * APNs returning 410 Gone — token revoked by Apple, we drop it from
        the table so we don't keep banging on a dead address
    """
    __tablename__ = "device_tokens"
    __table_args__ = (UniqueConstraint("uin", "token", name="uq_device_tokens_uin_token"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    uin: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("users.uin", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    # What to push to. On iOS a hex APNs device token (64 characters in the
    # original format, variable since iOS 13); on Android the whole
    # UnifiedPush ENDPOINT URL, because with UnifiedPush there is no gateway
    # and the URL the distributor handed the app IS the address
    # (services/unifiedpush.py). We store what the client sent, unaltered.
    #
    # ⚠⚠ 255 was the APNs number and it silently became the ceiling for a URL
    # somebody else generates. Conversations' distributor mints 344-character
    # endpoints (`up.conversations.im/push/v2.local.<paseto>`), so from
    # 2026-09-01 one user's registration answered 500 on every launch, 342
    # times a day, and their push simply did not work: Postgres refused the
    # row, and nothing on either side could say why.
    #
    # 1024 is chosen against the INDEX, not against the URL. This column is
    # indexed and carries the `(uin, token)` unique constraint, and a btree
    # entry has a hard ceiling near 2700 bytes; 1024 characters cannot exceed
    # it even if every one of them takes two bytes. The endpoint is refused
    # above that at the API boundary (routers/users.py) so the answer is a
    # 400 that names the problem rather than a 500 the client retries for ever.
    token: Mapped[str] = mapped_column(String(1024), nullable=False, index=True)
    # "ios" | "ios-voip" — VoIP tokens are a separate registration via
    # PushKit and route to a different endpoint. Distinguished here so the
    # APNs sender knows which kind to use.
    platform: Mapped[str] = mapped_column(String(16), nullable=False, default="ios")
    # Stable per-install identifier the client keeps in its Keychain (which
    # survives an app reinstall). NULL for pre-device-id clients. When set,
    # registration replaces this device's previous token instead of piling up
    # a new row per reinstall (each reinstall mints a fresh APNs token but
    # reuses the device_id) — the cause of duplicate push banners.
    device_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False,
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False,
    )
    # Push health, written by the UnifiedPush sender (and only when the state
    # CHANGES, so a working endpoint costs no writes). `push_last_error` holds
    # the last permanent failure — an HTTP status ("507", "429") or an
    # exception name — and is cleared on the next success. Surfaced to the
    # owner via GET /users/me/push-health so a user whose distributor stopped
    # delivering can SEE that, instead of silently receiving nothing.
    push_last_error: Mapped[str | None] = mapped_column(String(32), nullable=True)
    push_last_ok: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True,
    )
