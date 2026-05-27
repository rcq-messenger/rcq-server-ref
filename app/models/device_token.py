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
    # Hex-encoded APNs device token (64 chars for original APNs format,
    # variable length post-iOS 13). We don't reformat — store what iOS sent.
    token: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    # "ios" | "ios-voip" — VoIP tokens are a separate registration via
    # PushKit and route to a different endpoint. Distinguished here so the
    # APNs sender knows which kind to use.
    platform: Mapped[str] = mapped_column(String(16), nullable=False, default="ios")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False,
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False,
    )
