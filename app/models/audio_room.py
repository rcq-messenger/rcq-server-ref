from datetime import datetime, timezone

from sqlalchemy import BigInteger, DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class AudioRoom(Base):
    """Persistent audio room. Visible to anyone who knows the `join_key`
    (or who the owner shares it with). Lives forever — same crew can
    re-gather without recreating it. Deletion is owner-only.
    """

    __tablename__ = "audio_rooms"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(64))
    owner_uin: Mapped[int] = mapped_column(BigInteger, index=True)
    # 8-char alphanumeric, generated server-side, unique. Short enough
    # to share over voice ("X-K-7-Q-2-A-9-N"), long enough that brute
    # force isn't a real attack vector at our scale (62^8 ≈ 218T).
    join_key: Mapped[str] = mapped_column(String(16), unique=True, index=True)
    # Owner-only-speaking mode. When true, all non-owner mics are
    # auto-muted on the client side (server announces via
    # `audio_room_owner_only_changed`); the owner remains free to
    # speak. Default false. Toggled via /audio_rooms/{id}/owner_only.
    owner_only_speaking: Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )


class AudioRoomMembership(Base):
    """Per-user subscription to a room. Existence of this row =
    "room is in my list on the home screen". Created on create or
    first join-by-key; removed when the user explicitly leaves the
    room from their list. Independent of *active* presence in the
    voice session, which lives in-memory in `routers/ws.py`.
    """

    __tablename__ = "audio_room_memberships"

    id: Mapped[int] = mapped_column(primary_key=True)
    room_id: Mapped[int] = mapped_column(
        ForeignKey("audio_rooms.id", ondelete="CASCADE"), index=True
    )
    uin: Mapped[int] = mapped_column(BigInteger, index=True)
    # (`joined_at` was unmapped on 2026-08-22. Write-only since the feature
    # shipped: nothing ordered by it, nothing displayed it. Membership itself
    # is what the room needs; when each person joined the crew is not.)


# `AudioRoomMute` was deleted on 2026-08-22. The row was a permanent record of
# social conflict, unbounded in time and reachable only through the owner:
# "owner muted UIN X in room Y at time T", surviving leave, rejoin, and the end
# of the room's actual use. Mutes now live in Redis alongside the live roster
# (`routers/audio_rooms.muted_uins_for_room`), so the enforcement is unchanged
# while a member is in the room and nothing is written down afterwards. The
# cost, and it is a real one: a mute no longer survives the island restarting.
