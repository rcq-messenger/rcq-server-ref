from datetime import datetime, timezone

from sqlalchemy import BigInteger, Boolean, DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class Group(Base):
    __tablename__ = "groups"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(64))
    # Free-text group description, owner/admin-editable. NULL for
    # legacy groups + groups that never set one. Surfaced in Group
    # Info for members and on the join sheet for prospective members.
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    owner_uin: Mapped[int] = mapped_column(BigInteger, index=True)
    avatar_seed: Mapped[int] = mapped_column(BigInteger, default=0)
    # Uploaded avatar. Both NULL = no custom avatar, clients fall back
    # to the generic person.3 glyph. `avatar_media_key` is the base64
    # AES key used to decrypt the blob at `/media/{avatar_media_id}`;
    # members already see every group plaintext (e2ee is per-member),
    # so the same per-blob key model used by Stories is fine here.
    avatar_media_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    avatar_media_key: Mapped[str | None] = mapped_column(String(96), nullable=True)
    # Who can post into the group thread.
    #   "all"        — every member can send (the historical default).
    #   "owner_only" — broadcast mode; only the owner can post, members
    #                  can read + react. Server enforces on every send.
    post_policy: Mapped[str] = mapped_column(String(16), default="all")
    # Token cost to JOIN the group. NULL = free (default for legacy
    # rows). When set, the join endpoint deducts the price from the
    # joining user's wallet, credits the owner with `floor(price * 0.95)`,
    # and burns the 5% delta. Mirrors the marketplace fee model.
    entry_price_tokens: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    # Closed groups can only be joined via an explicit invitation
    # the owner extended (link-share inserts a GroupMember row
    # directly when the recipient accepts; bare /groups/{id}/join
    # 403s). Defaults False — pre-existing groups remain open so
    # the toggle is purely additive.
    is_closed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # When true, the member roster is hidden from Group Info for
    # everyone except the owner. The `members` array is still sent on
    # the wire — actual members need each other's keys to encrypt
    # group messages — so this is a display-only gate enforced by the
    # iOS client. Default False keeps existing groups' rosters open.
    members_hidden: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # Pinned plaintext announcement, owner/admin-editable. Surfaced as
    # a sticky header above the message list in ChatView so new joiners
    # who can't see the encrypted history at least see the rules /
    # welcome / link-of-the-day. Deliberately plaintext on the server:
    # the e2ee envelope path requires existing libsignal sessions, and
    # a brand-new joiner has none — they need to read the pin BEFORE
    # the X3DH dance with each member completes. The pin is meta-info
    # (group rules), not user message content, so the relaxation is
    # scoped to a single column.
    pinned_text: Mapped[str | None] = mapped_column(String(500), nullable=True)
    pinned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    pinned_by: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )


class GroupMember(Base):
    __tablename__ = "group_members"

    id: Mapped[int] = mapped_column(primary_key=True)
    group_id: Mapped[int] = mapped_column(ForeignKey("groups.id", ondelete="CASCADE"), index=True)
    uin: Mapped[int] = mapped_column(BigInteger, index=True)
    role: Mapped[str] = mapped_column(String(16), default="member")  # owner | admin | member
    joined_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )


class GroupMessageView(Base):
    """One row per (member, group, message) pair recording that the
    member opened the message in their chat view. Powers the "X viewed"
    counter under each message in closed groups, similar to Telegram.

    Closed-group-only by design (the iOS client gates the view-ping
    on `group.is_closed`); open groups keep the no-view-count
    semantics so the feature stays an opt-in privacy trade-off. The
    server stores `viewer_uin` for dedup but never surfaces it to
    other clients, only the aggregate count is returned.
    """

    __tablename__ = "group_message_views"

    id: Mapped[int] = mapped_column(primary_key=True)
    group_id: Mapped[int] = mapped_column(BigInteger, index=True)
    # Message-id is the iOS-side UUID4 lowercase string used everywhere
    # else (envelopes, reactions, edit ops). Server has no plaintext so
    # this is just an opaque pointer for the (group, msg, viewer) tuple.
    message_id: Mapped[str] = mapped_column(String(64), index=True)
    viewer_uin: Mapped[int] = mapped_column(BigInteger, index=True)
    viewed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )


class OfflineGroupMessage(Base):
    """Per-recipient queued group envelope. The sender encrypts the message
    once per group member using each member's identity_key, then ships an
    array of (to_uin, ciphertext) pairs. The server stores one row per
    offline member, with that member's specific ciphertext — every blob
    is sealed to a single recipient, server can't read any of them.
    Live members get their ciphertext via WS instead of the queue.
    """

    __tablename__ = "offline_group_messages"

    id: Mapped[int] = mapped_column(primary_key=True)
    to_uin: Mapped[int] = mapped_column(BigInteger, index=True)
    group_id: Mapped[int] = mapped_column(BigInteger, index=True)
    envelope_type: Mapped[str] = mapped_column(String(16))  # message | system | delete | read | reaction
    payload: Mapped[str] = mapped_column(Text)
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
