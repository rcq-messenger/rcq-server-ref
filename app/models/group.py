from datetime import datetime, timezone

from sqlalchemy import BigInteger, Boolean, DateTime, ForeignKey, Integer, SmallInteger, String, Text
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
    # (`entry_price_tokens` was unmapped on 2026-08-22. The pre-pivot "paid
    # groups" feature was cut on 2026-05-27 and the column has been NULL on
    # every row ever since. The physical DROP is queued in the "Columns the
    # ORM stopped mapping" note at the end of `core/db.py:init_db`.)
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
    # Owner-set content policy: whether links in messages are treated as
    # clickable and whether file attachments may be sent/opened. The server
    # cannot inspect sealed envelopes, so both are honored by CLIENTS (the
    # same receiver-side trust model as moderator deletes); storing them
    # here just makes the choice reach every member. Defaults keep existing
    # groups exactly as they were.
    links_allowed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    files_allowed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    # Slowmode: minimum seconds between messages per non-moderator member
    # (0 = off). Unlike the two flags above this one IS server-enforced for
    # authenticated senders on /messages/group-sealed — see messages.py.
    slowmode_sec: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    # Pinned plaintext announcement, owner/admin-editable. Surfaced as
    # a sticky header above the message list in ChatView so new joiners
    # who can't see the encrypted history at least see the rules /
    # welcome / link-of-the-day. Deliberately plaintext on the server:
    # the e2ee envelope path requires existing libsignal sessions, and
    # a brand-new joiner has none — they need to read the pin BEFORE
    # the X3DH dance with each member completes. The pin is meta-info
    # (group rules), not user message content, so the relaxation is
    # scoped to a single column.
    pinned_text: Mapped[str | None] = mapped_column(String(4096), nullable=True)
    pinned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # (`pinned_by` was unmapped on 2026-08-22. It named the admin who set the
    # current pin, was served on the wire, and no client ever rendered it: iOS
    # decoded it into a property nothing reads, Android and web never asked.
    # It was also missing from `uin_rows.PER_UIN_COLUMNS`, so a burned account
    # kept a byline on somebody else's group. A UIN nobody displays is pure
    # metadata; the pin itself stays.)
    # Unguessable half of a share link, so that "the link IS the capability"
    # actually holds. Group ids are sequential integers, which made the
    # capability a number an attacker could count to: walking the id space
    # enumerated every CLOSED group on the island together with its name and
    # its owner's UIN + nickname. A share link becomes
    # `.../g/<id>?k=<share_token>` and `/{id}/preview` requires the token
    # before it will describe a closed group to a non-member.
    #
    # NULL for legacy rows until the backfill in `init_db` fills them; the
    # preview gate treats NULL as "no token issued yet" and falls back to the
    # redacted card rather than locking members' existing links out.
    share_token: Mapped[str | None] = mapped_column(String(32), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )


class GroupMember(Base):
    __tablename__ = "group_members"

    id: Mapped[int] = mapped_column(primary_key=True)
    group_id: Mapped[int] = mapped_column(ForeignKey("groups.id", ondelete="CASCADE"), index=True)
    uin: Mapped[int] = mapped_column(BigInteger, index=True)
    role: Mapped[str] = mapped_column(String(16), default="member")  # owner | member
    # Granular moderator capabilities the OWNER grants per member: a
    # comma-joined subset of {delete, members, info}. Empty = a plain member.
    # The owner implicitly has all caps; this column is only meaningful for
    # non-owner members. Enforcement of `delete` is client-side (sealed sender),
    # `members`/`info` are enforced here. See routers/groups.py.
    permissions: Mapped[str] = mapped_column(String(128), default="", server_default="")
    # (`joined_at` was unmapped on 2026-08-22. Its one reader picked the oldest
    # member on owner succession, and `id` is monotonic on the same insert
    # order, so ORDER BY id returns the same person. What it cost to keep was a
    # per-person join timeline of every room: exactly when each relationship
    # started, for every member of every group on the island.)


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
    # Stage 2a: the 3-value storage class beside envelope_type, same meaning as
    # OfflineMessage.cls. The dormant sweep and `_keep_for` now branch on this
    # (cls == 2 is key-distribution material that must survive the sweep, #544)
    # while still falling back to envelope_type for the legacy rows that carry
    # NULL here. Group rows keep envelope_type; stage 5 reshapes this queue.
    cls: Mapped[int | None] = mapped_column(SmallInteger, nullable=True, default=None)
