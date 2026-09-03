"""Stage 5 of the core-metadata plan: one log per room.

One post into a room used to be written once per member: `offline_group_messages`
held 872 identical copies of every sender-keys broadcast in RCQ Beta and called
it delivery, 393 MB and 79% of the database for one room. Here a post is ONE row
in the room's log, and each (account, device) keeps a cursor into that log.

The log carries two kinds of rows under one sequence:
  * broadcast rows (`to_uin` NULL): a sender-keys `gmsg`, read by every member;
  * addressed rows (`to_uin` set): a sealed per-member envelope (`skdm`,
    `sknack`, a reaction or a legacy post from a client without sender keys),
    which only that member can open and only that member is served.
One sequence axis per room means one cursor per (room, account, device), and
the per-member fan-out table can go once every client reads the log.

`seq` comes from `group_seq`, a durable counter that the sweep never touches:
the same rule as `mailbox_seq` in stage 2b. A counter seeded from MAX(seq)
reseeds to 0 the moment the sweep empties a quiet room, and new rows would land
below every cursor where a fetch can never reach them.
"""
from datetime import datetime, timezone

from sqlalchemy import BigInteger, DateTime, Index, SmallInteger, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class GroupLog(Base):
    __tablename__ = "group_log"
    __table_args__ = (
        # A member's drain: everything above its cursor that is either for
        # everyone or for them.
        Index("ix_group_log_gid_to_seq", "group_id", "to_uin", "seq"),
        Index("ix_group_log_received_at", "received_at"),
    )

    group_id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=False)
    seq: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=False)
    # NULL = a broadcast every member reads; set = sealed to this one member.
    to_uin: Mapped[int | None] = mapped_column(BigInteger, nullable=True, default=None)
    envelope_type: Mapped[str] = mapped_column(String(16))
    # Stage 2a class (0 signal, 1 message, 2 key material), same meaning as on
    # the 1:1 queue; the server branches on it for push and retention.
    cls: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=1)
    payload: Mapped[str] = mapped_column(Text)
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )


class GroupSeq(Base):
    """The durable per-room counter behind `group_log.seq`. Never reseeded,
    never swept; allocated with an atomic upsert inside the post's transaction
    so two concurrent posts into one room serialise on this row."""
    __tablename__ = "group_seq"

    group_id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=False)
    next_seq: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)


class GroupLogCursor(Base):
    """How far one device of one member has read one room's log. Created at
    the room's head on the device's first fetch (a fresh install owes nobody
    a replay of the backlog, the same rule as the 1:1 account watermark),
    moved forward only by an ack, removed when the member leaves."""
    __tablename__ = "group_log_cursors"

    group_id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=False)
    uin: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=False)
    device_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    last_seq: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )


class GroupLogReader(Base):
    """One row per (account, device) that has read the room log at least once.

    The writers keep producing the legacy per-member rows for an account
    until EVERY device that drains the legacy queue for it (every
    `queue_cursors` row of the account) is also a log reader. Per device, not
    per account: an account's phone updating first must not silence its
    still-old desktop or iPhone (iOS ships through the founder's Xcode and
    can be weeks behind). An abandoned old device stops holding the account
    back when its legacy cursor is reaped as stale (30 days)."""
    __tablename__ = "group_log_readers"

    uin: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=False)
    device_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
