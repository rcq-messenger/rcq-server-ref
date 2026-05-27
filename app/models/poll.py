from datetime import datetime, timezone

from sqlalchemy import BigInteger, Boolean, DateTime, ForeignKey, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class Poll(Base):
    """A group poll. The QUESTION and OPTION LABELS never reach the
    server — they travel inside the encrypted `.poll` chat envelope,
    same lane as a normal group message. The server only stores
    structural metadata (option count, single-vs-multi, anonymity
    flag, lifecycle) and the per-option vote tallies, indexed by
    `option_index`. An admin reading the DB sees "UIN 12345 voted
    for option 2 on poll 7" but cannot reconstruct what option 2
    actually said — that's only available to group members who
    received the envelope.

    For anonymous polls, the server still stores `voter_uin` to
    enforce one-vote-per-user. The API NEVER returns voter_uin for
    anonymous polls (filtered in the response builder); honest-but-
    curious clients see only aggregate counts.
    """

    __tablename__ = "polls"
    __table_args__ = (
        Index("ix_polls_group_created", "group_id", "created_at"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    group_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("groups.id", ondelete="CASCADE"), index=True)
    # Author. Owner-of-group-only check happens in the router when
    # closing, but anyone in the group can create a poll for v1.
    creator_uin: Mapped[int] = mapped_column(BigInteger, nullable=False, index=True)
    # UUID of the chat envelope announcing this poll. Lets the iOS
    # client jump from a vote-notification back to the original
    # bubble without an extra round-trip.
    message_id: Mapped[str] = mapped_column(String(36), nullable=False)
    # 2-10. Drives ballot validation: option_index must be in
    # [0, num_options).
    num_options: Mapped[int] = mapped_column(Integer, nullable=False)
    # If true, a vote replaces the user's prior vote (re-clicking
    # different options swaps the ballot). If false, every option
    # accumulates an independent yes/no.
    single_choice: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    # When true, /polls/{id} responses omit voter UINs and only
    # return counts. Server still records voter_uin for dedupe.
    anonymous: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # Stamped when the creator (or, future, the group owner) closes
    # voting. Subsequent vote attempts 403.
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )


class PollVote(Base):
    """One vote row per (poll, voter, option_index). For
    single-choice polls the router replaces the existing row on a
    re-vote; for multi-choice we accumulate independent rows so the
    user can toggle individual options on/off.
    """

    __tablename__ = "poll_votes"
    __table_args__ = (
        Index("ix_poll_votes_poll_option", "poll_id", "option_index"),
        Index("ix_poll_votes_poll_voter", "poll_id", "voter_uin"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    poll_id: Mapped[int] = mapped_column(Integer, ForeignKey("polls.id", ondelete="CASCADE"), nullable=False)
    voter_uin: Mapped[int] = mapped_column(BigInteger, nullable=False)
    option_index: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
