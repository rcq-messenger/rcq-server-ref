from sqlalchemy import BigInteger
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class MailboxSeq(Base):
    """The durable per-recipient counter behind `offline_messages.seq`.

    One row per mailbox (recipient uin), holding the highest `seq` handed out
    for that mailbox. The deposit path allocates the next value with an atomic
    INSERT ... ON CONFLICT DO UPDATE ... RETURNING inside its own transaction,
    so two concurrent deposits to the same recipient serialise on this row and
    get distinct numbers rather than colliding.

    ⚠ This row is the whole point of the design and the queue sweep must NEVER
    touch it. `offline_messages` rows come and go — the sweep empties a quiet
    mailbox on the 30-day TTL — but `next_seq` has to keep climbing across an
    empty mailbox. Seeding a counter from MAX(seq) instead would reseed to 0 the
    moment the mailbox emptied, and the fresh rows would then land below every
    device's stored cursor where ?after= can never reach them: silent permanent
    loss (docs/core-metadata-plan.md, stage 2b). So the counter lives here,
    independent of whether the mailbox currently holds any rows.
    """

    __tablename__ = "mailbox_seq"

    # ⚠ autoincrement=False, and it is not decoration. SQLAlchemy treats a lone
    # integer primary key as a serial and Postgres then hangs a
    # nextval('mailbox_seq_to_uin_seq') default on the column. Harmless while
    # every caller supplies `to_uin` (they all do today), and a loaded gun the
    # first time one does not: the row would quietly be filed under a sequence
    # number rather than under a recipient, and that mailbox's counter would be
    # somebody else's. Same trap the comment in models/user.py records for the
    # UIN column, where a forgotten value minted a trophy number.
    to_uin: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=False)
    # Highest seq assigned so far for this mailbox. The first deposit sets it to
    # 1 (the value it also returns), each later one increments and returns.
    next_seq: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
