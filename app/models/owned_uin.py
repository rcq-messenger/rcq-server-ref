"""A number somebody holds but is not currently using.

Until now "owning" a UIN and "being" that UIN were the same thing: claiming a
number migrated your account onto it and the old one went back in the pool.
That makes a shop impossible to use carefully — every purchase is also an
identity change, and there is no way to hold #111 while still answering as
#7069.

This table is the vault. A row here means the number is spoken for and nobody
else may claim it, even though no account is currently sitting on it. The
holder is identified by their CURRENT uin; migrations rewrite that the same way
they rewrite every other table (see `app.services.uin_rows`), so moving between
your own numbers does not drop the rest of your collection.
"""

from datetime import datetime, timezone

from sqlalchemy import BigInteger, DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class OwnedUin(Base):
    __tablename__ = "owned_uins"

    # The held number, one row per number: a number can be in exactly one
    # vault, and the primary key is what enforces that under concurrency.
    # autoincrement=False: the number is GIVEN, never generated. SQLAlchemy
    # assumes an integer primary key is a serial and attaches a sequence, which
    # is meaningless here and would hand out a "next uin" to anyone who
    # inserted without one.
    uin: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=False)
    # Whoever holds it, by their current uin.
    owner_uin: Mapped[int] = mapped_column(BigInteger, index=True)
    # How it was obtained. It is what tells a number somebody PAID for from one
    # that was free, and support questions turn on that difference:
    #
    #   purchase  — a signed voucher was redeemed for it (/uin/redeem). Money.
    #   claimed   — taken for free from the open shelf (/uin/purchase).
    #   migrated  — kept on the way past, because it is scarce.
    #
    # "activate" is passed by /uin/activate and must never appear in the table:
    # that path re-keys the deed that already exists. If it ever shows up, a
    # branch that used to move the account has stopped doing so.
    #
    # ⚠⚠ Rows written before 2026-09-03 evening all say "purchase" whatever
    # they were: /uin/purchase reached the same writer and did not say which
    # door it came through, so a free claim and a paid redemption are
    # indistinguishable in the old data and CANNOT be backfilled. Anything that
    # counts money reads the till, not this column; this column answers "may
    # this row be swept" (never, for a purchase) and "how did you get it".
    source: Mapped[str] = mapped_column(String(16), default="purchase")
    acquired_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
