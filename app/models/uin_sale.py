"""The two rows a sale needs, and deliberately nothing else.

⚠⚠ No amount, no chain, no address, no transaction, no invoice id, no buyer.
The island's whole share of a sale is "this number was paid for, and this
voucher has been used". Everything a payment actually consists of is watched
outside, by the till, which in turn never learns which account redeemed
anything. Neither half can reconstruct the other's, and that is the point: a
subpoena to either one buys the pair "number, price" or the pair "number,
holder", never "person, payment".
"""

from datetime import datetime, timezone

from sqlalchemy import BigInteger, DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class UinHold(Base):
    """A number spoken for while somebody is paying for it.

    ⚠ Without this, two people pay for the same number and one of them has
    bought nothing: with no custody there is no automatic refund, so that
    failure has no clean ending. The hold is what makes the payment window
    safe, and it deliberately outlives the invoice - a payment that lands late
    should find the number still there.
    """

    __tablename__ = "uin_holds"

    #: The number being paid for. One hold per number, enforced by the key.
    uin: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=False)
    #: The till's own handle for this hold, so it can release what it placed.
    #: Opaque here; the island never interprets it.
    hold_id: Mapped[str] = mapped_column(String(64), index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )


class SpentVoucher(Base):
    """A voucher that has been redeemed, so it cannot be redeemed again.

    The nonce alone, and when. Not who, not for which number: the number is
    already recorded by the collection row the redemption created, and pairing
    the two here would be building the very map this design refuses to keep.

    Swept once the voucher's own expiry has passed - after that a replay fails
    on the clock and the row has nothing left to defend.
    """

    __tablename__ = "spent_vouchers"

    nonce: Mapped[str] = mapped_column(String(128), primary_key=True)
    spent_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True
    )
