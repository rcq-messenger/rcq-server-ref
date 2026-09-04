"""A number one person is selling to another, and nothing about the money.

⚠⚠ The island's whole share of a resale is "this number is for sale by this
account, at this price, payable here". It never learns that a payment
happened, who paid, or from what wallet: the buyer pays the SELLER directly
and the till, watching the chain from outside, signs a voucher saying so. So a
subpoena here buys "number, seller, asking price" and a subpoena to the till
buys "address, amount, transaction" — never the pair that says who bought what
from whom.

The payout address lives on the LISTING rather than on the account on purpose.
An address saved once and reused is a convenience the client can offer, but the
address that was promised when a listing went up is the address that must be
paid: a seller editing their default mid-sale would otherwise redirect money
somebody was already sending.
"""

from datetime import datetime, timezone

from sqlalchemy import BigInteger, DateTime, Integer, JSON, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class UinListing(Base):
    __tablename__ = "uin_listings"

    #: The number for sale. One listing per number, enforced by the key.
    uin: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=False)
    #: Who is selling it, by their current number. In PER_UIN_COLUMNS, so a
    #: seller who moves between their own numbers keeps their listings, and
    #: burning the account takes them down with it.
    seller_uin: Mapped[int] = mapped_column(BigInteger, index=True)
    #: This listing, as a thing that can be named in a signature.
    #:
    #: ⚠⚠ The voucher binds to THIS, not to `seller_uin`, and that is the whole
    #: reason it exists. A seller's number is mutable — moving between your own
    #: numbers re-keys `seller_uin` (PER_UIN_COLUMNS) — so a voucher naming the
    #: seller was void the moment they switched, and the buyer had paid.
    #: Minted fresh on every price change too: a re-priced listing is a
    #: different offer, and a voucher bought against the old price must not
    #: open the new one.
    listing_id: Mapped[str] = mapped_column(String(32), index=True)
    #: What they are asking, in cents. The island quotes it and the till signs
    #: for it; a listing whose price changed mid-sale stops the redemption
    #: rather than surprising either side.
    price_cents: Mapped[int] = mapped_column(Integer)
    #: Where the buyer pays: {chain: address}. See the note above on why this
    #: is a copy and not a pointer to the seller's saved default.
    payout: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True
    )
