from datetime import datetime, timezone

from sqlalchemy import DateTime, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class RelayInquiry(Base):
    """A request for private relays left on the `/organizations` page.

    The page had a submit button that stored nothing: it waited 700ms and
    said thank you. Anyone who asked to pay us was answered by a mock. This
    is the first half of the flow from `docs/private-relays-design.md`, and
    deliberately the half that does NOT involve money: the request has to
    reach a human before an invoice can mean anything.

    Unauthenticated on purpose. The people this page is for do not have an
    account yet, and demanding one to ASK a question is how you get no
    questions. That makes the table spammable, so it is rate limited at the
    route, every field is capped, and the admin queue can dismiss in one
    click.
    """

    __tablename__ = "relay_inquiries"
    __table_args__ = (
        Index("ix_relay_inquiries_status_created", "status", "created_at"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    # Which tier the form was on when they sent it: personal / team /
    # network / supporter. Free-form rather than an enum — the price table
    # is going to move, and an old row must not stop parsing because a tier
    # was renamed.
    tier: Mapped[str] = mapped_column(String(32))
    # How to reach them back. The ONE required field, and whatever they
    # chose to give: email, a UIN, a Telegram handle, a matrix address.
    # Never validated into a shape, because forcing a shape here means
    # turning away the person whose only contact is the one we did not
    # anticipate.
    contact: Mapped[str] = mapped_column(String(200))
    # Optional "what for": org size, country, what they are running from.
    about: Mapped[str] = mapped_column(Text, default="")
    # open → the queue. contacted → an operator answered. closed →
    # finished, either sold or dropped. Same vocabulary as the report queue
    # so the admin does not have to learn a second one.
    status: Mapped[str] = mapped_column(String(16), default="open", index=True)
    # Operator's private note. Never shown to the requester — there is no
    # surface that could show it: they left a contact, not an account.
    note: Mapped[str] = mapped_column(Text, default="")
    # Coarse origin marker for spam triage ("ru", "de", …) when the CDN
    # gives us one, plus the language the page was in. No IP is stored:
    # this is a sales queue, not a log.
    country: Mapped[str] = mapped_column(String(8), default="")
    lang: Mapped[str] = mapped_column(String(8), default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
