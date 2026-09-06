import hashlib
import secrets
from datetime import date, datetime, timezone

from sqlalchemy import BigInteger, Boolean, Date, DateTime, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base

#: How many bytes of randomness a card carries. 32 is not a round number
#: chosen for looks: this value is the ONLY thing between a stranger and the
#: right to write to somebody on a closed island, it is never rate-limited by a
#: human memory (nobody types it, it rides in a link or an envelope), and it
#: has to stay unguessable for the life of a contact rather than the life of a
#: session.
CARD_BYTES = 32


def new_card() -> str:
    """A fresh card, url-safe.

    ⚠ ON THE SERVER ONLY FOR TESTS AND FOR AN OPERATOR MINTING ONE BY HAND. In
    the shipping flow the CLIENT generates the card and sends the island only
    `hash_card(raw)`, so the island never holds the thing that opens its own
    residents' doors. A server-side mint would put the raw value in a response
    body, a log, and a database, which is three places it does not need to be.
    """
    return secrets.token_urlsafe(CARD_BYTES)


def hash_card(raw: str) -> str:
    """sha256-hex of a raw guest card: what actually goes in `GuestCard.card_hash`.

    Same construction as `models/invite.hash_invite_code` and
    `routers/gate._hash`, deliberately: three credential tables on one island
    should not be three different schemes, and the one that is different is the
    one that gets it wrong. Plain sha256 rather than a KDF because a card is
    256 bits of `secrets.token_urlsafe`, not a password: there is nothing to
    brute force, and a KDF's cost would land on the key-card path that every
    first message to a stranger walks.
    """
    return hashlib.sha256(raw.strip().encode("utf-8")).hexdigest()


class GuestCard(Base):
    """A resident's own doorbell key for a CLOSED island.

    On a closed island, knowing somebody's number is not enough to write to
    them: the key needed to seal an envelope is withheld from strangers. A
    guest card is what a resident hands out to be reachable anyway. It travels
    two ways, both of them past the island rather than through it: inside the
    fragment of a shared contact link (a fragment never reaches a server), and
    in the clear INSIDE the first sealed envelope the resident sends, which is
    how "I wrote to you first" becomes "you may write back" with no server
    state and no screen.

    ⚠⚠ WHAT THIS TABLE DELIBERATELY DOES NOT HOLD: who the card was given to.
    Not a uin, not a host, not a note about the person. The island learns that
    a resident has N cards outstanding and nothing more, because a table of
    "who may talk to whom" is the cross-island social graph this project
    refuses to keep, and an operator who can read it is exactly the operator a
    closed island was supposed to protect its members from.

    ⚠ And it does not hold the card. Only the sha256. The raw value exists on
    the resident's device and in the hands of whoever they gave it to; a
    database dump, a backup or a compromise therefore yields no ability to
    write to anybody. This is the same lesson `invites.code` learned on
    2026-08-22, when the live entry credential to an invite-gated island sat in
    the clear and a database read MINTED ACCESS.
    """

    __tablename__ = "guest_cards"
    __table_args__ = (
        # Every gated door looks a card up by hash, on the request path.
        Index("ix_guest_cards_card_hash", "card_hash", unique=True),
        # "show me my cards so I can revoke one" and the per-owner cap.
        Index("ix_guest_cards_owner", "owner_uin"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    #: sha256-hex of the raw card. The raw is never stored and never logged.
    card_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    #: Whose door this opens. The card is useless against anybody else, so a
    #: card that leaks costs its owner their quiet and costs nobody else
    #: anything.
    owner_uin: Mapped[int] = mapped_column(BigInteger, nullable=False)
    #: What the OWNER called it, for their own revoke screen ("the QR from the
    #: meetup"). Chosen by the owner, never by the island, and never derived
    #: from who used it.
    label: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    #: ⚠ A DATE, NOT A TIMESTAMP, and that is the whole point of the column.
    #: The owner needs "is this card still in use, can I revoke it" and gets it
    #: from a day. A timestamp would make this row a per-card activity feed:
    #: every time a particular stranger looked up their key, to the second,
    #: sitting next to the owner's number. The coarse version answers the
    #: user's question and does not answer the operator's.
    last_used_on: Mapped[date | None] = mapped_column(Date, nullable=True)
    #: Revoked cards are KEPT, not deleted: a revoked row is what makes the
    #: refusal instant and what stops the same card being re-registered by
    #: somebody who kept a copy.
    #:
    #: ⚠ They are removed with their owner, through `PER_UIN_COLUMNS`, and by
    #: nothing else. An earlier draft of this comment claimed an age sweep that
    #: does not exist, which is worse than no comment: it invites the next
    #: reader to assume the table is bounded when it is not.
    revoked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
