"""A resident's own doorbell keys, for a closed island.

  POST   /guest-cards        register a card this device just generated
  GET    /guest-cards        list mine, so one can be revoked
  DELETE /guest-cards/{hash} revoke one

⚠⚠ THE ISLAND NEVER SEES A CARD. The client generates 32 random bytes and
sends the sha256 of them; the raw value goes to the person it is for, in the
fragment of a shared link or inside a sealed envelope. That is why there is no
"mint" endpoint here returning a card: a server-side mint would put the live
credential in a response body, in an access log and in a database, which is
three places it does not need to be, and it would make a database read enough
to write to anybody — the exact failure `invites.code` had until 2026-08-22.

⚠ And the island never learns who a card was for. The client may name a card
for its owner's own eyes ("the QR from the meetup"); nothing in this file
accepts, stores or returns anything about the recipient. See
`models/guest_card.py` for why that is the point rather than an omission.
"""
from __future__ import annotations

import re

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import get_db
from app.core.rate_limit import rate_limit
from app.core.security import current_uin
from app.models.guest_card import GuestCard

router = APIRouter(prefix="/guest-cards", tags=["guest-cards"])

#: A sha256-hex and nothing else. Checked rather than trusted: this string is
#: interpolated into a WHERE and returned to the owner, and a client that sends
#: a raw card here by mistake must be refused loudly rather than have its live
#: credential stored as if it were a digest.
_HASH_RE = re.compile(r"^[0-9a-f]{64}$")

#: How many cards one resident may have out at once. Not a licence limit: an
#: unbounded list is a way to make a table grow on somebody else's disk, and a
#: person who genuinely needs more than this is describing a different feature
#: (an open island).
MAX_CARDS = 200


class CardIn(BaseModel):
    card_hash: str = Field(min_length=64, max_length=64)
    #: The owner's own note, for the owner's own revoke screen.
    label: str | None = Field(default=None, max_length=64)


class CardOut(BaseModel):
    card_hash: str
    label: str | None
    created_at: str
    #: The DAY it was last used, or null. Deliberately not a timestamp; see the
    #: column comment.
    last_used_on: str | None
    revoked: bool


def _out(row: GuestCard) -> CardOut:
    return CardOut(
        card_hash=row.card_hash,
        label=row.label,
        created_at=row.created_at.isoformat(),
        last_used_on=row.last_used_on.isoformat() if row.last_used_on else None,
        revoked=row.revoked,
    )


@router.post("", response_model=CardOut, status_code=status.HTTP_201_CREATED,
             dependencies=[Depends(rate_limit("guest_card_add", 60, 3600))])
async def add_card(
    body: CardIn,
    uin: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> CardOut:
    digest = body.card_hash.strip().lower()
    if not _HASH_RE.match(digest):
        # ⚠ Loudly. A client that sends the raw card here has just tried to
        # hand the island the thing this whole design keeps away from it, and
        # storing it quietly would look like success for months.
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "card_hash must be sha256-hex")

    held = await db.scalar(
        select(func.count()).select_from(GuestCard).where(
            GuestCard.owner_uin == uin, GuestCard.revoked.is_(False)
        )
    )
    if (held or 0) >= MAX_CARDS:
        raise HTTPException(status.HTTP_409_CONFLICT, "too many cards; revoke one first")

    existing = await db.scalar(select(GuestCard).where(GuestCard.card_hash == digest))
    if existing is not None:
        # Idempotent for the owner (a retry after a dropped response), and a
        # flat refusal for anybody else: re-registering somebody else's card
        # under your own number would let you decide who may write to them.
        if existing.owner_uin != uin:
            raise HTTPException(status.HTTP_409_CONFLICT, "card already registered")
        return _out(existing)

    row = GuestCard(card_hash=digest, owner_uin=uin, label=(body.label or None))
    db.add(row)
    await db.commit()
    await db.refresh(row)
    return _out(row)


@router.get("", response_model=list[CardOut])
async def list_cards(
    uin: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> list[CardOut]:
    rows = (
        await db.scalars(
            select(GuestCard)
            .where(GuestCard.owner_uin == uin)
            .order_by(GuestCard.created_at.desc())
            .limit(MAX_CARDS * 2)
        )
    ).all()
    return [_out(r) for r in rows]


# ⚠ `response_model=None` with the 204. FastAPI infers a response model from
# the `-> None` annotation and then refuses at import time, because a 204 must
# not carry a body: the whole app would not start, which is exactly what
# happened the first time this was written.
@router.delete("/{card_hash}", status_code=status.HTTP_204_NO_CONTENT,
               response_model=None)
async def revoke_card(
    card_hash: str,
    uin: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> None:
    digest = card_hash.strip().lower()
    if not _HASH_RE.match(digest):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "card_hash must be sha256-hex")
    # ⚠ Scoped to the caller in the UPDATE itself, not checked first and then
    # written: the check-then-act version lets somebody revoke a card that is
    # not theirs by winning a race, and revoking somebody's card is how you cut
    # them off from the person they were talking to.
    res = await db.execute(
        update(GuestCard)
        .where(GuestCard.card_hash == digest, GuestCard.owner_uin == uin)
        .values(revoked=True)
    )
    await db.commit()
    if res.rowcount == 0:
        # Same answer for "not yours" and "does not exist", so this endpoint is
        # not a way to ask whether a card belongs to somebody else.
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such card")
