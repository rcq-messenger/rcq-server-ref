"""UIN shop — pricing + availability for vanity 3-9 digit UINs.

BETA BEHAVIOUR: `/purchase` currently GRANTS a number for free. Testers are
meant to be able to take whatever number they like while the product is in
testing, so the price table below is decoration until a real payment path
exists. The endpoint is gated on `UIN_SHOP_ENABLED` and 404s when it is off,
so an island only hands out numbers if its operator asked for that.

Operators can also fulfil a specific number out-of-band via
`POST /admin/invites`, which reserves it against an invite and is
collision-checked against other live invites.

Pricing tier table (shorter UIN = scarcer = pricier):
    9 digits → $0.99
    8 digits → $1.99
    7 digits → $4.99
    6 digits → $14.99
    5 digits → $49.99
    4 digits → $199.00
    3 digits → $999.00

The ladder roughly triples per digit drop so the 3-digit ceiling
($999, Apple's standard tier cap) doesn't feel detached from the
tier below it. The 5-digit / 6-digit tiers are the practical sweet
spot for a "nice handle without burning a month's coffee budget".

The ladder is public (this file ships under AGPL), so treat a quoted
price as a public fact about a UIN's digit length, not as a secret.
"""

from __future__ import annotations

import secrets

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.db import get_db
from app.core.rate_limit import rate_limit
from app.core.security import current_uin, issue_token, uin_epoch
from app.models.user import User
from app.routers.migrate import MigrateOut, _perform_migration

router = APIRouter(prefix="/uin", tags=["uin_shop"])

# Hard ICQ-style bounds. Anything outside the [3, 9] digit window is
# rejected by /quote and /purchase up-front; the iOS picker
# enforces the same range client-side so server-side this is the
# defense-in-depth gate.
MIN_LEN = 3
MAX_LEN = 9

# Price cents keyed by UIN length. Roughly geometric: ~3x per
# digit drop until the 3-digit trophy tier at the Apple $999 cap.
_PRICES_CENTS: dict[int, int] = {
    9: 99,
    8: 199,
    7: 499,
    6: 1499,
    5: 4999,
    4: 19900,
    3: 99900,
}


def _length(uin: int) -> int:
    return len(str(uin))


class QuoteIn(BaseModel):
    uin: int = Field(gt=0)


class QuoteOut(BaseModel):
    uin: int
    length: int
    available: bool
    # USD cents. Null only when length is out of bounds (we still
    # return a 200 with available=False so iOS doesn't have to
    # special-case validation errors as crashes).
    price_cents: int | None
    price_display: str | None
    # When available=False, `reason` tells the UI what to render:
    # "taken" | "too_short" | "too_long" | "self".
    reason: str | None = None


@router.post(
    "/quote",
    response_model=QuoteOut,
    dependencies=[Depends(rate_limit("uin_quote", 30, 60))],
)
async def quote(
    body: QuoteIn,
    me: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> QuoteOut:
    length = _length(body.uin)
    if length < MIN_LEN:
        return QuoteOut(uin=body.uin, length=length, available=False, price_cents=None, price_display=None, reason="too_short")
    if length > MAX_LEN:
        return QuoteOut(uin=body.uin, length=length, available=False, price_cents=None, price_display=None, reason="too_long")
    if body.uin == me:
        return QuoteOut(uin=body.uin, length=length, available=False, price_cents=None, price_display=None, reason="self")

    taken = await db.scalar(select(User.uin).where(User.uin == body.uin)) is not None
    cents = _PRICES_CENTS[length]
    display = f"${cents / 100:.2f}"
    return QuoteOut(
        uin=body.uin,
        length=length,
        available=not taken,
        price_cents=cents if not taken else None,
        price_display=display if not taken else None,
        reason="taken" if taken else None,
    )


class SuggestionOut(BaseModel):
    uin: int
    length: int
    price_cents: int
    price_display: str


@router.get(
    "/suggestions",
    response_model=list[SuggestionOut],
    dependencies=[Depends(rate_limit("uin_suggestions", 20, 60))],
)
async def suggestions(
    count: int = Query(6, ge=1, le=20),
    me: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> list[SuggestionOut]:
    """Pick a handful of currently-free UINs across mixed digit lengths
    so the iOS composer can show a "try one of these" carousel without
    making the user guess random numbers.

    The bias is toward the interesting middle (4-7 digits) — that's
    where rarity feels meaningful without being prohibitively expensive.
    Availability is a point-in-time snapshot and nothing here reserves a
    number: a suggestion can be registered by someone else a moment
    later. Fulfilment re-checks when the operator mints the invite."""
    target_lengths = [4, 5, 5, 6, 6, 7, 7, 8]
    out: list[SuggestionOut] = []
    seen: set[int] = set()
    attempts = 0
    cap = count * 30
    while len(out) < count and attempts < cap:
        attempts += 1
        length = target_lengths[attempts % len(target_lengths)]
        lo = 10 ** (length - 1)
        hi = 10 ** length - 1
        candidate = secrets.randbelow(hi - lo + 1) + lo
        if candidate == me or candidate in seen:
            continue
        seen.add(candidate)
        taken = await db.scalar(select(User.uin).where(User.uin == candidate)) is not None
        if taken:
            continue
        cents = _PRICES_CENTS[length]
        out.append(SuggestionOut(
            uin=candidate,
            length=length,
            price_cents=cents,
            price_display=_price_display_for(cents),
        ))
    return out


def _price_display_for(cents: int) -> str:
    return f"${cents / 100:.2f}"


class ClaimIn(BaseModel):
    uin: int = Field(gt=0)
    # Shipped clients still post a `receipt` string. It is deliberately NOT
    # declared here and is ignored: it was never validated against anything,
    # and a field that looks like a payment check but is not is worse than no
    # field at all. Pydantic drops unknown keys, so old clients keep working.


@router.post("/purchase", response_model=MigrateOut)
async def claim(
    body: ClaimIn,
    me: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> MigrateOut:
    """BETA: claim any free 3-9 digit UIN and move this account onto it.

    This grants the number for FREE. That is the intended behaviour while the
    product is in testing — testers are meant to be able to take whatever
    number they like — and the price table above is decoration until a real
    payment path exists.

    It is gated on UIN_SHOP_ENABLED, and the gate is the whole point of this
    rewrite. The previous version of this endpoint ignored that flag entirely
    (only `/server/info` read it), so every island running this code, including
    self-hosted ones, silently handed out free vanity numbers whether or not
    its operator had switched the shop on. Free-on-the-flagship-during-beta is
    a product decision; free-everywhere-by-accident was a bug.

    Before this is ever framed to a user as a purchase, a real receipt /
    settlement check goes here, and the docstring above stops saying FREE.
    """
    if not settings.UIN_SHOP_ENABLED:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "uin shop is disabled")

    length = _length(body.uin)
    if length < MIN_LEN or length > MAX_LEN:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail={"code": "invalid_length"})
    if body.uin == me:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail={"code": "self_target"})
    if await db.scalar(select(User.uin).where(User.uin == body.uin)) is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, detail={"code": "taken"})

    user = await db.get(User, me)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found")
    # A suspended account does not get to reroll its identity, same rule the
    # migrate route enforces.
    if user.is_suspended:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail={"code": "suspended"})

    new_uin = await _perform_migration(db, user, target_uin=body.uin)
    # The freed number's tokens are retired inside _perform_migration, so the
    # old bearer cannot follow the number to whoever claims it next.
    return MigrateOut(new_uin=new_uin, token=issue_token(new_uin, await uin_epoch(new_uin)))


# `/quote` and `/suggestions` are read-only pricing helpers and stay open
# regardless of the flag. Both are rate-limited: `/quote` is a registration
# oracle (it reports whether any 3-9 digit UIN is taken), so an unmetered
# version enumerates the user base of a product whose pitch is having no
# public identifiers.
