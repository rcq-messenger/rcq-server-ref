"""UIN shop — pricing + availability for vanity 3-9 digit UINs.

Read-only: this router quotes prices and suggests free numbers. It does
NOT sell anything; see the note above `/quote` for why the old
`/purchase` endpoint was removed rather than gated. Fulfilment is
out-of-band via `POST /admin/invites` (reserve a specific UIN against an
invite, which is collision-checked against other live invites).

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

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import get_db
from app.core.rate_limit import rate_limit
from app.core.security import current_uin
from app.models.user import User

router = APIRouter(prefix="/uin", tags=["uin_shop"])

# Hard ICQ-style bounds. Anything outside the [3, 9] digit window is
# rejected by /quote up-front; the iOS picker
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


# NOTE: there is deliberately NO `/uin/purchase` endpoint.
#
# It existed until 2026-07-24 and was a hole, not a feature: its only
# payment check was `receipt: str = Field(min_length=1)` (any non-empty
# string passed) and it never consulted `UIN_SHOP_ENABLED` — that flag is
# read solely by `/server/info` to advertise the capability. So on EVERY
# island, including self-hosted ones, any authenticated caller could take
# a free 3-digit UIN — the top of this price ladder.
#
# It is deleted rather than feature-gated because there is no payment
# layer behind it to gate: a gate would still be a purchase path guarded
# by a flag, and the flag was already ignored once. Sales happen
# out-of-band (the operator reserves a specific UIN against an invite via
# `POST /admin/invites`, which — unlike this router ever did — checks for
# collisions with other live invites). Re-add a purchase endpoint only
# together with real receipt/settlement verification.
#
# `/quote` and `/suggestions` stay: they are read-only pricing helpers.
# Both are now rate-limited — `/quote` is a registration oracle (it
# reports whether any 3-9 digit UIN is taken), so an unmetered version
# enumerates the user base of a product whose pitch is having no
# public identifiers.
