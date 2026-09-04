"""UIN shop — pricing + availability for vanity 3-9 digit UINs.

BETA BEHAVIOUR: `/purchase` GRANTS a number for free, and since 2026-09-01 it
only grants an ORDINARY one — short and patterned numbers are reserved stock
and answer 403 `reserved` here (services/uin.is_reserved_uin). Collections are
closed with them: a take now always moves the account onto the number, because
the free-claim-and-keep combination is what put 161 numbers into 54 private
collections while the shelf everyone else picks from emptied. The endpoint is
gated on `UIN_SHOP_ENABLED` and 404s when it is off, so an island only hands
out numbers if its operator asked for that.

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

import json
import logging
import os
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.db import get_db
from app.core.rate_limit import rate_limit
from app.core.security import carry_device_id, current_device_id, current_uin, issue_token, uin_epoch
from app.models.owned_uin import OwnedUin
from app.models.uin_listing import UinListing
from app.models.uin_sale import SpentVoucher, UinHold
from app.models.user import User
from app.routers.migrate import _perform_migration
from app.services import uin_voucher
from app.services import server_settings
from app.services.uin import is_reserved_uin, uin_is_taken

log = logging.getLogger(__name__)

router = APIRouter(prefix="/uin", tags=["uin_shop"])

# Hard ICQ-style bounds. Anything outside the [3, 9] digit window is
# rejected by /quote and /purchase up-front; the iOS picker
# enforces the same range client-side so server-side this is the
# defense-in-depth gate.
MIN_LEN = 3
MAX_LEN = 9
# How many numbers one account may hold at once, beside the one it answers as.
#
# Was zero between 01.09 and 03.09, when collections were closed outright to
# stop the hoarding that had emptied the shelf: 161 numbers parked across 54
# accounts, eleven on one of them, while everyone else picked from what was
# left. What reopened them was making them cost money (founder, 03.09) - a
# hoard of ten short numbers is now a four-figure hoard, and the door they come
# through is a payment rather than a request.
#
# ⚠ The cap counts PROPERTY, not the number in use: `_owned_uins` and
# `/uin/mine` both hide the number the account answers as, so moving between
# your own numbers can never be refused for being one too many.
MAX_OWNED_UINS = 10

#: The shortest number that is ever for sale. Three digits stay off the market
#: entirely (founder, 03.09): 999 of them exist in the whole world, 761 are
#: already spoken for, and what is left is worth more as something handed to a
#: person by name than as the top row of a price list.
MIN_SALE_LEN = 4

#: How long the till's hold lasts. Two hours: an invoice lives one, and the
#: slack covers a transfer that confirms slowly.
#:
#: ⚠ Deliberately not a day. Placing a hold costs nothing and needs no payment,
#: so a long hold is a way to take numbers out of circulation for free - and
#: the four-digit shelf is 9000 numbers wide, not a million. A payment that
#: lands after the hold has lapsed is still honoured: a voucher does not need a
#: hold to be redeemed, it only needs the number to still be free.
HOLD_MINUTES = 120

# Price cents keyed by UIN length. Roughly geometric: ~3x per
# digit drop until the 3-digit trophy tier at the Apple $999 cap.
#
# ⚠ THE FLAGSHIP'S ladder, and only the default. An island that sells numbers
# is being paid into ITS OWN wallets by ITS OWN till, so the prices have to be
# its operator's: `RCQ_UIN_PRICES` in the .env, JSON keyed by digit count. A
# self-hosted island quoting these numbers is quoting a shop it is not.
_DEFAULT_PRICES_CENTS: dict[int, int] = {
    9: 99,
    8: 199,
    7: 499,
    6: 1499,
    5: 4999,
    4: 19900,
    3: 99900,
}


async def _prices() -> dict[int, int]:
    """The operator's ladder, or the flagship's when they have not set one.

    ⚠ Read live from `server_settings`, so a wrong price is corrected from the
    console rather than by a restart. A bad value is not a reason to fall back
    silently to somebody else's prices: the operator asked for something and
    would never find out it was ignored, and what is being got wrong is what
    people are charged. It logs loudly and keeps the default, which is the only
    safe direction — an island that quotes nothing sells nothing, and one that
    quotes the wrong number takes the wrong money.
    """
    raw = str(await server_settings.get("uin_prices") or "").strip()
    if not raw:
        return dict(_DEFAULT_PRICES_CENTS)
    try:
        parsed = json.loads(raw)
        out = {int(k): int(v) for k, v in parsed.items()}
        if not out or any(v < 0 for v in out.values()):
            raise ValueError("prices must be non-negative and non-empty")
        return out
    except Exception as exc:  # noqa: BLE001
        log.error(
            "[uin-shop] the price ladder is not usable (%s); falling back to the "
            "default. Numbers are quoted at the flagship's prices until this is "
            "fixed in the console.", exc,
        )
        return dict(_DEFAULT_PRICES_CENTS)




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
    # "taken" | "too_short" | "too_long" | "self" | "reserved".
    reason: str | None = None
    #: How this number would be acquired, so a client can draw the right button
    #: instead of inferring it from the length:
    #:   "free"     - ordinary space, `POST /uin/purchase` takes it for nothing;
    #:   "purchase" - scarce stock, only `POST /uin/redeem` with a paid voucher;
    #:   "resale"   - somebody is SELLING it: `price_cents` is their price and
    #:                `seller_uin` is who gets paid;
    #:   "closed"   - not obtainable here at all (three digits, or an island
    #:                with no till, or the number is already taken, or a resale
    #:                somebody else is paying for right now).
    #: ⚠ Older clients ignore the field and keep working: everything they knew
    #: how to take is still "free", and everything else still says available
    #: only when it really can be had.
    acquire: str = "closed"
    #: Whose number it is, when `acquire` is "resale". A person, not the
    #: island: what they are asking is their price and the money goes to them.
    seller_uin: int | None = None
    #: WHERE to pay, when `acquire` is "purchase" or "resale". The island's own till.
    #:
    #: ⚠⚠ This exists because the till is NOT one shared service. Every client
    #: shipped before 2026-09-04 has one compiled in (console-api.rcq.app) and
    #: that till serves exactly one island, so a client that ignores this field
    #: would take a self-hosted island's customer to OUR checkout and their
    #: money would arrive somewhere that cannot give them the number. Which is
    #: why an island only answers "purchase" to a client that has SAID it will
    #: use this field — see `client_reads_checkout_url`.
    checkout_url: str | None = None


async def require_shop_open() -> None:
    """The shop is the operator's decision, taken live.

    ⚠ Read through `server_settings`, not straight off the .env: an operator
    who opens or closes their shop from the console expects it to happen, and
    an island that needed a restart to stop selling would keep selling for as
    long as nobody had shell access. The .env value remains the default, so an
    island that never touches the console behaves exactly as before.

    Off, the endpoints are ABSENT rather than merely unused: an island that
    will never sell a number must not quote a price for one, because that is
    advertising somebody else's shop.
    """
    if not await server_settings.get_bool("uin_shop_enabled"):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "uin shop is disabled")


@router.post(
    "/quote",
    response_model=QuoteOut,
    dependencies=[Depends(require_shop_open), Depends(rate_limit("uin_quote", 30, 60))],
)
async def quote(
    body: QuoteIn,
    me: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
    x_rcq_checkout: str | None = Header(default=None),
) -> QuoteOut:
    length = _length(body.uin)
    if length < MIN_LEN:
        return QuoteOut(uin=body.uin, length=length, available=False, price_cents=None, price_display=None, reason="too_short")
    if length > MAX_LEN:
        return QuoteOut(uin=body.uin, length=length, available=False, price_cents=None, price_display=None, reason="too_long")
    if body.uin == me:
        return QuoteOut(uin=body.uin, length=length, available=False, price_cents=None, price_display=None, reason="self")

    # ⚠ `.get`, not `[...]`. The ladder is the operator's now, and a length
    # they left out is one they do not sell: an index would answer 500 to a
    # perfectly reasonable question about a number nobody is selling.
    cents = (await _prices()).get(length)
    if cents is None:
        return QuoteOut(uin=body.uin, length=length, available=False,
                        price_cents=None, price_display=None, reason="not_for_sale")
    display = f"${cents / 100:.2f}"
    scarce = is_reserved_uin(body.uin)
    taken = await uin_is_taken(db, body.uin)

    # ⚠⚠ ASKED BEFORE "taken", because a listed number IS taken — it belongs to
    # the person selling it. Reading availability first would answer "taken" to
    # everyone and the market would be invisible from the one place people
    # actually type a number (founder, 04.09: typing a number that somebody is
    # selling should say so, and say by whom).
    listing = await db.get(UinListing, body.uin)
    if listing is not None and listing.seller_uin != me:
        held = await _listing_held(db, body.uin)
        return QuoteOut(
            uin=body.uin, length=length,
            # False, like scarce stock: an older client reads this field alone
            # and would otherwise draw a "take it" button over somebody's
            # property. `acquire` is what a client that understands resale
            # keys off.
            available=False,
            price_cents=listing.price_cents,
            price_display=_price_display_for(listing.price_cents),
            reason="listed",
            acquire="closed" if held else "resale",
            seller_uin=listing.seller_uin,
            checkout_url=(await own_till_url()) if not held else None,
        )

    if taken:
        return QuoteOut(uin=body.uin, length=length, available=False,
                        price_cents=None, price_display=None, reason="taken")

    if scarce:
        # ⚠⚠ `available` STAYS FALSE for scarce stock, and the price rides
        # alongside it. Every client in people's hands reads that one field and
        # draws a "take it" button from it, and the endpoint behind that button
        # is `/uin/purchase`, which gives numbers away for nothing and refuses
        # the scarce ones with a 403. Flipping this to true would have made
        # three released clients offer, for free, exactly the numbers that are
        # now for sale - and then fail in their faces.
        #
        # A client that understands `acquire` keys off THAT instead, and gets
        # everything it needs: the price, and the one door that opens it.
        # ⚠⚠ AND THE CHECKOUT HAS TO BE OURS TO SEND PEOPLE TO.
        #
        # Every shipped client hardcodes ONE till — `console-api.rcq.app`
        # (web-chat/src/lib/till.ts, rcq-android/.../net/TillApi.kt), and that
        # till serves ONE island. So a self-hosted island that has its own till
        # and its own pubkey used to answer `purchase` here, the client drew a
        # buy button from it, and the customer was sent to OUR checkout to pay
        # US for a number on SOMEBODY ELSE'S island. Their own till would never
        # see the money and the buyer would never get the number.
        #
        # `RCQ_UIN_CLIENT_TILL_MINE` is the operator saying "the checkout the
        # clients already carry sells for me". Only the flagship can truthfully
        # say that today, which is also the standing rule: purchase is a
        # flagship surface, and a self-hosted island hands numbers out by
        # arrangement (`POST /admin/uin/grant`).
        #
        # This is the same principle the web market records at Market.tsx:48 —
        # THE SERVER DECIDES, and a client draws whatever the quote says. The
        # bug was never that clients lacked a gate; it was that the island
        # claimed a sale it could not take money for. An island that cannot be
        # paid now says `closed`, which every already-released client renders
        # correctly without a new build.
        # ⚠⚠ AND THE BUYER HAS TO REACH THE RIGHT CHECKOUT.
        #
        # The till is not one shared service: each one serves a single island,
        # and every client shipped before 2026-09-04 has ours compiled in
        # (web-chat/src/lib/till.ts, rcq-android/.../net/TillApi.kt). So an
        # island that answers "purchase" to such a client is sending its
        # customer to OUR checkout — the money arrives where the number is not,
        # their own till never sees it, and nobody can put it right afterwards.
        #
        # Two ways to be sure the buyer lands in the right place:
        #
        #   * the client SAYS it will use the address we hand back, by sending
        #     `X-RCQ-Checkout: island`. Nothing older can say it, which is the
        #     point — the declaration is the capability;
        #   * or the checkout compiled into those older clients happens to be
        #     ours, which only the flagship can say (`RCQ_UIN_CLIENT_TILL_MINE`).
        #
        # An island that satisfies neither says `closed` rather than taking a
        # payment it cannot honour. That is not a restriction on self-hosting:
        # set `RCQ_UIN_TILL_URL` and current clients buy from you directly.
        client_reads_checkout_url = (x_rcq_checkout or "").strip().lower() == "island"
        built_in_till_is_ours = os.environ.get(
            "RCQ_UIN_CLIENT_TILL_MINE", ""
        ).strip().lower() in {"1", "true", "yes"}
        own_till = await own_till_url()
        reachable = (client_reads_checkout_url and bool(own_till)) or built_in_till_is_ours
        sellable = (
            length >= MIN_SALE_LEN
            and bool(uin_voucher.public_key_b64())
            and reachable
        )
        return QuoteOut(
            uin=body.uin,
            length=length,
            available=False,
            price_cents=cents if sellable else None,
            price_display=display if sellable else None,
            reason="reserved",
            acquire="purchase" if sellable else "closed",
            # Always the island's OWN till when it has one, so a client that
            # asked for it never falls back to whatever it was compiled with.
            checkout_url=own_till if sellable else None,
        )

    return QuoteOut(
        uin=body.uin,
        length=length,
        available=True,
        price_cents=cents,
        price_display=display,
        reason=None,
        acquire="free",
    )


async def own_till_url() -> str | None:
    """This island's own checkout, or None when it runs no till.

    One place, so a resale and an island sale can never disagree about where a
    buyer pays, and read live so an operator can correct it from the console.
    """
    raw = str(await server_settings.get("uin_till_url") or "").strip()
    return raw.rstrip("/") or None


def _price_display_for(cents: int) -> str:
    return f"${cents / 100:.2f}"


class ListingIn(BaseModel):
    uin: int = Field(gt=0)
    price_cents: int = Field(ge=1, le=100_000_00)
    #: {chain: address}. At least one, and the chains are the till's to know —
    #: the island stores what it is given and never spends it.
    payout: dict[str, str]


class ListingOut(BaseModel):
    uin: int
    seller_uin: int
    price_cents: int
    price_display: str
    #: Somebody is paying for it right now, so the buy button is spent. The
    #: hold is short by design (founder, 04.09): a listing blocked for hours by
    #: a payment that never arrives is a listing nobody can buy.
    held: bool = False


def _listing_out(row: UinListing, held: bool) -> ListingOut:
    return ListingOut(
        uin=row.uin, seller_uin=row.seller_uin, price_cents=row.price_cents,
        price_display=_price_display_for(row.price_cents), held=held,
    )


@router.post("/listings", response_model=ListingOut, dependencies=[Depends(require_shop_open)])
async def create_listing(
    body: ListingIn,
    me: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> ListingOut:
    """Put a number you hold up for sale.

    ⚠⚠ Only a number in your COLLECTION, never the one you are answering as.
    Selling the number you are using would hand your identity to a stranger
    mid-conversation, and there is no undo for that. `_owned_uins` already
    filters the active number out, so this reads the deed directly and refuses
    when it is the one in use.

    The money never touches this island: the buyer pays the address in
    `payout` directly, and the till (which watches that address from outside)
    signs a voucher the buyer brings back here. So there is no commission to
    take and nothing in escrow, which is exactly why the seller's address is
    required up front — a listing nobody can pay is not a listing.
    """
    target = int(body.uin)
    if target == me:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail={"code": "in_use"})
    if not body.payout or not all(
        isinstance(k, str) and isinstance(v, str) and v.strip() for k, v in body.payout.items()
    ):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail={"code": "no_payout"})

    deed = await db.get(OwnedUin, target)
    if deed is None or int(deed.owner_uin) != me:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail={"code": "not_owned"})

    existing = await db.get(UinListing, target)
    if existing is not None:
        existing.price_cents = int(body.price_cents)
        existing.payout = {k: v.strip() for k, v in body.payout.items()}
        await db.commit()
        return _listing_out(existing, held=await _listing_held(db, target))

    row = UinListing(
        uin=target, seller_uin=me, price_cents=int(body.price_cents),
        payout={k: v.strip() for k, v in body.payout.items()},
    )
    db.add(row)
    await db.commit()
    return _listing_out(row, held=False)


@router.delete("/listings/{uin}", dependencies=[Depends(require_shop_open)])
async def delete_listing(
    uin: int,
    me: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Take a number off the market.

    ⚠ Refused while somebody is paying for it. The hold is what makes the
    payment window safe, and a seller who could pull the listing out from under
    a payment in flight would be taking money for nothing. Holds are short, so
    the wait is minutes.
    """
    row = await db.get(UinListing, uin)
    if row is None or int(row.seller_uin) != me:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail={"code": "not_listed"})
    if await _listing_held(db, uin):
        raise HTTPException(status.HTTP_409_CONFLICT, detail={"code": "being_paid"})
    await db.delete(row)
    await db.commit()
    return {"ok": True}


@router.get("/listings", response_model=list[ListingOut], dependencies=[Depends(require_shop_open)])
async def listings(
    count: int = Query(12, ge=1, le=50),
    me: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> list[ListingOut]:
    """A handful of what people are selling, newest first.

    A window rather than a catalogue, and refreshable — the same shape the
    free-number carousel has, for the same reason: a list that tries to be
    complete is a list nobody reads, and a market with ten thousand rows in it
    is a scroll, not a shop.

    Your own listings are not in it. You know what you are selling, and the
    place that shows it is your own collection.
    """
    rows = (
        await db.execute(
            select(UinListing)
            .where(UinListing.seller_uin != me)
            .order_by(UinListing.created_at.desc())
            .limit(count)
        )
    ).scalars().all()
    held = await _held_uins(db, [r.uin for r in rows])
    return [_listing_out(r, held=r.uin in held) for r in rows]


async def _listing_held(db: AsyncSession, uin: int) -> bool:
    hold = await db.get(UinHold, uin)
    return hold is not None and hold.expires_at > datetime.now(timezone.utc)


async def _held_uins(db: AsyncSession, uins: list[int]) -> set[int]:
    if not uins:
        return set()
    rows = (
        await db.execute(
            select(UinHold.uin).where(
                UinHold.uin.in_(uins), UinHold.expires_at > datetime.now(timezone.utc)
            )
        )
    ).scalars().all()
    return {int(u) for u in rows}


class SuggestionOut(BaseModel):
    uin: int
    length: int
    price_cents: int
    price_display: str


@router.get(
    "/suggestions",
    response_model=list[SuggestionOut],
    dependencies=[Depends(require_shop_open), Depends(rate_limit("uin_suggestions", 20, 60))],
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
    # ⚠ Was [4,5,5,6,6,7,7,8] — the interesting middle, which is now exactly
    # the reserved stock. Suggesting a number the next endpoint refuses is
    # worse than suggesting a plainer one, so the carousel starts where the
    # numbers are actually free; `is_reserved_uin` below is the real gate and
    # this list only decides what gets tried first.
    target_lengths = [7, 7, 8, 8, 9, 9]
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
        if is_reserved_uin(candidate):
            continue
        if await uin_is_taken(db, candidate):
            continue
        cents = (await _prices()).get(length)
        if cents is None:
            continue
        out.append(SuggestionOut(
            uin=candidate,
            length=length,
            price_cents=cents,
            price_display=_price_display_for(cents),
        ))
    return out


class ClaimIn(BaseModel):
    uin: int = Field(gt=0)
    # Take the number WITHOUT becoming it. Defaults to true so every already
    # shipped client keeps the behaviour it was written against; new clients
    # send false and the number simply joins the buyer's collection.
    switch: bool = True
    # Shipped clients still post a `receipt` string. It is deliberately NOT
    # declared here and is ignored: it was never validated against anything,
    # and a field that looks like a payment check but is not is worse than no
    # field at all. Pydantic drops unknown keys, so old clients keep working.


class PurchaseOut(BaseModel):
    """Superset of MigrateOut. `new_uin`/`token` are populated exactly when the
    caller asked to switch, so a client written against the old shape reads it
    unchanged; `switched` and `owned` are what the new screen renders."""

    new_uin: int | None = None
    token: str | None = None
    switched: bool = False
    # The caller's collection after this call: numbers held but not in use.
    owned: list[int] = []


class OwnedUinOut(BaseModel):
    uin: int
    length: int
    acquired_at: datetime


class MyUinsOut(BaseModel):
    # The number this account is answering as right now.
    active: int
    owned: list[OwnedUinOut]
    # How many one account may hold here. Sent so the client can show "3 of 10"
    # instead of only finding out at the eleventh attempt, and so a self-hoster
    # who changes the cap does not need a client release to reflect it.
    max_owned: int = MAX_OWNED_UINS


async def _owned_uins(db: AsyncSession, owner: int) -> list[int]:
    """The numbers this account holds and is NOT currently answering as.

    ⚠ The deed for the active number stays in the table (that is what keeps a
    bought number yours when you move off it), so the row for `owner` itself is
    filtered here rather than deleted there. A collection that listed you to
    yourself would also let `release` be pointed at the number you are using.
    """
    rows = (
        await db.execute(
            select(OwnedUin.uin)
            .where(OwnedUin.owner_uin == owner, OwnedUin.uin != owner)
            .order_by(OwnedUin.uin)
        )
    ).scalars().all()
    return [int(u) for u in rows]


@router.get("/mine", response_model=MyUinsOut)
async def my_uins(
    me: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> MyUinsOut:
    """This account's number and everything else it holds.

    Open regardless of UIN_SHOP_ENABLED: an operator switching the shop off
    should stop new sales, not hide from people what they already own."""
    # ⚠ `uin != me` here for the same reason it is in `_owned_uins`: since
    # 2026-09-03 the deed to a number SURVIVES being used, which is what keeps a
    # bought number yours when you move off it. Two readers of one table have to
    # answer the same way, or the collection screen lists the number you are
    # answering as and offers to release it.
    rows = (
        await db.execute(
            select(OwnedUin)
            .where(OwnedUin.owner_uin == me, OwnedUin.uin != me)
            .order_by(OwnedUin.acquired_at.desc())
        )
    ).scalars().all()
    return MyUinsOut(
        active=me,
        max_owned=MAX_OWNED_UINS,
        owned=[
            OwnedUinOut(uin=int(r.uin), length=_length(int(r.uin)), acquired_at=r.acquired_at)
            for r in rows
        ],
    )


@router.delete(
    "/mine/{uin}",
    response_model=MyUinsOut,
    # Same budget as activating: a handful of deliberate taps, never a loop.
    dependencies=[Depends(rate_limit("uin_release", 20, 3600))],
)
async def release(
    uin: int,
    me: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> MyUinsOut:
    """Give a held number back. Collecting numbers you did not choose is a side
    effect of the vault: activating one puts the previous one in the collection
    whether you wanted it or not, and the long number the network handed you at
    signup is usually the first thing you stop wanting (user request).

    The number returns to the pool, so somebody else may end up with it. That is
    the point, and it is why this is a separate deliberate call rather than a
    swipe.

    The active number is safe by construction: `activate` deletes the vault row
    for the number it moves onto, so `me` is never in this table. The check is
    here anyway — the invariant is three functions away, and the cost of it
    being wrong is an account releasing the number it is answering as.

    Not gated on UIN_SHOP_ENABLED, for the same reason `/mine` is not: an
    operator closing the shop should stop sales, not trap people in a
    collection."""
    # ⚠⚠ A number on the market is spoken for. Releasing it back to the pool
    # while somebody may be paying for it would sell a number that is no longer
    # there, and the buyer's money is already gone. Take it off the market
    # first; that is one tap and it says what it means.
    listed = await db.get(UinListing, uin)
    if listed is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, detail={"code": "listed"})
    if uin == me:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail={"code": "uin_in_use"})
    held = await db.get(OwnedUin, uin)
    if held is None or int(held.owner_uin) != me:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail={"code": "not_owned"})
    await db.delete(held)
    await db.commit()
    return await my_uins(me=me, db=db)


class ActivateIn(BaseModel):
    uin: int = Field(gt=0)


@router.post("/activate", response_model=PurchaseOut)
async def activate(
    body: ActivateIn,
    me: int = Depends(current_uin),
    device_id: str = Depends(current_device_id),
    db: AsyncSession = Depends(get_db),
) -> PurchaseOut:
    """Answer as a number you already hold. Your current number goes into the
    collection rather than back into the pool, so switching between your own
    numbers is reversible and never loses one.

    Separate from `/purchase` on purpose: buying and changing who you are were
    the same button, which is a bad thing to be one tap away from.

    Deliberately NOT gated on UIN_SHOP_ENABLED. The gate belongs on acquiring a
    number, and it is already there; this only lets somebody use what they
    already hold. A self-hosted island that granted a member a second number by
    hand must still let them switch to it, and an operator who closes their
    shop afterwards must not strand people on the wrong number."""
    # ⚠⚠ A number on the market is spoken for. Answering as it
    # while somebody may be paying for it would sell a number that is no longer
    # there, and the buyer's money is already gone. Take it off the market
    # first; that is one tap and it says what it means.
    listed = await db.get(UinListing, int(body.uin))
    if listed is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, detail={"code": "listed"})
    held = await db.get(OwnedUin, body.uin)
    if held is None or int(held.owner_uin) != me:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail={"code": "not_owned"})
    user = await db.get(User, me)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found")
    if user.is_suspended:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail={"code": "suspended"})

    # ⚠⚠ The vault row STAYS (2026-09-03, founder: "коллекция должна быть
    # коллекцией"). It used to be deleted here, on the reading that a number you
    # are answering as is not a number you are holding. That reading is what
    # made moving cost you what you had bought: with no row, the number you left
    # looked like the free one the network lends at signup, and the migration
    # put it back in the pool.
    #
    # So the row is the deed, not a parking ticket. It survives being used, it
    # is re-keyed onto the new number with everything else (`owned_uins` is in
    # PER_UIN_COLUMNS), and `release` remains the one deliberate way to give a
    # number up. `_owned_uins` filters out whichever number the account is
    # currently answering as, so a collection never lists you to yourself.
    # `source` is never written on this path: `switch=True` re-keys the deed
    # that already exists rather than making one. Named anyway, so that if this
    # ever stops moving the account the row it starts writing says where it
    # came from instead of quietly claiming somebody paid.
    return await _take(db, user, body.uin, switch=True, device_id=device_id,
                       source="activate")


class RedeemIn(BaseModel):
    uin: int = Field(gt=0)
    #: The till's signed proof that this number was paid for. Base64 of a small
    #: JSON document; see `app/services/uin_voucher.py` for its shape and for
    #: why the island learns nothing else about the payment.
    voucher: str = Field(min_length=16, max_length=4096)
    #: Move onto the number now, or leave it in the collection for later.
    switch: bool = False


@router.post("/redeem", response_model=PurchaseOut,
             dependencies=[Depends(rate_limit("uin_redeem", 20, 3600))])
async def redeem(
    body: RedeemIn,
    me: int = Depends(current_uin),
    device_id: str = Depends(current_device_id),
    db: AsyncSession = Depends(get_db),
) -> PurchaseOut:
    """Turn a paid-for voucher into a number.

    This is the ONLY door through which a scarce number leaves the shelf to a
    stranger, and the only one that may hand out a number without moving the
    account onto it. Everything about the payment happened somewhere else: the
    island checks a signature, checks the number is still free, and writes one
    row.

    ⚠ The order below is the whole safety of it. The voucher is verified, then
    the nonce is claimed by INSERT (the primary key is what makes two
    simultaneous redemptions of one voucher impossible, not a SELECT first),
    then the number is taken. A crash between them leaves a spent nonce and no
    number, which is a support question; the reverse leaves a number sold twice,
    which is not.
    """
    if not await server_settings.get_bool("uin_shop_enabled"):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "uin shop is disabled")
    target = int(body.uin)
    length = _length(target)
    if length < MIN_LEN or length > MAX_LEN:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail={"code": "invalid_length"})
    if target == me:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail={"code": "self_target"})

    user = await db.get(User, me)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found")
    if user.is_suspended:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail={"code": "suspended"})

    # ⚠⚠ A LISTED number is bought from its owner, not from the shelf, and the
    # two are verified with different documents on purpose. A voucher paid for
    # against ordinary space must never be spendable on somebody's $250
    # listing, and a resale voucher must never conjure a free number: the
    # signed field sets differ, so neither can be read as the other.
    listing = await db.get(UinListing, target)
    if listing is not None:
        return await _redeem_resale(db, user, listing, body, device_id=device_id)

    try:
        nonce = uin_voucher.verify(body.voucher, expect_uin=target)
    except uin_voucher.VoucherError as e:
        code = e.code
        status_code = (
            status.HTTP_404_NOT_FOUND if code == "sales_disabled"
            else status.HTTP_403_FORBIDDEN
        )
        raise HTTPException(status_code, detail={"code": code}) from None

    # Free? Asked AFTER the signature, so an invalid voucher never becomes a way
    # to probe which numbers exist. ⚠⚠ `ignore_holds` is not an optimisation:
    # the till holds the number for the minutes the payment takes, so without
    # it every real sale would be refused by its own reservation.
    if await uin_is_taken(db, target, ignore_holds=True):
        raise HTTPException(status.HTTP_409_CONFLICT, detail={"code": "taken"})

    db.add(SpentVoucher(nonce=nonce))
    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status.HTTP_409_CONFLICT, detail={"code": "voucher_spent"}
        ) from None

    # The hold this sale was made under, if there is one, has done its job.
    hold = await db.get(UinHold, target)
    if hold is not None:
        await db.delete(hold)

    # ⚠⚠ The deed for a PAID number is written HERE on the `switch` branch,
    # because `_take` writes one only when `switch` is false: `switch=True`
    # hands the number to `_perform_migration`, which makes it `users.uin` and
    # creates no `owned_uins` row at all. So a number bought with `switch:
    # true` left this island with NO record that it had ever been paid for.
    # The only trail was a spent nonce, and that is deliberately not linkable
    # to a number — which is a privacy property on the nonce and a hole here:
    # neither the operator nor the buyer could answer "was this number paid
    # for, and who holds it now".
    #
    # `owner_uin` is the buyer's number as it is right now; the migration below
    # re-keys it onto the new one (`OwnedUin.owner_uin` is in PER_UIN_COLUMNS,
    # services/uin_rows.py), leaving exactly what a `switch: false` purchase
    # leaves once its owner activates it: (uin=N, owner_uin=N). The collection
    # reader filters `uin != owner_uin`, so it lists nothing extra and
    # `release` cannot be pointed at the number in use.
    if body.switch:
        db.add(OwnedUin(uin=target, owner_uin=int(user.uin), source="purchase"))
        await db.flush()
    out = await _take(db, user, target, switch=bool(body.switch), device_id=device_id,
                      source="purchase")
    await db.commit()
    return out

async def _redeem_resale(
    db: AsyncSession, user: User, listing: UinListing, body: RedeemIn, *, device_id: str
) -> PurchaseOut:
    """Move a number from the person selling it to the person who paid them.

    Nothing here touches money. The buyer paid the seller's own address
    directly and the till, which watched that address, signed for it; this
    checks the signature, checks it is for THIS listing at THIS price, and
    moves one row.

    ⚠⚠ The seller and the price are checked against the listing as it stands
    NOW, not as it stood when the invoice was made. A seller who re-priced
    mid-payment, or a listing that changed hands, stops the redemption instead
    of completing a sale neither side agreed to. The buyer is not out of pocket
    silently: the till refuses to sign in the same situation, so a voucher that
    reaches here and fails is the narrow window the founder chose to accept
    (04.09) rather than hold anybody's money in escrow.
    """
    target = int(listing.uin)
    if int(listing.seller_uin) == int(user.uin):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail={"code": "own_listing"})

    try:
        nonce, seller, price_cents = uin_voucher.verify_resale(body.voucher, expect_uin=target)
    except uin_voucher.VoucherError as e:
        code = e.code
        status_code = (
            status.HTTP_404_NOT_FOUND if code == "sales_disabled"
            else status.HTTP_403_FORBIDDEN
        )
        raise HTTPException(status_code, detail={"code": code}) from None

    if seller != int(listing.seller_uin):
        raise HTTPException(status.HTTP_409_CONFLICT, detail={"code": "seller_changed"})
    if price_cents != int(listing.price_cents):
        raise HTTPException(status.HTTP_409_CONFLICT, detail={"code": "price_changed"})

    # The nonce first, by INSERT: the primary key is what makes two
    # simultaneous redemptions impossible, and a SELECT would not.
    db.add(SpentVoucher(nonce=nonce))
    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, detail={"code": "voucher_spent"}) from None

    deed = await db.get(OwnedUin, target)
    if deed is None or int(deed.owner_uin) != int(listing.seller_uin):
        # The seller no longer holds what they were selling: released, burned,
        # or already transferred. Nothing to hand over, and saying so plainly
        # is better than inventing a deed out of a voucher.
        raise HTTPException(status.HTTP_409_CONFLICT, detail={"code": "seller_gone"})

    # The transfer itself: the deed changes hands, the shop window comes down,
    # and the hold that protected the payment has done its job.
    deed.owner_uin = int(user.uin)
    deed.source = "purchase"
    await db.delete(listing)
    hold = await db.get(UinHold, target)
    if hold is not None:
        await db.delete(hold)

    if body.switch:
        out = await _take(db, user, target, switch=True, device_id=device_id, source="purchase")
        await db.commit()
        return out

    await db.commit()
    return PurchaseOut(switched=False, owned=await _owned_uins(db, int(user.uin)))


async def _take(
    db: AsyncSession, user: User, target: int, *, switch: bool, device_id: str,
    source: str,
) -> PurchaseOut:
    """Give `target` to `user`, either as their new identity or as a held
    number. Shared by /purchase and /activate so the collection bookkeeping
    cannot drift between the two."""
    owner = int(user.uin)
    if not switch:
        # ⚠⚠ Holding a number without answering as it is PAID FOR, and nothing
        # else re-opens this branch (2026-09-03). It was closed on 01-09 because
        # taking was free, and free-and-keep is what parked 161 numbers across 54
        # collections while the shelf everyone else picks from emptied. The
        # limiter that was missing is money, not a number: `/uin/redeem` is the
        # only caller that reaches here, and it reaches here holding a voucher
        # the till signed for this exact number.
        #
        # ⚠⚠ `source` is a PARAMETER and not the string "purchase", and the
        # sentence above about redeem being the only caller was WRONG when it
        # was written (03.09): `/uin/purchase` reaches this same branch for a
        # FREE ordinary number and stamped every one of those "purchase" too.
        # So the column that is supposed to mean "somebody paid for this" was
        # true of most rows that nobody paid for — which would have made the
        # operator's sales counters fiction, and made the sweep guard in
        # tools/reclaim_reserved.py protect free claims it was meant to
        # reclaim.
        held_count = await db.scalar(
            select(func.count()).select_from(OwnedUin).where(
                OwnedUin.owner_uin == owner, OwnedUin.uin != owner
            )
        )
        if (held_count or 0) >= MAX_OWNED_UINS:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                detail={"code": "collection_full", "max": MAX_OWNED_UINS},
            )
        db.add(OwnedUin(uin=target, owner_uin=owner, source=source))
        # ⚠⚠ COMMIT, not just flush. `get_db` yields a session and commits
        # NOTHING, so a route that only flushes answers 200 and saves nothing:
        # the session closes, the row rolls back, and the person is told they
        # own a number that was never written down. That is exactly what
        # happened the morning this branch reopened - the founder bought a
        # number, got 200 OK, and his collection stayed empty.
        #
        # The other two paths hid it: `switch=True` goes through
        # `_perform_migration`, which commits inside its own transaction, and
        # `/uin/redeem` commits right after calling this. Only the free take
        # into the collection had nobody to commit for it, and that branch had
        # been closed since 01.09, so reopening it exposed a gap nothing tested.
        await db.commit()
        return PurchaseOut(
            new_uin=owner,
            token=None,
            switched=False,
            owned=await _owned_uins(db, owner),
        )

    # Keeping the number they were using is `_perform_migration`'s job now, not
    # this function's. It used to be written here, one commit AFTER the swap:
    # the same two lines were missing from `/account/migrate`, which is how
    # migrating could still lose your number, and between the two commits the
    # number was in nobody's hands. Now it rides inside the migration's own
    # transaction and both callers inherit it.
    new_uin = await _perform_migration(db, user, target_uin=target)
    return PurchaseOut(
        new_uin=new_uin,
        # Keep naming this install on the new token (see carry_device_id).
        token=issue_token(new_uin, await uin_epoch(new_uin), carry_device_id(device_id)),
        switched=True,
        owned=await _owned_uins(db, new_uin),
    )


@router.post("/purchase", response_model=PurchaseOut)
async def claim(
    body: ClaimIn,
    me: int = Depends(current_uin),
    device_id: str = Depends(current_device_id),
    db: AsyncSession = Depends(get_db),
) -> PurchaseOut:
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
    if not await server_settings.get_bool("uin_shop_enabled"):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "uin shop is disabled")

    length = _length(body.uin)
    if length < MIN_LEN or length > MAX_LEN:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail={"code": "invalid_length"})
    if body.uin == me:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail={"code": "self_target"})
    # ⚠⚠ FROZEN 2026-09-01. This endpoint is what emptied the shelf: it handed
    # any free short or patterned number to whoever asked, for nothing, and
    # `switch=false` left the caller's previous number in their collection, so
    # asking repeatedly built a private hoard. Eleven numbers on one account,
    # 161 parked across 54, and 450 three-digit numbers on accounts that never
    # came back. The scarce stock now leaves only through a door somebody is
    # standing at: `POST /admin/uin/grant`, or an invite minted with the number
    # on it. Ordinary numbers still move freely — this is about the stock, not
    # about whether people may change their number.
    if is_reserved_uin(body.uin):
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail={"code": "reserved"})
    if await uin_is_taken(db, body.uin):
        raise HTTPException(status.HTTP_409_CONFLICT, detail={"code": "taken"})

    user = await db.get(User, me)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found")
    # A suspended account does not get to reroll its identity, same rule the
    # migrate route enforces.
    if user.is_suspended:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail={"code": "suspended"})
    # Cap the collection. Counted here rather than at activation, because
    # taking is what removes a number from everyone else.
    #
    # ⚠ Only for a take that does NOT move the account. With the cap at zero
    # this would otherwise refuse an ordinary migration too, and changing your
    # number was never the thing being limited: holding several was.
    if not body.switch:
        held = len(await _owned_uins(db, me))
        if held >= MAX_OWNED_UINS:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                detail={"code": "too_many_uins", "max": MAX_OWNED_UINS},
            )

    # The freed number's tokens are retired inside _perform_migration, so the
    # old bearer cannot follow the number to whoever claims it next.
    return await _take(db, user, body.uin, switch=body.switch, device_id=device_id,
                       source="claimed")


# `/quote` and `/suggestions` are pricing helpers for a shop that only the
# flagship runs, so they 404 with it (see require_shop_open). Both are also
# rate-limited: `/quote` is a registration
# oracle (it reports whether any 3-9 digit UIN is taken), so an unmetered
# version enumerates the user base of a product whose pitch is having no
# public identifiers.


class HoldRequestIn(BaseModel):
    #: A base64 JSON document signed by the till, exactly as `/uin/redeem`
    #: takes a voucher. See `app/services/uin_voucher.hold_signed_bytes`.
    request: str = Field(min_length=16, max_length=4096)


class HoldRequestOut(BaseModel):
    uin: int
    held: bool
    expires_at: datetime | None = None


@router.post("/hold", response_model=HoldRequestOut,
             dependencies=[Depends(rate_limit("uin_hold", 120, 60))])
async def till_hold(
    body: HoldRequestIn,
    db: AsyncSession = Depends(get_db),
) -> HoldRequestOut:
    """The till reserves a number while somebody pays for it, or lets it go.

    ⚠⚠ NO ACCOUNT AND NO ADMIN PASSWORD. The caller proves itself with the same
    Ed25519 key its vouchers carry, and that key can do exactly two things on
    this island: reserve a number, and say a number was paid for. Handing the
    till the admin credentials instead would have given a machine that watches
    a blockchain the ability to read the member list, and there is no version of
    that trade worth making.

    Placing a hold is also the availability check, and deliberately so: asking
    "is it free" and then reserving it are two steps a second buyer can walk
    between. Here the answer and the reservation are one row.

    ⚠ A hold request can be replayed inside its ten-minute life by anyone who
    sees one. That is bounded on purpose - the worst outcome is a number held
    (or released) that the till can release (or re-hold) again, and the till is
    the only thing that decides what a hold means. It can never grant anything.
    """
    # ⚠ Behind the shop flag, like every other paid door here. An island whose
    # operator never turned the shop on has nothing to sell, so it has no reason
    # to let anything reserve its numbers - and a reservation is the one thing a
    # holder of the till key can do that takes a number off the shelf.
    if not await server_settings.get_bool("uin_shop_enabled"):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "uin shop is disabled")

    try:
        kind, uin, hold_id, _exp = uin_voucher.verify_hold(body.request)
    except uin_voucher.VoucherError as e:
        code = e.code
        raise HTTPException(
            status.HTTP_404_NOT_FOUND if code == "sales_disabled" else status.HTTP_403_FORBIDDEN,
            detail={"code": code},
        ) from None

    existing = await db.get(UinHold, uin)
    if kind == "release":
        # Only the hold this till placed, and only under the id it placed it
        # with: releasing is idempotent, but it is not a way to lift somebody
        # else's reservation.
        if existing is not None and existing.hold_id == hold_id:
            await db.delete(existing)
            await db.commit()
        return HoldRequestOut(uin=uin, held=False)

    length = _length(uin)
    if length < MIN_LEN or length > MAX_LEN:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail={"code": "invalid_length"})
    if existing is not None and existing.hold_id == hold_id:
        # Re-placing our own hold extends it. This is what makes the till's
        # retry after a timeout harmless.
        existing.expires_at = datetime.now(timezone.utc) + timedelta(minutes=HOLD_MINUTES)
        await db.commit()
        return HoldRequestOut(uin=uin, held=True, expires_at=existing.expires_at)
    if await uin_is_taken(db, uin):
        raise HTTPException(status.HTTP_409_CONFLICT, detail={"code": "taken"})
    expires = datetime.now(timezone.utc) + timedelta(minutes=HOLD_MINUTES)
    db.add(UinHold(uin=uin, hold_id=hold_id, expires_at=expires))
    await db.commit()
    return HoldRequestOut(uin=uin, held=True, expires_at=expires)
