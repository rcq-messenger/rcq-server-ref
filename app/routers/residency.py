"""Buying residency on an account that ALREADY EXISTS.

Until 12.09 there was exactly one way to become a resident: redeem an entry
voucher at registration (routers/auth.py). That left out everybody the paid
plan actually wants the money from, the people who are already here and use
the thing daily. They could buy a voucher at the till, and then the only way
to spend it was to register a second account and abandon the first, with its
contacts, its rooms and its number. So this endpoint takes the same voucher,
signed by the same till for the same island, and applies it to the account
that is asking.

What it changes on the row, and nothing else:
  * `resident_since` is stamped with now, which is what the paid invite drip
    accrues from (routers/invites.py);
  * the "resident" mark is added to what the account HOLDS, and worn only if
    nothing else is worn (models/user.grant_badge), so a tester who pays
    keeps showing the tester mark until they choose otherwise;
  * `entered_via` is left alone: how they got in is history, and paying a
    year later does not rewrite it;
  * `invites_minted` is left alone: the counter carries over, see the invites
    module docstring for the arithmetic and why a reset is a free reroll.

⚠⚠ THE ORDER OF THE CHECKS IS THE FEATURE. "Already a resident" is answered
BEFORE the voucher is touched. A client that double-taps, or retries a
request whose response was lost, sends the same paid code twice; if the
second arrival spent the nonce first and only then noticed the account was
already a resident, the person would have paid twice for one thing and the
island would hold no record of it. Same reasoning as `uin_shop`: the nonce is
claimed by INSERT, the primary key is what makes two simultaneous redemptions
impossible, and every refusal that can be decided without the voucher is
decided first.
"""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import get_db
from app.core.rate_limit import rate_limit
from app.core.security import current_uin
from app.models.uin_sale import SpentVoucher
from app.models.user import User, earned_badges, grant_badge
from app.routers.invites import InvitesOut, invites_out
from app.routers.users import _announce_rename
from app.services import server_settings, uin_voucher

router = APIRouter(prefix="/residency", tags=["residency"])


class RedeemIn(BaseModel):
    #: The entry voucher exactly as the till handed it out. Bounds are the
    #: same shape `verify_entry` can possibly accept: a base64 JSON document
    #: with a 16..128 character nonce and a signature inside it.
    voucher: str = Field(min_length=16, max_length=4096)


class RedeemOut(BaseModel):
    resident_since: datetime
    #: What the account now WEARS. Unchanged if it was wearing something.
    badge: str | None = None
    #: What it now HOLDS, "resident" included.
    badges_earned: list[str] = []
    #: The invites answer as of this moment, so the client redraws in one
    #: round trip rather than following up with GET /invites.
    invites: InvitesOut


@router.post(
    "/redeem",
    response_model=RedeemOut,
    # ⚠ Fail-closed, like every route that turns a string into an entitlement.
    # Ten an hour is generous for a person with one voucher and a stiff price
    # for a script guessing at nonces; the 2026-09-01 flood is why a route
    # like this does not get the fail-soft default.
    dependencies=[Depends(rate_limit("residency_redeem", 10, 3600, fail_closed=True))],
)
async def redeem(
    body: RedeemIn,
    uin: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> RedeemOut:
    user = await db.get(User, uin)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found")
    # A banned account buying its way back to the invite drip is a banned
    # person letting other people in. Same refusal the shop gives.
    if user.is_suspended:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail={"code": "suspended"})
    # ⚠⚠ BEFORE the voucher is looked at, let alone spent. See the module
    # docstring: a double tap must not burn a paid code.
    if user.resident_since is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, detail={"code": "already_resident"})

    # The host comes from the island's own settings, never from a header, for
    # the reason `verify_entry` spells out. Error codes map exactly as
    # registration maps them: `sales_disabled` (no till key, or an island that
    # has not been told its own name) is a 404 because there is nothing here
    # to sell; everything else is a refusal of THIS voucher.
    try:
        nonce = uin_voucher.verify_entry(
            body.voucher, expect_host=str(await server_settings.get("island_host") or "")
        )
    except uin_voucher.VoucherError as e:
        status_code = (
            status.HTTP_404_NOT_FOUND if e.code == "sales_disabled"
            else status.HTTP_403_FORBIDDEN
        )
        raise HTTPException(status_code, detail={"code": e.code}) from None

    # Signed by the till. Now the second question, which the signature cannot
    # answer: has it been redeemed already. One row, nonce as the primary key,
    # exactly as registration and the number shop do it.
    db.add(SpentVoucher(nonce=nonce))
    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, detail={"code": "voucher_spent"}) from None

    now = datetime.now(timezone.utc)
    user.resident_since = now
    # Added to what they hold; worn only if nothing is. `entered_via` and
    # `invites_minted` are deliberately not touched, see the module docstring.
    grant_badge(user, "resident")
    await db.commit()

    # Everyone holding this person as a contact repaints the mark at once,
    # the way an operator's grant does (routers/admin.py), and with the same
    # respect for the owner's choice: paying must not be the thing that shows
    # a mark they keep off.
    await _announce_rename(db, uin, user.nickname, badge=None if user.badge_hidden else user.badge)

    return RedeemOut(
        resident_since=now,
        badge=user.badge,
        badges_earned=earned_badges(user),
        invites=await invites_out(db, user, now=now),
    )
