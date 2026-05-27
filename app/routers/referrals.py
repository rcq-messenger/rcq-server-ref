"""Referral system.

The referral code is the inviter's UIN. A new account may pass
`inviter_uin` once, at signup; that creates a pending `Referral`
and auto-adds the inviter as the newcomer's first contact (so they
never land in an empty messenger).

A referral activates once the invitee is online on 3 distinct
calendar days. Sealed-sender hides per-message counts, so
distinct-active-days is the retention signal we can both observe
and not have trivially faked. Activation is currently a tracking
counter only — pre-pivot there was a jeton bounty here, now removed.
"""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import get_db
from app.core.security import current_uin
from app.models.contact import Contact
from app.models.referral import Referral
from app.models.user import User

router = APIRouter(prefix="/referrals", tags=["referrals"])

ACTIVATION_DAYS: int = 3


async def record_referral(db: AsyncSession, inviter_uin: int, invitee_uin: int) -> bool:
    """Create a pending referral and bidirectionally connect the pair.

    Caller (the /auth/register handler) owns the commit. Returns False
    and writes nothing if the inviter is invalid — a bad code must
    never block registration.
    """
    if inviter_uin == invitee_uin:
        return False
    inviter = await db.scalar(
        select(User).where(
            User.uin == inviter_uin,
            User.is_fake.is_(False),
            User.is_suspended.is_(False),
        )
    )
    if inviter is None:
        return False

    db.add(Referral(inviter_uin=inviter_uin, invitee_uin=invitee_uin))
    for owner, contact in ((invitee_uin, inviter_uin), (inviter_uin, invitee_uin)):
        exists = await db.scalar(
            select(Contact.id).where(
                Contact.owner_uin == owner, Contact.contact_uin == contact
            )
        )
        if exists is None:
            db.add(Contact(owner_uin=owner, contact_uin=contact))
    return True


async def note_active_day(db: AsyncSession, user: User) -> None:
    """Bump the distinct-active-day counter at most once per UTC day,
    and mark a pending referral activated the moment it crosses the bar.

    Called from the WS connect handler, inside its session — the
    caller owns the commit.
    """
    today = datetime.now(timezone.utc).date().isoformat()
    if user.last_active_day == today:
        return
    user.last_active_day = today
    user.active_days = (user.active_days or 0) + 1
    if user.active_days < ACTIVATION_DAYS:
        return

    ref = await db.scalar(
        select(Referral).where(
            Referral.invitee_uin == user.uin,
            Referral.activated_at.is_(None),
        )
    )
    if ref is None:
        return
    ref.activated_at = datetime.now(timezone.utc)


class ReferralStatusOut(BaseModel):
    code: int
    invited_count: int
    activated_count: int
    pending_count: int
    activation_days: int


@router.get("/me", response_model=ReferralStatusOut)
async def my_referrals(
    uin: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> ReferralStatusOut:
    rows = (
        await db.execute(select(Referral).where(Referral.inviter_uin == uin))
    ).scalars().all()
    invited = len(rows)
    activated = sum(1 for r in rows if r.activated_at is not None)
    return ReferralStatusOut(
        code=uin,
        invited_count=invited,
        activated_count=activated,
        pending_count=invited - activated,
        activation_days=ACTIVATION_DAYS,
    )
