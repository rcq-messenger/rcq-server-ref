"""Invites a RESIDENT hands out, as opposed to the ones an operator mints.

The `invites` table is shared with `/admin/invites` and the shape of a row is
the same; what differs is who may make one and how many. An operator is trusted
and has no quota. A resident paid to be here, may bring a few people, and the
count is the whole feature.

⚠⚠ ONLY SOMEBODY WHO PAID HAS ANY. `resident_since` is set by exactly one path,
redeeming an entry voucher at registration, so an account that was already here
when the island started charging has none, and neither does one that walked in
on somebody else's invite. That is the founder's decision and the arithmetic is
brutal without it: the flagship already holds 2626 accounts that stay free for
ever, and five invites each would put 13,130 free entries into the world on the
first day, which is more than the paid plan expects to sell in years.

⚠ A DRIP, NOT A HANDFUL. One now and one more each period, up to the total.
Five at once is a bulk credential: the registration flood of 2026-09-01 opened
552 accounts in three minutes, and against a dripped allowance the same attack
costs six times as much to mount.

The accrual is COMPUTED ON READ. No cron, no accrual table, no per-user timer:
    granted   = min(total, 1 + (now - resident_since) // period)
    remaining = granted - users.invites_minted
It is idempotent, it is cheap, and it produces exactly what a nightly job
would. A resident who does not open the app for a year comes back to their
whole allowance waiting, capped, which is the right answer and not a bug.
"""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import get_db
from app.core.rate_limit import rate_limit
from app.core.security import current_uin
from app.models.invite import Invite, hash_invite_code
from app.models.user import User
from app.services import server_settings

router = APIRouter(prefix="/invites", tags=["invites"])


class InviteRow(BaseModel):
    #: sha256-hex, the primary key. The RAW code is returned once, by the mint
    #: call, and is not recoverable — same rule as an operator's invite.
    id: str
    label: str | None = None
    used: bool
    created_at: datetime
    expires_at: datetime | None = None


class InvitesOut(BaseModel):
    #: False when the island has the feature switched off entirely.
    enabled: bool
    #: False for everybody who did not pay. The client draws nothing at all
    #: rather than an empty counter that invites a question we do not want to
    #: answer on a screen ("why do I have none").
    eligible: bool
    total: int
    granted: int
    used: int
    remaining: int
    #: When the next one accrues, or null when they already hold the lot.
    next_at: datetime | None = None
    invites: list[InviteRow] = []


class MintedInvite(BaseModel):
    #: ⚠ Shown ONCE. The island keeps the hash.
    code: str
    link: str
    expires_at: datetime | None = None


async def _quota() -> tuple[int, int, int]:
    total = int(await server_settings.get("resident_invites_total") or 0)
    period = max(1, int(await server_settings.get("resident_invites_period_days") or 30))
    ttl = max(1, int(await server_settings.get("resident_invites_ttl_days") or 30))
    return total, period, ttl


def _accrued(user: User, *, total: int, period_days: int, now: datetime) -> tuple[int, datetime | None]:
    """How many this resident has EARNED so far, and when the next one lands."""
    if user.resident_since is None or total <= 0:
        return 0, None
    since = user.resident_since
    if since.tzinfo is None:
        since = since.replace(tzinfo=timezone.utc)
    periods = (now - since) // timedelta(days=period_days)
    granted = min(total, 1 + int(periods))
    if granted >= total:
        return granted, None
    return granted, since + timedelta(days=period_days * granted)


@router.get("", response_model=InvitesOut)
async def my_invites(
    uin: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> InvitesOut:
    total, period, _ttl = await _quota()
    user = await db.get(User, uin)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found")
    now = datetime.now(timezone.utc)
    granted, next_at = _accrued(user, total=total, period_days=period, now=now)
    used = int(user.invites_minted or 0)
    rows = (
        await db.execute(
            select(Invite).where(Invite.created_by == uin).order_by(Invite.created_at.desc())
        )
    ).scalars().all()
    return InvitesOut(
        enabled=total > 0,
        eligible=user.resident_since is not None,
        total=total,
        granted=granted,
        used=used,
        remaining=max(0, granted - used),
        next_at=next_at,
        invites=[
            InviteRow(
                id=r.code,
                label=r.label,
                used=r.used_count >= r.max_uses,
                created_at=r.created_at,
                expires_at=r.expires_at,
            )
            for r in rows
        ],
    )


@router.post(
    "",
    response_model=MintedInvite,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(rate_limit("invite_mint", 5, 3600))],
)
async def mint(
    request: Request,
    uin: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> MintedInvite:
    total, period, ttl = await _quota()
    if total <= 0:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail={"code": "not_available"})
    user = await db.get(User, uin)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found")
    if user.resident_since is None:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail={"code": "not_a_resident"})
    # ⚠ The admin mint path has no such check because an admin is the one being
    # trusted. Here the caller is not: a suspended account handing out entry
    # credentials is a banned person letting themselves back in.
    if user.is_suspended:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail={"code": "account_suspended"})

    now = datetime.now(timezone.utc)
    granted, _next = _accrued(user, total=total, period_days=period, now=now)

    # ⚠⚠ The entitlement is spent by a CONDITIONAL UPDATE, not by a read
    # followed by a write. Two requests arriving together would both read the
    # same remaining count and both mint; the `WHERE invites_minted < granted`
    # makes exactly one of them match. The Redis rate limiter above cannot
    # stand in for this: it is fail-OPEN when Redis is down, which is the
    # correct choice for a limiter and the wrong one for a quota.
    spent = await db.execute(
        update(User)
        .where(User.uin == uin, User.invites_minted < granted)
        .values(invites_minted=User.invites_minted + 1)
    )
    if spent.rowcount == 0:
        raise HTTPException(status.HTTP_409_CONFLICT, detail={"code": "no_invites_left"})

    raw = secrets.token_urlsafe(18)
    expires = now + timedelta(days=ttl)
    db.add(
        Invite(
            code=hash_invite_code(raw),
            label=None,
            max_uses=1,
            used_count=0,
            # ⚠ NEVER a reserved number. That field is how an operator hands
            # out a chosen UIN from scarce stock, and a resident minting an
            # invite must not be able to reach into it.
            uin=None,
            created_by=uin,
            expires_at=expires,
        )
    )
    await db.commit()
    host = request.headers.get("x-forwarded-host") or (request.url.hostname or "")
    return MintedInvite(code=raw, link=f"rcq://server/{host}?invite={raw}", expires_at=expires)


@router.delete("/{invite_id}", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
async def revoke(
    invite_id: str,
    uin: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Withdraw one of MINE.

    ⚠ Does not refund the credit. Refunding turns "five in total" into an
    unlimited reroll: mint, look at the code, revoke, mint again. The invite
    stops working, the allowance stays spent.
    """
    row = await db.get(Invite, invite_id)
    if row is None or row.created_by != uin:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such invite")
    await db.delete(row)
    await db.commit()
