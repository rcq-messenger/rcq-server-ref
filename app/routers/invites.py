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

THE FREE DRIP (12.09), and how it fits the rule above without breaking it.
The people who were already here when entry went on sale on 2026-09-07 did
not pay and do not become residents, but the founder wants them to be able
to bring somebody: a smaller drip, from a second source, on the same clock.
    joined  = identity_created_at or created_at
    anchor  = max(free_invites_before, joined + free_invites_min_age_days)
    granted = min(free_invites_total, 1 + (now - anchor) // period)
It applies only to a row that has NO `resident_since`, NO `entered_via`
(NULL means the row predates that column, i.e. it is legacy by construction;
an account let in on somebody's invite is stamped "invite" and gets none),
that registered BEFORE the cutoff, and that looks like a person
(services/account_signal.py: not a row the dead-account sweep would reap,
and around for at least a day). The 2026-09-01 flood predates the cutoff
too, and passes none of the rest.

⚠⚠ THE COUNTER CARRIES OVER ON A LATER PURCHASE. `invites_minted` is one
column, whichever source the invite came from. Somebody who spent 1 of their
3 free ones and then buys residency has 5 in total and 4 left to mint, and
the paid drip anchors on the day they paid like any resident's. It is NEVER
reset, not on purchase, not on a change of number, not on revocation: a
reset is a free reroll, and every reroll is an entry credential.
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
from app.services.account_signal import looks_like_a_person

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
    #: Where the allowance comes from: "resident" (paid), "free" (was here
    #: before entry was sold), or "" for nobody-in-particular. Additive: the
    #: shipped clients ignore a field they do not know and keep drawing off
    #: `eligible`, which is exactly `kind != ""`.
    kind: str = ""
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


async def _free_quota() -> tuple[int, datetime | None, int]:
    """(total, cutoff, min_age_days) for the free drip. A cutoff that does
    not parse reads as "off": the console refuses to save one (server_settings
    .validate), so this only happens to a row edited by hand, and guessing a
    date for it would be worse than handing out nothing."""
    total = int(await server_settings.get("free_invites_total") or 0)
    try:
        cutoff = server_settings.parse_instant(str(await server_settings.get("free_invites_before") or ""))
    except ValueError:
        cutoff = None
    min_age = max(0, int(await server_settings.get("free_invites_min_age_days") or 0))
    return total, cutoff, min_age


def _utc(value: datetime) -> datetime:
    """SQLite hands timestamps back naive; Postgres, aware. One clock."""
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def _accrued(user: User, *, total: int, period_days: int, now: datetime) -> tuple[int, datetime | None]:
    """How many this resident has EARNED so far, and when the next one lands."""
    if user.resident_since is None or total <= 0:
        return 0, None
    since = _utc(user.resident_since)
    periods = (now - since) // timedelta(days=period_days)
    granted = min(total, 1 + int(periods))
    if granted >= total:
        return granted, None
    return granted, since + timedelta(days=period_days * granted)


def _joined(user: User) -> datetime | None:
    """When the PERSON joined, not when this number began: a move copies
    `identity_created_at` and deliberately not `created_at` (routers/migrate.py),
    so this is the one that does not restart on a change of number."""
    when = user.identity_created_at or user.created_at
    return _utc(when) if when is not None else None


def _free_eligible(user: User, *, total: int, cutoff: datetime | None) -> bool:
    """The part of free-drip eligibility that needs no query. The rest,
    whether the row looks like a person, is `looks_like_a_person` and is asked
    only once this says yes, so a resident or a fresh walk-in never pays for
    it.

    ⚠ `entered_via` must be NULL, not "open". NULL is the one value that
    proves the row predates the column, which is the same thing as predating
    paid entry; "open" is a walk-in from after that day, and somebody who
    arrived on a friend's invite is "invite". A cutoff alone would not do:
    an island that sets the cutoff to a moment in the future would otherwise
    be handing invites to everybody who registers between now and then."""
    if total <= 0 or cutoff is None:
        return False
    if user.resident_since is not None or user.entered_via is not None:
        return False
    joined = _joined(user)
    return joined is not None and joined < cutoff


def _accrued_free(
    user: User, *, total: int, cutoff: datetime | None, min_age_days: int,
    period_days: int, now: datetime,
) -> tuple[int, datetime | None]:
    """How many free ones a legacy account has EARNED so far, and when the
    next one lands. Mirrors `_accrued`, anchored not on a payment but on the
    later of the cutoff and the account reaching its minimum age: the drip
    starts the day entry went on sale, and a row that was a week old on that
    day still waits out the month.

    Does not check eligibility; the caller does, with `_free_eligible`."""
    if total <= 0 or cutoff is None:
        return 0, None
    joined = _joined(user)
    if joined is None:
        return 0, None
    anchor = max(cutoff, joined + timedelta(days=min_age_days))
    if now < anchor:
        return 0, anchor
    periods = (now - anchor) // timedelta(days=period_days)
    granted = min(total, 1 + int(periods))
    if granted >= total:
        return granted, None
    return granted, anchor + timedelta(days=period_days * granted)


async def _source(
    db: AsyncSession, user: User, *, now: datetime,
) -> tuple[str, int, int, datetime | None]:
    """Which allowance this account draws from: (kind, total, granted, next_at).

    A resident draws the paid allowance and nothing else, even one who would
    have qualified for the free drip before paying: `invites_minted` is one
    counter and the paid total is the larger one, so switching source on
    purchase is exactly the carry-over the module docstring promises. Kind ""
    is nobody-in-particular, with the paid total reported so the client's
    "enabled" flag keeps meaning what it always meant."""
    total, period, _ttl = await _quota()
    if user.resident_since is not None:
        granted, next_at = _accrued(user, total=total, period_days=period, now=now)
        return "resident", total, granted, next_at
    free_total, cutoff, min_age = await _free_quota()
    if _free_eligible(user, total=free_total, cutoff=cutoff) and await looks_like_a_person(db, user.uin):
        granted, next_at = _accrued_free(
            user, total=free_total, cutoff=cutoff, min_age_days=min_age,
            period_days=period, now=now,
        )
        return "free", free_total, granted, next_at
    return "", total, 0, None


async def invites_out(db: AsyncSession, user: User, *, now: datetime | None = None) -> InvitesOut:
    """The whole `GET /invites` answer for one account. Also returned by
    `POST /residency/redeem`, so a client that just paid redraws its invites
    in the same round trip instead of asking twice."""
    now = now or datetime.now(timezone.utc)
    kind, total, granted, next_at = await _source(db, user, now=now)
    used = int(user.invites_minted or 0)
    rows = (
        await db.execute(
            select(Invite).where(Invite.created_by == user.uin).order_by(Invite.created_at.desc())
        )
    ).scalars().all()
    return InvitesOut(
        enabled=total > 0,
        eligible=kind != "",
        total=total,
        granted=granted,
        used=used,
        remaining=max(0, granted - used),
        next_at=next_at,
        kind=kind,
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


@router.get("", response_model=InvitesOut)
async def my_invites(
    uin: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> InvitesOut:
    user = await db.get(User, uin)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found")
    return await invites_out(db, user)


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
    total, _period, ttl = await _quota()
    free_total, _cutoff, _min_age = await _free_quota()
    if total <= 0 and free_total <= 0:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail={"code": "not_available"})
    user = await db.get(User, uin)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found")
    # ⚠ The admin mint path has no such check because an admin is the one being
    # trusted. Here the caller is not: a suspended account handing out entry
    # credentials is a banned person letting themselves back in. Asked before
    # the source is resolved, so a banned account does not get the person
    # query run for it either.
    if user.is_suspended:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail={"code": "account_suspended"})

    now = datetime.now(timezone.utc)
    kind, src_total, granted, _next = await _source(db, user, now=now)
    # No source at all: not a resident, and not a legacy account either. The
    # code string predates the free drip and is kept as it is, because the
    # shipped clients already have copy for it and it is still the truth for
    # everybody who gets it.
    if kind == "":
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail={"code": "not_a_resident"})
    if src_total <= 0:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail={"code": "not_available"})

    # ⚠⚠ The entitlement is spent by a CONDITIONAL UPDATE, not by a read
    # followed by a write. Two requests arriving together would both read the
    # same remaining count and both mint; the `WHERE invites_minted < granted`
    # makes exactly one of them match. The Redis rate limiter above cannot
    # stand in for this: it is fail-OPEN when Redis is down, which is the
    # correct choice for a limiter and the wrong one for a quota. The same
    # statement serves both sources: `granted` is whichever drip this account
    # draws from, and the counter it is checked against is the one column.
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
            # One use, whichever drip minted it. A free invite is the same row
            # as a paid one on purpose: `/auth/register` stamps whoever
            # redeems it "invite" either way, and that stamp is what keeps the
            # newcomer out of the free drip in turn.
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
