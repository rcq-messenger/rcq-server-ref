import re
import secrets
from datetime import datetime, timezone

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.invite import Invite
from app.models.owned_uin import OwnedUin
from app.models.uin_sale import UinHold
from app.models.user import User


def invite_is_live():
    """The clauses that make an invite still able to admit somebody.

    Written once here because three places have to agree on it exactly:
    `uin_is_taken` below, `POST /admin/uin/grant` and `POST /admin/invites`.
    When they disagree, the number is promised twice and nobody is told.

    Both clauses are what stops a DEAD invite locking a number forever, which
    is the other half of this fix and the easier half to get wrong:

      * `used_count < max_uses`: a spent invite reserves nothing. The number
        it promised has already been handed over, so the redeemer is in `users`
        and answers the first question below on their own; the row that is left
        is bookkeeping until `services/credential_sweep` takes it.
      * unexpired: an invite that timed out unredeemed reserves nothing
        either. Without this clause a `ttl_hours=1` code nobody used would keep
        a vanity number out of circulation for the ninety days it takes the
        sweep to delete the row.

    `expires_at IS NULL` means never expires, which is the default and the
    common case, so it has to pass.
    """
    return (
        Invite.used_count < Invite.max_uses,
        or_(Invite.expires_at.is_(None), Invite.expires_at > datetime.now(timezone.utc)),
    )


async def uin_is_taken(
    db: AsyncSession, uin: int, *, except_invite: str | None = None
) -> bool:
    """Is this number spoken for? Three tables answer, and all three have to.

    `users` is the obvious one. `owned_uins` is the one every caller but the
    shop used to forget: a HELD number has no `users` row at all (that is what
    holding one means, see models/owned_uin.py), so a check that only reads
    `users` reports somebody's collection as free space. The spec says the
    allocator rejects both (§2.1, "rejecting any that collide with an existing
    account or with a UIN reserved by the UIN shop").

    What that missing half cost: an ordinary registration, a `desired_uin`, a
    reserved invite or the random allocator could hand out a number that was
    already in somebody's collection. The holder is then left with a row
    pointing at a stranger's account (the number every client promised nobody
    else could take), and `/uin/activate` on it can never work again, because
    migrating onto a UIN that exists is a 409.

    `invites` is the third, added 2026-08-23, and its absence was the last
    hole: a live unspent invite RESERVES its number for whoever holds the code
    (`POST /admin/invites`, `app.tools.mint_invite`), and that number has
    neither a `users` row nor an `owned_uins` row until the code is redeemed.
    The two operator paths already asked this question of each other, so the
    operator could not promise the same number twice by hand, but the RANDOM
    allocator could still walk onto it, and so could a `desired_uin`, and both
    do so at a moment nobody is watching. What that produces is the silent
    failure the whole three-way check exists to prevent: `auth.register` spends
    the invite use in its atomic UPDATE BEFORE it tests availability, so the
    person holding the code gets an unrelated random number, their single-use
    invite is burnt, and no error is raised anywhere. The operator finds out
    when the person asks why they are not #777777.

    ⚠ A dead invite must NOT hold a number down. `invite_is_live()` above is
    the whole of that rule: spent and expired invites are ignored here, so a
    code that was redeemed or timed out releases its number immediately rather
    than at the mercy of the ninety-day credential sweep.

    `except_invite` is the invite being redeemed RIGHT NOW, by `code` (the
    sha256-hex, i.e. the primary key, not the raw token). `auth.register` has
    to pass it: it consumes one use before it asks this question, so on a
    multi-use reserved invite the row is still live at that point and would
    report its own redeemer's number as taken, and the registration would then
    fall through to a random number and the vanity code would do nothing. Every
    other caller is handing a number to somebody who has no claim on it, so
    "reserved by anyone at all" is the right answer for all of them.

    Deliberately NOT parameterised by "unless the caller holds it": the one
    flow that must accept a held number is `/uin/activate`, which looks the row
    up by primary key, checks the owner itself, and never asks this question.
    """
    if await db.scalar(select(User.uin).where(User.uin == uin)) is not None:
        return True
    if await db.scalar(select(OwnedUin.uin).where(OwnedUin.uin == uin)) is not None:
        return True
    # ⚠ A LIVE HOLD is the fourth, and it exists for the minutes a payment takes
    # (2026-09-03). While somebody is paying for a number, nothing else may hand
    # it out: with the money watched outside this island there is no automatic
    # refund, so "sold to two people" is a failure with no clean ending. An
    # EXPIRED hold holds nothing, for the same reason a dead invite does not.
    live_hold = select(UinHold.uin).where(
        UinHold.uin == uin,
        UinHold.expires_at > datetime.now(timezone.utc),
    )
    if await db.scalar(live_hold) is not None:
        return True
    reserving = select(Invite.code).where(Invite.uin == uin, *invite_is_live())
    if except_invite:
        reserving = reserving.where(Invite.code != except_invite)
    return await db.scalar(reserving) is not None


#: Numbers short enough to be worth something on their own. Six digits and
#: below: 999 three-digit numbers exist in the whole world and never more.
RESERVED_MAX_LEN = 6

#: The shapes people actually ask for. Kept deliberately small and readable
#: rather than clever: every extra rule here takes numbers out of circulation
#: for ordinary users, and a number nobody would pay for is a number somebody
#: should just be given.
_PATTERNS = (
    re.compile(r"^(\d)\1+$"),          # 4444, 777777777
    re.compile(r"^(\d\d)\1+$"),        # 1212, 505050
    re.compile(r"^(\d\d\d)\1+$"),      # 123123, 800800800
    re.compile(r"^0*123456789?$"),     # the ladder up
    re.compile(r"^9?876543210*$"),     # and down
    re.compile(r"\d0{4,}$"),           # 120000000
)


def is_reserved_uin(uin: int) -> bool:
    """Is this number part of the scarce stock rather than ordinary space?

    Scarce means one of two things: SHORT (six digits or fewer — there are 999
    three-digit numbers in existence and there will never be more) or a
    PATTERN a person would recognise across a room.

    Why this exists at all. Until 2026-09-01 an island handed these out three
    ways, all of them blind: the random allocator could mint one, `desired_uin`
    on an unauthenticated registration could ask for any free number and get
    it, and `POST /uin/purchase` let a logged-in account claim any free 3-9
    digit number for nothing and keep its old one in a collection. The result
    measured on the flagship that morning: 563 of the 999 three-digit numbers
    taken, 113 of those by accounts active in the last month; 161 more parked
    in 54 collections, eleven of them on one account. The entire scarce stock
    was being consumed by whoever asked first, before it was ever offered to
    anyone.

    Reserving is NOT the same as never giving one out. It means the number
    leaves through a door somebody is standing at — `POST /admin/uin/grant`,
    an invite minted with a reserved number, or a settled purchase when there
    is one — instead of falling out of the allocator.
    """
    if uin <= 0:
        return False
    s = str(uin)
    if len(s) <= RESERVED_MAX_LEN:
        return True
    return any(p.search(s) for p in _PATTERNS)


async def allocate_uin(db: AsyncSession) -> int:
    """Allocate a free UIN in the legacy ICQ range. ICQ used 6–9 digit numbers — we
    follow the same shape so the feel is right.

    "Free" is the three-table question above, invites included. The extra read
    is one indexless scan of a table that holds join codes and is small on
    every island by construction; the loop almost always ends on its first
    candidate, because the range is ~10^9 wide and no island has a millionth
    of it.

    ⚠ Reserved numbers are skipped, not merely deprioritised. `UIN_MIN` is
    100_000, so every six-digit number was inside the mint window, and the
    ladders and repdigits above sit inside it at every length. The retry loop
    already exists for collisions and absorbs this at no cost: reserved numbers
    are a vanishing fraction of a 10^9-wide range.
    """
    for _ in range(100):
        candidate = secrets.randbelow(settings.UIN_MAX - settings.UIN_MIN) + settings.UIN_MIN
        if is_reserved_uin(candidate):
            continue
        if await uin_is_taken(db, candidate):
            continue
        return candidate
    raise RuntimeError("UIN allocation exhausted")
