"""Which local account a signing key resolves to, written once.

Two endpoints answer the question "who on THIS island holds key X", and they
must give the same answer:

* `POST /auth/recover` mints a session for the account the key resolves to;
* `GET /federation/uin-for-key` tells a group owner which account to ADD when
  a member from another island joins a room here (§5c), so the owner does not
  register a duplicate copy for keys that already have one.

⚠⚠ They drifted, and the drift put people outside their own rooms. Recover
ordered by first claim, uin-for-key ordered by uin alone. When a key had two
rows on one island (seven keys on the flagship do, one of them twelve), an owner
could add the lower-numbered row to the group while the member later recovered
into the older one, and that account was not a member of anything. No single
client could see it happen: each endpoint looked correct on its own.

So both call `uin_for_signing_key` below, and the order lives nowhere else.
"""
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import User


def first_claim_order():
    """ORDER BY clauses for "whoever claimed this key first".

    ⚠ COALESCE, and it is the whole repair of the 2026-08 recovery bug.
    `created_at` is a fact about the NUMBER - a migration deliberately does not
    copy it - so ordering by it alone sent a person to the back of the queue
    for their own key every time they moved, and handed their recovery to any
    older row carrying the same key. `identity_created_at` follows the PERSON
    across a move; rows written before the column existed have NULL and fall
    back to `created_at`, which for a row that never moved is the same instant.

    `uin` is only the tie-break for two rows claimed in the same instant, so
    the answer is deterministic. It must never be the primary key of the sort:
    `desired_uin` has no floor, and ordering by number let anyone who learned a
    public key register a copy with a LOWER number and inherit the owner's
    recovery (see the comment at the call site in routers/auth.py).
    """
    first_claim = func.coalesce(User.identity_created_at, User.created_at)
    return (first_claim.asc(), User.uin.asc())


async def uin_for_signing_key(db: AsyncSession, signing_key: str) -> int | None:
    """The uin `/auth/recover` lands on for `signing_key`, or None.

    Callers strip the key first; this compares it verbatim, as both endpoints
    always have.
    """
    return (
        await db.execute(
            select(User.uin)
            .where(User.signing_key == signing_key)
            .order_by(*first_claim_order())
            .limit(1)
        )
    ).scalar_one_or_none()
