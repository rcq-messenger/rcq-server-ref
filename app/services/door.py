"""Who may be handed the key that seals an envelope to somebody.

On an OPEN island the answer is "anybody", and that is not an oversight: it is
what makes a number enough to reach a person, which is the thing RCQ is for.
This module exists for the other kind of island.

⚠⚠ THE TENSION THIS FILE RESOLVES, because getting it wrong breaks one of two
things and the wrong answer is invisible in a smoke test:

  * A closed island that lets any resident fetch any key is a paid island where
    one purchased membership buys the keys of every member. Buy in, walk the
    numbers, walk out, write to all of them forever. Sealed sender means
    nobody can even tell it happened.
  * A closed island that lets NO resident fetch a key by number breaks the
    ordinary reason companies want one: writing to a colleague whose number is
    on their badge, who is not yet in your contacts.

The resolution is not a middle setting, it is a distinction between two shapes
of request:

  POINT   "give me the key for number N", one number, named by the caller.
          A resident may. This is messaging a colleague.
  LIST    a search result, a lookup of many, a directory page.
          Nobody may, ever, on a closed island. A list is a harvest, and the
          harvest is the attack. Lists keep their nicknames and avatars and
          lose the three key fields.

A stranger holds neither, and gets in with a GUEST CARD instead: 32 bytes the
resident generated and handed out themselves (models/guest_card.py). That is
the only path from outside, and it is the resident's to revoke.
"""
from __future__ import annotations

from datetime import date, datetime, timezone

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.guest_card import GuestCard, hash_card
from app.models.user import User


async def island_is_closed() -> bool:
    """Whether this island withholds keys from strangers.

    Read live from server settings rather than the environment, so an operator
    who closes the island in the console does not have to restart it, and so a
    mistake is one click from being undone.
    """
    from app.services import server_settings

    return bool(await server_settings.get("closed_island"))


def strip_keys_from_lists(closed: bool) -> bool:
    """True when a LIST response must not carry identity/signing keys.

    Deliberately not a per-caller decision. On a closed island a list is never
    a legitimate way to obtain a sealing key, for anybody, including a resident
    in good standing: the one and only thing a list adds over a point lookup is
    doing it in bulk, and bulk is the whole of the attack.
    """
    return closed


async def _is_resident(db: AsyncSession, uin: int | None) -> bool:
    if uin is None:
        return False
    return await db.scalar(select(User.uin).where(User.uin == uin)) is not None


async def redeem_card(db: AsyncSession, *, target_uin: int, raw: str | None) -> bool:
    """Does `raw` open `target_uin`'s door? Stamps the day if it does.

    ⚠ Looked up by HASH and scoped to the target in the same query. A card is
    useless against anybody but its owner, so a leaked card costs its owner
    their quiet and costs no one else anything — which is only true if the
    lookup cannot match a row belonging to somebody else.
    """
    if not raw:
        return False
    row = await db.scalar(
        select(GuestCard).where(
            GuestCard.card_hash == hash_card(raw),
            GuestCard.owner_uin == target_uin,
            GuestCard.revoked.is_(False),
        )
    )
    if row is None:
        return False
    # A DAY, not a timestamp: enough for the owner to see a card is still in
    # use, not enough to be an activity feed. Written only when it changes, so
    # the common case costs no write at all.
    today = datetime.now(timezone.utc).date()
    if row.last_used_on != today:
        await db.execute(
            update(GuestCard).where(GuestCard.id == row.id).values(last_used_on=today)
        )
    return True


async def may_fetch_key(
    db: AsyncSession,
    *,
    target_uin: int,
    caller_uin: int | None,
    card: str | None,
    closed: bool | None = None,
) -> bool:
    """The POINT-lookup rule. See the module docstring for why LIST differs.

    Order matters only for cost: the cheap in-memory checks run before the two
    that touch the database.
    """
    if closed is None:
        closed = await island_is_closed()
    # An open island is unchanged, and that is most islands.
    if not closed:
        return True
    # Yourself, always: a client re-reads its own card on every boot.
    if caller_uin is not None and caller_uin == target_uin:
        return True
    # A resident asking about one named number. This is the colleague case, and
    # it is why the LIST rule above has to be absolute: with lists stripped,
    # this path costs an attacker one request per number they can already name,
    # against an island where the numbers are not enumerable.
    if await _is_resident(db, caller_uin):
        return True
    # A stranger with the resident's own card. The only door from outside.
    return await redeem_card(db, target_uin=target_uin, raw=card)
