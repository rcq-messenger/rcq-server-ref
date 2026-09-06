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

  POINT      "give me the key for number N", one number, named by the caller.
             A resident may. This is messaging a colleague.
  DISCOVERY  a search result, a lookup of arbitrary numbers, a directory page.
             Nobody may, ever, on a closed island. Bulk IS the attack. These
             keep their nicknames and avatars and lose the three key fields.

⚠⚠ AND THE DISTINCTION IS NOT "point versus list", which is where the first
draft of this file was wrong and would have taken the island down. `GET
/contacts` is a list. A group roster is a list. Both CARRY the relationship
rather than search for one: your contacts are people you already added, a
roster is a room you are already in. Strip those and every existing
conversation stops sending at once, and group messaging does not degrade but
stops dead, because `POST /messages/group-sealed` wants one ciphertext per
member and a roster without keys cannot produce them. The line is between a
list that ANSWERS a relationship and a list that SEARCHES for one.

A stranger holds neither, and gets in with a GUEST CARD instead: 32 bytes the
resident generated and handed out themselves (models/guest_card.py). That is
the only path from outside, and it is the resident's to revoke.
"""
from __future__ import annotations

from datetime import date, datetime, timezone

from fastapi import Request
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.guest_card import GuestCard, hash_card
from app.models.user import User


#: The header a caller presents a guest card in.
#:
#: ⚠ A HEADER, not a query parameter, and this is not a style choice. A card is
#: a live credential: in a query string it lands in the island's access log, in
#: Caddy's, in any middlebox between them, and in a Referer. That is exactly
#: how session tokens leaked into journald until 22.08 — 816 distinct tokens
#: over 449 accounts, 815 of them still valid — and a card has no expiry at all.
GUEST_CARD_HEADER = "X-RCQ-Guest-Card"


def card_from(request: Request) -> str | None:
    """The card a caller presented, if any. Never logged, never echoed."""
    raw = request.headers.get(GUEST_CARD_HEADER)
    if not raw:
        return None
    raw = raw.strip()
    # A card is `secrets.token_urlsafe(32)`, so ~43 characters. Anything wildly
    # longer is not a card and must not become a database lookup.
    return raw if 0 < len(raw) <= 128 else None


async def island_is_closed() -> bool:
    """Whether this island withholds keys from strangers.

    Read live from server settings rather than the environment, so an operator
    who closes the island in the console does not have to restart it, and so a
    mistake is one click from being undone.
    """
    from app.services import server_settings

    return bool(await server_settings.get("closed_island"))


def strip_keys_from_discovery(closed: bool) -> bool:
    """True when a DISCOVERY response must not carry identity/signing keys.

    Discovery is `/users/search` and a lookup of numbers the caller merely
    named: lists that hand back people the caller has no relationship with.
    Deliberately not a per-caller decision, because the one thing discovery
    adds over a point lookup is doing it in bulk, and bulk is the attack.

    ⚠ NOT for `/contacts`, group rosters, or a roulette pairing. Those answer a
    relationship instead of searching for one, and stripping them stops every
    conversation on the island at once. See the module docstring.

    ⚠ Stripping is not refusing. `/users/search` is the ONLY way to add a
    same-island contact in the web (pages/AddContact.tsx) and the only thing
    behind `rcq find`, and the rows there render a nickname, a badge and a
    number and never touch the key. Refuse the rows and a closed island can
    never gain a contact; strip the keys and nobody notices.
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


#: ⚠⚠ DOORS 2, 3 AND 7 ARE DELIBERATELY NOT GATED, and this is a finding rather
#: than an omission. `/keys/{uin}/bundle`, `/keys/{uin}/devices/{id}/bundle` and
#: `/keys/{uin}/devices` have no refusal code left to use:
#:
#:   * 404 already means something else there. `routers/keys.py:418` returns it
#:     for "multi-device: v=1 only", and its own comment says senders treat a
#:     404 as the signal to fall back. A byte-identical 404 would not refuse
#:     anybody, it would quietly downgrade their cryptography.
#:   * 403 is worse than useless: all three clients answer it by RETRYING THE
#:     SAME REQUEST WITH THE SESSION TOKEN (RcqApi.kt:419+431,
#:     SignalSession.swift:379, signal-device.ts:1008). A closed island
#:     refusing an anonymous fetch therefore gets the request back
#:     authenticated, `may_fetch_key` sees a resident, and lets it through. The
#:     gate removes itself, and on the way it drags every bundle fetch back
#:     onto the authenticated path, re-linking sender to recipient and undoing
#:     the point of anonymous key fetches.
#:
#: They also protect nothing on their own: a v=1 envelope is sealed with the
#: key from door 6, so gating 2/3/7 while 6 is open buys forward secrecy for an
#: attacker and nothing for the island. The gate belongs on door 6 (same
#: island) and door 1 (another island), and doors 2/3/7 answer exactly what
#: door 6 would have answered for the same target.
#:
#: ⚠⚠ AS OF TODAY ONLY DOOR 6 IS ACTUALLY GATED. Door 1,
#: `/federation/keys/{uin}`, still hands the identity key to any browser with
#: no account at all, so a closed island is closed from the inside and open
#: from the outside. This comment claimed both were done and it was wrong.
#:
#: It is left open ON PURPOSE until the clients ship, and the order cannot be
#: reversed: gating door 1 first would cut every cross-island conversation on
#: every island, because no released client presents a card there yet. Clients
#: first, then this.


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
