"""Stage 4b of the core-metadata plan: who owns the contact list.

Stage 4a (2026-08-23) gave every account a vault (SPEC 4.9) and all four
clients started mirroring their contact list into the `contacts` slot, one
way, with the island's `contacts` table still authoritative. Stage 4b is the
measurement and the plumbing for the step after it: every install says
whether it keeps its list in the vault (`vault_contacts`, SPEC 2.12), the
island records that per DEVICE, and a client that no longer wants the
`/contacts` JOIN can resolve the numbers out of its own slot through
`POST /users/lookup`.

⚠⚠ WHAT THIS MODULE DOES NOT DO, AND WHY. It does not stop writing edges.
The first cut of this file froze the pair -- `add_edges` wrote nothing once
BOTH accounts had moved -- and that is wrong in a way that is worth spelling
out, because the flag below makes it one line away again.

Freezing a pair does not "make the island's copy read-only". It makes the
pair a STRANGER to every server-side rule that stands on these rows, on the
day of the freeze, with no client-side replacement shipped anywhere. Five
rules read them and four of the five defaults route straight through the row:

  * `ws._caller_allowed`: `call_policy` is "contacts" BY DEFAULT
    (models/user.py). No row, no call. Two people who became contacts after
    the flip could not ring each other at all, and neither of them had
    touched a setting.
  * `groups._can_invite_to_group`: `group_invite_policy` is "contacts" BY
    DEFAULT. You could not add your own new contact to a room.
  * `users.lookup` / `users.info`: `last_seen_visibility` is "contacts" BY
    DEFAULT, and the picture needs `is_contact or shares`. A real mutual
    contact rendered as a permanently picture-less, never-seen row.
  * `presence.presence_watchers`: the audience IS `contacts.contact_uin`, so
    a new contact received no presence and no `contact_renamed` frame, and
    could not pick the new nickname up from a roster pull either.
  * `random._are_already_connected`: strangers-only quietly stopped holding,
    pair by pair, with nothing logged.

The plan does move all five (core-metadata-plan.md, "what the island stops
being able to enforce"), and it moves them AT THE DROP, in one change, next
to the client halves that replace them. A freeze is that drop for the pairs
it touches; it is not a softer step before it.

⚠⚠ And the client half of 4a makes it worse than a set of missing rules. The
mirror every client shipped is SERVER-WINS: `ContactsVault.fold` (iOS, and
the same `foldServerList` on web/desktop/CLI) removes from the slot every
entry the server list does not carry and writes a 90-day tombstone for it.
That is correct while the island records the edges. The moment it stops, one
sibling install still on the 4a phase -- an iPad opened once a fortnight, a
linked browser -- folds an empty answer over the pair and DELETES the
relationship out of the shared vault slot, on every device, with no error
anywhere. The island has no row, the vault has a tombstone, and re-adding
the person repeats it. So the freeze cannot precede the client work; it can
only follow it.

The plan's own migration invariant says the same thing in one line: "at no
point is a contact list only in one place". A pair created during a freeze
is in exactly one place.

WHAT THE MARK IS FOR, THEN. Readiness. It answers "how much of the island
still needs the `contacts` table", per account and per install, which is the
number the drop waits on. Measuring costs nothing and breaks nothing; it is
also what `POST /users/lookup` exists for, since a client that has moved
still has to turn the numbers in its slot into rows.
"""
from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete as sa_delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.contact import Contact, ContactVaultDevice
from app.models.queue_cursor import QueueCursor

# ⚠⚠ THE DROP SWITCH. False, and it stays False until all five rules above
# have moved to the clients AND every client ships both halves (the local
# rules and a fold that no longer treats the server list as truth). Flipping
# it alone does not "start the soak": it drops the five rules for whichever
# pairs happen to move first, silently and one pair at a time. It is here
# rather than deleted so the drop is one flag and one test run, and so the
# reason it is off is written next to it instead of in a commit message.
FREEZE_NEW_EDGES = False

# How long a `vault_contacts` mark counts for without being re-advertised.
# Clients fire `/users/me/capabilities` on every app start, so a live install
# refreshes this daily and a build that stopped advertising -- the actual
# rollback this has to survive, where the user sideloads a version that has
# never heard of the field and so can never post `false` -- ages out instead
# of counting as moved forever. Deliberately long: this measures "has this
# install moved", not "is this install awake".
VAULT_MARK_TTL_DAYS = 30


async def vault_backed(db: AsyncSession, uins: Iterable[int]) -> set[int]:
    """Which of these accounts keep their contact list in the vault.

    An account qualifies when at least one of its devices has advertised
    `vault_contacts` (SPEC 2.12) within [VAULT_MARK_TTL_DAYS] and none of its
    legacy-draining devices (its `queue_cursors` rows) is still without that
    mark. So a phone that updated first does not speak for a still-old
    desktop.

    An account with no `queue_cursors` rows at all and one marked device
    qualifies: it has never drained a legacy queue from anywhere, so there
    is no old device to protect.

    ⚠ This is a readiness measurement, not a gate on anything a user can
    feel; see the module docstring. Two of its inputs are approximations and
    both have to be re-read before the drop leans on it: a stale
    `queue_cursors` row is reaped after 7 days (SUPERSEDED_CURSOR_DAYS), so a
    rarely-opened sibling stops blocking sooner than it stops existing, and
    two UNNAMED installs of one account share one `device_id` (SPEC 2.11),
    so a fresh install marks on behalf of an old one.
    """
    uins = [u for u in set(uins) if u]
    if not uins:
        return set()
    fresh = datetime.now(timezone.utc) - timedelta(days=VAULT_MARK_TTL_DAYS)
    marked = set((await db.execute(
        select(ContactVaultDevice.uin)
        .where(ContactVaultDevice.uin.in_(uins), ContactVaultDevice.last_seen >= fresh)
        .distinct()
    )).scalars().all())
    if not marked:
        return set()
    # Devices of those accounts that still drain the legacy queue and have
    # never advertised the vault list.
    blocked = set((await db.execute(
        select(QueueCursor.uin)
        .where(
            QueueCursor.uin.in_(list(marked)),
            ~select(ContactVaultDevice.uin).where(
                ContactVaultDevice.uin == QueueCursor.uin,
                ContactVaultDevice.device_id == QueueCursor.device_id,
                ContactVaultDevice.last_seen >= fresh,
            ).exists(),
        )
        .distinct()
    )).scalars().all())
    return marked - blocked


async def mark_vault_device(db: AsyncSession, uin: int, device_id: str) -> None:
    """This install keeps its contact list in the vault."""
    now = datetime.now(timezone.utc)
    row = await db.get(ContactVaultDevice, (uin, device_id))
    if row is None:
        db.add(ContactVaultDevice(uin=uin, device_id=device_id, first_seen=now, last_seen=now))
    else:
        row.last_seen = now


async def unmark_vault_device(db: AsyncSession, uin: int, device_id: str) -> None:
    """This install has gone back to the server list (a rolled-back release).

    The way out matters more than the way in: without it a client that ships
    the vault list and then has to withdraw it would leave its account marked
    with no path back. It is not the only way out -- a build that predates
    the field cannot post `false`, which is why the mark also ages out on
    [VAULT_MARK_TTL_DAYS] -- but it is the immediate one.
    """
    await db.execute(
        sa_delete(ContactVaultDevice).where(
            ContactVaultDevice.uin == uin, ContactVaultDevice.device_id == device_id
        )
    )


async def edges_frozen(db: AsyncSession, a: int, b: int) -> bool:
    """Has this PAIR moved off the island's contact table?

    Always False while [FREEZE_NEW_EDGES] is off, which is the shipped state.
    """
    if not FREEZE_NEW_EDGES:
        return False
    if a == b:
        return False
    moved = await vault_backed(db, (a, b))
    return a in moved and b in moved


async def add_edges(db: AsyncSession, a: int, b: int) -> bool:
    """Record the mutual contact edge between `a` and `b`, both directions.

    Does not commit; the caller owns the transaction. Returns False and
    writes nothing only when the pair has moved AND the drop has been flipped
    on; see the module docstring for why that is not today.

    Existing rows are left alone rather than duplicated, which also makes the
    accept paths idempotent: two taps on Accept over a slow network used to
    race the unique constraint instead of being a no-op.
    """
    if a == b:
        return False
    if await edges_frozen(db, a, b):
        return False
    for owner, contact in ((a, b), (b, a)):
        exists = await db.scalar(
            select(Contact.id).where(
                Contact.owner_uin == owner, Contact.contact_uin == contact
            )
        )
        if exists is None:
            db.add(Contact(owner_uin=owner, contact_uin=contact))
    return True
