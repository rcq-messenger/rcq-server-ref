"""Single source of truth for "which rows belong to a UIN".

Two flows have to agree on this list and historically did not:

* `/account/migrate` (+ any operator-side vanity-UIN fulfilment) RE-KEYS
  these rows onto the new number, and
* `DELETE /auth/account` PURGES them so a recycled UIN never inherits the
  previous holder's data.

Both used to carry their own hand-written list of UPDATE/DELETE statements,
and both lists were incomplete, in different ways. Every table below keys on
a UIN as a plain `BigInteger` with **no foreign key**, so nothing happens to
these rows automatically when the old `users` row is deleted: they simply
survive, pointing at a number that now belongs to somebody else.

What that cost before this module existed (migration path):

* `offline_group_messages.to_uin` — the migrating user's queued group
  ciphertext was stranded and then delivered to the next holder of the number.
* `queue_cursors.uin` — the new holder inherited the old holder's drain
  high-water mark, so their own queued messages were skipped as "already read".
* `reports.target_uin` — a moderation record stayed on the number instead of
  following the person, i.e. migrating laundered your report history.
* `home_island_records.uin` — the seller's SIGNED federation identity record
  followed the number to its new owner.
* `user_capabilities` and the per-UIN tables of features since deleted were
  silently stranded.

Anything that DOES have `ForeignKey("users.uin", ondelete="CASCADE")`
(one-time prekeys, devices, nearby check-ins) is deliberately absent: the
database already handles those, and listing them here would double-handle
them.

★ Keeping this list TRUE against the live schema is the whole point of the
module: diffing it against `\\dt` is what found the `gossip_records` gap.
2026-08-22 removed seven entries with the features that owned them:
`group_message_views`, `stories` + `story_views`, `hood_messages`,
`hood_banners`, `referrals` (both directions) and `audio_room_mutes`. Each of
those tables is gone, so the absence is correct rather than a new hole.
`groups.pinned_by` was never in this list and is now unmapped, which closes a
real gap the erasure map missed: a burned account kept a byline on somebody
else's pinned message.
"""

from __future__ import annotations

from sqlalchemy import delete, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audio_room import AudioRoom, AudioRoomMembership
from app.models.capability import UserCapability
from app.models.contact import Contact, ContactRequest
from app.models.federation import HomeIslandRecord
from app.models.group import (
    Group,
    GroupMember,
    OfflineGroupMessage,
)
from app.models.message import OfflineMessage
from app.models.owned_uin import OwnedUin
from app.models.poll import Poll, PollVote
from app.models.queue_cursor import QueueCursor
from app.models.report import Report

# (model, uin-bearing column). Order is irrelevant — none of these carry FKs
# between each other on the UIN.
PER_UIN_COLUMNS: list[tuple[type, object]] = [
    (Contact, Contact.owner_uin),
    (Contact, Contact.contact_uin),
    (ContactRequest, ContactRequest.from_uin),
    (ContactRequest, ContactRequest.to_uin),
    (OfflineMessage, OfflineMessage.to_uin),
    (OfflineGroupMessage, OfflineGroupMessage.to_uin),
    (Group, Group.owner_uin),
    (GroupMember, GroupMember.uin),
    (AudioRoom, AudioRoom.owner_uin),
    (AudioRoomMembership, AudioRoomMembership.uin),
    (Poll, Poll.creator_uin),
    (PollVote, PollVote.voter_uin),
    (QueueCursor, QueueCursor.uin),
    (UserCapability, UserCapability.uin),
    # The vault follows its holder when they move between their own
    # numbers, and empties when the account is burned — a released
    # number goes back in the pool rather than staying reserved by a
    # person who no longer exists.
    (OwnedUin, OwnedUin.owner_uin),
    (Report, Report.reporter_uin),
    # Moderation history follows the PERSON, not the number: without this a
    # user could shed an open report simply by migrating to a new UIN.
    (Report, Report.target_uin),
]

# Rows that must NOT ride along to the new UIN — they assert something about
# the old number specifically, so carrying them over would be a lie.
#
# `home_island_records` is a self-signed "this UIN lives on these islands"
# record served by `GET /federation/island-record/{uin}`. Re-keying it would
# hand the new holder a record signed for the old identity; the client
# republishes a fresh one on next boot, so dropping it is both correct and
# self-healing.
DROP_ON_REKEY: list[tuple[type, object]] = [
    (HomeIslandRecord, HomeIslandRecord.uin),
]


async def rekey_uin_rows(db: AsyncSession, old_uin: int, new_uin: int) -> None:
    """Move every per-UIN row from `old_uin` to `new_uin`.

    Caller is responsible for having created the `new_uin` user row first
    (some of these tables are read via joins against `users`).
    """
    for model, column in PER_UIN_COLUMNS:
        await db.execute(
            update(model).where(column == old_uin).values({column.key: new_uin})
        )
    for model, column in DROP_ON_REKEY:
        await db.execute(delete(model).where(column == old_uin))


async def purge_uin_rows(db: AsyncSession, uin: int) -> None:
    """Delete every per-UIN row for `uin`, so a recycled number starts clean."""
    for model, column in PER_UIN_COLUMNS + DROP_ON_REKEY:
        await db.execute(delete(model).where(column == uin))
