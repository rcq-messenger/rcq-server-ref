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
(one-time prekeys, devices) is deliberately absent: the
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

2026-08-22 (stage 1b) added `invites.created_by`, the last per-UIN column the
map found missing. See the entry for what it does and does not cover.

★★ Note for whoever reads this next: a table being SWEPT does not make it safe
to drop from this list. A sweep runs on a horizon measured in months; a burn is
supposed to be immediate. `polls` and `poll_votes` both gained a sweep in the
same release as this note and both stay here for exactly that reason.

★ Diffed against the flagship's live schema on 2026-08-22 (stage 1 review).
Twenty-seven columns on the island name a person; this list carries eighteen of
them and the other nine are accounted for, so the next reader can start from the
delta rather than the whole set:

* CASCADE off `users.uin`, so the database handles them and listing them here
  would double-handle: `device_tokens.uin`, `devices.uin`,
  `one_time_prekeys.uin`. (`/auth/account` deletes
  `device_tokens` explicitly as well, because push must stop before the row
  does.)
* `report_messages.author_uin` has NO FK to `users`, but it rides
  `report_id -> reports.id ON DELETE CASCADE` and its only writer
  (`reports.add_message`) requires the caller to BE the report's reporter, so
  every row it names is reachable through the two `Report` entries below.
  ⚠ On a MIGRATION the column is therefore left pointing at the old number
  while the report itself is re-keyed. That is cosmetic today: `author_uin` is
  served to the admin console only, and the reporter/operator split the clients
  render is the `from_admin` flag beside it.
* `uin_epochs.uin` must OUTLIVE the user row (see the model) and is the one
  deliberate exception on the island.
* `invites.uin` and `owned_uins.uin` are numbers being held or promised, not
  rows belonging to the burning account; see the notes at their entries.
* `gossip_records` has no uin column at all. It is keyed by the global signing
  key, which is why `purge_uin_rows` structurally cannot reach it, and it is the
  one item in section 2 of the metadata map still open.
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
from app.models.invite import Invite
from app.models.mailbox_seq import MailboxSeq
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
    # The durable per-mailbox seq counter (stage 2b). It follows the account on
    # a migration — the rekeyed offline_messages rows keep their old seqs, so a
    # fresh counter at the new number would allocate seq 1 and collide with them
    # (503 on the first post) — and it is deleted on a burn so a recycled number
    # starts its mailbox clean.
    (MailboxSeq, MailboxSeq.to_uin),
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
    # An operator's outstanding invites belong to the operator. On a migration
    # they follow them to the new number; on a burn they go, because a code
    # that still admits strangers to the island, minted by an account that no
    # longer exists, is an entry credential with nobody behind it.
    #
    # ⚠ Currently always NULL: neither `POST /admin/invites` (Basic-auth, no
    # session uin) nor `app.tools.mint_invite` writes it, so this matches
    # nothing today. Listed anyway, because the whole job of this module is to
    # be TRUE against the schema rather than against current behaviour: the
    # day something starts stamping the minter, the burn path already covers it.
    #
    # ⚠ `Invite.uin` is deliberately NOT here. That column is a RESERVED vanity
    # number promised to whoever redeems the code, not a row belonging to the
    # burning account. Re-keying it would move somebody else's promise, and
    # deleting it on burn would cancel a reservation the operator made.
    (Invite, Invite.created_by),
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
