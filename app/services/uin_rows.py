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

2026-08-23 removed `polls` and `poll_votes` with the polls feature. ⚠ Unlike
the seven above, their TABLES are still there: that release drops the models
and leaves the physical tables for a manual DROP (the reasoning is in
`core/db.py`, in the block that logs the remaining row counts on every boot).
They are therefore absent from the list below and always will be, because the
models they would name no longer exist. The BURN still reaches them: see the
raw-SQL tail of `purge_uin_rows`, which deletes by table and column name from
whichever of the two this island turns out to have. Do not re-add entries here,
and do not remove that tail before the DROP has run everywhere: an erasure
promise that waits for an operator to get round to something is not one.
The re-key path deliberately does NOT follow: a migration leaves
`polls.creator_uin` / `poll_votes.voter_uin` naming the number the account
left, which is dead metadata on a dead feature rather than something the new
number needs to inherit, and the burn is what has to be true.

★★ Note for whoever reads this next: a table being SWEPT does not make it safe
to drop from this list. A sweep runs on a horizon measured in months; a burn is
supposed to be immediate. Every table below that also has a retention sweep is
listed here as well, and that is deliberate rather than duplication.

★ Diffed against the flagship's live schema on 2026-08-22 (stage 1 review),
when twenty-seven columns on the island named a person, eighteen of them in
this list. Stages 2b, 5 and 4a have since added `mailbox_seq.to_uin`,
`group_log.to_uin`, `group_log_cursors.uin`, `group_log_readers.uin` and
`vault_slots.uin` to the list. ★ The authoritative check is section 2 of
`test_dead_weight_local.py`, which walks the live metadata and fails on any
uin-bearing column that is neither listed here, cascaded, nor allowlisted
with a reason; the nine that are accounted for elsewhere:

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

from sqlalchemy import delete, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import LEGACY_POLL_TABLES

from app.models.audio_room import AudioRoom, AudioRoomMembership
from app.models.capability import UserCapability
from app.models.contact import Contact, ContactRequest, ContactVaultDevice
from app.models.federation import HomeIslandRecord
from app.models.group_log import GroupLog, GroupLogCursor, GroupLogReader
from app.models.group import (
    Group,
    GroupMember,
    OfflineGroupMessage,
)
from app.models.invite import Invite
from app.models.mailbox_seq import MailboxSeq
from app.models.message import OfflineMessage
from app.models.owned_uin import OwnedUin
from app.models.queue_cursor import QueueCursor
from app.models.report import Report
from app.models.vault import VaultSlot

# (model, uin-bearing column). Order is irrelevant — none of these carry FKs
# between each other on the UIN.
PER_UIN_COLUMNS: list[tuple[type, object]] = [
    (Contact, Contact.owner_uin),
    (Contact, Contact.contact_uin),
    (ContactRequest, ContactRequest.from_uin),
    (ContactRequest, ContactRequest.to_uin),
    # Stage 4b: the per-install "my contact list lives in the vault" switch.
    # It follows the person on a migration (else the island resumes writing
    # `contacts` rows for the new number, which is the exact thing the flip
    # stopped) and goes on a burn like every other per-device mark.
    (ContactVaultDevice, ContactVaultDevice.uin),
    (OfflineMessage, OfflineMessage.to_uin),
    (OfflineGroupMessage, OfflineGroupMessage.to_uin),
    # Stage 5: the rows of the room log sealed to this account, and its
    # cursors into every room. Broadcast rows name nobody and stay.
    (GroupLog, GroupLog.to_uin),
    (GroupLogCursor, GroupLogCursor.uin),
    # The per-device "reads the log" switch. It follows the person on a
    # migration (else the writers resume the legacy per-member rows for the
    # new number until the first fetch) and goes on a burn. Missed by stage 5
    # and found by test_dead_weight_local on 2026-08-23.
    (GroupLogReader, GroupLogReader.uin),
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
    (QueueCursor, QueueCursor.uin),
    (UserCapability, UserCapability.uin),
    # Stage 4a: the sealed slots. They follow the person on a migration (the
    # key is derived from the identity, not the number) and go on a burn.
    (VaultSlot, VaultSlot.uin),
    # The held-number collection (`owned_uins`, "the UIN vault" in
    # uin_shop.py; not the sealed-blob vault above) follows its holder when
    # they move between their own numbers, and empties when the account is
    # burned — a released number goes back in the pool rather than staying
    # reserved by a person who no longer exists.
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
    # The polls leftovers, by raw SQL because there is no model to point at any
    # more. This is the ONE place in the codebase that still touches them, and
    # it is here rather than deferred to the manual DROP because a burn is a
    # promise that runs today: `poll_votes` holds (poll_id, voter_uin,
    # option_index, created_at) for every ballot ever cast on this island, the
    # ones marked anonymous included, and `polls.creator_uin` sits beside
    # `polls.message_id` and so names the author of one encrypted group
    # envelope. Neither has a foreign key to `users`, so nothing else reaches
    # them; without this a burned account stays named in both until an operator
    # gets round to the DROP.
    #
    # ⚠ `LEGACY_POLL_TABLES` is populated at BOOT (core/db.init_db) and is empty
    # unless the table is really there. Do not turn this into a try/except
    # around the statement: on Postgres a failed statement poisons the whole
    # transaction, and the transaction this runs in is an account deletion.
    #
    # ⚠ The column names are not user input, they are the two literals in
    # `_LEGACY_POLL_TABLES`; the uin is bound.
    for table, column in LEGACY_POLL_TABLES.items():
        await db.execute(
            text(f"DELETE FROM {table} WHERE {column} = :uin"), {"uin": uin}
        )
