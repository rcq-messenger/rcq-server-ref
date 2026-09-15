"""Deleting an account row and everything keyed on its number, in one place.

Spec 2026-09-15, section 8.4. Until the guest sweeps existed there was one
caller, `DELETE /auth/account` (a person burning their own account), and the
sequence lived inline there. Guest copies added three more callers that must
delete a row EXACTLY the same way: the guest sweep, the operator's "Delete
guest copy", and `tools/guest_rows_hold.py`. Three hand copies of a burn is how
the five orphan `group_members` rows of 2026-09-06 happened, so the sequence was
moved here and the burn route calls it too.

What a purge does, in order, all in the caller's session and ONE commit:

  * optionally tells the account's own sockets `account_burned` (a burn does;
    a sweep does not, see `announce_burn`);
  * deletes every room the account OWNS, telling their members
    `group_deleted` with `reason`. A guest never owns a room (8.1), so for the
    guest callers this is always empty;
  * removes the account from every room it is a member of, and returns those
    room ids so a caller can tell the rooms their roster changed;
  * `purge_uin_rows`, `purge_gossip_mirror` and the push tokens;
  * bumps the number's token epoch, so a saved bearer dies with the row and
    does not authenticate as whoever gets the number next;
  * deletes the row and commits.

After the commit: the epoch cache, and `unmark_guest` for a guest row. The
membership broadcast is NOT done here, because the burn route never did it (a
burned account's rooms pick the change up on their next roster read) and the
sweep wants to send it only once the commit is certain.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import guest_policy
from app.core.security import bump_uin_epoch, cache_uin_epoch
from app.models.device_token import DeviceToken
from app.models.group import Group, GroupMember
from app.models.user import User
from app.services.connection_manager import manager
from app.services.uin_rows import purge_gossip_mirror, purge_uin_rows

log = logging.getLogger(__name__)


@dataclass
class PurgeResult:
    #: Rooms the account was a plain member of. They still exist, minus it.
    member_rooms: list[int] = field(default_factory=list)
    #: Rooms the account owned. They are gone.
    owned_rooms: list[int] = field(default_factory=list)
    #: Whether the row was a guest copy or an unclaimed seat.
    was_guest: bool = False


async def purge_account(
    db: AsyncSession,
    uin: int,
    reason: str,
    *,
    announce_burn: bool = True,
) -> PurgeResult | None:
    """Delete account `uin` and every row keyed on its number, and COMMIT.

    Returns None when there is no such row (nothing is written).

    `reason` rides on the `group_deleted` frame sent for each owned room
    ("owner_burned" for a burn) and on the log line.

    `announce_burn=False` for deletions the person did not ask for (the guest
    sweep, the operator, the rollback hold). ⚠ `account_burned` tells every
    connected client of this number to wipe its local identity and go back to
    the login screen. That is right when the person pressed "burn" on another
    device. It is wrong for a guest copy removed for being idle: a client that
    had the copy open as its account would throw away an identity whose home
    is still alive. The epoch bump already ends every session either way.

    ⚠ A caller that decided to delete on the strength of a condition (idle,
    unclaimed) must re-check that condition in THIS session with the row
    locked before calling, or a guest who settled a moment ago is deleted as
    a resident. `guest_sweep` does.
    """
    user = await db.get(User, uin)
    if user is None:
        return None
    result = PurgeResult(was_guest=user.guest_status is not None)

    # Fan-out happens BEFORE the row delete so the socket auth (token still
    # valid) does not trip the disconnect path inside the burn itself. Without
    # it a second device keeps using a stale token until its next launch; the
    # founder hit exactly that after burning from web with iOS open.
    if announce_burn:
        await manager.broadcast([uin], {"type": "account_burned"})

    # Owned rooms are deleted entirely (burn = total nuke, founder decision).
    # Their members are told before the delete, while the membership rows
    # still exist to enumerate.
    result.owned_rooms = list(
        (await db.execute(select(Group.id).where(Group.owner_uin == uin))).scalars().all()
    )
    for gid in result.owned_rooms:
        member_uins = (
            await db.execute(
                select(GroupMember.uin)
                .where(GroupMember.group_id == gid)
                .where(GroupMember.uin != uin)
            )
        ).scalars().all()
        for muin in member_uins:
            await manager.send(muin, {"type": "group_deleted", "group_id": gid, "reason": reason})

    result.member_rooms = [
        gid
        for gid in (
            await db.execute(select(GroupMember.group_id).where(GroupMember.uin == uin))
        ).scalars().all()
        if gid not in result.owned_rooms
    ]

    # CASCADE on GroupMember.group_id removes the owned rooms' membership rows.
    # (`polls.group_id` used to be named here too. Polls were removed on
    # 2026-08-23; the orphaned table still carries its physical FK on Postgres,
    # so it keeps cascading, but nothing in the app depends on that.)
    if result.owned_rooms:
        await db.execute(delete(Group).where(Group.id.in_(result.owned_rooms)))
    await db.execute(delete(GroupMember).where(GroupMember.uin == uin))

    # Every other per-UIN row, so a RECYCLED number never inherits this
    # account's data. The list lives in `app/services/uin_rows.py`, shared with
    # the migration path so the two cannot drift again.
    await purge_uin_rows(db, uin)
    # ⚠ The one row `purge_uin_rows` structurally cannot reach, and it needs
    # the KEY rather than the number. `gossip_records` is this island's mirror
    # of some identity's signed home-island record, keyed by the Ed25519 `sk`;
    # for a deleted account it kept serving "this identity lives at these
    # islands under these numbers" for ever. Read from the row before it goes.
    await purge_gossip_mirror(db, user.signing_key)
    await db.execute(delete(DeviceToken).where(DeviceToken.uin == uin))

    # The number goes back into circulation, so retire every token minted for
    # THIS holder (see app/models/uin_epoch.py).
    new_epoch = await bump_uin_epoch(db, uin)

    await db.delete(user)
    await db.commit()
    await cache_uin_epoch(uin, new_epoch)
    # AFTER the commit, best effort: a stale mark only restricts a number
    # nobody holds any more (app/core/guest_policy.py).
    if result.was_guest:
        await guest_policy.unmark_guest(uin)
    log.info("[account-delete] uin purged (%s)", reason)
    return result


async def announce_rooms_after_purge(db: AsyncSession, room_ids: list[int]) -> None:
    """Tell each room that a member is gone. For callers that purge somebody
    who did not ask for it (the guest sweep, the operator), so the other
    members' rosters and sender-key recipients drop the row now rather than on
    their next refresh. Best effort per room: the purge is already committed.
    """
    from app.routers.groups import (  # local: groups imports a great deal
        _broadcast_membership,
        _members_with_users,
        _serialize,
    )

    for gid in room_ids:
        try:
            g = await db.get(Group, gid)
            if g is None:
                continue
            members = await _members_with_users(db, gid)
            await _broadcast_membership(gid, members, _serialize(g, members))
        except Exception:  # noqa: BLE001
            log.warning("[account-delete] roster broadcast failed for a room", exc_info=True)
