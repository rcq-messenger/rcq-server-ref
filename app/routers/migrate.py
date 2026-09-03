"""Account migration — move ALL of a user's valuable data from their
current UIN onto another UIN (freshly allocated by default, or a
specific target supplied by an operator-side flow). Profile + contacts +
groups move atomically; libsignal material is deliberately NOT moved
(the new account starts with no signal sessions, peers re-handshake
on next message via the standard prekey flow).

After commit:
- Old UIN row is deleted, and the number itself is kept for the caller as an
  `owned_uins` row rather than falling back into the allocator pool (§10.1.3):
  the account that just left it is the only one that may take it again. Two
  exceptions, both in step 2b: a collection already past the shop's cap, and a
  number somebody else turns out to be holding. In both the number goes back
  into the pool instead, which is what this route did before it kept anything
- Old UIN's WebSocket sessions get an `account_burned` push so
  multi-device clients tear down stale state
- Every group the account belongs to gets a `group_membership_changed`, the
  same event any other roster change rides. Until 2026-08-23 the line above
  was the whole of the socket traffic, so the only people told were the ones
  who already knew: every other member's cached roster kept the OLD number and
  the per-member sealed group path silently dropped the entry addressed to it
  (step 6, and `groups.broadcast_roster_rekey` for the fan-out cost)
- The router returns the new UIN + a fresh JWT; client persists
  both, drops its old socket, and reconnects under the new identity
"""

from __future__ import annotations

import logging
import os

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import delete, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import get_db
from app.core.rate_limit import rate_limit
from app.core.security import (
    bump_uin_epoch,
    cache_uin_epoch,
    carry_device_id,
    current_device_id,
    current_uin,
    issue_token,
    uin_epoch,
)
from app.models.device_token import DeviceToken
from app.models.owned_uin import OwnedUin
from app.models.user import User
from app.services.connection_manager import manager
from app.services.uin import allocate_uin
from app.services.uin_rows import rekey_uin_rows

log = logging.getLogger(__name__)

router = APIRouter(prefix="/account", tags=["account"])

# Cooldown between two migrations on the same account. Read from the env
# so prod can dial it up to ~1 per 7 days without a redeploy. Default 0
# = no cooldown (dev / beta).
MIGRATION_COOLDOWN_SECONDS: int = int(
    os.environ.get("RCQ_MIGRATION_COOLDOWN_SECONDS", "0")
)

# Last-migration-at memo is Redis-backed so the cooldown is enforced
# consistently across uvicorn workers. Key TTL doubles as the gate.
_MIGRATION_COOLDOWN_KEY_PREFIX = "migrate:cooldown:"


class MigrateOut(BaseModel):
    new_uin: int
    token: str


async def _perform_migration(
    db: AsyncSession,
    user: User,
    target_uin: int,
) -> int:
    """Swap the caller's account onto `target_uin`. Caller already
    validated that `target_uin` is free and not the same as the
    user's own UIN. Returns the new UIN."""

    old_uin = user.uin

    # Step 1: stand up the new User row with the OLD profile + identity
    # keys copied verbatim. Reusing identity_key + signing_key keeps
    # peers' libsignal sessions valid (they cache by identity key, not
    # UIN), so chats survive the swap once the contact rows update.
    new_user = User(
        uin=target_uin,
        nickname=user.nickname,
        identity_key=user.identity_key,
        signing_key=user.signing_key,
        signal_identity_key=None,
        signal_registration_id=None,
        signed_prekey_id=None,
        signed_prekey_public=None,
        signed_prekey_signature=None,
        signed_prekey_uploaded_at=None,
        kyber_prekey_id=None,
        kyber_prekey_public=None,
        kyber_prekey_signature=None,
        kyber_prekey_uploaded_at=None,
        first_name=user.first_name,
        last_name=user.last_name,
        age=user.age,
        gender=user.gender,
        city=user.city,
        country=user.country,
        about=user.about,
        interests=user.interests,
        homepage=user.homepage,
        status_message=user.status_message,
        # The picture is part of the profile that "moves with you" — the shop
        # says so in as many words ("Contacts, groups, profile and chat history
        # come with you either way"). It was the one profile field the copy
        # forgot, so moving onto a shorter number silently left the avatar
        # behind: the blob and its key stay on the island, and the new row
        # pointed at neither. Same media id, same key — nothing is re-uploaded.
        avatar_media_id=user.avatar_media_id,
        avatar_media_key=user.avatar_media_key,
        status="offline",
        # Suspension follows the PERSON. Without this, migrating minted a
        # clean account and a ban lasted exactly as long as it took the
        # banned user to press "new number".
        is_suspended=user.is_suspended,
        last_seen_visibility=user.last_seen_visibility,
        gender_visibility=user.gender_visibility,
        profile_visibility=user.profile_visibility,
        # Item 22. Not copying it would have silently re-opened the card of
        # everybody who bought a shorter number — the same class of bug as the
        # avatar the copy above forgot, and worse, because it undoes a privacy
        # choice rather than losing a picture.
        profile_card_policy=user.profile_card_policy,
        group_invite_policy=user.group_invite_policy,
        call_policy=user.call_policy,
        read_receipts_visibility=user.read_receipts_visibility,
        push_preferences=user.push_preferences,
        # Everything below describes the PERSON, not the number they answered
        # as, so it follows them across. Dropping it was never a decision:
        #   * hof_* — their standing on the wall, including the founder's own
        #     approval. Without this a moved number quietly disappeared from
        #     the Hall of Fame and had to be approved a second time.
        # `last_seen` and `created_at` are deliberately NOT copied: they are
        # facts about this row, and created_at is when this number began.
        #
        # ⚠⚠ `identity_created_at` IS copied, and it exists for exactly this
        # line. Recovery resolves a signing key to whoever claimed it first; the
        # key travels with the person, so the claim has to travel with it. While
        # only `created_at` carried that order, every move put the person behind
        # any other row holding the same key - and on the flagship seven keys
        # are already held by more than one account, one of them by twelve. A
        # row that predates the column reads NULL and falls back to
        # `created_at`, which for a number that never moved is the same moment.
        identity_created_at=user.identity_created_at or user.created_at,
        #
        # Three fields left this list on 2026-08-22 with the columns behind
        # them: `trade_policy` (guarded a router that has not existed since the
        # pivot) and `active_days` / `last_active_day`. The claim above that
        # the Hall of Fame read the activity streak was wrong, and it was the
        # only reason anyone believed the streak had a consumer:
        # `services/hof_stats.py` scores contributors from `reports` and
        # `users.hof_bonus_*` and has never looked at it.
        #
        # Two more left on 2026-08-23: `presence_persistent` and
        # `presence_ttl_minutes`, the "stay visible after leaving" pair. There
        # is no privacy choice left to carry across, the setting is gone
        # entirely (models/user.py says why).
        hof_opt_in=user.hof_opt_in,
        hof_approved=user.hof_approved,
        hof_avatar=user.hof_avatar,
        hof_tier=user.hof_tier,
        hof_bonus_reports=user.hof_bonus_reports,
        hof_bonus_confirmed=user.hof_bonus_confirmed,
    )
    db.add(new_user)
    try:
        await db.flush()  # surface the new user before FK swaps
    except IntegrityError as exc:
        # Two callers raced onto the same target UIN (or it was registered
        # between the availability check and here). The loser used to get an
        # unhandled 500 that no client maps to anything useful.
        await db.rollback()
        raise HTTPException(
            status.HTTP_409_CONFLICT, detail={"code": "taken"}
        ) from exc

    # Step 2: re-key every owned-by-uin row. UPDATEs rather than
    # insert+delete so we don't have to worry about cascading deletes
    # wiping rows mid-flight.
    #
    # The table list lives in `app/services/uin_rows.py` because the burn path
    # (`DELETE /auth/account`) has to agree with it row for row. Both used to
    # keep private, hand-maintained lists and both had gaps: this path silently
    # stranded queued GROUP ciphertext, the queue drain cursor, moderation
    # reports and the signed federation record, none of which carry a foreign
    # key and so survived the old user row pointing at a number that had just
    # changed hands.
    await rekey_uin_rows(db, old_uin, target_uin)

    # Step 2b: the number they are leaving joins their collection instead of
    # dropping back into the allocator pool (§10.1.1 and §10.1.3 item 3: "the
    # old UIN is stamped as OwnedUin(owner=new_uin, source=migrated) so it
    # doesn't fall back into the allocator pool and so the user can swap back
    # later via a second migration").
    #
    # This lived in `uin_shop._take` and so applied to /uin/purchase and
    # /uin/activate only: "new number" in settings, the route people actually
    # press, released the number to the next registration while every client
    # says the number you leave stays yours. Doing it HERE, before the commit
    # below, also closes the window the shop had between two transactions where
    # the number belonged to nobody.
    #
    # ⚠ WHAT IT COSTS, so nobody has to rediscover it: this row IS an
    # old-identity to new-identity mapping, with a timestamp, and it survives
    # for as long as the number is held. `/uin/purchase` and `/uin/activate`
    # have always written one and there it matches what the user asked for
    # (they are collecting numbers); on THIS route it is new, and this route is
    # also the one somebody presses to stop being findable. Nothing else on the
    # island answers "which account used to be 100200300": `rekey_uin_rows`
    # rewrites rows onto the new number rather than recording the pair, and
    # `uin_epochs` only counts how many times a number changed hands. The
    # metadata map already marks `owned_uins.source` and `acquired_at` for
    # removal (docs/metadata-map-2026-08-22.md) and calls the `source` marker
    # "the alias feature creating the alias-linkage record it exists to
    # prevent". Kept anyway, because §10.1.3 item 3 says to and because a
    # migration that silently loses your number is the louder failure. The
    # escape is `DELETE /uin/mine/{uin}`, which puts the number back in the
    # pool; whether the "new number" flow should offer that in the same breath
    # is a founder question, not one to settle by quietly changing this line.
    #
    # The number this account is LEAVING. Two things can be true of it: it may
    # already have an `owned_uins` row (from the era when moving kept it), and
    # that row may belong to somebody else entirely. Both are handled below;
    # neither results in a new row any more, because collections are closed.
    stale = await db.get(OwnedUin, old_uin)
    if stale is not None and int(stale.owner_uin) != target_uin:
        # ⚠⚠ SOMEBODY ELSE holds the number this account is answering as. That
        # is a corrupt state (registration used to check only `users`, so a
        # number sitting in a collection could be handed to a stranger), and it
        # is not one this route may resolve in its own favour: re-pointing the
        # row would silently transfer the holder's number to whoever happened
        # to be occupying it, and there is no way back: the holder's
        # /uin/activate answers `not_owned` and DELETE /uin/mine/{uin} 404s, so
        # they cannot even see it any more.
        #
        # Leaving the row with its owner is also the recovery: deleting the old
        # `User` row below frees the number, and the holder's /uin/activate
        # works again, which is what this code path did by accident before it
        # touched `owned_uins` at all. The caller simply does not keep this one.
        # Skipping rather than inserting is what avoids the duplicate primary
        # key that would otherwise fail the whole migration at commit.
        #
        # No numbers on the line: naming either of them here would write the
        # old-identity/new-identity pair into the journal, which is the one
        # thing this flow exists to make unanswerable. The durable record is
        # the `owned_uins` row itself.
        log.warning(
            "[migrate] the vacated number is held by ANOTHER account, so it was "
            "not stamped; the holder's row is left alone and the number returns "
            "to the pool"
        )
    elif stale is not None:
        # Ours (the re-key above moved it), left over from when moving kept the
        # number. Collections are closed, so it is deleted rather than restamped
        # — otherwise a pre-existing row would quietly keep the number out of
        # the pool that every other line here is now putting it back into.
        await db.delete(stale)
    else:
        # ⚠⚠ The vacated number goes back into the POOL (2026-09-01).
        #
        # It used to be stamped as an `owned_uins` row for the account that had
        # just left it, on the §10.1.3 reasoning that only its previous holder
        # should be able to take it again. In practice that turned every move
        # into an acquisition: `/uin/purchase` was free during the beta, so the
        # cheapest way to collect numbers was to keep moving, and 161 of them
        # ended up parked across 54 collections while the shelf everyone else
        # picks from emptied. One identity, one number.
        #
        # What this costs, honestly: a move is no longer reversible by right.
        # Change your mind after migrating and the old number may already be
        # gone. That is the same deal every other user gets, and it is the
        # reason the number is there for them at all.
        log.info("[migrate] vacated number returned to the pool")

    # Device push tokens belong to the device, not the account. After
    # migration the iOS client re-registers under the new UIN, so we
    # drop the old DeviceToken rows here to avoid double-pushing the
    # next legitimate notification (same APNs token, two UINs).
    await db.execute(delete(DeviceToken).where(DeviceToken.uin == old_uin))

    # Step 3: old_uin goes back into circulation, so retire every token minted
    # for THIS holder — otherwise the migrating user's own saved bearer keeps
    # authenticating as whoever is handed the number next.
    old_epoch = await bump_uin_epoch(db, old_uin)

    # Step 4: drop the old User row. FK-cascading rows (prekeys, devices,
    # ) go with it; everything without an FK was re-keyed
    # above.
    await db.delete(user)
    await db.flush()
    await db.commit()
    await cache_uin_epoch(old_uin, old_epoch)

    # Step 5: only NOW tell anyone still connected under old_uin that we're
    # done — same `account_burned` event the burn flow uses. Multi-device
    # clients hit it and tear down their local state, so it must not fire
    # until the swap is durable: broadcasting before the commit meant a failed
    # commit left clients wiping state for a migration that never happened.
    await manager.broadcast([old_uin], {"type": "account_burned"})

    # Step 6: and tell the GROUPS. Until 2026-08-23 step 5 was the whole of the
    # socket traffic a migration produced, which meant the only people told
    # were the ones who already knew. Every other member of every group this
    # account is in kept a cached roster naming the OLD number, and
    # `POST /messages/group-sealed` filters the sender's payload entries
    # against the LIVE roster: the entry addressed to the number that no longer
    # exists was dropped, silently and necessarily silently (sealed sender
    # leaves the island no sender to answer), so the migrated member received
    # nothing and the sender saw only a smaller `delivered` count. It lasted
    # until each sender independently refetched the roster.
    #
    # `broadcast_roster_rekey` rides the ordinary `group_membership_changed`
    # path, so nothing new lands on any client, and it is built to be cheap for
    # somebody in many large groups; its docstring says what that cost is
    # and what was traded for it.
    #
    # AFTER the commit, like step 5 and for the same reason, and after it in
    # order too: the roster it reads has to be the one the migration left
    # behind. Imported here rather than at module scope only to keep this
    # module importable from `uin_shop`, which imports it at module scope.
    from app.routers.groups import broadcast_roster_rekey  # noqa: PLC0415

    try:
        notified = await broadcast_roster_rekey(db, target_uin)
    except Exception:  # noqa: BLE001
        # A committed migration must not become a 500 over a nudge. The client
        # already has the new number and the fallback is the refresh every
        # client does on reconnect.
        log.exception("[migrate] telling the groups failed; rosters refresh on their own")
    else:
        if notified:
            # No numbers on the line (see step 2b): the count is the whole of
            # what is useful here anyway.
            log.info("[migrate] %d group(s) told their roster moved", len(notified))

    return target_uin


# ⚠ A LIMIT, not the cooldown. `RCQ_MIGRATION_COOLDOWN_SECONDS` is the
# product decision (how often a person may change their number, dialled by the
# operator) and it defaults to 0, so until 2026-08-23 this route had no ceiling
# of any kind: `step 6` fans a `group_membership_changed` out to every group
# the account is in, and looping the route looped that fan-out as well as the
# UIN accumulation the `owned_uins` comment already describes. Five an hour is
# far above any real use of "new number" and far below anything that can hurt
# the cluster.
@router.post(
    "/migrate",
    response_model=MigrateOut,
    dependencies=[Depends(rate_limit("account_migrate", 5, 3600))],
)
async def migrate(
    uin: int = Depends(current_uin),
    device_id: str = Depends(current_device_id),
    db: AsyncSession = Depends(get_db),
) -> MigrateOut:
    user = await db.get(User, uin)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found")
    # A suspended account may not mint a fresh identity. `is_suspended` now
    # rides along in `_perform_migration` too, so this is belt-and-braces:
    # refuse outright rather than hand out a new number and rely on the flag
    # having been copied correctly.
    if user.is_suspended:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail={"code": "suspended"})

    if MIGRATION_COOLDOWN_SECONDS > 0:
        from app.core.redis import get_redis
        redis = await get_redis()
        cooldown_key = f"{_MIGRATION_COOLDOWN_KEY_PREFIX}{uin}"
        remaining = await redis.ttl(cooldown_key)
        if remaining is not None and remaining > 0:
            raise HTTPException(
                status.HTTP_429_TOO_MANY_REQUESTS,
                detail={
                    "code": "cooldown",
                    "remaining_seconds": int(remaining),
                },
            )

    new_uin = await allocate_uin(db)
    new_uin = await _perform_migration(db, user, target_uin=new_uin)

    if MIGRATION_COOLDOWN_SECONDS > 0:
        from app.core.redis import get_redis
        redis = await get_redis()
        await redis.set(
            f"{_MIGRATION_COOLDOWN_KEY_PREFIX}{uin}",
            "1",
            ex=MIGRATION_COOLDOWN_SECONDS,
        )

    # Carry the install's name onto the new token (see carry_device_id): a
    # session that loses it stops matching its own push endpoint, and the phone
    # gets woken about messages it already has.
    return MigrateOut(
        new_uin=new_uin,
        token=issue_token(new_uin, await uin_epoch(new_uin), carry_device_id(device_id)),
    )
