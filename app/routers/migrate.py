"""Account migration — move ALL of a user's valuable data from their
current UIN onto another UIN (freshly allocated by default, or a
specific target supplied by an operator-side flow). Profile + contacts +
groups move atomically; libsignal material is deliberately NOT moved
(the new account starts with no signal sessions, peers re-handshake
on next message via the standard prekey flow).

After commit:
- Old UIN row is deleted (UIN goes back into the allocator pool —
  if reissued later, the new owner has a fresh empty account)
- Old UIN's WebSocket sessions get an `account_burned` push so
  multi-device clients tear down stale state
- The router returns the new UIN + a fresh JWT; client persists
  both, drops its old socket, and reconnects under the new identity
"""

from __future__ import annotations

import os

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import delete
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import get_db
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
from app.models.user import User
from app.services.connection_manager import manager
from app.services.uin import allocate_uin
from app.services.uin_rows import rekey_uin_rows

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
        group_invite_policy=user.group_invite_policy,
        call_policy=user.call_policy,
        read_receipts_visibility=user.read_receipts_visibility,
        push_preferences=user.push_preferences,
        # Everything below describes the PERSON, not the number they answered
        # as, so it follows them across. Dropping it was never a decision:
        #   * trade_policy — whether they accept UIN trade offers at all.
        #   * presence_* — the "stay visible for N minutes" setting. Losing it
        #     reset a privacy choice to the default without saying so.
        #   * active_days / last_active_day — the activity streak the Hall of
        #     Fame and the stats page read.
        #   * hof_* — their standing on the wall, including the founder's own
        #     approval. Without this a moved number quietly disappeared from
        #     the Hall of Fame and had to be approved a second time.
        # `last_seen` and `created_at` are deliberately NOT copied: they are
        # facts about this row, and created_at is when this number began.
        trade_policy=user.trade_policy,
        presence_persistent=user.presence_persistent,
        presence_ttl_minutes=user.presence_ttl_minutes,
        active_days=user.active_days,
        last_active_day=user.last_active_day,
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
    # nearby check-ins) go with it; everything without an FK was re-keyed
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

    return target_uin


@router.post("/migrate", response_model=MigrateOut)
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
