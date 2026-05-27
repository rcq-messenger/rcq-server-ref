"""Account migration — move ALL of a user's valuable data from their
current UIN onto another UIN (freshly allocated by default, or a
specific target supplied by /uin/purchase). Profile + contacts +
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
from sqlalchemy import delete, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import get_db
from app.core.security import current_uin, issue_token
from app.models.contact import Contact, ContactRequest
from app.models.device_token import DeviceToken
from app.models.audio_room import AudioRoom, AudioRoomMembership, AudioRoomMute
from app.models.group import Group, GroupMember
from app.models.message import OfflineMessage
from app.models.poll import Poll, PollVote
from app.models.story import Story
from app.models.user import User
from app.services.connection_manager import manager
from app.services.uin import allocate_uin

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
        is_fake=False,
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
        status="offline",
        last_seen_visibility=user.last_seen_visibility,
        gender_visibility=user.gender_visibility,
        profile_visibility=user.profile_visibility,
        group_invite_policy=user.group_invite_policy,
        call_policy=user.call_policy,
        read_receipts_visibility=user.read_receipts_visibility,
        push_preferences=user.push_preferences,
    )
    db.add(new_user)
    await db.flush()  # surface the new user before FK swaps

    # Step 2: re-key every owned-by-uin row. UPDATEs rather than
    # insert+delete so we don't have to worry about cascading deletes
    # wiping rows mid-flight.
    await db.execute(
        update(Contact).where(Contact.owner_uin == old_uin).values(owner_uin=target_uin)
    )
    await db.execute(
        update(Contact).where(Contact.contact_uin == old_uin).values(contact_uin=target_uin)
    )
    await db.execute(
        update(ContactRequest).where(ContactRequest.from_uin == old_uin).values(from_uin=target_uin)
    )
    await db.execute(
        update(ContactRequest).where(ContactRequest.to_uin == old_uin).values(to_uin=target_uin)
    )

    await db.execute(
        update(OfflineMessage).where(OfflineMessage.to_uin == old_uin).values(to_uin=target_uin)
    )

    await db.execute(
        update(Group).where(Group.owner_uin == old_uin).values(owner_uin=target_uin)
    )
    await db.execute(
        update(GroupMember).where(GroupMember.uin == old_uin).values(uin=target_uin)
    )

    await db.execute(
        update(AudioRoom).where(AudioRoom.owner_uin == old_uin).values(owner_uin=target_uin)
    )
    await db.execute(
        update(AudioRoomMembership)
        .where(AudioRoomMembership.uin == old_uin)
        .values(uin=target_uin)
    )
    await db.execute(
        update(AudioRoomMute).where(AudioRoomMute.uin == old_uin).values(uin=target_uin)
    )

    await db.execute(
        update(Poll).where(Poll.creator_uin == old_uin).values(creator_uin=target_uin)
    )
    await db.execute(
        update(PollVote).where(PollVote.voter_uin == old_uin).values(voter_uin=target_uin)
    )

    await db.execute(
        update(Story).where(Story.owner_uin == old_uin).values(owner_uin=target_uin)
    )

    # Device push tokens belong to the device, not the account. After
    # migration the iOS client re-registers under the new UIN, so we
    # drop the old DeviceToken rows here to avoid double-pushing the
    # next legitimate notification (same APNs token, two UINs).
    await db.execute(delete(DeviceToken).where(DeviceToken.uin == old_uin))

    # Step 3: tell anyone still connected under old_uin that we're
    # done — same `account_burned` event the burn flow uses. Multi-
    # device clients hit it and tear down their local state.
    await manager.broadcast([old_uin], {"type": "account_burned"})

    # Step 4: drop the old User row. Anything still referencing
    # old_uin cascades.
    await db.delete(user)
    await db.flush()
    await db.commit()

    return target_uin


@router.post("/migrate", response_model=MigrateOut)
async def migrate(
    uin: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> MigrateOut:
    user = await db.get(User, uin)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found")

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

    return MigrateOut(new_uin=new_uin, token=issue_token(new_uin))
