"""Audio Rooms — persistent Discord-style voice rooms.

Layout:
- A *room* is a row in `audio_rooms` (id, name, owner, join_key, created_at).
- A *membership* is a row in `audio_room_memberships` — existence means the
  room shows up in that user's home-screen list. Created at room creation
  for the owner; created on first successful join-by-key for joiners.
- *Active presence* (who is currently in voice) is in-memory in
  `app.routers.ws._active_audio_rooms` and surfaced through
  `audio_room_active_uins(room_id)` so the GET list can return live counts.

Endpoints:
- POST   /audio_rooms                     — create room (returns key)
- GET    /audio_rooms                     — my rooms (subscriptions + live count)
- POST   /audio_rooms/join                — accept a key → membership row
- DELETE /audio_rooms/{id}/membership     — unsubscribe (leave my list)
- DELETE /audio_rooms/{id}                — owner-only: kill the room

WebRTC media + per-room signalling live in `routers/ws.py` (`room_enter` /
`room_leave` / `room_offer` / `room_answer` / `room_ice` events).
"""

from __future__ import annotations

import secrets
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import get_db
from app.core.rate_limit import rate_limit
from app.core.security import current_uin
from app.models.audio_room import AudioRoom, AudioRoomMembership, AudioRoomMute
from app.models.user import User

router = APIRouter(prefix="/audio_rooms", tags=["audio_rooms"])

# Cap rooms an account can OWN. Total rooms a user can SUBSCRIBE to
# is uncapped — joining by key just appends a membership row, no
# resource cost beyond the row itself.
MAX_OWNED_ROOMS_PER_USER = 5
# Per session-roster cap. Mesh WebRTC scales as n*(n-1) connections
# (8 → 56), beyond which the default video/audio bitrate budget
# stops being viable in pure mesh. Hard limit is enforced server-side
# in ws.py at room_enter so clients can't sneak past it.
MAX_ROOM_PARTICIPANTS = 8

# Join-key alphabet is unambiguous-uppercase + digits (no 0/O/I/1) so
# users reading it aloud or copying from chat don't trip on lookalikes.
_JOIN_KEY_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
_JOIN_KEY_LENGTH = 8


def _generate_join_key() -> str:
    """8-char unambiguous join key. Caller is responsible for retrying on
    the off chance of a collision (probability is ~10^-12 at our scale)."""
    return "".join(secrets.choice(_JOIN_KEY_ALPHABET) for _ in range(_JOIN_KEY_LENGTH))


# ── DTOs ────────────────────────────────────────────────────────────────


class AudioRoomOut(BaseModel):
    id: int
    name: str
    owner_uin: int
    # Surfaced to every member, not just the owner — once a member knows
    # the key they can re-share it freely. Leak-resistance was never a
    # design goal; the key is an invitation, not a secret.
    join_key: str
    # Owner-only-speaking mode. When true, non-owner clients auto-mute
    # their mic on receipt of `audio_room_owner_only_changed` (or on
    # initial /audio_rooms list fetch).
    owner_only_speaking: bool = False
    created_at: datetime
    # Number of UINs currently inside the live voice session. Driven
    # by the in-memory roster in ws.py; 0 if nobody is connected.
    active_count: int = 0


class CreateRoomIn(BaseModel):
    name: str = Field(min_length=1, max_length=64)


class JoinRoomIn(BaseModel):
    join_key: str = Field(min_length=4, max_length=16)


# ── helpers ─────────────────────────────────────────────────────────────


async def _live_count(room_id: int) -> int:
    """Pull live participant count from the WS-layer roster. Lazy import
    so this module doesn't pull the WS router at import time (avoids a
    circular dependency — ws.py imports nothing from here).

    Async now — roster lives in Redis after the multi-worker refactor."""
    from app.routers.ws import audio_room_active_uins

    members = await audio_room_active_uins(room_id)
    return len(members)


async def _serialize(db: AsyncSession, room: AudioRoom) -> AudioRoomOut:
    return AudioRoomOut(
        id=room.id,
        name=room.name,
        owner_uin=room.owner_uin,
        join_key=room.join_key,
        owner_only_speaking=room.owner_only_speaking,
        created_at=room.created_at,
        active_count=await _live_count(room.id),
    )


async def muted_uins_for_room(db: AsyncSession, room_id: int) -> set[int]:
    """All UINs the owner has muted in this room. Used by the WS
    layer to bake `muted_by_owner` into roster entries on entry."""
    rows = (
        await db.execute(
            select(AudioRoomMute.uin).where(AudioRoomMute.room_id == room_id)
        )
    ).scalars().all()
    return set(rows)


# ── endpoints ───────────────────────────────────────────────────────────


@router.post(
    "",
    response_model=AudioRoomOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(rate_limit("audio_room_create", 10, 3600))],
)
async def create_room(
    body: CreateRoomIn,
    uin: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> AudioRoomOut:
    owned = (
        await db.execute(select(AudioRoom).where(AudioRoom.owner_uin == uin))
    ).scalars().all()
    if len(owned) >= MAX_OWNED_ROOMS_PER_USER:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"limit reached: max {MAX_OWNED_ROOMS_PER_USER} owned rooms",
        )

    # Retry once on key collision — second collision means something is
    # very wrong with the entropy source and a 500 is the right answer.
    for _ in range(2):
        key = _generate_join_key()
        clash = await db.scalar(select(AudioRoom).where(AudioRoom.join_key == key))
        if clash is None:
            break
    else:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "key generation failed")

    room = AudioRoom(name=body.name, owner_uin=uin, join_key=key)
    db.add(room)
    await db.flush()
    db.add(AudioRoomMembership(room_id=room.id, uin=uin))
    await db.commit()
    await db.refresh(room)
    return await _serialize(db, room)


@router.get("", response_model=list[AudioRoomOut])
async def list_rooms(
    uin: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> list[AudioRoomOut]:
    rows = (
        await db.execute(
            select(AudioRoom)
            .join(AudioRoomMembership, AudioRoomMembership.room_id == AudioRoom.id)
            .where(AudioRoomMembership.uin == uin)
            .order_by(AudioRoom.created_at.desc())
        )
    ).scalars().all()
    return [await _serialize(db, r) for r in rows]


@router.post(
    "/join",
    response_model=AudioRoomOut,
    # Brute-force protection on the 8-char join key (32^8 ≈ 1.1T
    # combinations — at 30/min one IP needs ~70 years to enumerate
    # by chance, well past any meaningful attack window).
    dependencies=[Depends(rate_limit("audio_room_join", 30, 60))],
)
async def join_by_key(
    body: JoinRoomIn,
    uin: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> AudioRoomOut:
    # Keys are case-insensitive — users reading from chat or speech may
    # not preserve case. Stored canonical form is uppercase.
    key = body.join_key.strip().upper()
    room = await db.scalar(select(AudioRoom).where(AudioRoom.join_key == key))
    if room is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such room")

    existing = await db.scalar(
        select(AudioRoomMembership).where(
            and_(
                AudioRoomMembership.room_id == room.id,
                AudioRoomMembership.uin == uin,
            )
        )
    )
    if existing is None:
        db.add(AudioRoomMembership(room_id=room.id, uin=uin))
        await db.commit()

    return await _serialize(db, room)


@router.delete("/{room_id}/membership")
async def leave_my_list(
    room_id: int,
    uin: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Unsubscribe — drop this room from my home-screen list. The room
    itself stays alive for everyone else. Owner cannot unsubscribe (they
    must use DELETE /audio_rooms/{id} to kill the whole room)."""
    membership = await db.scalar(
        select(AudioRoomMembership).where(
            and_(
                AudioRoomMembership.room_id == room_id,
                AudioRoomMembership.uin == uin,
            )
        )
    )
    if membership is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not a member")

    room = await db.get(AudioRoom, room_id)
    if room is not None and room.owner_uin == uin:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "owner cannot unsubscribe — delete the room instead",
        )

    await db.delete(membership)
    await db.commit()
    return {"deleted": True}


class KickIn(BaseModel):
    uin: int


@router.post("/{room_id}/kick", response_model=AudioRoomOut)
async def kick_member(
    room_id: int,
    body: KickIn,
    uin: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> AudioRoomOut:
    """Owner-only: remove a member from the room and from their
    home-screen list. Two-step:

      1. Drop the membership row → the room disappears from their list
         and they can no longer join voice via `room_enter`. The next
         `GET /audio_rooms` doesn't return this room for them.
      2. If they're currently in voice → kick them out of the live
         session via `audio_room_kicked` (their client tears down the
         mesh) AND fan out `room_member_left` to remaining peers so
         they drop the dead RTCPeerConnection.

    Owner cannot kick themselves (they have to delete the room
    instead). Owner cannot kick a non-member (404). Idempotent: re-
    kicking a UIN that's already gone returns 404 — better than a
    silent success that hides client bugs.
    """
    room = await db.get(AudioRoom, room_id)
    if room is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such room")
    if room.owner_uin != uin:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "owner only")
    if body.uin == uin:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "owner cannot kick themselves — delete the room instead",
        )

    membership = await db.scalar(
        select(AudioRoomMembership).where(
            and_(
                AudioRoomMembership.room_id == room_id,
                AudioRoomMembership.uin == body.uin,
            )
        )
    )
    if membership is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not a member")

    await db.delete(membership)
    await db.commit()

    # Live-session eviction. Atomic now via Redis pipeline inside
    # `evict_from_audio_room` — no external lock needed (cluster-wide
    # state lives in Redis after the multi-worker refactor).
    from app.routers.ws import evict_from_audio_room
    from app.services.connection_manager import manager

    remaining = await evict_from_audio_room(room_id, body.uin)

    # Tell the kicked user: room is gone from your list, AND if you
    # were in voice, your session is over.
    await manager.send(body.uin, {
        "type": "audio_room_membership_revoked",
        "room_id": room_id,
    })
    await manager.send(body.uin, {
        "type": "audio_room_kicked",
        "room_id": room_id,
        "reason": "kicked",
    })
    # Tell remaining live members the kicked UIN left so their mesh
    # drops the dead connection.
    if remaining:
        await manager.broadcast(list(remaining), {
            "type": "room_member_left",
            "room_id": room_id,
            "uin": body.uin,
        })

    return await _serialize(db, room)


class RotateKeyOut(BaseModel):
    """Owner-side reply for /rotate_key. Carries the freshly-minted
    `join_key` so the owner sees it without a second call. Other
    members get the new key via the `audio_room_key_rotated` WS push.
    """
    id: int
    name: str
    owner_uin: int
    join_key: str
    created_at: datetime
    active_count: int = 0


@router.post("/{room_id}/rotate_key", response_model=RotateKeyOut)
async def rotate_join_key(
    room_id: int,
    uin: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> RotateKeyOut:
    """Owner-only: mint a fresh join key. The previous key is
    overwritten in-place — anyone holding it gets a 404 from the
    next `/join` attempt. Existing memberships are NOT touched, so
    everyone currently subscribed keeps the room. The new key is
    pushed to all subscribers via WS so their cached `joinKey`
    updates without a manual refresh.

    Use case: owner kicks someone, then rotates the key so the
    kicked user can't readd via the cached invite.
    """
    room = await db.get(AudioRoom, room_id)
    if room is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such room")
    if room.owner_uin != uin:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "owner only")

    # Retry once on the (vanishingly unlikely) collision — same shape
    # as creation. Don't fail the rotate over an entropy fluke.
    for _ in range(2):
        new_key = _generate_join_key()
        clash = await db.scalar(select(AudioRoom).where(AudioRoom.join_key == new_key))
        if clash is None or clash.id == room.id:
            break
    else:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "key generation failed")

    room.join_key = new_key
    await db.commit()
    await db.refresh(room)

    # Push the new key to every subscriber so their local cached
    # AudioRoom.joinKey reflects the rotation.
    subscribers = (
        await db.execute(
            select(AudioRoomMembership.uin).where(
                AudioRoomMembership.room_id == room_id
            )
        )
    ).scalars().all()

    from app.services.connection_manager import manager

    payload = {
        "type": "audio_room_key_rotated",
        "room_id": room_id,
        "new_key": new_key,
    }
    for sub_uin in subscribers:
        await manager.send(sub_uin, payload)

    return RotateKeyOut(
        id=room.id,
        name=room.name,
        owner_uin=room.owner_uin,
        join_key=room.join_key,
        created_at=room.created_at,
        active_count=await _live_count(room.id),
    )


# ── Owner mute controls ────────────────────────────────────────────


class MuteMemberIn(BaseModel):
    uin: int
    muted: bool


class OwnerOnlyIn(BaseModel):
    enabled: bool


class RenameRoomIn(BaseModel):
    name: str = Field(min_length=1, max_length=64)


@router.post("/{room_id}/members/{uin}/mute", response_model=AudioRoomOut)
async def set_member_mute(
    room_id: int,
    uin: int,
    body: MuteMemberIn,
    caller_uin: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> AudioRoomOut:
    """Owner-only: mute / unmute a single member.

    `body.uin` mirrors the path parameter for symmetry with other
    endpoints; we use the path version. Body's `muted: bool` is
    the new state.

    Server-side this is a soft gate: writes a row to
    `audio_room_mutes` (or deletes one), then WS-broadcasts
    `audio_room_member_muted` to every member. Mesh WebRTC means
    we cannot drop the muted user's audio packets — enforcement
    runs on the muted user's CLIENT (their iOS app flips
    `setMicMuted(true)` on receipt of the event). Other members
    render a "muted by owner" badge on the user's tile.
    """
    room = await db.get(AudioRoom, room_id)
    if room is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such room")
    if room.owner_uin != caller_uin:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "owner only")
    if uin == caller_uin:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "owner cannot mute themselves — use the toolbar mic toggle",
        )

    # Toggle the mute row. Composite (room_id, uin) is the natural
    # key — query first so unmute is idempotent (no row to delete
    # → still 200, just no-op).
    existing = await db.scalar(
        select(AudioRoomMute).where(
            and_(AudioRoomMute.room_id == room_id, AudioRoomMute.uin == uin)
        )
    )
    if body.muted:
        if existing is None:
            db.add(AudioRoomMute(room_id=room_id, uin=uin))
            await db.commit()
    else:
        if existing is not None:
            await db.delete(existing)
            await db.commit()

    # Fan-out — every subscribed member gets the event so their tile
    # repaints with the badge. The muted user's client honors the
    # state by flipping its own mic mute.
    from app.services.connection_manager import manager

    subscribers = (
        await db.execute(
            select(AudioRoomMembership.uin).where(
                AudioRoomMembership.room_id == room_id
            )
        )
    ).scalars().all()
    payload = {
        "type": "audio_room_member_muted",
        "room_id": room_id,
        "uin": uin,
        "muted_by_owner": body.muted,
    }
    for sub_uin in subscribers:
        await manager.send(sub_uin, payload)

    return await _serialize(db, room)


@router.post("/{room_id}/owner_only", response_model=AudioRoomOut)
async def set_owner_only(
    room_id: int,
    body: OwnerOnlyIn,
    caller_uin: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> AudioRoomOut:
    """Owner-only: flip the room into "only the owner can speak"
    mode. Non-owner clients receive `audio_room_owner_only_changed`
    and auto-mute their mics; the owner stays unrestricted. Same
    soft-enforcement model as the per-member mute — mesh WebRTC
    can't drop packets server-side.

    Toggle endpoint: pass `enabled: true` to enable, false to
    release. Idempotent — re-posting the same state is a no-op.
    """
    room = await db.get(AudioRoom, room_id)
    if room is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such room")
    if room.owner_uin != caller_uin:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "owner only")

    if room.owner_only_speaking != body.enabled:
        room.owner_only_speaking = body.enabled
        await db.commit()
        await db.refresh(room)

    from app.services.connection_manager import manager

    subscribers = (
        await db.execute(
            select(AudioRoomMembership.uin).where(
                AudioRoomMembership.room_id == room_id
            )
        )
    ).scalars().all()
    payload = {
        "type": "audio_room_owner_only_changed",
        "room_id": room_id,
        "enabled": body.enabled,
    }
    for sub_uin in subscribers:
        await manager.send(sub_uin, payload)

    return await _serialize(db, room)


@router.patch("/{room_id}", response_model=AudioRoomOut)
async def rename_room(
    room_id: int,
    body: RenameRoomIn,
    caller_uin: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> AudioRoomOut:
    """Owner-only: rename a persistent audio room. Fans an
    `audio_room_renamed` WS event to every subscriber so home-
    screen lists + active room views update without a refetch.
    Pure metadata update — no impact on join_key, membership, or
    the live mesh roster."""
    room = await db.get(AudioRoom, room_id)
    if room is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such room")
    if room.owner_uin != caller_uin:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "owner only")

    new_name = body.name.strip()
    if not new_name:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "name required")
    if room.name == new_name:
        # No-op rename — return the current state without bumping
        # the row or fanning out a redundant event.
        return await _serialize(db, room)

    room.name = new_name
    await db.commit()
    await db.refresh(room)

    from app.services.connection_manager import manager

    subscribers = (
        await db.execute(
            select(AudioRoomMembership.uin).where(
                AudioRoomMembership.room_id == room_id
            )
        )
    ).scalars().all()
    payload = {
        "type": "audio_room_renamed",
        "room_id": room_id,
        "name": new_name,
    }
    for sub_uin in subscribers:
        await manager.send(sub_uin, payload)

    return await _serialize(db, room)


@router.delete("/{room_id}")
async def delete_room(
    room_id: int,
    uin: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    room = await db.get(AudioRoom, room_id)
    if room is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such room")
    if room.owner_uin != uin:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "owner only")

    # Snapshot subscribed UINs BEFORE the cascade delete so we can
    # fan out a deletion notice to all home-screen lists.
    subscribers = (
        await db.execute(
            select(AudioRoomMembership.uin).where(
                AudioRoomMembership.room_id == room_id
            )
        )
    ).scalars().all()

    # Snapshot anyone currently in the live session so we can boot
    # their clients out of the room view + tear down their mesh.
    # Roster lives in Redis now; both helpers are async.
    from app.routers.ws import (
        audio_room_active_uins,
        purge_audio_room,
    )

    active_uins = list(await audio_room_active_uins(room_id))

    await db.delete(room)
    await db.commit()

    # Wipe the cluster-wide roster — clients will see room_member_left
    # for every peer below, then room_deleted, and tear down cleanly.
    await purge_audio_room(room_id)

    from app.services.connection_manager import manager

    payload = {"type": "audio_room_deleted", "room_id": room_id}
    for sub_uin in set(list(subscribers) + active_uins):
        await manager.send(sub_uin, payload)

    # Tell whoever is currently in the room their session ended too,
    # via the same event the live `room_leave` flow emits — keeps
    # client-side teardown logic unified.
    for active_uin in active_uins:
        await manager.send(active_uin, {
            "type": "audio_room_kicked",
            "room_id": room_id,
            "reason": "deleted",
        })

    return {"deleted": True}


# ── helper for ws.py ─────────────────────────────────────────────────────


async def is_room_member(db: AsyncSession, room_id: int, uin: int) -> bool:
    """Membership check used by ws.py before letting a UIN into the live
    voice session of a given room. Joining the voice requires the user
    to already be subscribed (i.e. they used the join key at least once).
    """
    membership = await db.scalar(
        select(AudioRoomMembership).where(
            and_(
                AudioRoomMembership.room_id == room_id,
                AudioRoomMembership.uin == uin,
            )
        )
    )
    return membership is not None


async def lookup_user_nickname(db: AsyncSession, uin: int) -> str | None:
    user = await db.get(User, uin)
    return user.nickname if user else None
