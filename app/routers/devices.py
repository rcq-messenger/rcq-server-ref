"""Linked web devices — the connect-to-web sessions for an account.

A web link gets its OWN session token (a JWT with a `dev` claim) so it can be
revoked independently of the phone. While an account has >=1 linked device it
is "multi-device": `GET /keys/{uin}/bundle` withholds the v=2 bundle so senders
fall back to v=1 (the Double Ratchet can't be shared across devices, so v=2 to
a multi-homed identity silently desyncs on whichever device didn't decrypt
first). Removing the last device auto-restores v=2 (the hash disappears).

Redis-backed — these are ephemeral session state, not durable account data:
  devices:{uin}      hash  device_id -> JSON{label, created_at}
  dev_revoked:{uin}  set   revoked device_ids (the JWT denylist current_uin checks)
"""

from __future__ import annotations

import json
import secrets
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import get_db
from app.core.redis import get_redis
from app.core.security import current_device_id, current_uin, issue_device_token
from app.models.queue_cursor import QueueCursor

router = APIRouter(prefix="/devices", tags=["devices"])

_MAX_DEVICES = 5
# A linked web session lives ~90 days; the device token's exp matches.
DEVICE_TTL_SECONDS = 90 * 24 * 3600


def _devices_key(uin: int) -> str:
    return f"devices:{uin}"


def _revoked_key(uin: int) -> str:
    return f"dev_revoked:{uin}"


async def has_linked_devices(uin: int) -> bool:
    """True if the account has >=1 linked web session (→ serve v=1, not v=2)."""
    redis = await get_redis()
    return bool(await redis.exists(_devices_key(uin)))


class LinkIn(BaseModel):
    label: str = Field(default="Web", max_length=64)


class LinkOut(BaseModel):
    device_id: str
    token: str


@router.post("/link", response_model=LinkOut)
async def link_device(body: LinkIn, uin: int = Depends(current_uin)) -> LinkOut:
    """Register a new web session for the caller and mint its own session token
    (a `dev`-claim JWT). The phone calls this in its connect-to-web flow and
    puts the returned token (NOT its own) in the LinkBlob, so the web session is
    independently revocable."""
    redis = await get_redis()
    if await redis.hlen(_devices_key(uin)) >= _MAX_DEVICES:
        raise HTTPException(status.HTTP_409_CONFLICT, detail={"code": "too_many_devices"})
    device_id = secrets.token_hex(8)
    entry = json.dumps({
        "label": body.label,
        "created_at": datetime.now(timezone.utc).isoformat(),
    })
    await redis.hset(_devices_key(uin), device_id, entry)
    await redis.expire(_devices_key(uin), DEVICE_TTL_SECONDS)
    return LinkOut(device_id=device_id, token=issue_device_token(uin, device_id))


class DeviceOut(BaseModel):
    device_id: str
    label: str
    created_at: str


@router.get("", response_model=list[DeviceOut])
async def list_devices(uin: int = Depends(current_uin)) -> list[DeviceOut]:
    redis = await get_redis()
    raw = await redis.hgetall(_devices_key(uin))
    out: list[DeviceOut] = []
    for did, entry in raw.items():
        did = did.decode() if isinstance(did, bytes) else did
        entry = entry.decode() if isinstance(entry, bytes) else entry
        try:
            d = json.loads(entry)
        except (ValueError, TypeError):
            d = {}
        out.append(DeviceOut(
            device_id=did,
            label=d.get("label", "Web"),
            created_at=d.get("created_at", ""),
        ))
    return out


@router.delete("/me")
async def revoke_own_device(
    uin: int = Depends(current_uin),
    device_id: str = Depends(current_device_id),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Let a linked session disconnect ITSELF.

    Until now only the phone could take a device out of the registry, so
    signing out of the desktop or the web cleared local state and left the
    entry standing: the phone went on listing a device that no longer exists,
    and its token stayed valid. Reported 2026-08-04 — "на компе вышел из
    профиля и удалил, а в телефоне всё равно показывает, что десктоп
    подключён".

    Declared ABOVE `/{device_id}`: FastAPI matches routes in declaration order,
    and the parameterised one would otherwise swallow "me".

    ⚠ Revokes ONLY a device that is actually in this account's registry. A
    phone's token also carries a `dev` claim — the per-install id — and acting
    on that would denylist the phone's own token and sign it out. The registry
    hash holds linked sessions and nothing else, so membership in it is the
    exact test for "is this a linked session revoking itself". Anything else is
    a no-op rather than an error: sign-out must never fail on bookkeeping.
    """
    redis = await get_redis()
    if not device_id or not await redis.hexists(_devices_key(uin), device_id):
        return {"ok": True}
    return await _revoke(uin, device_id, db)


@router.delete("/{device_id}")
async def revoke_device(
    device_id: str,
    uin: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Disconnect a web session: drop it from the registry AND denylist its
    token. When the last device is removed the hash disappears, so the account
    is single-device again and `GET /keys/{uin}/bundle` resumes serving v=2.
    Returns 200 {ok:true} (any 2xx satisfies the clients)."""
    return await _revoke(uin, device_id, db)


async def _revoke(uin: int, device_id: str, db: AsyncSession) -> dict:
    redis = await get_redis()
    await redis.hdel(_devices_key(uin), device_id)
    await redis.sadd(_revoked_key(uin), device_id)
    await redis.expire(_revoked_key(uin), DEVICE_TTL_SECONDS)
    # Drop this device's offline-queue cursor so it no longer holds back the
    # min-cursor cleanup of the user's queue (a removed device shouldn't pin rows
    # for the others). Best-effort.
    await db.execute(
        delete(QueueCursor).where(QueueCursor.uin == uin, QueueCursor.device_id == device_id)
    )
    await db.commit()
    return {"ok": True}
