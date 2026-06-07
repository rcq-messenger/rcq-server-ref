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

from app.core.redis import get_redis
from app.core.security import current_uin, issue_device_token

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


@router.delete("/{device_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_device(device_id: str, uin: int = Depends(current_uin)) -> None:
    """Disconnect a web session: drop it from the registry AND denylist its
    token. When the last device is removed the hash disappears, so the account
    is single-device again and `GET /keys/{uin}/bundle` resumes serving v=2."""
    redis = await get_redis()
    await redis.hdel(_devices_key(uin), device_id)
    await redis.sadd(_revoked_key(uin), device_id)
    await redis.expire(_revoked_key(uin), DEVICE_TTL_SECONDS)
