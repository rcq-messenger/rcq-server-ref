"""Linked web devices — the connect-to-web sessions for an account.

A web link gets its OWN session token (a JWT with a `dev` claim) so it can be
revoked independently of the phone. While an account has >=1 linked device it
is "multi-device": `GET /keys/{uin}/bundle` withholds the v=2 bundle so senders
fall back to v=1 (the Double Ratchet can't be shared across devices, so v=2 to
a multi-homed identity silently desyncs on whichever device didn't decrypt
first). Removing the last device auto-restores v=2 (the hash disappears).

Redis-backed. These are session state rather than account rows, though on a
90-day TTL they are durable enough that losing them is a real incident (see
`core/redis_keys.migrate_legacy_account_keys`):
  dev:{bucket}    hash  device_id -> JSON{label, created_at}
  devrv:{bucket}  set   revoked device_ids (the denylist `device_is_revoked`
                        answers from, consulted both when a token is
                        PRESENTED and when one is MINTED, see auth.py)

`{bucket}` is the HMAC of the account, not the account: these were
`devices:{uin}` and `dev_revoked:{uin}` until 2026-08-22, which made a bare
`KEYS *` a list of every account holding or having revoked a linked browser.
See `core/redis_keys` for the derivation and for the one family deliberately
left in the clear.

⚠ A revoke can only ever be as good as the id it names. The linked session must
keep refreshing under the `device_id` minted here, because that is the only
handle the phone's "disconnect" button has on it: a client that re-mints under
an id of its own choosing is invisible to this registry, and the disconnect
becomes a button that changes nothing (report #607).
"""

from __future__ import annotations

import json
import logging
import os
import secrets
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import log_identity
from app.core.db import get_db
from app.core.redis import get_redis
from app.core.redis_keys import DEV_REVOKED_PREFIX, DEVICES_PREFIX, account_key
from app.core.security import current_device_id, current_uin, issue_device_token, uin_epoch
from app.models.queue_cursor import QueueCursor
from app.services.connection_manager import manager

log = logging.getLogger(__name__)

router = APIRouter(prefix="/devices", tags=["devices"])

_MAX_DEVICES = 5
# A linked web session lives ~90 days; the device token's exp matches.
DEVICE_TTL_SECONDS = 90 * 24 * 3600

# The 100200300 rule (he retracted auto-blocking new sessions — with a lost
# phone there is nobody left to confirm one — and asked for a COOLDOWN long
# enough for the owner to notice a new session and act). How long a freshly
# LINKED session must live before it may revoke something older than itself.
REVOKE_COOLDOWN_SECONDS = int(os.environ.get("RCQ_REVOKE_COOLDOWN_SECONDS", str(24 * 3600)))


def _devices_key(uin: int) -> str:
    return account_key(DEVICES_PREFIX, uin)


def _revoked_key(uin: int) -> str:
    return account_key(DEV_REVOKED_PREFIX, uin)


async def has_linked_devices(uin: int) -> bool:
    """True if the account has >=1 linked web session (→ serve v=1, not v=2)."""
    redis = await get_redis()
    return bool(await redis.exists(_devices_key(uin)))


async def is_linked_device(uin: int, device_id: str | None) -> bool:
    """True if `device_id` is one of this account's LINKED sessions, as opposed
    to one of its own installs. Membership in the registry hash is the exact
    test — a phone's token carries a `dev` claim too, and the two are told apart
    nowhere else."""
    if not device_id or device_id == "primary":
        return False
    redis = await get_redis()
    return bool(await redis.hexists(_devices_key(uin), device_id))


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
    independently revocable.

    The row starts PENDING: this endpoint runs when the QR is shown / the blob
    is minted, which is BEFORE any browser picked it up — so an abandoned link
    used to leave a ghost "Web" device in the list until the registry TTL
    (open item "призрачная веб-сессия"). The flag clears on the token's first
    real use (`mark_device_seen` from the WS connect and the queue drain), and
    a row still pending after `_PENDING_TTL` is swept by the list."""
    redis = await get_redis()
    if await redis.hlen(_devices_key(uin)) >= _MAX_DEVICES:
        raise HTTPException(status.HTTP_409_CONFLICT, detail={"code": "too_many_devices"})
    device_id = secrets.token_hex(8)
    entry = json.dumps({
        "label": body.label,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "pending": True,
    })
    await redis.hset(_devices_key(uin), device_id, entry)
    await redis.expire(_devices_key(uin), DEVICE_TTL_SECONDS)
    await _announce(uin, "device_linked", device_id, body.label)
    return LinkOut(
        device_id=device_id,
        token=issue_device_token(uin, device_id, await uin_epoch(uin)),
    )


# How long a pending (never-used) link row may sit in the list. Long enough to
# cover a slow QR handoff, short enough that an abandoned scan does not haunt
# the devices screen. After this the list sweeps the row lazily.
_PENDING_TTL_SECONDS = 15 * 60


async def mark_device_seen(uin: int, device_id: str | None) -> None:
    """First real use of a linked device's token — clear its PENDING flag.

    Called from the WS connect and the offline-queue drain: every live session
    does one of those within seconds of adopting the link blob, including the
    web builds that predate the flag (nothing to ship client-side). Best-effort
    and cheap (one HGET, an HSET only on the first call that finds the flag)."""
    if not device_id or device_id == "primary":
        return
    try:
        redis = await get_redis()
        raw = await redis.hget(_devices_key(uin), device_id)
        if not raw:
            return
        raw = raw.decode() if isinstance(raw, bytes) else raw
        entry = json.loads(raw)
        if not entry.get("pending"):
            return
        entry.pop("pending", None)
        await redis.hset(_devices_key(uin), device_id, json.dumps(entry))
    except Exception:
        # A lost clear only means the row stays "pending" until its next use.
        return


async def _linked_created_at(uin: int, device_id: str | None) -> datetime | None:
    """When this LINKED session was born, or None for anything not in the
    registry (native installs, "primary", absent ids)."""
    if not device_id or device_id == "primary":
        return None
    redis = await get_redis()
    raw = await redis.hget(_devices_key(uin), device_id)
    if not raw:
        return None
    raw = raw.decode() if isinstance(raw, bytes) else raw
    try:
        return datetime.fromisoformat(json.loads(raw).get("created_at", ""))
    except (ValueError, TypeError):
        return None


async def revoker_gate(uin: int, revoker_device_id: str | None, target_created_at: datetime | None) -> None:
    """May THIS session revoke THAT one? The stolen-link threat model: a
    freshly-linked session must not be able to throw the owner out.

    - A NATIVE install (registered/recovered — not in the linked registry)
      revokes freely: whoever holds the account keys IS the account, and no
      denylist changes that (#607's root).
    - A linked session revokes anything YOUNGER than itself freely (the owner
      kicking the thief must never wait).
    - A linked session revokes something OLDER only once it has survived the
      cooldown — long enough for the owner to notice it in the device list
      and act first. Until then: 403 revoke_cooldown with the wait.
    """
    revoker_born = await _linked_created_at(uin, revoker_device_id)
    if revoker_born is None:
        return
    now = datetime.now(timezone.utc)
    if revoker_born.tzinfo is None:
        revoker_born = revoker_born.replace(tzinfo=timezone.utc)
    age = (now - revoker_born).total_seconds()
    if age >= REVOKE_COOLDOWN_SECONDS:
        return
    if target_created_at is not None:
        target_born = target_created_at if target_created_at.tzinfo else target_created_at.replace(tzinfo=timezone.utc)
        if revoker_born <= target_born:
            return
    raise HTTPException(
        status.HTTP_403_FORBIDDEN,
        detail={
            "code": "revoke_cooldown",
            "wait_seconds": int(REVOKE_COOLDOWN_SECONDS - age),
        },
    )


class DeviceOut(BaseModel):
    device_id: str
    label: str
    created_at: str
    # A link whose token was never used yet (QR shown, no browser picked it
    # up). Old clients ignore the extra field; new ones may label the row.
    pending: bool = False


@router.get("", response_model=list[DeviceOut])
async def list_devices(uin: int = Depends(current_uin)) -> list[DeviceOut]:
    redis = await get_redis()
    raw = await redis.hgetall(_devices_key(uin))
    now = datetime.now(timezone.utc)
    out: list[DeviceOut] = []
    for did, entry in raw.items():
        did = did.decode() if isinstance(did, bytes) else did
        entry = entry.decode() if isinstance(entry, bytes) else entry
        try:
            d = json.loads(entry)
        except (ValueError, TypeError):
            d = {}
        if d.get("pending"):
            # An abandoned handoff: the QR was shown, nobody ever used the
            # token. Sweep it here rather than in a background job — the list
            # is the only place the ghost was ever visible.
            try:
                born = datetime.fromisoformat(d.get("created_at", ""))
                stale = (now - born).total_seconds() > _PENDING_TTL_SECONDS
            except ValueError:
                stale = True
            if stale:
                await redis.hdel(_devices_key(uin), did)
                continue
        out.append(DeviceOut(
            device_id=did,
            label=d.get("label", "Web"),
            created_at=d.get("created_at", ""),
            pending=bool(d.get("pending")),
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
    caller_device: str | None = Depends(current_device_id),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Disconnect a web session: drop it from the registry AND denylist its
    token. When the last device is removed the hash disappears, so the account
    is single-device again and `GET /keys/{uin}/bundle` resumes serving v=2.
    Returns 200 {ok:true} (any 2xx satisfies the clients).

    Gated by [revoker_gate]: a freshly-linked session cannot kick sessions
    older than itself until the cooldown passes (self-disconnect stays on
    `DELETE /devices/me`, ungated)."""
    await revoker_gate(uin, caller_device, await _linked_created_at(uin, device_id))
    return await _revoke(uin, device_id, db)


async def _announce(uin: int, kind: str, device_id: str, label: str | None = None) -> None:
    """Tell every session of this account that the device registry changed.

    Without this the phone's "linked devices" screen only ever refreshed when
    the user left it and came back: signing out on the desktop (which now calls
    `DELETE /devices/me`) left the phone listing it as connected until then —
    the tail of the 2026-08-04 report. The registry lived entirely outside the
    socket, so there was nothing for a client to listen to.

    Sent to ALL devices INCLUDING the one being revoked: it carries the
    `device_id`, so a web session can recognise its own revocation and sign
    itself out instead of dying at the next 401. Best-effort — the registry
    write is the source of truth, and a failed announcement must never fail the
    link or the revoke.
    """
    payload: dict[str, object] = {"type": kind, "device_id": device_id}
    if label is not None:
        payload["label"] = label
    try:
        await manager.send(uin, payload)
    except Exception:  # noqa: BLE001 — bookkeeping must not break the operation
        # Same treatment as `keys._announce`: the failure and its traceback are
        # what an operator reads this for, the account number is not.
        log.exception("[devices] failed to announce %s uin=%s", kind, log_identity(uin))


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
    await _announce(uin, "device_revoked", device_id)
    # Closing the socket is not decoration: the denylist is consulted at the
    # HANDSHAKE, so a session that simply never reconnects went on receiving
    # messages, presence and call signalling on the socket it already had —
    # for as long as an idle tab stays open.
    #
    # ⚠ The announcement above races this and may not reach the device being
    # disconnected (it travels through Redis; the close is immediate on this
    # worker). It is the account's OTHER devices that need it, to refresh the
    # linked-devices list. Nothing may depend on the revoked session hearing
    # its own goodbye — being cut off is the message.
    try:
        await manager.kick_device(uin, device_id)
    except Exception:  # noqa: BLE001 — the registry write is the source of truth
        # The device id stays: it is a random opaque handle this module minted,
        # it is what a revoke is ABOUT, and it names nobody on its own.
        log.exception(
            "[devices] failed to kick sockets uin=%s dev=%s", log_identity(uin), device_id,
        )
    return {"ok": True}
