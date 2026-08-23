"""The vault: opaque, versioned, client-sealed slots per account.

    GET    /vault                          -> {slots: [{slot, version}]}   live slots only
    PUT    /vault/{slot}  {blob, version}  -> {version}                    409 when stale
    GET    /vault/{slot}                   -> {blob, version}              404 {no_slot, version}
    DELETE /vault/{slot}?version=N         -> 204                          409 when stale

See `app.models.vault` for what it is and why the version rule exists.

The contract on a write: `version` is the version the client READ (0 only
when the island answered that the slot has never existed). The island stores
the blob as version+1, or refuses with `409 {code: "stale", version:
<current>}` and stores nothing. The island never compares contents, never
merges, and never tells one device what another wrote except through the
blob itself; a refused writer re-reads, merges on its own terms and retries.

★ A version number is never reused within (account, slot). A delete keeps
the row as a tombstone (no blob) and ADVANCES the version; `GET` on a
tombstone is 404 with that version in the body, and the next write must name
it. Without this a slot deleted and re-created would count 1, 2, 3 again,
and a device that remembered "version 3" from before the delete would read
the new version 3 as "nothing changed" (the ABA case the review of
2026-08-23 found). A deleted-and-never-rewritten slot therefore costs one
small row for the life of the account; it does not count against the cap.

A delete names the version it read for the same reason a write does: a
delete is a write that lands on top of something, and the unconditional form
is exactly the #605 pattern. Deleting what is already gone is 204 either way,
so a retried delete cannot fail.

Every accepted write and every delete nudges the account's sessions with
`{"type": "vault_changed", "slot", "version"}` (the NEW version, which on a
delete is the tombstone's). The writer sees its own nudge and ignores it by
version; every other device of the account re-reads the slot. ⚠ The nudge is
pub/sub to live sockets with no queue and no replay: a device whose socket
was down at that moment never hears it. Clients therefore re-read every
slot they use on EVERY socket (re)connect, not only on boot, and `GET /vault`
exists so that check is one small request (slots and versions, no blobs).

What the island cannot tell a client: whether a blob it serves is the latest
one ever written. The version is the only handle. First-party clients seal
with the slot name and the version in the AEAD associated data, so the island
cannot relabel one version as another, and remember the highest version they
have seen per slot, so an island that answers with a lower one (a restored
backup, or lying) is refusing to go backwards rather than re-adding what was
deliberately removed.

`POST /auth/reissue` rotates the identity the first-party slot names and
keys are derived from. The island empties the account's vault in the same
transaction, because every slot would be unreachable under the new
derivation and the ciphertext under a key the user just retired has no
business staying. The client that rotates reads its slots BEFORE the reissue
and writes them back under the new derivation AFTER it.

Limits, also advertised in /server/info: MAX_BLOB_BYTES decoded per slot,
MAX_SLOTS live slots per account, and per account per hour 1200 reads, 240
writes and 60 deletes (429 with Retry-After), plus a daily byte budget on
writes so one account cannot churn the table. Writes are per merged state,
never per entry: a client that imports 300 contacts makes ONE write.

What the island learns: that an account has N slots of these sizes, and when
they change. It does not learn what is in them, and the slot names are
client-derived noise, not labels. ⚠ They are also a stable per-account
pseudonym, which is why the access-log redactors (app/main.py and the
Caddyfile) rewrite `/vault/<hex>` the way they rewrite `/users/<uin>`.
"""
from __future__ import annotations

import base64
import binascii
import re

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import get_db
from app.core.rate_limit import enforce_cost_budget, rate_limit
from app.core.security import current_uin
from app.models.vault import VaultSlot
from app.services.connection_manager import manager

router = APIRouter(prefix="/vault", tags=["vault"])

# Decoded bytes per slot. A contact list is a few dozen bytes per entry; 256
# KB is thousands of contacts with headroom for whatever stage 7 adds. Big
# enough never to be the reason a write fails, small enough that the table
# cannot become somebody's file host.
MAX_BLOB_BYTES = 256 * 1024
# Base64 of that, with padding. Checked by pydantic before the handler runs,
# so an oversized body is refused before anything decodes it.
MAX_BLOB_B64 = MAX_BLOB_BYTES * 4 // 3 + 4
# Live slots per account. Today's clients use a handful; the cap is there so
# the table has a ceiling per account, not to be reached. Tombstones do not
# count.
MAX_SLOTS = 32
# Decoded bytes an account may write per day, across its slots. 64 MB is 256
# full rewrites of the largest slot; a contact list changes a few times a day.
DAILY_WRITE_BYTES = 64 * 1024 * 1024
# A version is a small counter. Anything near int64 is not one and is a 422
# rather than a driver error at the bind.
MAX_VERSION = 2**62

_SLOT_RE = r"^[0-9a-f]{32}$"
_slot_path = Path(pattern=_SLOT_RE, description="32 lower-case hex characters, client-chosen")


class VaultPutIn(BaseModel):
    blob: str = Field(max_length=MAX_BLOB_B64)
    # The version this write was based on; 0 = "the slot has never existed".
    version: int = Field(ge=0, le=MAX_VERSION)


class VaultVersionOut(BaseModel):
    version: int


class VaultSlotOut(BaseModel):
    blob: str
    version: int


class VaultSlotRef(BaseModel):
    slot: str
    version: int


class VaultListOut(BaseModel):
    slots: list[VaultSlotRef]


def _canonical_blob(raw: str) -> str:
    """Validate the base64 and return it re-encoded, so what the island
    stores is byte-for-byte what every client will decode to."""
    s = raw.strip()
    if not s:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail={"code": "empty_blob"})
    if len(s) > MAX_BLOB_B64:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail={"code": "blob_too_large", "max_bytes": MAX_BLOB_BYTES})
    if not re.fullmatch(r"[A-Za-z0-9+/]*={0,2}", s):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail={"code": "bad_base64"})
    try:
        data = base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail={"code": "bad_base64"})
    if not data:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail={"code": "empty_blob"})
    if len(data) > MAX_BLOB_BYTES:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail={"code": "blob_too_large", "max_bytes": MAX_BLOB_BYTES})
    return base64.b64encode(data).decode()


async def _current_version(db: AsyncSession, uin: int, slot: str) -> int:
    v = (
        await db.execute(select(VaultSlot.version).where(VaultSlot.uin == uin, VaultSlot.slot == slot))
    ).scalar_one_or_none()
    return int(v or 0)


def _stale(current: int) -> HTTPException:
    return HTTPException(status.HTTP_409_CONFLICT, detail={"code": "stale", "version": current})


async def _nudge(uin: int, slot: str, version: int) -> None:
    await manager.broadcast([uin], {"type": "vault_changed", "slot": slot, "version": version})


@router.get("", response_model=VaultListOut, dependencies=[Depends(rate_limit("vault_list", 600, 3600))])
async def list_slots(
    uin: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> VaultListOut:
    rows = (
        await db.execute(
            select(VaultSlot.slot, VaultSlot.version)
            .where(VaultSlot.uin == uin, VaultSlot.blob.is_not(None))
            .order_by(VaultSlot.slot)
        )
    ).all()
    return VaultListOut(slots=[VaultSlotRef(slot=s, version=v) for s, v in rows])


@router.get("/{slot}", response_model=VaultSlotOut, dependencies=[Depends(rate_limit("vault_get", 1200, 3600))])
async def get_slot(
    slot: str = _slot_path,
    uin: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> VaultSlotOut:
    row = await db.get(VaultSlot, (uin, slot))
    if row is None or row.blob is None:
        # The version rides along so a writer knows what to base the next
        # write on: 0 for never-written, the tombstone's for deleted.
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail={"code": "no_slot", "version": row.version if row else 0})
    return VaultSlotOut(blob=row.blob, version=row.version)


@router.put("/{slot}", response_model=VaultVersionOut, dependencies=[Depends(rate_limit("vault_put", 240, 3600))])
async def put_slot(
    body: VaultPutIn,
    slot: str = _slot_path,
    uin: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> VaultVersionOut:
    blob = _canonical_blob(body.blob)
    await enforce_cost_budget(f"uin:{uin}", "vault_bytes", len(blob) * 3 // 4, DAILY_WRITE_BYTES, 86400)

    if body.version == 0:
        # The writer believes the slot has never existed. The cap applies to
        # new slots only; an existing slot can always be rewritten.
        n = (
            await db.execute(
                select(func.count()).select_from(VaultSlot).where(VaultSlot.uin == uin, VaultSlot.blob.is_not(None))
            )
        ).scalar_one()
        if n >= MAX_SLOTS:
            # Unless it exists already (live or tombstone), in which case this
            # is a stale write and the right answer is the version, not the cap.
            current = await _current_version(db, uin, slot)
            if current:
                raise _stale(current)
            raise HTTPException(status.HTTP_400_BAD_REQUEST, detail={"code": "slot_limit", "max_slots": MAX_SLOTS})
        try:
            async with db.begin_nested():
                db.add(VaultSlot(uin=uin, slot=slot, blob=blob, version=1))
                await db.flush()
        except IntegrityError:
            # Somebody (this account from another device, or this device a
            # moment ago) created it first, or it is a tombstone whose version
            # the writer has to name. Same answer as any stale write.
            raise _stale(await _current_version(db, uin, slot))
        new_version = 1
    else:
        # A tombstone at exactly this version is re-created here too: the
        # WHERE matches the row regardless of blob, and the blob comes back.
        res = await db.execute(
            update(VaultSlot)
            .where(VaultSlot.uin == uin, VaultSlot.slot == slot, VaultSlot.version == body.version)
            .values(blob=blob, version=body.version + 1)
        )
        if res.rowcount != 1:
            raise _stale(await _current_version(db, uin, slot))
        new_version = body.version + 1

    await db.commit()
    await _nudge(uin, slot, new_version)
    return VaultVersionOut(version=new_version)


@router.delete("/{slot}", status_code=status.HTTP_204_NO_CONTENT, dependencies=[Depends(rate_limit("vault_delete", 60, 3600))])
async def delete_slot(
    slot: str = _slot_path,
    version: int = Query(ge=1, le=MAX_VERSION, description="the version this delete is based on"),
    uin: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> Response:
    row = await db.get(VaultSlot, (uin, slot))
    if row is None or row.blob is None:
        # Nothing there (never written, or already a tombstone): a delete of
        # what does not exist is a no-op, not an error, so a retry cannot
        # fail and two devices deleting at once both succeed.
        return Response(status_code=status.HTTP_204_NO_CONTENT)
    res = await db.execute(
        update(VaultSlot)
        .where(VaultSlot.uin == uin, VaultSlot.slot == slot, VaultSlot.version == version, VaultSlot.blob.is_not(None))
        .values(blob=None, version=version + 1)
    )
    if res.rowcount != 1:
        raise _stale(await _current_version(db, uin, slot))
    await db.commit()
    await _nudge(uin, slot, version + 1)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
