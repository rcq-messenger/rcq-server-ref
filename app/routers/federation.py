"""Federation Layer B (F1): the self-signed home-island record.

Two additive endpoints, fully decoupled from the existing send/queue/bundle
paths. See `docs/federation-protocol.md`.

  PUT /federation/island-record       (authed) store your signed record
  GET /federation/island-record/{uin} (open)   fetch a user's signed record

The server is a dumb, untrusted store: it keeps the opaque client-signed JSON
keyed by the authenticated local UIN, enforces only anti-rollback + a size bound,
and serves it to anyone. All cryptographic trust is verified client-side against
the identity key the user anchors by safety number; the server holds no libsignal
and is deliberately not the trust root.
"""
import json

from fastapi import APIRouter, Body, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import get_db
from app.core.rate_limit import rate_limit
from app.core.security import current_uin
from app.models.federation import HomeIslandRecord

router = APIRouter(prefix="/federation", tags=["federation"])

# The signed document is small: a key, a short list of (host, uin) homes, a
# timestamp, a signature. Anything larger is malformed or abusive.
_MAX_DOC_BYTES = 8 * 1024


@router.put(
    "/island-record",
    dependencies=[Depends(rate_limit("federation_record_put", 30, 60))],
)
async def put_island_record(
    doc: dict = Body(...),
    uin: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Store the caller's signed home-island record for this island.

    Validates shape minimally (version, a positive integer `ts`, a non-empty
    `homes`, a `sig`), enforces anti-rollback, and stores the document verbatim.
    Does NOT verify the signature — see module docstring.
    """
    # Re-serialize compactly so we store exactly what we validated, and so the
    # size bound is on the stored bytes, not on incidental request whitespace.
    raw = json.dumps(doc, separators=(",", ":"), ensure_ascii=False)
    if len(raw.encode("utf-8")) > _MAX_DOC_BYTES:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "record too large")

    if doc.get("v") != 1:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "unsupported record version")
    ts = doc.get("ts")
    if not isinstance(ts, int) or isinstance(ts, bool) or ts <= 0:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "missing or invalid ts")
    homes = doc.get("homes")
    if not isinstance(homes, list) or not homes:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "missing homes")
    if not isinstance(doc.get("ik"), str) or not isinstance(doc.get("sig"), str):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "missing ik or sig")

    existing = (
        await db.execute(select(HomeIslandRecord).where(HomeIslandRecord.uin == uin))
    ).scalar_one_or_none()
    if existing is not None:
        # Anti-rollback: a later write must not regress to an older island list.
        # Equal ts is allowed (idempotent re-publish of the same record).
        if ts < existing.ts:
            raise HTTPException(status.HTTP_409_CONFLICT, "stale ts")
        existing.doc = raw
        existing.ts = ts
    else:
        db.add(HomeIslandRecord(uin=uin, doc=raw, ts=ts))
    await db.commit()
    return {"ok": True, "ts": ts}


@router.get("/island-record/{uin}")
async def get_island_record(
    uin: int,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Return a user's signed home-island record, or 404 if none is stored.

    Open by design: the record is public, signed routing data that reveals only
    where an identity is reachable. The client verifies its signature.
    """
    row = (
        await db.execute(select(HomeIslandRecord).where(HomeIslandRecord.uin == uin))
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no record")
    return json.loads(row.doc)
