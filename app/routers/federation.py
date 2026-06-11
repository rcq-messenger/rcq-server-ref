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
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import get_db
from app.core.rate_limit import rate_limit
from app.core.security import current_uin
from app.models.federation import HomeIslandRecord
from app.models.user import User

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


class PublicKeysOut(BaseModel):
    """A user's PUBLIC key card — nothing secret, nothing consumable.

    Carries the always-visible IDENTITY fields a cross-island client needs to
    render a peer like a normal contact (nickname + island, optional profile
    bits) instead of a bare `uin@host`. `nickname` is always present (it is
    always-visible identity, exactly as same-island search exposes it); the
    optional `gender`/`status_message` are gated by the user's
    `profile_visibility` ("everyone" only), so a privacy-conscious user on an
    open island still leaks only their nickname here.
    """
    uin: int
    identity_key: str                        # v=1 X25519 (seal an envelope to them)
    signing_key: str                         # v=1 Ed25519 (verify their sigs + the record `sk`)
    signal_identity_key: str | None = None   # v=2 libsignal (safety-number key + the record `ik`)
    nickname: str | None = None              # always-visible identity (display name)
    gender: str | None = None                # profile_visibility=="everyone" only
    status_message: str | None = None        # profile_visibility=="everyone" only


@router.get(
    "/keys/{uin}",
    response_model=PublicKeysOut,
    dependencies=[Depends(rate_limit("federation_keys_get", 120, 60))],
)
async def get_public_keys(
    uin: int,
    db: AsyncSession = Depends(get_db),
) -> PublicKeysOut:
    """Open, minimal public-key card for cross-island anchoring (federation §4).

    A sender on another island fetches this to anchor the `ik`/`sk` of a peer's
    signed home-island record before depositing. Returns ONLY public keys: it
    consumes no one-time prekey and exposes nothing the safety number does not
    already let a contact verify. Unlike `/keys/{uin}/bundle` (which is
    authenticated and consumes an OPK), this is the cheap, idempotent, open card
    a dumb mailbox serves for its residents so other islands can reach them. IP
    rate-limited to bound UIN enumeration.
    """
    u = await db.get(User, uin)
    if u is None or not u.identity_key:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such user")
    # Optional profile bits only when the user keeps an open profile — same
    # gate /users/{uin}/info applies to outsiders. Nickname is always-visible
    # identity and ships regardless.
    profile_open = (u.profile_visibility or "everyone") == "everyone"
    return PublicKeysOut(
        uin=u.uin,
        identity_key=u.identity_key,
        signing_key=u.signing_key,
        signal_identity_key=u.signal_identity_key,
        nickname=u.nickname,
        gender=u.gender if (profile_open and (u.gender_visibility or "nobody") == "everyone") else None,
        status_message=u.status_message if profile_open else None,
    )
