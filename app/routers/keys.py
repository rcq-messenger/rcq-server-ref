from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import get_db
from app.core.security import current_uin
from app.models.prekey import OneTimePreKey
from app.models.user import User

router = APIRouter(prefix="/keys", tags=["keys"])

# How many OPKs the client should keep on the server. Replenish endpoint is
# expected to be called when the count drops below ~25.
TARGET_PREKEY_COUNT = 100


class SignedPreKey(BaseModel):
    id: int
    public: str  # b64 of 33-byte libsignal PublicKey
    signature: str  # b64 of the IdentityKey signature over `public`


class OneTimePreKeyIn(BaseModel):
    id: int
    public: str  # b64 of 33-byte libsignal PublicKey


class KyberPreKey(BaseModel):
    """libsignal Kyber pre-key — the post-quantum half of PQXDH. We ship
    a single rotating last-resort key (no pool); reuse is acceptable as
    forward secrecy comes from the EC ephemeral side."""

    id: int
    public: str  # b64 of the serialized KEMPublicKey
    signature: str  # b64 of the IdentityKey signature over `public`


class BundleIn(BaseModel):
    """Full Stage 3 key bundle uploaded by the owner. Replaces any prior
    libsignal material on the same account — a fresh bootstrap (e.g. burn
    + re-register, or an in-place re-key) overrides everything."""

    # Base64 of the 33-byte serialized libsignal IdentityKey.
    signal_identity_key: str = Field(min_length=1)
    # libsignal registrationId, range [1, 16380].
    registration_id: int = Field(ge=1, le=16380)
    signed_prekey: SignedPreKey
    kyber_prekey: KyberPreKey
    # Initial pool of one-time prekeys. Subsequent top-ups go through
    # POST /keys/prekeys.
    one_time_prekeys: list[OneTimePreKeyIn] = Field(default_factory=list)


class PreKeysIn(BaseModel):
    """Replenish-only payload. Adds OPKs to the pool without disturbing
    the active signed prekey or identity key."""

    one_time_prekeys: list[OneTimePreKeyIn]


class BundleOut(BaseModel):
    """What a sender sees when initiating an X3DH session with `uin`. The
    server consumes one OPK from the pool on the way out so the same
    prekey is never returned twice (X3DH uniqueness)."""

    uin: int
    registration_id: int
    signal_identity_key: str
    signed_prekey: SignedPreKey
    kyber_prekey: KyberPreKey
    # Optional — if the recipient has run out of OPKs, X3DH can still
    # proceed using just the signed prekey at the cost of slightly weaker
    # initiation properties (no per-session contributory prekey). Senders
    # log a warning when this is null but proceed.
    one_time_prekey: OneTimePreKeyIn | None = None


class StatusOut(BaseModel):
    """Pool-health report for the owner so the client can decide when to
    top up. Returned by GET /keys/me/status."""

    has_bundle: bool
    one_time_prekey_count: int
    target_count: int
    signed_prekey_age_seconds: int | None  # None when no signed prekey yet


@router.post("/bundle", status_code=status.HTTP_204_NO_CONTENT)
async def upload_bundle(
    body: BundleIn,
    uin: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> None:
    """First-time bootstrap or full re-key. Overwrites identity key,
    registration id, and the signed prekey on the user row, and replaces
    the OPK pool wholesale. Subsequent top-ups go through /keys/prekeys."""
    user = await db.get(User, uin)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found")
    user.signal_identity_key = body.signal_identity_key
    user.signal_registration_id = body.registration_id
    user.signed_prekey_id = body.signed_prekey.id
    user.signed_prekey_public = body.signed_prekey.public
    user.signed_prekey_signature = body.signed_prekey.signature
    user.signed_prekey_uploaded_at = datetime.now(timezone.utc)
    user.kyber_prekey_id = body.kyber_prekey.id
    user.kyber_prekey_public = body.kyber_prekey.public
    user.kyber_prekey_signature = body.kyber_prekey.signature
    user.kyber_prekey_uploaded_at = datetime.now(timezone.utc)

    # Wipe any prior pool and stage the new one. Cheaper than a per-row
    # upsert and matches the "fresh bootstrap" semantics of this endpoint.
    await db.execute(delete(OneTimePreKey).where(OneTimePreKey.uin == uin))
    for pk in body.one_time_prekeys:
        db.add(OneTimePreKey(uin=uin, prekey_id=pk.id, public_key=pk.public))
    await db.commit()


@router.post("/prekeys", status_code=status.HTTP_204_NO_CONTENT)
async def replenish_prekeys(
    body: PreKeysIn,
    uin: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Add more OPKs to the existing pool. Doesn't touch identity / signed
    prekey. Idempotent on `prekey_id` collision — duplicates are silently
    skipped so a retry of a partially-uploaded batch is safe."""
    existing = set(
        (
            await db.execute(
                select(OneTimePreKey.prekey_id).where(OneTimePreKey.uin == uin)
            )
        ).scalars().all()
    )
    for pk in body.one_time_prekeys:
        if pk.id in existing:
            continue
        db.add(OneTimePreKey(uin=uin, prekey_id=pk.id, public_key=pk.public))
    await db.commit()


@router.get("/{uin}/bundle", response_model=BundleOut)
async def fetch_bundle(
    uin: int,
    _me: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> BundleOut:
    """Hand a sender what they need to start an X3DH session with `uin`.
    Consumes one OPK from the pool — each prekey is single-use by design.

    Concurrency: relies on the single-worker uvicorn invariant the app
    is currently deployed with. Two parallel sender requests landing in
    the same event-loop tick will serialize on the SELECT-then-UPDATE
    here without contention. The day we scale to multi-worker we need
    `SELECT ... FOR UPDATE SKIP LOCKED` (PG-only) or a row-versioned
    compare-and-set. TODO when the migration to PG ships."""
    user = await db.get(User, uin)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such user")
    if (
        user.signal_identity_key is None
        or user.signed_prekey_id is None
        or user.kyber_prekey_id is None
    ):
        # Stage 2 user — has only the legacy X25519/Ed25519 keys, hasn't
        # uploaded a complete libsignal PQXDH bundle yet. Caller treats
        # 404 here as "fall back to v=1 envelope path".
        raise HTTPException(status.HTTP_404_NOT_FOUND, "user has no signal bundle")

    opk = (
        await db.execute(
            select(OneTimePreKey)
            .where(OneTimePreKey.uin == uin, OneTimePreKey.consumed == False)  # noqa: E712
            .order_by(OneTimePreKey.id.asc())
            .limit(1)
        )
    ).scalar_one_or_none()
    opk_out: OneTimePreKeyIn | None = None
    if opk is not None:
        opk.consumed = True
        opk_out = OneTimePreKeyIn(id=opk.prekey_id, public=opk.public_key)
        await db.commit()

    return BundleOut(
        uin=user.uin,
        registration_id=user.signal_registration_id or 0,
        signal_identity_key=user.signal_identity_key,
        signed_prekey=SignedPreKey(
            id=user.signed_prekey_id,
            public=user.signed_prekey_public or "",
            signature=user.signed_prekey_signature or "",
        ),
        kyber_prekey=KyberPreKey(
            id=user.kyber_prekey_id,
            public=user.kyber_prekey_public or "",
            signature=user.kyber_prekey_signature or "",
        ),
        one_time_prekey=opk_out,
    )


@router.get("/me/status", response_model=StatusOut)
async def my_status(
    uin: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> StatusOut:
    user = await db.get(User, uin)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found")
    has_bundle = user.signal_identity_key is not None
    count = (
        await db.execute(
            select(func.count())
            .select_from(OneTimePreKey)
            .where(OneTimePreKey.uin == uin, OneTimePreKey.consumed == False)  # noqa: E712
        )
    ).scalar_one()
    age: int | None = None
    if user.signed_prekey_uploaded_at is not None:
        age = int((datetime.now(timezone.utc) - user.signed_prekey_uploaded_at).total_seconds())
    return StatusOut(
        has_bundle=has_bundle,
        one_time_prekey_count=int(count),
        target_count=TARGET_PREKEY_COUNT,
        signed_prekey_age_seconds=age,
    )
