from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import engine, get_db
from app.core.security import current_uin
from app.models.device import Device
from app.models.prekey import OneTimePreKey
from app.models.user import User, _as_aware

# Primary device = the phone, libsignal deviceId 1, bundle on the User row.
PRIMARY_DEVICE_ID = 1
# libsignal caps deviceId at 127 (matches the WASM/iOS/Android clients).
MAX_DEVICE_ID = 127

router = APIRouter(prefix="/keys", tags=["keys"])

# How many OPKs the client should keep on the server. Replenish endpoint is
# expected to be called when the count drops below ~25.
TARGET_PREKEY_COUNT = 100


async def _claim_opk(db: AsyncSession, *, uin: int, device_id: int | None):
    """Atomically claim one un-consumed one-time prekey for (uin, device_id) and
    mark it consumed (the caller commits). Returns the ORM row, or None when the
    pool is empty.

    The row lock (FOR UPDATE SKIP LOCKED on Postgres) is what makes this safe
    under concurrency: two senders fetching the same recipient's bundle at the
    same time each lock+take a DIFFERENT free prekey instead of both reading the
    same un-consumed one before either commits. A handed-out-twice single-use
    prekey is exactly what made ~10% of first-in-session messages undecryptable
    on the recipient (generic push + lost message). SQLite (self-host) serializes
    writers, so the plain select is already safe there."""
    pool = (
        OneTimePreKey.device_id.is_(None)
        if device_id is None
        else OneTimePreKey.device_id == device_id
    )
    stmt = (
        select(OneTimePreKey)
        .where(
            OneTimePreKey.uin == uin,
            pool,
            OneTimePreKey.consumed == False,  # noqa: E712
        )
        .order_by(OneTimePreKey.id.asc())
        .limit(1)
    )
    if engine.dialect.name == "postgresql":
        stmt = stmt.with_for_update(skip_locked=True)
    opk = (await db.execute(stmt)).scalar_one_or_none()
    if opk is not None:
        opk.consumed = True
    return opk


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
    # libsignal deviceId this bundle is for. 1 = the primary device (phone).
    # Additive field — pre-multi-device clients ignore it and keep using
    # deviceId 1. Senders that fan out read it to address the right session.
    device_id: int = 1
    # X25519 sealed-sender (OUTER ECIES) pubkey to encrypt the outer envelope
    # to for THIS device. Primary = the UIN identity_key; secondary = that
    # device's own key. Additive — old clients ignore it and keep using the
    # UIN identity_key from /users/{uin}/info as before.
    sealed_sender_pub: str = ""
    registration_id: int
    signal_identity_key: str
    # The account's Ed25519 `signing_key` (v=1 sealed-sender signing pubkey).
    # Additive — pre-federation clients ignore it. Federation (Layer B) resolvers
    # read it to anchor the `sk` in a peer's signed home-island record
    # (docs/federation-protocol.md §2.4). Empty for the rare legacy row missing it.
    signing_key: str = ""
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
    # The identity key currently published as this account's PRIMARY device.
    #
    # A client compares it with its own: same means "I am device 1"; different
    # means another install owns the primary slot and this one must register as
    # a secondary device instead of overwriting it. Overwriting is what broke
    # 1:1 delivery for anyone running a phone and a desktop at once — both
    # published here, so peers built sessions against whichever wrote last and
    # the other device's messages became undecryptable.
    #
    # Public key of the caller's own account: it leaks nothing they can't fetch
    # from their own bundle.
    signal_identity_key: str | None = None


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
    # Scoped to the PRIMARY pool (device_id IS NULL) so a re-bootstrap of the
    # phone never wipes a linked web device's prekeys.
    await db.execute(
        delete(OneTimePreKey).where(
            OneTimePreKey.uin == uin, OneTimePreKey.device_id.is_(None)
        )
    )
    for pk in body.one_time_prekeys:
        db.add(OneTimePreKey(uin=uin, prekey_id=pk.id, public_key=pk.public, device_id=None))
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
                select(OneTimePreKey.prekey_id).where(
                    OneTimePreKey.uin == uin, OneTimePreKey.device_id.is_(None)
                )
            )
        ).scalars().all()
    )
    for pk in body.one_time_prekeys:
        if pk.id in existing:
            continue
        db.add(OneTimePreKey(uin=uin, prekey_id=pk.id, public_key=pk.public, device_id=None))
    await db.commit()


@router.get("/{uin}/bundle", response_model=BundleOut)
async def fetch_bundle(
    uin: int,
    _me: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> BundleOut:
    """Hand a sender what they need to start an X3DH session with `uin`.
    Consumes one OPK from the pool — each prekey is single-use by design.

    Concurrency: the OPK is claimed under a row lock (FOR UPDATE SKIP LOCKED
    on Postgres) so two senders fetching this bundle at once each take a
    DIFFERENT free prekey. Without it the SELECT-then-UPDATE races (multi-worker,
    or just two requests interleaving at an await on one worker): both read the
    same un-consumed OPK before either commits, both encrypt to the recipient
    with that single-use key, and the recipient's libsignal consumes it on the
    first decrypt — making the second message undecryptable (InvalidKeyId), so
    it shows a generic push and never lands in the chat. See `_claim_opk`."""
    user = await db.get(User, uin)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such user")
    # Multi-device: while a web session is linked to this account, withhold the
    # v=2 bundle so the sender falls back to v=1 (stateless → decryptable on
    # every device of this identity). The Double Ratchet can't be shared across
    # devices, so v=2 to a multi-homed account silently desyncs on whichever
    # device didn't decrypt first. The 404 is the same "fall back to v=1" signal
    # senders already handle. Auto-restores once the last device is removed.
    from app.routers.devices import has_linked_devices  # local import: avoid cycle
    if await has_linked_devices(uin):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "multi-device: v=1 only")
    if (
        user.signal_identity_key is None
        or user.signed_prekey_id is None
        or user.kyber_prekey_id is None
    ):
        # Stage 2 user — has only the legacy X25519/Ed25519 keys, hasn't
        # uploaded a complete libsignal PQXDH bundle yet. Caller treats
        # 404 here as "fall back to v=1 envelope path".
        raise HTTPException(status.HTTP_404_NOT_FOUND, "user has no signal bundle")

    opk = await _claim_opk(db, uin=uin, device_id=None)
    opk_out: OneTimePreKeyIn | None = None
    if opk is not None:
        opk_out = OneTimePreKeyIn(id=opk.prekey_id, public=opk.public_key)
        await db.commit()

    return BundleOut(
        uin=user.uin,
        device_id=PRIMARY_DEVICE_ID,
        sealed_sender_pub=user.identity_key,
        registration_id=user.signal_registration_id or 0,
        signal_identity_key=user.signal_identity_key,
        signing_key=user.signing_key or "",
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
            .where(
                OneTimePreKey.uin == uin,
                OneTimePreKey.device_id.is_(None),
                OneTimePreKey.consumed == False,  # noqa: E712
            )
        )
    ).scalar_one()
    age: int | None = None
    if user.signed_prekey_uploaded_at is not None:
        age = int((datetime.now(timezone.utc) - _as_aware(user.signed_prekey_uploaded_at)).total_seconds())
    return StatusOut(
        has_bundle=has_bundle,
        one_time_prekey_count=int(count),
        target_count=TARGET_PREKEY_COUNT,
        signed_prekey_age_seconds=age,
        signal_identity_key=user.signal_identity_key,
    )


# ============================================================================
# Multi-device (additive) — secondary devices (the web client) register their
# OWN libsignal bundle here; the primary device (phone, deviceId 1) stays on
# the User row and the legacy /keys/{uin}/bundle path is unchanged. A sender
# that wants to reach every device of a UIN calls GET /keys/{uin}/devices, then
# fetches one bundle per device and fans out one ciphertext each. See
# docs/web-multidevice-plan.md.
# ============================================================================


class DeviceRegisterIn(BundleIn):
    """A secondary device's full libsignal bundle (same shape as BundleIn)
    plus its X25519 sealed-sender (outer) pubkey and an optional human label.
    The server assigns the deviceId."""

    sealed_sender_pub: str = Field(min_length=1)
    label: str | None = None


class DeviceRegisterOut(BaseModel):
    device_id: int


class DeviceInfo(BaseModel):
    device_id: int
    label: str | None = None


class DevicesOut(BaseModel):
    """Devices of `uin` with a usable libsignal bundle. A fanning-out sender
    fetches each device's bundle and sends one ciphertext per entry."""

    uin: int
    devices: list[DeviceInfo]


@router.post("/devices", response_model=DeviceRegisterOut, status_code=status.HTTP_201_CREATED)
async def register_device(
    body: DeviceRegisterIn,
    uin: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> DeviceRegisterOut:
    """Register a SECONDARY device (e.g. the web client) under the caller's UIN.
    The server assigns the next free libsignal deviceId (>= 2) — the client
    never self-asserts it, so two devices can't collide. The device's own
    identity + signed/kyber prekeys + initial OPK pool are stored independently
    of the phone's (deviceId 1)."""
    user = await db.get(User, uin)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found")

    existing_ids = (
        await db.execute(select(Device.device_id).where(Device.uin == uin))
    ).scalars().all()
    next_id = (max(existing_ids) if existing_ids else PRIMARY_DEVICE_ID) + 1
    if next_id > MAX_DEVICE_ID:
        raise HTTPException(status.HTTP_409_CONFLICT, "device limit reached")

    now = datetime.now(timezone.utc)
    device = Device(
        uin=uin,
        device_id=next_id,
        label=body.label,
        sealed_sender_pub=body.sealed_sender_pub,
        signal_identity_key=body.signal_identity_key,
        signal_registration_id=body.registration_id,
        signed_prekey_id=body.signed_prekey.id,
        signed_prekey_public=body.signed_prekey.public,
        signed_prekey_signature=body.signed_prekey.signature,
        signed_prekey_uploaded_at=now,
        kyber_prekey_id=body.kyber_prekey.id,
        kyber_prekey_public=body.kyber_prekey.public,
        kyber_prekey_signature=body.kyber_prekey.signature,
        kyber_prekey_uploaded_at=now,
    )
    db.add(device)
    for pk in body.one_time_prekeys:
        db.add(OneTimePreKey(uin=uin, prekey_id=pk.id, public_key=pk.public, device_id=next_id))
    await db.commit()
    return DeviceRegisterOut(device_id=next_id)


@router.get("/{uin}/devices", response_model=DevicesOut)
async def list_devices(
    uin: int,
    _me: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> DevicesOut:
    """Every device of `uin` a sender should fan out to: the primary device
    (deviceId 1) when the user has a libsignal bundle, plus each non-revoked
    secondary device."""
    user = await db.get(User, uin)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such user")
    devices: list[DeviceInfo] = []
    if user.signal_identity_key is not None:
        devices.append(DeviceInfo(device_id=PRIMARY_DEVICE_ID, label="primary"))
    rows = (
        await db.execute(
            select(Device)
            .where(Device.uin == uin, Device.revoked_at.is_(None))
            .order_by(Device.device_id.asc())
        )
    ).scalars().all()
    for d in rows:
        devices.append(DeviceInfo(device_id=d.device_id, label=d.label))
    return DevicesOut(uin=uin, devices=devices)


@router.get("/{uin}/devices/{device_id}/bundle", response_model=BundleOut)
async def fetch_device_bundle(
    uin: int,
    device_id: int,
    _me: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> BundleOut:
    """Per-device prekey bundle for X3DH against a SPECIFIC device of `uin`.
    deviceId 1 = the primary (phone) bundle on the User row (delegates to the
    legacy path); >= 2 = a secondary device. Consumes one OPK from THAT
    device's pool."""
    if device_id == PRIMARY_DEVICE_ID:
        return await fetch_bundle(uin, _me, db)

    device = (
        await db.execute(
            select(Device).where(
                Device.uin == uin,
                Device.device_id == device_id,
                Device.revoked_at.is_(None),
            )
        )
    ).scalar_one_or_none()
    if device is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such device")

    opk = await _claim_opk(db, uin=uin, device_id=device_id)
    opk_out: OneTimePreKeyIn | None = None
    if opk is not None:
        opk_out = OneTimePreKeyIn(id=opk.prekey_id, public=opk.public_key)
        await db.commit()

    return BundleOut(
        uin=uin,
        device_id=device.device_id,
        sealed_sender_pub=device.sealed_sender_pub,
        registration_id=device.signal_registration_id,
        signal_identity_key=device.signal_identity_key,
        signed_prekey=SignedPreKey(
            id=device.signed_prekey_id,
            public=device.signed_prekey_public,
            signature=device.signed_prekey_signature,
        ),
        kyber_prekey=KyberPreKey(
            id=device.kyber_prekey_id,
            public=device.kyber_prekey_public,
            signature=device.kyber_prekey_signature,
        ),
        one_time_prekey=opk_out,
    )


@router.post("/devices/{device_id}/prekeys", status_code=status.HTTP_204_NO_CONTENT)
async def replenish_device_prekeys(
    device_id: int,
    body: PreKeysIn,
    uin: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Top up a secondary device's OPK pool. Caller must own the device.
    Idempotent on prekey_id collision, like the primary /keys/prekeys."""
    device = (
        await db.execute(
            select(Device).where(
                Device.uin == uin,
                Device.device_id == device_id,
                Device.revoked_at.is_(None),
            )
        )
    ).scalar_one_or_none()
    if device is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such device")
    existing = set(
        (
            await db.execute(
                select(OneTimePreKey.prekey_id).where(
                    OneTimePreKey.uin == uin, OneTimePreKey.device_id == device_id
                )
            )
        ).scalars().all()
    )
    for pk in body.one_time_prekeys:
        if pk.id in existing:
            continue
        db.add(OneTimePreKey(uin=uin, prekey_id=pk.id, public_key=pk.public, device_id=device_id))
    await db.commit()
