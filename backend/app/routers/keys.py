import asyncio
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import log_identity
from app.core.db import engine, get_db
from app.core.config import settings
from app.core.rate_limit import rate_limit
from app.core.security import current_device_id, current_uin, current_uin_optional
from app.models.device import Device
from app.models.prekey import OneTimePreKey
from app.models.user import User, _as_aware
from app.services.apns import send_to_user as apns_send
from app.services.connection_manager import manager
from app.services.unifiedpush import send_to_user as up_send

log = logging.getLogger(__name__)

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
        # Starts the tombstone's clock (services/prekey_sweep). Set here rather
        # than in a DB default because this is the moment of consumption and
        # the row already existed.
        opk.consumed_at = datetime.now(timezone.utc)
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


async def _announce_device_event_now(
    uin: int,
    kind: str,
    device_id: int,
    label: str | None,
    push_body: str,
) -> None:
    """A key-slot event every session of the account should hear about (#643):
    a phrase-restored install was invisible — it appeared in no device list
    and announced nothing, so whoever held the phrase could quietly read as a
    full device. The slot claim is the one thing such an install cannot avoid
    if it wants to read or send v=2, so this is where the account learns.

    Live sessions get a registry-style WS event (same channel the QR-link
    screen already listens to); every device gets a push wake. ⚠ The alert
    BODY carries no label and no device detail: it travels through APNs and
    the push host in the clear. (The recipient uin rides every push of every
    kind as routing metadata — see apns.send_to_user — so the marginal thing
    those hosts learn here is the notif_kind.) Best-effort — a failed
    announcement must never fail the registration that caused it."""
    try:
        payload: dict[str, object] = {"type": kind, "device_id": device_id}
        if label:
            payload["label"] = label
        await manager.send(uin, payload)
    except Exception:  # noqa: BLE001 — bookkeeping must not break the claim
        # ⚠ `uin=` behind RCQ_LOG_IDENTITIES like every other line that names
        # a person. A `log.exception` is not exempt: it runs on a path that
        # fires for every device claim and every key rotation, and the account
        # it prints is the same one the push senders one layer down stopped
        # printing. The traceback is the operational half and it stays whole.
        log.exception("[keys] failed to announce %s uin=%s", kind, log_identity(uin))
    push_args = dict(
        alert_body=push_body,
        thread_id="devices",
        notif_kind=kind,
    )
    # One try EACH: a raise out of the APNs path (a corrupt .p8 makes
    # _get_jwt throw before its own network try) would otherwise swallow the
    # UnifiedPush wake with it — and Android is where most of this account's
    # devices are. A security announce must not be all-or-nothing across
    # transports.
    for send in (apns_send, up_send):
        try:
            await send(uin, **push_args)
        except Exception:  # noqa: BLE001
            log.exception(
                "[keys] failed to push %s uin=%s via %s",
                kind, log_identity(uin), send.__module__,
            )


# Strong refs to in-flight announces: asyncio holds only a weak one, and a
# task collected mid-await is an announcement that silently never happened.
_announce_tasks: set[asyncio.Task] = set()


def _announce_device_event(
    uin: int,
    kind: str,
    device_id: int,
    label: str | None,
    push_body: str,
) -> None:
    """Schedule the announce and return immediately.

    ⚠ Deliberately NOT awaited by the endpoints. apns_send walks the account's
    tokens with a 15s ceiling EACH, so awaiting it inline put an APNs stall
    directly in front of the 201 — and a client that gives up and retries a
    device registration burns a second slot of the 127 for the same install.
    The registration is the source of truth; telling the account about it is
    bookkeeping that must never hold the door."""
    task = asyncio.create_task(_announce_device_event_now(uin, kind, device_id, label, push_body))
    _announce_tasks.add(task)
    task.add_done_callback(_announce_tasks.discard)


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
    # A DIFFERENT identity under the primary slot means the install that held
    # it is gone — a reinstalled phone, a phrase restore, or someone else's
    # machine claiming the slot. The account's other devices deserve to hear
    # that (#643); a first-time bootstrap (no prior key) is silent, and so is
    # a re-upload of the same identity (signed-prekey rotation).
    prev_ik = user.signal_identity_key
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
    if prev_ik is not None and prev_ik != body.signal_identity_key:
        _announce_device_event(
            uin,
            "device_rekeyed",
            PRIMARY_DEVICE_ID,
            None,
            "This account's primary device was re-keyed",
        )


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


# ── Stage 3 of the metadata plan: key lookup stops naming the pair ─────────
#
# The three lookups below used to require the sender's own session token. The
# token bought nothing the endpoints need (they serve PUBLIC key material) and
# cost exactly one thing: every lookup told this island, under A's identity,
# whose keys A was fetching, i.e. "A is about to talk to B", on every session
# start and on every device-list refresh. The queue row was being stripped of
# the sender; this was the same pair, written elsewhere.
#
# Now they are open. What bounds them instead:
#   * a per-IP rate limit on all three (the device list is harmless to read;
#     a bundle without a one-time prekey is too: the signed prekey is public);
#   * the one thing worth protecting, the one-time prekey pool, is handed out
#     only against an anonymous deposit token (RFC 9474 blind signature, spent
#     once, unlinkable to its issuance) in `X-Deposit-Token`, or, for a client
#     that has not yet learned to mint one, against its session token as
#     before. A caller with neither gets the bundle minus the OPK, which
#     libsignal accepts (weaker first-message initiation, nothing else).
# The session-token path is the transition and goes when every client mints;
# the `anon_keys` capability tells a client which path this island offers.
_TOKEN_HEADER = "x-deposit-token"


def _token_from_request(request: Request) -> dict | None:
    """`X-Deposit-Token: <base64 of the {epoch_id, prepared, sig} JSON>`, or None."""
    raw = request.headers.get(_TOKEN_HEADER)
    if not raw:
        return None
    import base64
    import json
    try:
        pad = "=" * (-len(raw) % 4)
        blob = base64.urlsafe_b64decode(raw + pad)
        obj = json.loads(blob)
        return obj if isinstance(obj, dict) else {}
    except Exception:
        return {}


async def _may_take_opk(request: Request, me: int | None) -> bool:
    """Whether this bundle fetch is allowed to consume a one-time prekey.

    A presented token is verified and spent; a bad or replayed one is a 403
    rather than a silent downgrade, so a client with a stale epoch learns to
    re-fetch `/deposit-auth/params` instead of quietly losing its OPKs."""
    token = _token_from_request(request)
    if token is not None:
        if not settings.DEPOSIT_AUTH_ENABLED:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "this island issues no deposit tokens")
        from app.core import deposit_auth_store
        from app.core.redis import get_redis
        if not await deposit_auth_store.verify_and_consume_token(token, await get_redis()):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "invalid or spent deposit token")
        return True
    return me is not None


@router.get(
    "/{uin}/bundle",
    response_model=BundleOut,
    dependencies=[Depends(rate_limit("keys_bundle", 300, 60))],
)
async def fetch_bundle(
    uin: int,
    request: Request,
    me: int | None = Depends(current_uin_optional),
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
    # ⚠ This withholding is for the LEGACY caller only — the one that asked for
    # "the bundle of this account" and can therefore reach exactly one device.
    # A device-aware sender goes through GET /keys/{uin}/devices/{id}/bundle,
    # which calls `_primary_bundle` below directly and is NOT gated: it encrypts
    # a separate copy per device, which is the real fix this guard stands in for.
    from app.routers.devices import has_linked_devices  # local import: avoid cycle
    if await has_linked_devices(uin):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "multi-device: v=1 only")
    return await _primary_bundle(uin, db, request, me)


async def _primary_bundle(uin: int, db: AsyncSession, request: Request | None = None, me: int | None = None) -> BundleOut:
    """The primary device's (device 1) bundle, with no multi-device gate.

    Split out of `fetch_bundle` so the per-device path can reach device 1 while
    the legacy path keeps falling back to v=1 for a multi-homed account.
    """
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

    # The token is spent only once the bundle is known to exist: a token burnt
    # on a 404 is a token the sender minted for nothing.
    with_opk = True if request is None else await _may_take_opk(request, me)
    opk = await _claim_opk(db, uin=uin, device_id=None) if with_opk else None
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
    # The libsignal identity this device currently publishes.
    #
    # ⚠ Here so that a sender can ask "is the install I share a ratchet with
    # still the one behind this device?" WITHOUT reading a bundle. Reading a
    # bundle CONSUMES one of the account's one-time prekeys (see _claim_opk),
    # and a silence probe that re-reads a bundle every half hour to answer a
    # question that is almost always "yes, unchanged" drains a pool that only
    # refills while its owner's client is online. An emptied pool means every
    # later X3DH with that account loses its one-time contributory secret —
    # the probe would erode the exact property it exists to protect.
    #
    # Additive and public: this key is in every bundle the same caller can
    # already fetch. Old clients ignore the field.
    signal_identity_key: str | None = None


class DevicesOut(BaseModel):
    """Devices of `uin` with a usable libsignal bundle. A fanning-out sender
    fetches each device's bundle and sends one ciphertext per entry."""

    uin: int
    devices: list[DeviceInfo]


@router.post("/devices", response_model=DeviceRegisterOut, status_code=status.HTTP_201_CREATED)
async def register_device(
    body: DeviceRegisterIn,
    uin: int = Depends(current_uin),
    auth_device: str | None = Depends(current_device_id),
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
        # The bridge report #695 was missing: remember WHICH auth session
        # claimed this slot, so retiring the slot can also end the session.
        auth_device_id=auth_device,
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
    _announce_device_event(
        uin,
        "device_registered",
        next_id,
        body.label,
        "New device connected to this account",
    )
    return DeviceRegisterOut(device_id=next_id)


@router.get(
    "/{uin}/devices",
    response_model=DevicesOut,
    dependencies=[Depends(rate_limit("keys_devices", 600, 60))],
)
async def list_devices(
    uin: int,
    me: int | None = Depends(current_uin_optional),
    db: AsyncSession = Depends(get_db),
) -> DevicesOut:
    """Every device of `uin` a sender should fan out to: the primary device
    (deviceId 1) when the user has a libsignal bundle, plus each non-revoked
    secondary device."""
    user = await db.get(User, uin)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such user")
    # The user-typed label ("Web (Chrome)", a browser and OS fingerprint) is
    # served to the OWNER only, whose key-slots screen names the slots by it
    # and who authenticates this one call about their own account (no pair to
    # leak there). A sender asking about somebody else gets "".
    own = me is not None and me == uin
    devices: list[DeviceInfo] = []
    if user.signal_identity_key is not None:
        devices.append(DeviceInfo(
            device_id=PRIMARY_DEVICE_ID,
            label="primary" if own else "",
            signal_identity_key=user.signal_identity_key,
        ))
    rows = (
        await db.execute(
            select(Device)
            .where(Device.uin == uin, Device.revoked_at.is_(None))
            .order_by(Device.device_id.asc())
        )
    ).scalars().all()
    for d in rows:
        devices.append(DeviceInfo(
            device_id=d.device_id,
            label=(d.label or "") if own else "",
            signal_identity_key=d.signal_identity_key,
        ))
    return DevicesOut(uin=uin, devices=devices)


@router.get(
    "/{uin}/devices/{device_id}/bundle",
    response_model=BundleOut,
    dependencies=[Depends(rate_limit("keys_bundle", 300, 60))],
)
async def fetch_device_bundle(
    uin: int,
    device_id: int,
    request: Request,
    me: int | None = Depends(current_uin_optional),
    db: AsyncSession = Depends(get_db),
) -> BundleOut:
    """Per-device prekey bundle for X3DH against a SPECIFIC device of `uin`.
    deviceId 1 = the primary (phone) bundle on the User row (delegates to the
    legacy path); >= 2 = a secondary device. Consumes one OPK from THAT
    device's pool."""
    if device_id == PRIMARY_DEVICE_ID:
        return await _primary_bundle(uin, db, request, me)

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

    with_opk = await _may_take_opk(request, me)
    opk = await _claim_opk(db, uin=uin, device_id=device_id) if with_opk else None
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


def _strip_revoked_device(device: Device, now: datetime) -> None:
    """Reduce a revoked row to the (uin, device_id) tombstone and nothing else.

    A revoked device kept its full libsignal bundle, its sealed-sender public
    key, the user-typed label ("Web (Chrome)", a browser and OS fingerprint)
    and its whole lifespan, forever. Verified by grep before this was written:
    every read path in the codebase filters `revoked_at IS NULL`, and the ONE
    consumer of a dead row is the id allocator in `register_device`, which does
    `max(device_id) + 1` over every row of the account and needs the pair and
    nothing else. So there is no reader to break.

    Why the slot stays reserved rather than the row being deleted here: a
    sender's cached device roster, and any copy already sitting in
    `offline_messages` addressed to `to_device_id`, both outlive the revoke. If
    the number were handed to a new device, ciphertext meant for the old one
    would be delivered to an install that cannot open it. `services/device_sweep`
    removes the tombstone once that is no longer possible.

    `created_at` is NOT NULL and cannot go, so it is folded onto the revoke
    instant: the row stops recording how long the device lived, which is the
    part that says something about the person.
    """
    device.label = None
    device.auth_device_id = None
    device.sealed_sender_pub = ""
    device.signal_identity_key = ""
    device.signal_registration_id = 0
    device.signed_prekey_id = 0
    device.signed_prekey_public = ""
    device.signed_prekey_signature = ""
    device.signed_prekey_uploaded_at = now
    device.kyber_prekey_id = 0
    device.kyber_prekey_public = ""
    device.kyber_prekey_signature = ""
    device.kyber_prekey_uploaded_at = now
    device.created_at = now


@router.post("/devices/{device_id}/revoke", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_device_slot(
    device_id: int,
    uin: int = Depends(current_uin),
    caller_device: str | None = Depends(current_device_id),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Retire a key slot (founder batch 21.08, item 13): senders stop fanning
    out to it on their next roster fetch, and its one-time prekeys are gone so
    no NEW session can be established against it. The install that held the
    slot keeps whatever it already decrypted — a revoke is "stop talking to
    it", not remote erasure — and its AUTH session, if it is a linked one, is
    disconnected separately on the phone's linked-devices screen.

    Slot 1 is refused: that is the account's primary bundle on the User row,
    the thing every legacy sender encrypts to. Removing it is a key rotation
    (`/auth/reissue`), not a slot operation.

    Gated by the same [revoker_gate] cooldown as session revocation: a
    freshly-linked session cannot strip the owner's slots until it has either
    outlived the cooldown or is older than what it touches."""
    if device_id == PRIMARY_DEVICE_ID:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail={"code": "primary_slot"})
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
    from app.routers.devices import revoker_gate

    await revoker_gate(uin, caller_device, device.created_at)
    label = device.label
    # Report #695: retiring the slot alone was a polite fiction. The slot table
    # and the session registry were two disjoint registries with no bridge, so
    # "deleting" an old phone here stopped senders encrypting to it and nothing
    # else: the phone stayed signed in, its socket stayed up, and it went on
    # reading and writing. When the slot knows which auth session claimed it,
    # that session is ended the same way the linked-devices screen ends one:
    # token denylisted (enforced on presentation AND on minting, #607) and the
    # open sockets kicked. Not for the CALLER's own slot: revoking the slot you
    # are speaking through means "stop fanning out to me", not "log me out".
    #
    # ⚠ This cuts the session, not the knowledge. An install that holds the
    # recovery phrase can register itself anew under a fresh install id; the
    # only full eviction of a seed-holder is a key rotation (/auth/reissue).
    # Slots claimed before `auth_device_id` existed carry NULL and keep the
    # old retire-only behaviour.
    session_to_end = device.auth_device_id
    now = datetime.now(timezone.utc)
    device.revoked_at = now
    await db.execute(
        delete(OneTimePreKey).where(OneTimePreKey.uin == uin, OneTimePreKey.device_id == device_id)
    )
    _strip_revoked_device(device, now)
    await db.commit()
    if session_to_end and session_to_end != caller_device:
        from app.routers.devices import _revoke as _revoke_session

        await _revoke_session(uin, session_to_end, db)
    _announce_device_event(
        uin,
        "device_slot_revoked",
        device_id,
        label,
        "A device slot was removed from this account",
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
