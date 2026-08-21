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
import base64
import binascii
import json

from fastapi import APIRouter, Body, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.db import get_db
from app.core.rate_limit import rate_limit
from app.core.security import current_uin
from app.models.federation import GossipRecord, HomeIslandRecord
from app.models.user import User

router = APIRouter(prefix="/federation", tags=["federation"])

# The signed document is small: a key, a short list of (host, uin) homes, a
# timestamp, a signature. Anything larger is malformed or abusive.
_MAX_DOC_BYTES = 8 * 1024


def _front_alias_in_homes(homes: list) -> str | None:
    """The first `homes` host that is a configured CDN/domain FRONT, or None.

    A front is a road to an island, not an island: a record listing one as a
    home describes a mailbox that does not exist ("backup" copies land on the
    fronted island itself, so the redundancy is fiction). Old clients that
    stamped the road instead of the island published exactly such records, and
    the clients' read-before-publish carry-over then re-publishes the phantom
    home forever — the store is where the loop is broken."""
    aliases = {h.strip().lower() for h in settings.FRONT_ALIAS_HOSTS.split(",") if h.strip()}
    if not aliases:
        return None
    for h in homes:
        host = h.get("host") if isinstance(h, dict) else None
        if isinstance(host, str) and host.strip().lower() in aliases:
            return host
    return None


def _record_signed_bytes(doc: dict) -> bytes:
    """Reconstruct the EXACT bytes a client signs for a home-island record.

    Must match the clients' `signedPart` + canonical JSON byte-for-byte
    (web `federation.ts`, Android `RcqFederation.kt`, iOS `RcqFederation.swift`):
    the object `{v:1, ik, sk, homes:[{host,uin}…], ts}` serialized with keys
    sorted recursively, compact separators, UTF-8, ints as ints. Built field by
    field (never "doc minus sig") so an injected field can never enter the
    signed bytes.
    """
    homes = [{"host": h["host"], "uin": h["uin"]} for h in doc["homes"]]
    part = {"v": 1, "ik": doc["ik"], "sk": doc["sk"], "homes": homes, "ts": doc["ts"]}
    return json.dumps(part, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _verify_record_sig(doc: dict) -> bool:
    """True iff `doc.sig` is a valid Ed25519 signature over the canonical signed
    bytes under `doc.sk`. Self-authenticates an unauthenticated gossip write:
    only the holder of `sk`'s private key can produce a row under `sk`."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(doc["sk"]))
        pub.verify(base64.b64decode(doc["sig"]), _record_signed_bytes(doc))
        return True
    except (InvalidSignature, ValueError, KeyError, TypeError, binascii.Error):
        return False


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
    front = _front_alias_in_homes(homes)
    if front is not None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"front is not an island: {front}")

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
        await db.commit()
        return {"ok": True, "ts": ts}
    db.add(HomeIslandRecord(uin=uin, doc=raw, ts=ts))
    try:
        await db.commit()
    except IntegrityError:
        # Two first boots of a fresh account can both pass the SELECT above and
        # both INSERT; the loser used to surface as a 500. Take the update path
        # against the row the winner just wrote, same anti-rollback rule.
        await db.rollback()
        existing = (
            await db.execute(select(HomeIslandRecord).where(HomeIslandRecord.uin == uin))
        ).scalar_one()
        if ts < existing.ts:
            raise HTTPException(status.HTTP_409_CONFLICT, "stale ts")
        existing.doc = raw
        existing.ts = ts
        await db.commit()
    return {"ok": True, "ts": ts}


@router.get(
    "/island-record/{uin}",
    dependencies=[Depends(rate_limit("federation_island_record_get", 120, 60))],
)
async def get_island_record(
    uin: int,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Return a user's signed home-island record, or 404 if none is stored.

    Open by design: the record is public, signed routing data that reveals only
    where an identity is reachable. The client verifies its signature.

    IP rate-limited to bound UIN enumeration, the same reason and the same
    shape as `/federation/keys/{uin}` below. Open and unlimited, this was the
    cheaper of the two oracles: one GET per uin walks out the whole
    cross-island linkage map (1925 records on the flagship): who is reachable
    on which island, which is a social graph across borders, not a key card.

    120/min because that is what the neighbour uses and because the traffic
    says it is far above any real client. Measured on the flagship's own access
    log, 02.08 to 21.08: 5998 reads, and the busiest single minute from one
    entire /24 was 28, and a /24 aggregates a relay's whole user base, since
    a relayed request arrives wearing the relay's address. A client resolves a
    given peer's record at most once per ten minutes (`PEER_CACHE_TTL_MS`, the
    same constant in web and Android) plus one for itself at boot, so one
    device's steady state is a handful per minute at worst.
    """
    row = (
        await db.execute(select(HomeIslandRecord).where(HomeIslandRecord.uin == uin))
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no record")
    return json.loads(row.doc)


# ── Gossip: mirror ANY identity's signed record (address-mobility B1) ──────────
# These let a peer's routing record be served from any honest island a contact
# uses, not only the peer's own island. Keyed by the global identity (`sk`),
# self-authenticated by server-side signature verification on write.


@router.put(
    "/gossip-record",
    dependencies=[Depends(rate_limit("federation_gossip_put", 60, 60))],
)
async def put_gossip_record(
    doc: dict = Body(...),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Mirror a signed home-island record onto this island (open, no auth).

    A client mirrors a contact's record here after it has resolved + verified
    it, so this island can serve that contact's homes to others when the
    contact's own island is unreachable. Unauthenticated, so the server itself
    VERIFIES the Ed25519 signature over the canonical signed bytes under
    `doc.sk` — a row can only exist for a document that key actually signed.
    Anti-rollback by `ts`, keyed by `sk`.
    """
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
    sk = doc.get("sk")
    if not isinstance(sk, str) or not isinstance(doc.get("ik"), str) or not isinstance(doc.get("sig"), str):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "missing ik/sk/sig")
    front = _front_alias_in_homes(homes)
    if front is not None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"front is not an island: {front}")
    # The whole point of an open write: prove the record is genuinely signed by
    # the key it claims, so a stranger cannot poison `sk`'s slot.
    if not _verify_record_sig(doc):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "bad signature")

    existing = (
        await db.execute(select(GossipRecord).where(GossipRecord.sk == sk))
    ).scalar_one_or_none()
    if existing is not None:
        if ts < existing.ts:
            raise HTTPException(status.HTTP_409_CONFLICT, "stale ts")
        existing.doc = raw
        existing.ts = ts
    else:
        db.add(GossipRecord(sk=sk, doc=raw, ts=ts))
    await db.commit()
    return {"ok": True, "ts": ts}


@router.get(
    "/gossip-record",
    dependencies=[Depends(rate_limit("federation_gossip_get", 120, 60))],
)
async def get_gossip_record(
    sk: str = Query(..., min_length=1, max_length=128),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Return a mirrored signed record by its identity key `sk`, or 404.

    Open: the record is public signed routing data. `sk` is a base64 query
    param (path-unsafe `+`/`/`). The client re-verifies the signature and
    anchors `sk`/`ik` to the peer it already knows before trusting the homes.

    Rate-limited for the same reason as the by-uin read above and the key card
    below: bounding enumeration. A 32-byte key is not guessable the way a uin
    is, so what this bounds is bulk HARVESTING: walking a list of keys you
    already hold and turning it into the same cross-island map. The PUT beside
    it has been limited since it shipped; the GET was simply missed. Same
    120/min, and this endpoint is measured in single digits per WEEK on the
    flagship (10 reads, 02.08 to 21.08).
    """
    row = (
        await db.execute(select(GossipRecord).where(GossipRecord.sk == sk.strip()))
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


class UinForKeyOut(BaseModel):
    uin: int


@router.get(
    "/uin-for-key",
    response_model=UinForKeyOut,
    dependencies=[Depends(rate_limit("federation_uin_for_key", 120, 60))],
)
async def uin_for_key(
    signing_key: str,
    db: AsyncSession = Depends(get_db),
) -> UinForKeyOut:
    """Resolve the local account bound to a given Ed25519 signing key (base64).

    Open + idempotent. The signing key is already public (it ships in the open
    key card above), so this exposes nothing new — it's just the inverse map,
    `key → uin`. Used by cross-island GROUP add (§5c): the inviting member
    looks up whether the foreign contact already has an account on THIS island
    before registering one for their keys, so an owner-initiated add never
    mints a duplicate account. Returns the SAME lowest uin that
    `/auth/recover` would resolve for the key (so the added uin matches the one
    the contact later recovers). IP rate-limited to bound enumeration.
    """
    sk = signing_key.strip()
    uin = (
        await db.execute(
            select(User.uin).where(User.signing_key == sk).order_by(User.uin).limit(1)
        )
    ).scalar_one_or_none()
    if uin is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no account for key")
    return UinForKeyOut(uin=uin)
