import asyncio
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.db import get_db
from app.core.rate_limit import rate_limit
from app.core.security import current_device_id, current_uin, current_uin_optional
from app.models.capability import UserCapability
from app.models.group import Group, GroupMember, OfflineGroupMessage
from app.models.message import OfflineMessage
from app.models.queue_cursor import QueueCursor
from app.models.user import User
from app.services.apns import is_group_muted, send_to_user as apns_send
from app.services.unifiedpush import send_to_user as up_send
from app.services.connection_manager import manager

log = logging.getLogger(__name__)

# Envelope types where a push notification makes sense. We skip "ephemeral"
# things like read receipts, typing relays, reactions, bounces, visits and
# delete-tombstones — they're either delivery-state plumbing or cosmetic, no
# benefit in waking the recipient's device for one.
# "secscreen" carries BOTH the screenshot-taken notice (the recipient should be
# alerted immediately, even backgrounded — it's a secret-chat security signal)
# AND the silent secure-mode toggle. We push it so a screenshot taken while the
# recipient's WS is down/stale doesn't sit unseen until they reopen the app; the
# NSE shows a real "screenshot" body for the shot and suppresses the toggle.
_PUSHABLE_TYPES = {"message", "system", "secscreen"}

router = APIRouter(prefix="/messages", tags=["messages"])


class SealedSendIn(BaseModel):
    to_uin: int
    # message | nudge | delete | system | read | reaction | bounce | visit.
    # The server is type-agnostic — it just routes the opaque payload — so the
    # list is informational. New envelope kinds don't need a server change.
    envelope_type: str = Field(default="message")
    payload: str  # base64 LibSignal sealed-sender ciphertext (sender lives inside)
    # F3 deposit-auth: an OPTIONAL anonymous blinded token {epoch_id, prepared, sig}
    # the recipient's island issued (RFC 9474 RSABSSA). When present it is verified
    # + consumed (single-use), letting the island rate-limit deposits without
    # de-anonymizing the sender. Absent = the legacy per-IP path (back compatible).
    deposit_token: dict | None = None


class SendOut(BaseModel):
    delivered: bool
    queued: bool
    server_time: datetime


class HistoryRow(BaseModel):
    id: int
    envelope_type: str
    payload: str
    received_at: datetime
    group_id: int | None = None


@router.post(
    "/sealed",
    response_model=SendOut,
    # Cap sends at 120/min per identity. Sealed-sender means we
    # can't always bind to UIN (server doesn't know who's sending),
    # so the limiter falls back to client IP. 120/min covers heavy
    # legit use (typing fast, sending media) while one-script abuse
    # tops out before saturating uvicorn.
    dependencies=[Depends(rate_limit("messages_send", 120, 60))],
)
async def send_sealed(
    body: SealedSendIn,
    db: AsyncSession = Depends(get_db),
) -> SendOut:
    """Anonymous, server-side metadata-free 1:1 delivery.

    The server intentionally does NOT take any auth here — sealed sender is the whole
    point: the recipient is the only party who can identify the sender (by decrypting
    the envelope client-side). Block lists therefore move to the client: the recipient
    decrypts, sees who sent it, drops the message silently if blocked.

    For dev we accept all requests. Production will plant a delivery-token mechanism
    here (recipient-issued tokens, redeemable anonymously) to discourage spam without
    re-introducing sender identification. Marked TODO below.
    """
    target = await db.get(User, body.to_uin)
    if target is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such user")

    # F3 deposit-auth (anonymous delivery-token rate limiting). A token, when
    # present, is verified + atomically consumed (single-use, double-spend
    # rejected) — sealed sender preserved. Absent = the legacy per-IP cap above.
    # Enforcement (DEPOSIT_AUTH_REQUIRED) is a deliberate operator flip once
    # clients mint tokens; until then this is purely additive.
    token_ok = False
    if body.deposit_token is not None:
        from app.core import deposit_auth_store
        from app.core.redis import get_redis
        if not await deposit_auth_store.verify_and_consume_token(body.deposit_token, await get_redis()):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "invalid or spent deposit token")
        token_ok = True
    if settings.DEPOSIT_AUTH_REQUIRED and not token_ok:
        raise HTTPException(status.HTTP_402_PAYMENT_REQUIRED, "a deposit token is required")

    now = datetime.now(timezone.utc)
    pkt = {
        "type": body.envelope_type,
        "payload": body.payload,
        "server_time": now.isoformat(),
    }
    # Always queue alongside WS delivery. `manager.send()` returning
    # True only means the bytes hit the OS write buffer — the recipient
    # can still lose them if their WS dropped mid-flight, if iOS
    # backgrounded with a stale socket, or if the network NAT'ed
    # them out. The client dedupes by message UUID in MessageStore,
    # so receiving the same envelope via WS and via /queue drain on
    # next reconnect is a no-op. Drain-and-delete pattern in fetch_queue
    # keeps the table from growing.
    delivered = await manager.send(body.to_uin, pkt)
    msg = OfflineMessage(
        to_uin=body.to_uin,
        envelope_type=body.envelope_type,
        payload=body.payload,
        received_at=now,
    )
    db.add(msg)
    await db.commit()
    queued = True
    pushed = 0
    # APNs push only when WS thought it was offline — otherwise the
    # active client gets the envelope via WS already and a redundant
    # push would buzz the user twice.
    if not delivered and body.envelope_type in _PUSHABLE_TYPES:
        pushed = await apns_send(
            body.to_uin,
            alert_body="New message",
            envelope_b64=body.payload,
            envelope_type=body.envelope_type,
        )
        # Android has no APNs — fire the parallel UnifiedPush wake (no-op when
        # the recipient has no Android endpoints, the iOS-only common case).
        pushed += await up_send(
            body.to_uin,
            alert_body="New message",
            envelope_b64=body.payload,
            envelope_type=body.envelope_type,
        )
    log.warning(
        "[sealed] to=%s type=%s ws_delivered=%s queued=%s pushed=%s",
        body.to_uin, body.envelope_type, delivered, queued, pushed,
    )
    return SendOut(delivered=delivered, queued=queued, server_time=now)


class GroupRecipientPayload(BaseModel):
    to_uin: int
    payload: str


class GroupSealedSendIn(BaseModel):
    group_id: int
    envelope_type: str = Field(default="message")
    # Stage 2 e2ee: sender encrypts the envelope ONCE PER MEMBER (skipping
    # themselves) using each member's identity_key. Server fans the right
    # ciphertext to the right recipient. The list shape replaces the old
    # single-payload schema — every iOS Stage-1 client sends this version.
    payloads: list[GroupRecipientPayload]


@router.post(
    "/group-sealed",
    response_model=SendOut,
    # Group sends ship N payloads in one POST (one per member), so
    # the per-call cost is higher than a 1:1 send. 60/min keeps a
    # script from group-blasting at scale while a real user posting
    # in a few groups stays well under.
    dependencies=[Depends(rate_limit("messages_group_send", 60, 60))],
)
async def send_group_sealed(
    body: GroupSealedSendIn,
    caller: int | None = Depends(current_uin_optional),
    db: AsyncSession = Depends(get_db),
) -> SendOut:
    """Per-recipient fan-out for a group. Sender provides one ciphertext
    per member; server validates each `to_uin` is actually a member and
    routes accordingly. Server has no plaintext access — every payload is
    a sealed-sender envelope encrypted to that one recipient's identity
    key. Confidentiality and authentication match the 1:1 path.

    Broadcast-mode enforcement (post_policy='owner_only'): sealed sender
    normally hides WHICH member sent a message, but in a broadcast group
    every post is known to come from the owner, so requiring the owner to
    authenticate leaks nothing AND is the only way to enforce the policy
    server-side — the composer-hide on clients is bypassable (an old/web/
    modified client can POST here directly). We therefore reject any
    *identified* non-owner caller. Auth is OPTIONAL so we stay
    backward-compatible: clients that still send the group fan-out
    anonymously (no token) fall back to the client-side gate for now; once
    every client attaches the owner token for owner_only sends, this can
    tighten to reject anonymous owner_only posts too (see TODO below)."""
    # Only an actual POST ("message" — text/media bubble) is gated. Reactions,
    # reads, typing, edits and deletes still fan out from any member so a
    # broadcast group keeps its reaction/read interactions (and web clients,
    # which always send a token, don't get their member reactions rejected).
    if body.envelope_type == "message":
        g = await db.get(Group, body.group_id)
        if g is not None and g.post_policy == "owner_only" and caller is not None and caller != g.owner_uin:
            # An authenticated caller who is NOT the owner tried to post to a
            # broadcast group. Web clients always send their token, so this
            # closes the "any member can post via chat.rcq.app" hole at once.
            raise HTTPException(status.HTTP_403_FORBIDDEN, "owner_only: only the group owner may post")
        # TODO(owner_only-phase2): once Android+iOS attach the owner token for
        # owner_only MESSAGE sends (anonymous otherwise, to keep sealed-sender
        # for 'all' groups), drop the `caller is not None` clause so an
        # anonymous owner_only post is rejected too — closing the
        # modified-native-client bypass.
    members = set(
        (
            await db.execute(select(GroupMember.uin).where(GroupMember.group_id == body.group_id))
        ).scalars().all()
    )
    if not members:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "group has no members")

    now = datetime.now(timezone.utc)
    delivered_any = False
    offline_recipients: list[int] = []
    for entry in body.payloads:
        # Drop entries that don't correspond to real group members. Cheap
        # client mistake guard — we don't error on it because the client
        # is anonymous (sealed sender) and we can't tell who they are.
        if entry.to_uin not in members:
            continue
        pkt = {
            "type": body.envelope_type,
            "payload": entry.payload,
            "group_id": body.group_id,
            "server_time": now.isoformat(),
        }
        # Always queue + WS-attempt. `manager.send()` returning True is
        # optimistic (bytes in OS buffer != client got them) so we
        # queue regardless so the recipient drains anything they
        # missed on next /messages/queue fetch. Client dedupes by UUID.
        delivered = await manager.send(entry.to_uin, pkt)
        if delivered:
            delivered_any = True
        else:
            offline_recipients.append(entry.to_uin)
        db.add(OfflineGroupMessage(
            to_uin=entry.to_uin,
            group_id=body.group_id,
            envelope_type=body.envelope_type,
            payload=entry.payload,
            received_at=now,
        ))
    await db.commit()
    # Group fan-out: same per-recipient encrypted-envelope pattern as
    # 1:1. Each offline member needs THEIR ciphertext (each is sealed to
    # one identity key), so we look up the matching payload entry from
    # the request before pushing.
    #
    # APNs sends are detached (fire-and-forget) so the sender's HTTP
    # response doesn't wait on N×Apple-roundtrip. With ~20-member groups
    # the awaited loop was holding the sender's HTTP response for
    # multiple seconds, leaving the sender's bubble stuck on the
    # "sending" clock icon while recipients had already received the
    # message via WS. Each task opens its own DB session inside
    # is_group_muted + apns_send, so detaching is safe.
    if body.envelope_type in _PUSHABLE_TYPES:
        payload_by_uin = {p.to_uin: p.payload for p in body.payloads}
        envelope_type = body.envelope_type
        group_id = body.group_id
        # Title the banner with the group's name + carry it in the payload so
        # the client shows WHICH group (this sealed path used to send neither,
        # so small-group pushes always read as the generic "New group message").
        gname = g.name or "RCQ"

        async def _push(target_uin: int) -> None:
            if await is_group_muted(target_uin, group_id):
                return
            await apns_send(
                target_uin,
                alert_title=gname,
                alert_body="New group message",
                envelope_b64=payload_by_uin.get(target_uin),
                envelope_type=envelope_type,
                thread_id=f"group-{group_id}",
                group_id=group_id,
                group_name=gname,
            )
            await up_send(
                target_uin,
                alert_title=gname,
                alert_body="New group message",
                envelope_b64=payload_by_uin.get(target_uin),
                envelope_type=envelope_type,
                thread_id=f"group-{group_id}",
                group_id=group_id,
                group_name=gname,
            )

        for uin in offline_recipients:
            asyncio.create_task(_push(uin))
    log.warning(
        "[group-sealed] gid=%s type=%s payloads=%d delivered_any=%s offline=%d",
        body.group_id, body.envelope_type, len(body.payloads),
        delivered_any, len(offline_recipients),
    )
    return SendOut(delivered=delivered_any, queued=True, server_time=now)


class GroupBroadcastIn(BaseModel):
    group_id: int
    # Declared inner type — "message" today (reactions/edits/reads keep the
    # per-member path for now). Drives the owner_only gate + pushability;
    # the queued/WS envelope itself always rides as type "gmsg".
    envelope_type: str = Field(default="message")
    # base64 of the sender-keys wire JSON {v, kid, e, i, n, ct}: ONE
    # ChaCha20-Poly1305 ciphertext under the sender's current group message
    # key. The server cannot read it and cannot tell who sent it — `kid` is
    # an opaque per-(sender, group, epoch) distribution id, so group posts
    # stay pseudonymous at the server (vs fully anonymous on the legacy
    # sealed path; accepted — members learn the sender anyway).
    payload: str = Field(max_length=1_500_000)


@router.post(
    "/group-broadcast",
    response_model=SendOut,
    # One small POST per group message regardless of group size — same
    # budget as 1:1 sends (the legacy group endpoint's 60/min existed
    # because every call carried N payloads).
    dependencies=[Depends(rate_limit("messages_broadcast", 120, 60))],
)
async def send_group_broadcast(
    body: GroupBroadcastIn,
    caller: int | None = Depends(current_uin_optional),
    db: AsyncSession = Depends(get_db),
) -> SendOut:
    """Sender-keys group delivery: the sender encrypts ONCE with their group
    chain key and the server fans the SAME ciphertext to every member whose
    client advertised the `sender_keys` capability — O(1) crypto + upload for
    the sender instead of the legacy once-per-member sealing. Members without
    the capability are deliberately skipped (they can't parse `gmsg`); the
    sender covers them with the legacy per-member fan-out (dual-send) until
    their clients update.

    The chain key itself was distributed per-member over the existing sealed
    channel (`skdm` envelopes via /messages/group-sealed), so confidentiality
    still ends at the members: the server only ever holds one opaque blob.

    owner_only enforcement is STRICT here from day one (unlike the legacy
    endpoint's phase-1 leniency): this endpoint is new, no deployed client
    posts to it anonymously in owner_only groups, so an unauthenticated or
    non-owner `message` broadcast to a broadcast-mode group is rejected
    outright."""
    g = await db.get(Group, body.group_id)
    if g is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such group")
    if (
        body.envelope_type == "message"
        and g.post_policy == "owner_only"
        and caller != g.owner_uin
    ):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "owner_only: only the group owner may post")

    recipients = (
        (
            await db.execute(
                select(GroupMember.uin)
                .join(UserCapability, UserCapability.uin == GroupMember.uin)
                .where(
                    GroupMember.group_id == body.group_id,
                    UserCapability.sender_keys.is_(True),
                )
            )
        ).scalars().all()
    )
    if not recipients:
        # A capable client always advertises before its first broadcast, so
        # at minimum the sender's own uin matches. Empty therefore means a
        # bogus group id / not-a-member race — nothing to deliver.
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no broadcast-capable members")

    now = datetime.now(timezone.utc)
    delivered_any = False
    offline_recipients: list[int] = []
    # The sender's own uin is included on purpose: their other devices get
    # the broadcast as the carbons copy (the sending device dedupes by
    # message UUID, same as the WS/queue double-delivery case).
    for uin in recipients:
        pkt = {
            "type": "gmsg",
            "payload": body.payload,
            "group_id": body.group_id,
            "server_time": now.isoformat(),
        }
        delivered = await manager.send(uin, pkt)
        if delivered:
            delivered_any = True
        else:
            offline_recipients.append(uin)
        db.add(OfflineGroupMessage(
            to_uin=uin,
            group_id=body.group_id,
            envelope_type="gmsg",
            payload=body.payload,
            received_at=now,
        ))
    await db.commit()
    # Push offline members for real posts only (mirrors _PUSHABLE_TYPES
    # gating on the declared inner type). Everyone gets the SAME envelope —
    # that's the whole point. The iOS NSE shows a generic group banner for
    # gmsg (it never advances ratchet state out-of-process).
    if body.envelope_type in _PUSHABLE_TYPES:
        group_id = body.group_id
        payload = body.payload
        # Title the banner with the group's name (not the generic "RCQ") so the
        # user can tell which group a push came from at a glance.
        gname = g.name or "RCQ"

        async def _push(target_uin: int) -> None:
            if await is_group_muted(target_uin, group_id):
                return
            await apns_send(
                target_uin,
                alert_title=gname,
                alert_body="New group message",
                envelope_b64=payload,
                envelope_type="gmsg",
                thread_id=f"group-{group_id}",
                group_id=group_id,
                group_name=gname,
            )
            await up_send(
                target_uin,
                alert_title=gname,
                alert_body="New group message",
                envelope_b64=payload,
                envelope_type="gmsg",
                thread_id=f"group-{group_id}",
                group_id=group_id,
                group_name=gname,
            )

        for uin in offline_recipients:
            # Never push the sender their OWN message: they backgrounded right
            # after sending and fell into offline_recipients. Their other
            # devices still get the WS/queue carbon — just no APNs banner.
            if uin == caller:
                continue
            asyncio.create_task(_push(uin))
    log.warning(
        "[group-broadcast] gid=%s type=%s recipients=%d delivered_any=%s offline=%d",
        body.group_id, body.envelope_type, len(recipients),
        delivered_any, len(offline_recipients),
    )
    return SendOut(delivered=delivered_any, queued=True, server_time=now)


class AckIn(BaseModel):
    # IDs the client successfully ingested into its local store. Two
    # parallel arrays because OfflineMessage.id and OfflineGroupMessage.id
    # are auto-increment per-table and can collide; clients split by the
    # `group_id` field on HistoryRow (None → direct, set → group).
    direct_ids: list[int] = Field(default_factory=list)
    group_ids: list[int] = Field(default_factory=list)


class AckOut(BaseModel):
    deleted: int


async def _advance_cursor(
    db: AsyncSession, uin: int, device_id: str, max_direct: int, max_group: int
) -> int:
    """Move THIS device's drain cursor forward (never backward), then reap any
    queued rows now below EVERY device's cursor. Returns rows reaped."""
    cursor = await db.get(QueueCursor, (uin, device_id))
    if cursor is None:
        cursor = QueueCursor(uin=uin, device_id=device_id, last_direct_id=0, last_group_id=0)
        db.add(cursor)
    if max_direct > cursor.last_direct_id:
        cursor.last_direct_id = max_direct
    if max_group > cursor.last_group_id:
        cursor.last_group_id = max_group
    await db.flush()
    return await _reap_below_min(db, uin)


async def _reap_below_min(db: AsyncSession, uin: int) -> int:
    """Delete queued rows every one of the user's devices has already drained
    (id <= the minimum cursor across the user's devices). The TTL sweep is the
    backstop for rows held up by a device that went away without unlinking."""
    cursors = (
        await db.execute(select(QueueCursor).where(QueueCursor.uin == uin))
    ).scalars().all()
    if not cursors:
        return 0
    min_direct = min(c.last_direct_id for c in cursors)
    min_group = min(c.last_group_id for c in cursors)
    reaped = 0
    if min_direct > 0:
        res = await db.execute(
            delete(OfflineMessage).where(
                OfflineMessage.to_uin == uin, OfflineMessage.id <= min_direct
            )
        )
        reaped += res.rowcount or 0
    if min_group > 0:
        res = await db.execute(
            delete(OfflineGroupMessage).where(
                OfflineGroupMessage.to_uin == uin, OfflineGroupMessage.id <= min_group
            )
        )
        reaped += res.rowcount or 0
    return reaped


@router.get("/queue", response_model=list[HistoryRow])
async def fetch_queue(
    ack: bool = False,
    uin: int = Depends(current_uin),
    device_id: str = Depends(current_device_id),
    db: AsyncSession = Depends(get_db),
) -> list[HistoryRow]:
    """Fetch queued offline envelopes for the authenticated UIN, PER DEVICE.

    The queue is shared across a user's devices (their phone + a connect-to-web
    browser). Each device drains independently via a per-device cursor
    (`QueueCursor`): we return only rows above THIS device's cursor, so a phone
    and a linked browser each receive every message instead of whichever drains
    first deleting them for the other (founder report).

    `ack=true` (new clients): rows are returned without advancing the cursor; the
    client POSTs /messages/queue/ack with the ids it persisted, which advances
    the cursor. `ack=false` (legacy drain-on-fetch): we advance this device's
    cursor past everything returned (instead of the old per-uin delete, which
    robbed the user's other devices). A row is reaped only once every device's
    cursor has passed it; the TTL sweep backstops abandoned cursors.
    """
    cursor = await db.get(QueueCursor, (uin, device_id))
    after_direct = cursor.last_direct_id if cursor else 0
    after_group = cursor.last_group_id if cursor else 0

    rows_1to1 = (
        await db.execute(
            select(OfflineMessage)
            .where(OfflineMessage.to_uin == uin, OfflineMessage.id > after_direct)
            .order_by(OfflineMessage.received_at.asc())
        )
    ).scalars().all()
    rows_group = (
        await db.execute(
            select(OfflineGroupMessage)
            .where(OfflineGroupMessage.to_uin == uin, OfflineGroupMessage.id > after_group)
            .order_by(OfflineGroupMessage.received_at.asc())
        )
    ).scalars().all()

    out: list[HistoryRow] = []
    for r in rows_1to1:
        out.append(HistoryRow(
            id=r.id, envelope_type=r.envelope_type, payload=r.payload,
            received_at=r.received_at, group_id=None,
        ))
    for r in rows_group:
        out.append(HistoryRow(
            id=r.id, envelope_type=r.envelope_type, payload=r.payload,
            received_at=r.received_at, group_id=r.group_id,
        ))
    out.sort(key=lambda x: x.received_at)

    if not ack:
        # Legacy drain-on-fetch: the client takes everything in one shot, so
        # advance this device's cursor past all returned rows.
        max_direct = max((r.id for r in rows_1to1), default=after_direct)
        max_group = max((r.id for r in rows_group), default=after_group)
        await _advance_cursor(db, uin, device_id, max_direct, max_group)
        await db.commit()
    return out


@router.post("/queue/ack", response_model=AckOut)
async def ack_queue(
    body: AckIn,
    uin: int = Depends(current_uin),
    device_id: str = Depends(current_device_id),
    db: AsyncSession = Depends(get_db),
) -> AckOut:
    """Advance THIS device's drain cursor past the envelopes it has persisted.

    Per-device (keyed off the token's `dev` claim): acking on the linked browser
    does NOT remove rows the phone still needs — a queued row is reaped only once
    every device's cursor has passed it. The cursor only moves FORWARD, so a
    stale or out-of-order ACK list is harmless (idempotent). Returns rows
    actually reaped by the resulting min-cursor cleanup.
    """
    max_direct = max(body.direct_ids) if body.direct_ids else 0
    max_group = max(body.group_ids) if body.group_ids else 0
    reaped = await _advance_cursor(db, uin, device_id, max_direct, max_group)
    await db.commit()
    return AckOut(deleted=reaped)
