import asyncio
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import get_db
from app.core.rate_limit import rate_limit
from app.core.security import current_device_id, current_uin
from app.models.group import GroupMember, OfflineGroupMessage
from app.models.message import OfflineMessage
from app.models.queue_cursor import QueueCursor
from app.models.user import User
from app.services.apns import is_group_muted, send_to_user as apns_send
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

    # TODO(sealed-sender-prod): per-recipient delivery-token rate limiting.

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
    db: AsyncSession = Depends(get_db),
) -> SendOut:
    """Per-recipient fan-out for a group. Sender provides one ciphertext
    per member; server validates each `to_uin` is actually a member and
    routes accordingly. Server has no plaintext access — every payload is
    a sealed-sender envelope encrypted to that one recipient's identity
    key. Confidentiality and authentication match the 1:1 path."""
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

        async def _push(target_uin: int) -> None:
            if await is_group_muted(target_uin, group_id):
                return
            await apns_send(
                target_uin,
                alert_body="New group message",
                envelope_b64=payload_by_uin.get(target_uin),
                envelope_type=envelope_type,
                thread_id=f"group-{group_id}",
                group_id=group_id,
            )

        for uin in offline_recipients:
            asyncio.create_task(_push(uin))
    log.warning(
        "[group-sealed] gid=%s type=%s payloads=%d delivered_any=%s offline=%d",
        body.group_id, body.envelope_type, len(body.payloads),
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
