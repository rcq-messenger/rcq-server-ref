import asyncio
import logging
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import delete, func, insert, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.db import get_db
from app.core.rate_limit import _client_ip, enforce_cost_budget, rate_limit
from app.core.security import current_device_id, current_uin, current_uin_optional
from app.models.capability import UserCapability
from app.models.device_token import DeviceToken
from app.models.group import Group, GroupMember, OfflineGroupMessage
from app.models.message import OfflineMessage
from app.models.queue_cursor import QueueCursor
from app.models.user import User
from app.services.apns import group_push_targets, send_to_user as apns_send
from app.services.unifiedpush import send_to_user as up_send
from app.services.connection_manager import manager
from app.services.offline_queue_sweep import dormant_cutoff
from app.services.queue_drain import account_watermark, drain_floor

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

# Ceiling on one group fan-out POST. The largest live group is ~1.9k members
# (the founder beta group every registration is added to), so this leaves
# generous headroom for the biggest legitimate send while bounding a request
# body that had no limit anywhere: not on the model, not in Caddy.
_MAX_GROUP_PAYLOADS = 4096

# Recipients per minute per caller, shared across BOTH group endpoints (same
# rule name, so a dual-send spends one budget). The unit is recipients, not
# requests, because that is what actually costs us — one row in
# `offline_group_messages` plus one APNs/UnifiedPush wake each.
#
# Sized off real traffic, not off the request caps: the flagship group is
# ~1.9k members, so the authenticated budget is ~30 posts/min into the
# biggest group we have and effectively unreachable in any normal one.
#
# The anonymous budget is separate and lower, but NOT tight, because the
# identity there is an IP and most of our API traffic arrives collapsed
# behind a handful of relay exits — a strict per-IP number would punish
# everyone sharing an exit. It still cuts the single-source worst case by
# an order of magnitude.
_FANOUT_BUDGET_AUTHED = 60_000
_FANOUT_BUDGET_ANON = 30_000
_FANOUT_WINDOW_SECONDS = 60

router = APIRouter(prefix="/messages", tags=["messages"])


def _fanout_charge(request: Request, caller: int | None) -> tuple[str, int]:
    """Budget identity + allowance for a group fan-out.

    Authenticated callers are charged per UIN; sealed-sender posts (the
    normal path for an 'all' group, where the server deliberately does not
    learn the author) fall back to the client IP on a smaller allowance.
    """
    if caller is not None:
        return f"uin:{caller}", _FANOUT_BUDGET_AUTHED
    return f"ip:{_client_ip(request)}", _FANOUT_BUDGET_ANON


async def _sender_device_tokens(db: AsyncSession, caller: int | None) -> frozenset[str]:
    """Every push token/endpoint registered by `caller`, any platform.

    Used to keep the PHYSICAL sending device out of a push fan-out: on a
    multi-account phone each local account registers the same token string,
    so a `uin == caller` check alone still wakes the author's own phone
    through a sibling account that looks offline server-side. Matching by
    token identifies "same device" regardless of which account is targeted."""
    if caller is None:
        return frozenset()
    rows = (
        await db.execute(select(DeviceToken.token).where(DeviceToken.uin == caller))
    ).scalars().all()
    return frozenset(rows)


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
    # Wake the devices that did NOT get it over the socket.
    #
    # `delivered` answers "is this ACCOUNT online anywhere", not "did every
    # device get it" — so a desktop left open used to suppress the wake for the
    # phone in the user's pocket, and the message only surfaced when the app was
    # next opened ("сообщения пропускаются, когда приложение выключено",
    # 2026-08-04). Asking which DEVICES hold a socket lets the other ones be
    # woken while the connected one is left alone (it already has the envelope).
    # Endpoints that predate device-aware registration carry no device id; when
    # something IS connected they are skipped, exactly as before, since they
    # might belong to that connected device.
    if body.envelope_type in _PUSHABLE_TYPES:
        online_devices = frozenset(await manager.online_devices(body.to_uin))
        if not delivered or online_devices:
            pushed = await apns_send(
                body.to_uin,
                alert_body="New message",
                envelope_b64=body.payload,
                envelope_type=body.envelope_type,
                skip_devices=online_devices,
            )
            # Android has no APNs — fire the parallel UnifiedPush wake (no-op when
            # the recipient has no Android endpoints, the iOS-only common case).
            pushed += await up_send(
                body.to_uin,
                alert_body="New message",
                envelope_b64=body.payload,
                envelope_type=body.envelope_type,
                skip_devices=online_devices,
            )
    log.warning(
        "[sealed] to=%s type=%s ws_delivered=%s queued=%s pushed=%s",
        body.to_uin, body.envelope_type, delivered, queued, pushed,
    )
    return SendOut(delivered=delivered, queued=queued, server_time=now)


def _queueable(member_rows: list[tuple[int, datetime | None]]) -> set[int]:
    """Of `(uin, last_seen)`, the members whose group backlog we actually
    keep — everyone the dormant sweep would not immediately delete again.

    Group fan-out writes one row PER MEMBER, so the flagship's 1733-member
    group turns a single post into 1733 inserts. `offline_queue_sweep` has
    reaped the dormant share of those since 2026-07-31 (tens of thousands per
    six-hour cycle on prod) precisely because nobody drains them. Deciding the
    same thing at write time costs one already-needed join and skips the
    insert entirely.

    `users.last_seen` is refreshed on WS connect, heartbeat and disconnect, so
    a member who is online right now is never in the skipped set — and one who
    comes back later is woken by push (the fan-out below still targets them)
    and starts accumulating backlog again from that moment.
    """
    cutoff = dormant_cutoff()
    if cutoff is None:
        return {uin for uin, _ in member_rows}
    return {
        uin for uin, last_seen in member_rows
        if last_seen is not None and last_seen >= cutoff
    }


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
    payloads: list[GroupRecipientPayload] = Field(max_length=_MAX_GROUP_PAYLOADS)


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
    request: Request,
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
    # Fetched unconditionally: the push block below titles its banner with
    # `g.name` for EVERY pushable type, so binding this only under the
    # "message" gate left `g` unbound on a "system"/"secscreen" group send —
    # an UnboundLocalError 500 raised AFTER the commit, i.e. recipients got
    # the message and the sender saw a failure. iOS types systemNotice as
    # "system", so that path is reachable from a shipped client.
    g = await db.get(Group, body.group_id)
    if body.envelope_type == "message":
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
    # Membership AND recency in one read: whether we hold offline backlog for
    # a member depends on how long they have been away (see `_queueable`).
    member_rows = (
        await db.execute(
            select(GroupMember.uin, User.last_seen)
            .outerjoin(User, User.uin == GroupMember.uin)
            .where(GroupMember.group_id == body.group_id)
        )
    ).all()
    if not member_rows:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "group has no members")
    members = {uin for uin, _ in member_rows}
    queueable = _queueable(member_rows)

    now = datetime.now(timezone.utc)
    # Drop entries that don't correspond to real group members. Cheap client
    # mistake guard — we don't error on it because the client is anonymous
    # (sealed sender) and we can't tell who they are.
    entries = [e for e in body.payloads if e.to_uin in members]
    # Charge the fan-out BEFORE doing any of it. This endpoint does not (and
    # must not) check that the SENDER is a member — sealed sender means the
    # server cannot know who is posting — so without a budget anyone who knows
    # a group id and some member UINs can aim the whole group's worth of queue
    # rows and pushes at the database, repeatedly. Counting `entries` rather
    # than `body.payloads` charges the real work: junk recipients were already
    # dropped above and cost nothing.
    identity, allowance = _fanout_charge(request, caller)
    await enforce_cost_budget(
        identity, "group_fanout", len(entries), allowance, _FANOUT_WINDOW_SECONDS
    )
    # One pipelined publish for the whole group instead of a `manager.send()`
    # per member (two Redis round-trips each, awaited in series).
    online = await manager.fanout_each([
        (
            e.to_uin,
            {
                "type": body.envelope_type,
                "payload": e.payload,
                "group_id": body.group_id,
                "server_time": now.isoformat(),
            },
        )
        for e in entries
    ])
    # Queue regardless of the live send: being online at publish time is
    # optimistic (bytes in an OS buffer != client ingested them), so the
    # recipient drains anything they missed on their next /messages/queue
    # fetch and dedupes by UUID.
    rows = [
        {
            "to_uin": e.to_uin,
            "group_id": body.group_id,
            "envelope_type": body.envelope_type,
            "payload": e.payload,
            "received_at": now,
        }
        for e in entries
        if e.to_uin in queueable
    ]
    if rows:
        await db.execute(insert(OfflineGroupMessage), rows)
    await db.commit()
    delivered_any = bool(online)
    offline_recipients = [e.to_uin for e in entries if e.to_uin not in online]
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
    # message via WS. Each task opens its own short DB session inside
    # apns_send / up_send, so detaching is safe.
    if body.envelope_type in _PUSHABLE_TYPES:
        payload_by_uin = {p.to_uin: p.payload for p in body.payloads}
        envelope_type = body.envelope_type
        group_id = body.group_id
        # Title the banner with the group's name + carry it in the payload so
        # the client shows WHICH group (this sealed path used to send neither,
        # so small-group pushes always read as the generic "New group message").
        gname = (g.name if g is not None else None) or "RCQ"
        sender_tokens = await _sender_device_tokens(db, caller)
        # Never push the sender their OWN message (they backgrounded right
        # after sending); their other devices still get the queue carbon.
        # `group_push_targets` then drops everyone with no registered endpoint
        # and everyone who muted this group — two queries for the whole group,
        # where the old per-recipient shape opened three sessions EACH.
        wake = await group_push_targets(
            db, [uin for uin in offline_recipients if uin != caller], group_id
        )

        async def _push(target_uin: int) -> None:
            await apns_send(
                target_uin,
                alert_title=gname,
                alert_body="New group message",
                envelope_b64=payload_by_uin.get(target_uin),
                envelope_type=envelope_type,
                thread_id=f"group-{group_id}",
                group_id=group_id,
                group_name=gname,
                exclude_tokens=sender_tokens,
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
                exclude_tokens=sender_tokens,
            )

        for uin in wake:
            asyncio.create_task(_push(uin))
    log.warning(
        "[group-sealed] gid=%s type=%s payloads=%d queued=%d delivered_any=%s offline=%d",
        body.group_id, body.envelope_type, len(body.payloads), len(rows),
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
    request: Request,
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
    # Authentication is REQUIRED here, unlike the legacy sealed path. This is
    # the cheapest amplifier in the API: a single small POST fans one blob to
    # every capable member, so the per-request cap alone priced an anonymous
    # caller at the whole flagship group times 120 a minute. Requiring a token
    # costs no privacy on this path — every shipped client (iOS, Android,
    # web/desktop) already authenticates it, so the server learns the poster
    # today regardless, and `kid` makes them pseudonymous to the server on the
    # wire anyway. The legacy sealed endpoint stays anonymous; that is where
    # sealed sender actually lives.
    if caller is None:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "group-broadcast requires authentication",
        )
    g = await db.get(Group, body.group_id)
    if g is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such group")
    if (
        body.envelope_type == "message"
        and g.post_policy == "owner_only"
        and caller != g.owner_uin
    ):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "owner_only: only the group owner may post")

    recipient_rows = (
        await db.execute(
            select(GroupMember.uin, User.last_seen)
            .join(UserCapability, UserCapability.uin == GroupMember.uin)
            .outerjoin(User, User.uin == GroupMember.uin)
            .where(
                GroupMember.group_id == body.group_id,
                UserCapability.sender_keys.is_(True),
            )
        )
    ).all()
    recipients = [uin for uin, _ in recipient_rows]
    if not recipients:
        # A capable client always advertises before its first broadcast, so
        # at minimum the sender's own uin matches. Empty therefore means a
        # bogus group id / not-a-member race — nothing to deliver.
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no broadcast-capable members")

    # Same budget, same rule name as the sealed path: a dual-send (broadcast to
    # capable members + per-member fan-out to the legacy ones) is one logical
    # post and spends one allowance.
    identity, allowance = _fanout_charge(request, caller)
    await enforce_cost_budget(
        identity, "group_fanout", len(recipients), allowance, _FANOUT_WINDOW_SECONDS
    )

    now = datetime.now(timezone.utc)
    queueable = _queueable(recipient_rows)
    # The sender's own uin is included on purpose: their other devices get
    # the broadcast as the carbons copy (the sending device dedupes by
    # message UUID, same as the WS/queue double-delivery case).
    pkt = {
        "type": "gmsg",
        "payload": body.payload,
        "group_id": body.group_id,
        "server_time": now.isoformat(),
    }
    online = await manager.fanout(recipients, pkt)
    rows = [
        {
            "to_uin": uin,
            "group_id": body.group_id,
            "envelope_type": "gmsg",
            "payload": body.payload,
            "received_at": now,
        }
        for uin in recipients
        if uin in queueable
    ]
    if rows:
        await db.execute(insert(OfflineGroupMessage), rows)
    await db.commit()
    delivered_any = bool(online)
    offline_recipients = [uin for uin in recipients if uin not in online]
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
        sender_tokens = await _sender_device_tokens(db, caller)
        # Never push the sender their OWN message: they backgrounded right
        # after sending and fell into offline_recipients. Their other devices
        # still get the WS/queue carbon — just no APNs banner. The rest of the
        # filtering (no endpoint registered, group muted) is batched, not one
        # short-lived DB session per recipient.
        wake = await group_push_targets(
            db, [uin for uin in offline_recipients if uin != caller], group_id
        )

        async def _push(target_uin: int) -> None:
            await apns_send(
                target_uin,
                alert_title=gname,
                alert_body="New group message",
                envelope_b64=payload,
                envelope_type="gmsg",
                thread_id=f"group-{group_id}",
                group_id=group_id,
                group_name=gname,
                exclude_tokens=sender_tokens,
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
                exclude_tokens=sender_tokens,
            )

        for uin in wake:
            asyncio.create_task(_push(uin))
    log.warning(
        "[group-broadcast] gid=%s type=%s recipients=%d queued=%d delivered_any=%s offline=%d",
        body.group_id, body.envelope_type, len(recipients), len(rows),
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


async def _acked_prefix(
    db: AsyncSession, model: type, uin: int, base: int, acked: list[int] | None
) -> int:
    """How far the cursor may move given the ids a client actually persisted.

    ⚠ This exists because taking `max(acked)` loses messages, permanently, and
    it did (founder's second account, 2026-08-13).

    The cursor is a single watermark and the drain asks for `id > cursor`, so
    everything below it is unreachable for good. A client that acks a SUBSET —
    say the sender-key distributions it could process, but not the group
    messages interleaved between them — moved the watermark to the highest id
    in that subset and buried every un-acked row underneath. One account lost
    532 group messages over nine days that way: they were still on disk, still
    addressed to it, and no request could ever return them again. It looked to
    the user like the group simply stopped at a date.

    So the cursor advances over the CONTIGUOUS acked prefix and stops at the
    first hole. Anything past the hole stays queued and comes back on the next
    drain, which is exactly what a queue is for.
    """
    if not acked:
        return base
    acked_set = set(acked)
    ids = (
        await db.execute(
            select(model.id).where(model.to_uin == uin, model.id > base).order_by(model.id.asc())
        )
    ).scalars().all()
    out = base
    for i in ids:
        if i not in acked_set:
            break
        out = i
    return out


async def _advance_cursor(
    db: AsyncSession, uin: int, device_id: str, max_direct: int, max_group: int,
    cursor: QueueCursor | None = None,
) -> int:
    """Move THIS device's drain cursor forward (never backward), then reap any
    queued rows now below EVERY device's cursor. Returns rows reaped.

    ⚠ A cursor created here starts at this account's watermark, NOT at zero: an
    axis left at zero would hand this device the whole queue on its next drain
    (and pin the account's reap floor at zero forever). The caller has already
    read above that watermark, so seeding it loses nothing.
    """
    if cursor is None:
        cursor = await db.get(QueueCursor, (uin, device_id))
    if cursor is None:
        floor_direct, floor_group = await account_watermark(db, uin)
        cursor = QueueCursor(
            uin=uin, device_id=device_id,
            last_direct_id=floor_direct, last_group_id=floor_group,
        )
        db.add(cursor)
    if max_direct > cursor.last_direct_id:
        cursor.last_direct_id = max_direct
    if max_group > cursor.last_group_id:
        cursor.last_group_id = max_group
    cursor.updated_at = datetime.now(timezone.utc)
    await db.flush()
    return await _reap_below_min(db, uin)


# How long a drain cursor may go untouched before it stops holding the queue
# back. Comfortably longer than a holiday with the phone off, short enough that
# a reinstalled device does not pin an account's queue for a season.
STALE_CURSOR_DAYS = 30


def _as_utc(ts: datetime | None) -> datetime | None:
    """Read a timestamp back as aware UTC. Postgres hands these back aware, but
    SQLite (the local test harness) drops the zone, and comparing the two raises."""
    if ts is None or ts.tzinfo is not None:
        return ts
    return ts.replace(tzinfo=timezone.utc)


async def _reap_below_min(db: AsyncSession, uin: int) -> int:
    """Delete queued rows every one of the user's devices has already drained
    (id <= the minimum cursor across the user's LIVE devices). The TTL sweep is
    the backstop for rows held up by a device that went away without
    unlinking."""
    cursors = (
        await db.execute(select(QueueCursor).where(QueueCursor.uin == uin))
    ).scalars().all()
    # Drop cursors nobody is behind any more. Reinstalling mints a NEW device
    # id, so the abandoned one would otherwise sit at its old position forever
    # and hold every later row above the reap floor — the queue would then only
    # ever be cleared by the TTL sweep. A stamp-less row predates the column and
    # is left alone until it next acks (which stamps it).
    cutoff = datetime.now(timezone.utc) - timedelta(days=STALE_CURSOR_DAYS)
    stale = [c for c in cursors if _as_utc(c.updated_at) is not None and _as_utc(c.updated_at) < cutoff]
    if stale:
        for c in stale:
            await db.delete(c)
        await db.flush()
        cursors = [c for c in cursors if c not in stale]
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
    # ⚠ A device we have never seen starts where this account's furthest device
    # already got to — NOT at zero. See app/services/queue_drain.py.
    #
    # Reinstalling mints a new device id, so starting at zero replayed the
    # entire queue: up to the 30-day TTL of history, including messages the
    # person had deleted on the old install, whose local tombstones died with
    # it. A tester hit this repeatedly ("ресетнула приложение ... но при входе
    # продолжает подгружаться переписка, вместе с удалёнными"), and her account
    # carries eight cursors — eight reinstalls, eight replays. It reads as the
    # app hoarding history somewhere secret; it is the island's own queue,
    # handed out again to something it considers a brand-new device.
    #
    # Anything genuinely undelivered sits ABOVE that mark and still arrives,
    # which is what the queue is for. Anything below it was already delivered to
    # this account once, and re-delivering it is the bug.
    after_direct, after_group, cursor = await drain_floor(db, uin, device_id)
    if cursor is None:
        # Pin that floor as this device's cursor NOW, before handing rows out.
        # Leaving it unwritten until the ack lets a sibling device's ack raise
        # the account watermark in between, and this device would then be
        # rebased onto the higher mark — burying the very rows it is holding.
        cursor = QueueCursor(
            uin=uin, device_id=device_id,
            last_direct_id=after_direct, last_group_id=after_group,
            updated_at=datetime.now(timezone.utc),
        )
        db.add(cursor)
        try:
            await db.commit()
        except IntegrityError:  # concurrent first drain from the same device
            await db.rollback()
            cursor = await db.get(QueueCursor, (uin, device_id))
            if cursor is not None:
                after_direct, after_group = cursor.last_direct_id, cursor.last_group_id

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
        await _advance_cursor(db, uin, device_id, max_direct, max_group, cursor)
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

    ⚠ A device with no cursor bases off the account watermark, NOT zero. Basing
    at zero was the second half of the replay bug: the fetch above already hands
    a brand-new device only the rows above that watermark, so the ids it acks
    never form a contiguous prefix from zero — `_acked_prefix` therefore stopped
    at the very first row and wrote a cursor of 0, and the device's next drain
    was the entire queue, as notifications.
    """
    base_direct, base_group, cursor = await drain_floor(db, uin, device_id)
    max_direct = await _acked_prefix(db, OfflineMessage, uin, base_direct, body.direct_ids)
    max_group = await _acked_prefix(db, OfflineGroupMessage, uin, base_group, body.group_ids)
    reaped = await _advance_cursor(db, uin, device_id, max_direct, max_group, cursor)
    await db.commit()
    return AckOut(deleted=reaped)
