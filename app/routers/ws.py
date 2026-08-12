import asyncio
import logging
import time
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Query, WebSocket, WebSocketDisconnect, status
from sqlalchemy import select, update

from app.core import metrics
from app.core.db import SessionLocal
from app.core.rate_limit import allow_ws_connect
from app.core.security import authorize_session, decode_device_id
from app.models.contact import Contact
from app.models.device_token import DeviceToken
from app.models.user import User, presence_is_fresh, visible_status
from app.routers import hood, random as random_chat
from app.routers.presence import presence_watchers
from app.routers.referrals import note_active_day
from app.services.apns import send_voip_to_user
from app.services.unifiedpush import send_call_to_user as up_call
from app.services.connection_manager import manager

router = APIRouter(tags=["ws"])
# uvicorn owns the handlers in this process; the app-level logger has none,
# so a plain getLogger(__name__) would write the reconnect counter into a
# void — which is worse than not counting it, because it looks counted.
_log = logging.getLogger("uvicorn.error")

# Concurrent-call guard. Per-uin → (call_id, counterparty_uin). When a
# call_offer arrives, we check both endpoints — if either side is already
# in a call, the offer is rejected with `reason=busy` straight back to
# Active 1:1 calls + audio room presence — Redis-backed for multi-worker
# safety. A user busy on worker 1 must be visible as busy to worker 2.
# Schemas:
#
#   calls:active            HASH  uin → "{call_id}|{peer_uin}"
#   room:user_active        HASH  uin → room_id (string)
#   room:{room_id}:members  SET   {uin1, uin2, ...}
#
# Atomic check-and-set for call registration uses a small Lua script —
# without it, two concurrent call_offers from different workers could
# both succeed and double-register a user.

from app.core.redis import get_redis as _get_redis

_CALLS_KEY = "calls:active"
_ROOM_USER_PIN_KEY = "room:user_active"


def _room_members_key(room_id: int) -> str:
    return f"room:{room_id}:members"


async def audio_room_active_uins(room_id: int) -> set[int]:
    """Snapshot of UINs currently in a room's voice session. Read-only,
    consumed by the audio_rooms router for live counts on GET. Async
    now (Redis-backed cluster-wide read).

    NOTE: previously this function also filtered through
    `manager.is_online()` and opportunistically SREM'd zombies. That
    caused the room count to flicker (1 → empty → 1) whenever the
    user's own WS briefly reconnected — they'd be temporarily out of
    `_ONLINE_KEY`, get evicted from the roster on read, then re-added
    on the next room_enter. The phantom-accumulation problem the
    filter was meant to fix is now handled by `_debounced_offline`
    plus iOS-side `restoreOnForeground` re-sending room_enter on
    reconnect — leaving a much smaller window for phantoms to
    persist. If they do show up again, fix it with a periodic
    server-side sweep, NOT a per-read filter.
    """
    redis = await _get_redis()
    members = await redis.smembers(_room_members_key(room_id))
    return {int(m) for m in members if isinstance(m, str) and m.isdigit()} if members else set()


async def purge_audio_room(room_id: int) -> None:
    """Drop all presence for a room — used by `DELETE /audio_rooms/{id}`
    once the row is gone. Clients receive the `audio_room_deleted` push
    separately and tear down their meshes."""
    redis = await _get_redis()
    members = await audio_room_active_uins(room_id)
    pipe = redis.pipeline(transaction=True)
    pipe.delete(_room_members_key(room_id))
    if members:
        # Only un-pin users whose active room is THIS room (defensive
        # against a race where they switched rooms between read + delete).
        for u in members:
            pipe.hdel(_ROOM_USER_PIN_KEY, str(u))
    await pipe.execute()


async def evict_from_audio_room(room_id: int, uin: int) -> set[int]:
    """Drop a single UIN from the room's active set. Returns the
    remaining occupants (so the caller can fan out `room_member_left`).
    Used by the owner-kick flow."""
    redis = await _get_redis()
    pipe = redis.pipeline(transaction=True)
    pipe.srem(_room_members_key(room_id), str(uin))
    pipe.hdel(_ROOM_USER_PIN_KEY, str(uin))
    pipe.smembers(_room_members_key(room_id))
    results = await pipe.execute()
    remaining = results[2] or set()
    return {int(m) for m in remaining if isinstance(m, str) and m.isdigit()}


def _call_entry_is_live(entry_raw: str | None) -> bool:
    """Is this `calls:active` value a call in progress, or a leak?

    ⚠ Presence of the field is NOT the answer. Nothing expires this hash; it
    is cleared by call_end or by the socket-close handler, and neither runs
    when the worker holding the socket dies. Anyone left behind is busy for
    ever. Anything past [_CALL_REGISTRATION_STALE_S], or written before the
    timestamp field existed, is treated as gone."""
    if not entry_raw:
        return False
    parts = str(entry_raw).split("|")
    if len(parts) < 3 or not parts[2].isdigit():
        return False
    return (int(time.time()) - int(parts[2])) <= _CALL_REGISTRATION_STALE_S


async def _is_busy(uin: int) -> bool:
    """True if the UIN is mid-call OR in an audio room — both block each
    other under the single-busy assumption."""
    redis = await _get_redis()
    pipe = redis.pipeline(transaction=False)
    pipe.hget(_CALLS_KEY, str(uin))
    pipe.hexists(_ROOM_USER_PIN_KEY, str(uin))
    call_entry, in_room = await pipe.execute()
    return _call_entry_is_live(call_entry) or bool(in_room)


async def _room_entry_busy_state(uin: int, target_room_id: int) -> tuple[bool, int | None]:
    """Refined busy-check for `room_enter` specifically.

    Returns `(blocked, pinned_room_id)`:
      - `blocked` is True only when the user is genuinely occupied
        somewhere ELSE: mid-1:1-call, or pinned in a DIFFERENT room.
      - Re-entering the SAME room the pin already points at is NOT
        blocked — that's the recovery path. iOS re-sends `room_enter`
        after the app foregrounds (`restoreOnForeground`), and the
        previous flat `_is_busy()` check rejected it with `busy`
        because the pin from the interrupted session was still set.
        That left the user permanently locked out: couldn't re-enter
        (busy) and couldn't leave (never reached a stable in-room
        state to press Leave). Treating a same-room pin as a no-op
        re-entry lets the Lua reservation below run its `result == 0`
        ("already in") branch and reload the roster cleanly.

    `pinned_room_id` is returned so the caller can log / reason about
    the prior state if needed."""
    redis = await _get_redis()
    pipe = redis.pipeline(transaction=False)
    pipe.hget(_CALLS_KEY, str(uin))
    pipe.hget(_ROOM_USER_PIN_KEY, str(uin))
    call_entry, pinned_raw = await pipe.execute()
    in_call = _call_entry_is_live(call_entry)
    pinned_room: int | None = None
    if pinned_raw is not None and str(pinned_raw).isdigit():
        pinned_room = int(pinned_raw)
    if in_call:
        return True, pinned_room
    if pinned_room is not None and pinned_room != target_room_id:
        return True, pinned_room
    return False, pinned_room


# Lua script — atomic check-and-set across HASH lookups. Without this,
# two workers handling concurrent call_offers from each end of the
# same pair could both pass the busy-check and end up both registering.
_REGISTER_CALL_LUA = """
local calls = KEYS[1]
local rooms = KEYS[2]
local a = ARGV[1]
local b = ARGV[2]
local payload_a = ARGV[3]
local payload_b = ARGV[4]
local now = tonumber(ARGV[5])
local stale_after = tonumber(ARGV[6])

-- An entry older than `stale_after` is not a call, it is a leak: the only
-- thing that clears this hash is call_end or the socket-close handler, and
-- neither runs if the worker holding that socket dies. Whoever it belonged
-- to could then never place or receive a call again, for ever, with nothing
-- in any log to say why. Found on prod 2026-08-12: fifteen entries, two of
-- them real accounts stuck since June.
local function free_if_stale(uin)
    local entry = redis.call('HGET', calls, uin)
    if entry == false then return end
    -- ⚠ Anchor on the WHOLE shape, `call_id|peer|ts`. Matching just a trailing
    -- number reads the PEER UIN of a two-field legacy entry as a timestamp,
    -- and a uin-sized number is a date in the far future, so the entry looks
    -- eternally fresh and never gets freed — the opposite of the point.
    local ts = string.match(entry, '^[^|]*|%d+|(%d+)$')
    -- No timestamp at all: written by a build from before this field existed,
    -- so it is older than this deploy and cannot be a live call.
    if ts == nil or (now - tonumber(ts)) > stale_after then
        redis.call('HDEL', calls, uin)
    end
end

free_if_stale(a)
free_if_stale(b)

if redis.call('HEXISTS', calls, a) == 1 then return 0 end
if redis.call('HEXISTS', calls, b) == 1 then return 0 end
if redis.call('HEXISTS', rooms, a) == 1 then return 0 end
if redis.call('HEXISTS', rooms, b) == 1 then return 0 end

redis.call('HSET', calls, a, payload_a)
redis.call('HSET', calls, b, payload_b)
return 1
"""

# How long a call registration may sit before it is assumed leaked. Generous:
# clearing it early costs only the single-busy guarantee for an unusually long
# call (a third caller rings instead of being auto-declined), while clearing it
# too late costs someone their calls entirely.
_CALL_REGISTRATION_STALE_S = 2 * 60 * 60


async def _register_call(call_id: str, a: int, b: int) -> bool:
    """Atomic check-and-set for `call_offer`. Returns True if both ends
    were free and we registered the pair, False if either side was busy
    on a 1:1 call OR in an audio room. Cluster-wide via the Lua script
    so two workers can't both succeed."""
    redis = await _get_redis()
    now = int(time.time())
    # `call_id|peer|started_at`. The timestamp is what lets a leaked entry be
    # recognised as leaked; readers must tolerate its absence, since entries
    # written by older workers during a rolling restart carry only two fields.
    payload_a = f"{call_id}|{b}|{now}"
    payload_b = f"{call_id}|{a}|{now}"
    result = await redis.eval(
        _REGISTER_CALL_LUA, 2, _CALLS_KEY, _ROOM_USER_PIN_KEY,
        str(a), str(b), payload_a, payload_b,
        str(now), str(_CALL_REGISTRATION_STALE_S),
    )
    return bool(result)


_CLEAR_CALL_LUA = """
local calls = KEYS[1]
local call_id = ARGV[1]
for i = 2, #ARGV do
    local uin = ARGV[i]
    local current = redis.call('HGET', calls, uin)
    if current ~= false then
        local sep = string.find(current, '|', 1, true)
        if sep ~= nil then
            local cid = string.sub(current, 1, sep - 1)
            if cid == call_id then
                redis.call('HDEL', calls, uin)
            end
        end
    end
end
return 1
"""


async def _clear_call(call_id: str, *uins: int) -> None:
    """Drop the active-call entries for the listed UINs IF they still
    point at this call_id. Idempotent — safe to invoke multiple times.
    The Lua script ensures the check-and-delete is atomic."""
    if not uins:
        return
    redis = await _get_redis()
    args = [call_id] + [str(u) for u in uins]
    await redis.eval(_CLEAR_CALL_LUA, 1, _CALLS_KEY, *args)


async def _caller_allowed(caller_uin: int, callee_uin: int) -> bool:
    """Does the CALLEE's `call_policy` let `caller_uin` ring them? This is the
    authoritative gate: the caller's own policy is irrelevant (it only governs
    who may call THEM). `everyone` → yes; `nobody` → no; `contacts` → only a
    mutual contact. Enforced server-side so a `nobody` policy holds no matter
    what the caller's client shows."""
    async with SessionLocal() as db:
        callee = await db.get(User, callee_uin)
        policy = (callee.call_policy if callee else None) or "everyone"
        if policy == "everyone":
            return True
        if policy == "nobody":
            return False
        # "contacts": the caller must be in the callee's contact list.
        exists = await db.scalar(
            select(Contact.id).where(
                Contact.owner_uin == callee_uin,
                Contact.contact_uin == caller_uin,
            )
        )
        return exists is not None


@router.websocket("/ws/{uin}")
async def ws_endpoint(ws: WebSocket, uin: int, token: str = Query(...)) -> None:
    # ⚠ This used to be `decode_token`, i.e. a signature check and nothing
    # else. Revoking a linked web device and taking over a recycled number both
    # went through Redis/the epoch table and were enforced on every HTTP route
    # — and on none of the websocket, which is the channel that actually
    # carries messages, presence and call signalling. A revoked browser could
    # not call the API and could still sit on a socket receiving everything.
    #
    # `authorize_session` is the single place that answers "is this token still
    # good", suspension included, so the 4408 branch below is gone with it.
    try:
        token_uin = await authorize_session(token)
    except HTTPException as exc:
        # ⚠ These codes do NOT reach the client and never have. Closing before
        # `accept()` makes Starlette refuse the HANDSHAKE, so the peer sees an
        # HTTP 403 and OkHttp reports it through onFailure, where no code is
        # available — verified against prod. The numbers are kept because they
        # are what the journal and any future accept-then-close would use, not
        # because anything reads them today.
        # ⏭ A suspended account therefore retries forever on the ordinary
        # backoff instead of being told it is banned. Fixing that needs
        # accept-then-close here AND a client that reads the code; today the
        # only code any client acts on is 4000 (superseded).
        await ws.close(code=4408 if exc.status_code == status.HTTP_403_FORBIDDEN else 4401)
        return
    except Exception:
        await ws.close(code=4401)
        return
    # Device key: a connect-to-web linked browser carries a `dev` claim and
    # coexists with the phone ("primary"); both stay live and receive.
    device_id = decode_device_id(token)
    if token_uin != uin:
        await ws.close(code=4403)
        return

    # Connect ceiling, checked BEFORE accept() so an account in a redial loop
    # costs a refused handshake instead of a session: no queue drain, no
    # presence fan-out, no boot chain behind it.
    #
    # ⚠ The concurrency cap in connection_manager does not cover this. Measured
    # on prod 12.08: the worst account opened 1198 sockets in an hour while
    # never holding more than 12 at once, because each died after ten seconds
    # and was redialled immediately. Accumulation and churn are two different
    # failures and need two different guards.
    #
    # Like the 4408/4401 codes above, this one does not reach the peer — the
    # close happens pre-accept, so the client sees an HTTP error and its own
    # backoff decides what happens next. That is the point: for a client too
    # old to have the backoff fix, this at least makes its loop cheap for us.
    if not await allow_ws_connect(uin):
        metrics.record_socket_refused()
        await ws.close(code=4429)
        return

    await manager.connect(uin, ws, device_id)
    # How fast sockets are being BORN, not how many are open. One client in a
    # reconnect loop shows up here and nowhere else: the open count stays flat
    # while it churns, which is exactly how the storm hid.
    metrics.record_socket(opened=True)
    try:
        await _on_connect(uin)
        while True:
            msg = await ws.receive_json()
            await _handle_client_message(uin, msg, device_id)
    except WebSocketDisconnect:
        pass
    except RuntimeError as exc:
        # Starlette raises a bare RuntimeError when receive_json() is entered
        # on a socket whose state has already left CONNECTED. That is exactly
        # what happens to the OLD socket when a reconnect supersedes it:
        # manager.connect() closes it with 4000 while this task is still
        # parked in receive. It is an ordinary disconnect, not a fault, but it
        # surfaced as a full traceback ~3.5k times a day and buried every real
        # error in the log. Count it as a disconnect; anything else re-raises.
        if "not connected" not in str(exc):
            raise
        _log.info("ws uin=%s: socket closed under receive (superseded)", uin)
    finally:
        metrics.record_socket(opened=False)
        await manager.disconnect(uin, ws)
        await _on_disconnect(uin)


# Presence debounce: brief WS drops (iOS network switch, idle timeout)
# would otherwise flicker watchers between online/offline within seconds.
# Disconnect schedules the offline-broadcast with a grace window; if the
# user reconnects before it fires, the task is cancelled and no flicker
# is observed. 60s is comfortable for a cellular handoff or a slow
# Wi-Fi reassociation; smaller windows (20s) produced reproducible
# online/offline flicker on cell-network testers.
_pending_offline_tasks: dict[int, asyncio.Task] = {}
_OFFLINE_DEBOUNCE_SECONDS = 60.0


async def _on_connect(uin: int) -> None:
    pending = _pending_offline_tasks.pop(uin, None)
    if pending is not None and not pending.done():
        pending.cancel()
    async with SessionLocal() as db:
        user = await db.get(User, uin)
        if user is None:
            return
        # Watchers derive "online" from `last_seen` freshness — so a
        # presence broadcast is only needed when `last_seen` had gone
        # stale (watchers currently believe this user is offline). A
        # brief WS reconnect keeps `last_seen` fresh → no redundant
        # broadcast → no flicker on watchers' animated contact rows.
        was_stale = not presence_is_fresh(user.last_seen)
        # Heal a legacy stored "offline" — the `status` column now only
        # carries the user-chosen sub-state (away/dnd/invisible).
        if user.status == "offline":
            user.status = "online"
        user.last_seen = datetime.now(timezone.utc)
        # Count this as an active day (once per UTC day) and pay out a
        # referral the moment the invitee crosses the activation bar.
        await note_active_day(db, user)
        await db.commit()

        if was_stale:
            final_watchers = await presence_watchers(db, uin)
            visible = "offline" if user.status == "invisible" else user.status
            await manager.broadcast(
                list(final_watchers),
                {"type": "presence", "uin": uin, "status": visible, "status_message": user.status_message},
            )

        # Offline queue drain happens exclusively over the HTTP
        # `/messages/queue` endpoint now (called by clients on
        # boot, on `.opened` WS events, and after push taps). The
        # WS post-connect drain that used to live here raced with
        # the HTTP path: each ran in its own DB transaction, both
        # SELECTed the same rows under MVCC, and both tried to
        # send + DELETE — duplicating live deliveries to the
        # client and inflating unread counters. Single source of
        # truth fixes the race; the client's `.opened` handler
        # already triggers the HTTP fetch immediately after
        # connect, so there's no functional regression.


async def _on_disconnect(uin: int) -> None:
    async with SessionLocal() as db:
        user = await db.get(User, uin)
        if user is None:
            return
        user.last_seen = datetime.now(timezone.utc)
        await db.commit()

    # If still connected via another session (multi-device), no offline
    # work to do — return immediately.
    if await manager.is_online(uin):
        return

    # Otherwise schedule the offline cleanup with a grace window. iOS WS
    # reconnects routinely on network switches; firing the offline path
    # immediately would flicker watchers between online/offline.
    existing = _pending_offline_tasks.get(uin)
    if existing is not None and not existing.done():
        existing.cancel()
    _pending_offline_tasks[uin] = asyncio.create_task(_debounced_offline(uin))


async def _debounced_offline(uin: int) -> None:
    try:
        await asyncio.sleep(_OFFLINE_DEBOUNCE_SECONDS)
        # Reconnected during the grace window — abort.
        if await manager.is_online(uin):
            return

        async with SessionLocal() as db:
            user = await db.get(User, uin)
            if user is None:
                return
            # NOTE: `status` is deliberately NOT written to "offline" here.
            # Offline is derived from `last_seen` freshness — the client
            # stopped pinging, so it already reads as offline to everyone,
            # and writing "offline" would clobber a user-chosen
            # away/dnd/invisible. This block only fans out the live
            # presence event + cleans up calls / rooms / hood.
            # A user who opted to stay visible (presence_persistent within its
            # TTL) must NOT be flapped to offline just because the socket
            # dropped — that defeats the whole "stay online" setting and spams
            # watchers with online/offline (+ knock sounds) every time the app
            # backgrounds. effective/visible_status keeps them online; only fan
            # out a real offline.
            if visible_status(user) == "offline":
                final_watchers = await presence_watchers(db, uin)
                await manager.broadcast(
                    list(final_watchers),
                    {"type": "presence", "uin": uin, "status": "offline", "status_message": None},
                )
            await random_chat.on_disconnect(uin)
            bucket, count = await hood.remove_subscriber(uin)
            if bucket is not None:
                remaining = await hood.subscribers_for(bucket)
                if remaining:
                    await manager.broadcast(
                        remaining,
                        {"type": "hood_count", "bucket_id": bucket, "count": count},
                    )

            redis = await _get_redis()
            entry_raw = await redis.hget(_CALLS_KEY, str(uin))
            if entry_raw is not None:
                try:
                    # `call_id|peer` from an older worker, `call_id|peer|ts`
                    # from this one. Splitting on a fixed count would make the
                    # timestamp part of the peer and throw, and throwing here
                    # means NOT clearing the registration — the exact leak the
                    # timestamp was added to stop.
                    parts = entry_raw.split("|")
                    call_id, peer = parts[0], int(parts[1])
                except (ValueError, AttributeError, IndexError):
                    call_id, peer = "", 0
                if call_id:
                    await _clear_call(call_id, uin, peer)
                    await manager.send(peer, {
                        "type": "call_end",
                        "from_uin": uin,
                        "call_id": call_id,
                        "reason": "peer_disconnected",
                    })

            room_id_raw = await redis.hget(_ROOM_USER_PIN_KEY, str(uin))
            if room_id_raw is not None:
                try:
                    room_id_int = int(room_id_raw)
                except (ValueError, TypeError):
                    room_id_int = None
                if room_id_int is not None:
                    remaining = await evict_from_audio_room(room_id_int, uin)
                    if remaining:
                        await manager.broadcast(list(remaining), {
                            "type": "room_member_left",
                            "room_id": room_id_int,
                            "uin": uin,
                        })
    except asyncio.CancelledError:
        return
    finally:
        _pending_offline_tasks.pop(uin, None)


async def _handle_client_message(
    uin: int, msg: dict, device_id: str = "primary"
) -> None:
    """The WS channel is mostly server→client (presence + delivery). Clients send most
    things over HTTP. We accept a tiny client-initiated set: ping, typing relays,
    Hood-Chat presence, and call signalling (offer / answer / ICE / end)."""
    kind = msg.get("type")
    # Any frame proves this DEVICE is still here, which is what the per-device
    # push decision reads. Cheap (one SADD + EXPIRE) and it keeps the online
    # marker's TTL short enough that a dead worker's leftovers age out.
    await manager.touch_device(uin, device_id)
    if kind == "ping":
        await manager.send(uin, {"type": "pong", "t": datetime.now(timezone.utc).isoformat()})
        # Heartbeat. Online-state is DERIVED from `last_seen` freshness, so
        # refreshing it on every ping (~25s from iOS) IS what keeps the
        # user online — and the moment the pings stop, staleness alone
        # flips them offline with no disconnect handler needing to fire.
        async with SessionLocal() as db:
            await db.execute(
                update(User)
                .where(User.uin == uin)
                .values(last_seen=datetime.now(timezone.utc))
            )
            await db.commit()
        return
    if kind == "typing":
        target = int(msg.get("to_uin", 0))
        if target:
            await manager.send(target, {"type": "typing", "from_uin": uin, "active": bool(msg.get("active", True))})
        return
    if kind == "hood_subscribe":
        bucket = str(msg.get("bucket", "")).strip()
        if not bucket:
            return
        count = await hood.add_subscriber(uin, bucket)
        recipients = await hood.subscribers_for(bucket)
        if recipients:
            await manager.broadcast(
                recipients,
                {"type": "hood_count", "bucket_id": bucket, "count": count},
            )
        return
    if kind == "hood_unsubscribe":
        bucket, count = await hood.remove_subscriber(uin)
        if bucket is not None:
            recipients = await hood.subscribers_for(bucket)
            if recipients:
                await manager.broadcast(
                    recipients,
                    {"type": "hood_count", "bucket_id": bucket, "count": count},
                )
        return
    # Call signalling — server is a dumb relay for SDP / ICE / hangups,
    # PLUS a single-call guard. Two parties can never be in two calls at
    # once because we register both endpoints on call_offer and refuse
    # to register a new offer if either side is already mid-call. Media
    # itself goes peer-to-peer over WebRTC's DTLS-SRTP, server is out
    # of that path.
    if kind in {
        "call_offer",
        "call_answer",
        "call_ice",
        "call_end",
        # Mid-call audio→video upgrade. Renegotiation SDPs travel the
        # same dumb-relay path as the original offer/answer; the call
        # is already registered in `_active_calls` so no concurrency
        # check is needed for these.
        "call_renegotiate",
        "call_renegotiate_answer",
        "call_renegotiate_decline",
        # ICE restart: recover a dropped/failed connection mid-call without
        # re-ringing. Same dumb-relay path as renegotiate; the call is already
        # registered so no concurrency check (the guard fires only on offer).
        "call_ice_restart",
        "call_ice_restart_answer",
    }:
        target = int(msg.get("to_uin", 0))
        if not target:
            return
        call_id = str(msg.get("call_id", ""))

        # Concurrency guard fires only on call_offer. Answer/ICE/end can't
        # establish a new pair on their own and are no-ops if the call
        # was already cleaned up by the offer's rejection.
        if kind == "call_offer":
            # Honour the callee's "who can call me" policy server-side. The
            # caller's OWN policy must NOT gate this — it only controls who may
            # call THEM. Done before registering the pair so a rejected offer
            # leaves no dangling active-call entry.
            if not await _caller_allowed(uin, target):
                await manager.send(uin, {
                    "type": "call_end",
                    "from_uin": target,
                    "call_id": call_id,
                    "reason": "unavailable",
                })
                return
            registered = await _register_call(call_id, uin, target)
            if not registered:
                # Caller (or callee) is busy on another call. Tell the
                # caller's client to short-circuit straight to .ended.
                await manager.send(uin, {
                    "type": "call_end",
                    "from_uin": target,
                    "call_id": call_id,
                    "reason": "busy",
                })
                return

        relay: dict = {"type": kind, "from_uin": uin}
        for key in ("call_id", "sdp", "candidate", "media", "reason"):
            if key in msg:
                relay[key] = msg[key]
        delivered = await manager.send(target, relay)

        # Bind the call to the device that answered. `call_offer` is delivered
        # to every device of the callee on purpose — all of them should ring —
        # but until per-install device ids landed, an account only ever held ONE
        # socket, so nothing had to un-ring the others. Now they keep ringing to
        # their own timeout and keep trickling ICE into the same call_id, which
        # the caller adds to a peer connection those candidates were never part
        # of. Tell the callee's OTHER devices the call is over; the one that
        # answered is skipped so it doesn't cancel itself.
        if kind == "call_answer":
            await manager.send(
                uin,
                {
                    "type": "call_end",
                    "from_uin": target,
                    "call_id": call_id,
                    "reason": "answered_elsewhere",
                },
                except_device=device_id,
            )

        # Clear the active-call registration on call_end from either side.
        # Done after the relay so the remote peer sees the end first; the
        # server-side bookkeeping then matches what both clients now think.
        if kind == "call_end":
            await _clear_call(call_id, uin, target)

        # If the recipient is offline AND this is the call_offer (the only
        # event worth waking the device for — answer/ice/end are
        # follow-ups during an active call), fire a VoIP push so iOS wakes
        # the app from killed state. PushKit hands the payload to the
        # iOS-side `VoIPPushService.didReceiveIncomingPush`, which calls
        # CallKit's `reportNewIncomingCall` synchronously.
        if not delivered and kind == "call_offer":
            async with SessionLocal() as db:
                caller = await db.get(User, uin)
                caller_nick = caller.nickname if caller else str(uin)
            voip_payload = {
                "call_id": call_id,
                "from_uin": uin,
                "nickname": caller_nick,
                "media": msg.get("media", "video"),
                "sdp": msg.get("sdp", ""),
            }
            await send_voip_to_user(target, payload=voip_payload)
            # Android wakes via UnifiedPush (no PushKit) — same call payload so
            # the receiver can ring with a full-screen incoming-call UI. No-op
            # when the callee has no Android endpoints.
            await up_call(target, payload=voip_payload)

            # No socket AND no way to wake them: nothing is going to ring on
            # the other side, at all. The caller was left listening to a
            # ringback that meant nothing until it timed out, which reads as
            # "they are ignoring me" rather than "they cannot be reached"
            # (user request). Every wake channel we have lives in
            # `device_tokens` — ios, ios-voip, android-up — so their absence
            # is the whole answer.
            #
            # Sent to the CALLER only, and additive: a client that does not
            # know this event ignores it and keeps the old behaviour.
            async with SessionLocal() as db:
                wakeable = await db.scalar(
                    select(DeviceToken.id).where(DeviceToken.uin == target).limit(1)
                )
            if wakeable is None:
                await manager.send(
                    uin,
                    {
                        "type": "call_unreachable",
                        "from_uin": target,
                        "call_id": call_id,
                    },
                )
            else:
                # They can be woken, but they are not there right now: the offer
                # left as a push, and nothing is ringing on the other side until
                # that push lands and raises a screen. The caller meanwhile hears
                # a ringback, which is a promise the server has no basis for —
                # "гудки идут, когда собеседник офлайн, которых быть не должно"
                # (#463). So say what actually happened and let the caller's UI
                # stop pretending. Additive like `call_unreachable`: a client
                # that does not know this event keeps the old behaviour.
                await manager.send(
                    uin,
                    {
                        "type": "call_offline",
                        "from_uin": target,
                        "call_id": call_id,
                    },
                )

        # call_end fallback. If the recipient's WS wasn't connected
        # (their device just woke from the offer push but hasn't
        # finished establishing WS, or they got force-quit between
        # offer and cancel) the regular WS relay above silently
        # dropped — leaving CallKit's incoming UI ringing forever
        # on their end. Mirror the offer fallback with a VoIP push
        # carrying `kind=end`; the iOS-side handler dismisses the
        # existing CallKit entry. PushKit's "must report a new
        # incoming call" contract is satisfied client-side via the
        # report-then-immediately-end escape hatch.
        if not delivered and kind == "call_end":
            voip_payload = {
                "call_id": call_id,
                "from_uin": uin,
                "kind": "end",
                "reason": msg.get("reason", "remote_ended"),
            }
            await send_voip_to_user(target, payload=voip_payload)
            # Android: dismiss a ringing full-screen call UI that the offer-wake
            # raised but the WS relay couldn't reach (woke too late).
            await up_call(target, payload=voip_payload)
        return

    # ── Audio Rooms ──
    # `room_enter` puts the UIN into an in-memory roster and tells
    # everyone else in the room (so their clients can mint mesh peer
    # connections to the newcomer); the entrant gets the full roster
    # back via `room_roster` so they can do the same in reverse. Mesh
    # signalling (`room_offer` / `room_answer` / `room_ice`) is a dumb
    # relay between two co-tenants — server checks both endpoints are in
    # the same room before forwarding, so a malicious client can't probe
    # at strangers' peer connections.
    if kind == "room_enter":
        room_id = int(msg.get("room_id", 0))
        if not room_id:
            return
        # Single-busy: an ongoing 1:1 call blocks room entry, and an
        # ongoing room blocks a 1:1 call (handled in `_register_call`).
        # A stale pin pointing at THIS room is NOT busy — it's the
        # foreground-recovery re-entry path; see `_room_entry_busy_state`.
        blocked, _pinned = await _room_entry_busy_state(uin, room_id)
        if blocked:
            await manager.send(uin, {
                "type": "room_enter_rejected",
                "room_id": room_id,
                "reason": "busy",
            })
            return
        async with SessionLocal() as db:
            from app.routers.audio_rooms import (
                MAX_ROOM_PARTICIPANTS,
                is_room_member,
                lookup_user_nickname,
            )
            from app.models.audio_room import AudioRoom

            room = await db.get(AudioRoom, room_id)
            if room is None:
                await manager.send(uin, {
                    "type": "room_enter_rejected",
                    "room_id": room_id,
                    "reason": "no_such_room",
                })
                return
            if not await is_room_member(db, room_id, uin):
                await manager.send(uin, {
                    "type": "room_enter_rejected",
                    "room_id": room_id,
                    "reason": "not_member",
                })
                return
            entrant_nick = await lookup_user_nickname(db, uin) or str(uin)

        # Reserve the slot via Redis — capacity check + insert is
        # atomic via a Lua script so two simultaneous entrants on
        # different workers can't both squeak past the limit.
        redis = await _get_redis()
        # Lua: SCARD members → check cap → SADD if free.
        # Returns: 1 = added, 0 = already-in, -1 = full.
        lua = """
        local members = KEYS[1]
        local pin = KEYS[2]
        local uin = ARGV[1]
        local room_id = ARGV[2]
        local cap = tonumber(ARGV[3])
        if redis.call('SISMEMBER', members, uin) == 1 then
            return 0
        end
        if redis.call('SCARD', members) >= cap then
            return -1
        end
        redis.call('SADD', members, uin)
        redis.call('HSET', pin, uin, room_id)
        return 1
        """
        result = await redis.eval(
            lua, 2,
            _room_members_key(room_id), _ROOM_USER_PIN_KEY,
            str(uin), str(room_id), str(MAX_ROOM_PARTICIPANTS),
        )
        if result == -1:
            await manager.send(uin, {
                "type": "room_enter_rejected",
                "room_id": room_id,
                "reason": "full",
            })
            return
        # result == 0 (already in) OR 1 (added) — both fine; load roster.
        roster_members = await redis.smembers(_room_members_key(room_id))
        roster_uins = sorted(int(m) for m in roster_members if isinstance(m, str) and m.isdigit())

        # Hydrate roster nicknames + owner-set mute flags in one DB
        # pass for the entrant. Mute flags from `audio_room_mutes` so
        # the entrant's UI paints the "muted by owner" badge from
        # frame 0; without this they'd only see other members' mute
        # state after a subsequent `audio_room_member_muted` event
        # landed.
        from app.routers.audio_rooms import muted_uins_for_room
        from app.models.audio_room import AudioRoom as _AR

        async with SessionLocal() as db:
            from sqlalchemy import select as _sel

            users = (
                await db.execute(_sel(User).where(User.uin.in_(roster_uins)))
            ).scalars().all()
            muted = await muted_uins_for_room(db, room_id)
            owner_only = bool(
                await db.scalar(_sel(_AR.owner_only_speaking).where(_AR.id == room_id))
            )
        roster = [
            {
                "uin": u.uin,
                "nickname": u.nickname,
                "muted_by_owner": u.uin in muted,
            }
            for u in users
        ]
        # Tell the entrant who's already inside (so they know who to
        # peer-connect to). Self is included — keeps client logic
        # simple, the client filters itself out.
        await manager.send(uin, {
            "type": "room_roster",
            "room_id": room_id,
            "members": roster,
            "owner_only_speaking": owner_only,
        })
        # Tell everyone else (excluding the entrant) that someone joined.
        # On their side this triggers minting a fresh mesh peer connection
        # to the newcomer. To break the offer/answer symmetry tie, by
        # convention the *existing* member is the offerer — the newcomer
        # waits for offers from each existing peer.
        #
        # Skip the broadcast on a duplicate `room_enter` (Lua returned 0,
        # already in roster). iOS re-sends `room_enter` on app-foreground
        # to re-sync state when its WS reconnects within the offline
        # grace window. Without this guard each routine app resume would
        # fan out a spurious `room_member_entered` to every other
        # participant and force them to tear down + re-mint their
        # WebRTC peer connection to this user — audible "everyone
        # dropped" hiccup on every backgrounding cycle.
        peers = [u for u in roster_uins if u != uin]
        if peers and result == 1:
            entrant_muted = uin in muted
            await manager.broadcast(peers, {
                "type": "room_member_entered",
                "room_id": room_id,
                "member": {
                    "uin": uin,
                    "nickname": entrant_nick,
                    "muted_by_owner": entrant_muted,
                },
            })
        return

    if kind == "room_leave":
        room_id = int(msg.get("room_id", 0))
        if not room_id:
            return
        redis = await _get_redis()
        # Idempotent leave — only fire room_member_left if the user
        # was actually present.
        was_member = await redis.sismember(_room_members_key(room_id), str(uin))
        if was_member:
            remaining = await evict_from_audio_room(room_id, uin)
            if remaining:
                await manager.broadcast(list(remaining), {
                    "type": "room_member_left",
                    "room_id": room_id,
                    "uin": uin,
                })
        return

    if kind in {"room_offer", "room_answer", "room_ice"}:
        room_id = int(msg.get("room_id", 0))
        target = int(msg.get("to_uin", 0))
        if not room_id or not target:
            return
        # Both endpoints must be in this room or the relay is a no-op.
        redis = await _get_redis()
        pipe = redis.pipeline(transaction=False)
        pipe.sismember(_room_members_key(room_id), str(uin))
        pipe.sismember(_room_members_key(room_id), str(target))
        sender_in, target_in = await pipe.execute()
        if not sender_in or not target_in:
            return
        relay: dict = {
            "type": kind,
            "room_id": room_id,
            "from_uin": uin,
        }
        for k in ("sdp", "candidate"):
            if k in msg:
                relay[k] = msg[k]
        await manager.send(target, relay)
        return

    if kind == "room_speaking":
        # Lightweight visual indicator: client emits when local mic
        # crosses a VAD threshold (entering or leaving "is talking"
        # state). Pure UX — not load-bearing. Dropped silently if the
        # sender isn't actually in the room.
        room_id = int(msg.get("room_id", 0))
        speaking = bool(msg.get("speaking", False))
        if not room_id:
            return
        redis = await _get_redis()
        members = await redis.smembers(_room_members_key(room_id))
        member_uins = {int(m) for m in members if isinstance(m, str) and m.isdigit()}
        if uin not in member_uins:
            return
        peers = [u for u in member_uins if u != uin]
        if peers:
            await manager.broadcast(peers, {
                "type": "room_speaking",
                "room_id": room_id,
                "uin": uin,
                "speaking": speaking,
            })
        return
