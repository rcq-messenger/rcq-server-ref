import asyncio
from datetime import datetime, timezone

from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect
from sqlalchemy import update

from app.core.db import SessionLocal
from app.core.security import decode_token
from app.models.contact import Contact
from app.models.user import User, presence_is_fresh
from app.routers import hood, random as random_chat
from app.routers.presence import presence_watchers
from app.routers.referrals import note_active_day
from app.services.apns import send_voip_to_user
from app.services.connection_manager import manager

router = APIRouter(tags=["ws"])

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


async def _is_busy(uin: int) -> bool:
    """True if the UIN is mid-call OR in an audio room — both block each
    other under the single-busy assumption."""
    redis = await _get_redis()
    pipe = redis.pipeline(transaction=False)
    pipe.hexists(_CALLS_KEY, str(uin))
    pipe.hexists(_ROOM_USER_PIN_KEY, str(uin))
    in_call, in_room = await pipe.execute()
    return bool(in_call) or bool(in_room)


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
    pipe.hexists(_CALLS_KEY, str(uin))
    pipe.hget(_ROOM_USER_PIN_KEY, str(uin))
    in_call, pinned_raw = await pipe.execute()
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

if redis.call('HEXISTS', calls, a) == 1 then return 0 end
if redis.call('HEXISTS', calls, b) == 1 then return 0 end
if redis.call('HEXISTS', rooms, a) == 1 then return 0 end
if redis.call('HEXISTS', rooms, b) == 1 then return 0 end

redis.call('HSET', calls, a, payload_a)
redis.call('HSET', calls, b, payload_b)
return 1
"""


async def _register_call(call_id: str, a: int, b: int) -> bool:
    """Atomic check-and-set for `call_offer`. Returns True if both ends
    were free and we registered the pair, False if either side was busy
    on a 1:1 call OR in an audio room. Cluster-wide via the Lua script
    so two workers can't both succeed."""
    redis = await _get_redis()
    payload_a = f"{call_id}|{b}"
    payload_b = f"{call_id}|{a}"
    result = await redis.eval(
        _REGISTER_CALL_LUA, 2, _CALLS_KEY, _ROOM_USER_PIN_KEY,
        str(a), str(b), payload_a, payload_b,
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


@router.websocket("/ws/{uin}")
async def ws_endpoint(ws: WebSocket, uin: int, token: str = Query(...)) -> None:
    try:
        token_uin = decode_token(token)
    except Exception:
        await ws.close(code=4401)
        return
    if token_uin != uin:
        await ws.close(code=4403)
        return

    # Suspended users get a clean refusal at the WS gate. Sealed-
    # sender means we can't block their /messages/sealed POSTs
    # (server doesn't know who sent them), but without a live WS
    # they can't receive replies, presence, group events, or any
    # signalling — the app effectively becomes read-only-history
    # until the admin un-bans. Custom 4408 close code surfaces a
    # distinct reason in the iOS reconnect logic if we ever want
    # to show "your account was suspended" UI there.
    async with SessionLocal() as db:
        user = await db.get(User, uin)
        if user is not None and user.is_suspended:
            await ws.close(code=4408)
            return

    await manager.connect(uin, ws)
    try:
        await _on_connect(uin)
        while True:
            msg = await ws.receive_json()
            await _handle_client_message(uin, msg)
    except WebSocketDisconnect:
        pass
    finally:
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
                    call_id, peer_str = entry_raw.split("|", 1)
                    peer = int(peer_str)
                except (ValueError, AttributeError):
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


async def _handle_client_message(uin: int, msg: dict) -> None:
    """The WS channel is mostly server→client (presence + delivery). Clients send most
    things over HTTP. We accept a tiny client-initiated set: ping, typing relays,
    Hood-Chat presence, and call signalling (offer / answer / ICE / end)."""
    kind = msg.get("type")
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
    }:
        target = int(msg.get("to_uin", 0))
        if not target:
            return
        call_id = str(msg.get("call_id", ""))

        # Concurrency guard fires only on call_offer. Answer/ICE/end can't
        # establish a new pair on their own and are no-ops if the call
        # was already cleaned up by the offer's rejection.
        if kind == "call_offer":
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
