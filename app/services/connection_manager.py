"""Cross-worker WebSocket fanout via Redis pub/sub.

The challenge
-------------
WebSocket objects can't be serialized — they live in the worker
process that accepted the upgrade. Yet a request handled on worker A
may need to push to a user whose WS lives on worker B. We solve that
by keeping local connection tracking on each worker AND mirroring
every "send" through a Redis pub/sub channel that every worker
subscribes to.

Topology
--------
  worker 1            ┌──────────────────┐
   _conns: {uin→set}  │   Redis pub/sub  │
   subscribes ──────► │  channel "ws:fanout"
                      │                  │
  worker 2            └──────────────────┘
   _conns: {uin→set}        ▲
   subscribes ──────────────┘

When a router calls `manager.send(uin, payload)`, the manager
publishes to `ws:fanout` with an envelope describing target+payload.
Every worker's subscriber receives the publish and checks its local
`_conns` to find a matching socket; if found, it delivers locally.

Online presence
---------------
`is_online(uin)` needs cross-worker visibility too — APNs push
fallback decisions hinge on it. We maintain a Redis SET
`ws:online_uins` updated on connect/disconnect. Slight imprecision
on multi-device-multi-worker cases (worst case: false-offline, push
gets sent when user is technically connected on another worker — a
stale push, not a missed one).
"""
import asyncio
import json
import logging
import os
import time
from collections import defaultdict
from collections.abc import Iterable
from typing import Any

from fastapi import WebSocket

from app.core.config import log_identity
from app.core.redis import get_redis

log = logging.getLogger(__name__)

# Single channel for all fanout. Envelope describes target ("user" or
# "all") and the inner payload — every worker filters on receive.
_FANOUT_CHANNEL = "ws:fanout"
# Set of UINs currently connected to ANY worker. Used by `is_online()`.
_ONLINE_KEY = "ws:online_uins"
# Per-account set of the DEVICE ids currently connected to any worker, so a
# push decision can be made per device instead of per account. Without it
# `manager.send()`'s single "is this user online" answer suppressed the wake
# for EVERY device as soon as ONE was connected: a desktop left open meant the
# phone in your pocket was never woken at all (found 2026-08-04).
#
# Deliberately expiring, unlike `_ONLINE_KEY`: a worker that dies takes its
# SREMs with it, and a device wrongly believed to be online is a message the
# user never hears about. The TTL is refreshed on connect and on every client
# frame (iOS pings ~25s), so a live device never lapses, while a dead worker's
# leftovers age out on their own.
_ONLINE_DEVS_TTL = 180

# Most sockets one account may hold on ONE worker at a time. Generous on
# purpose: a phone, a tablet, a desktop and a couple of browser tabs is a real
# person, four dozen is a client that has lost the plot. Tunable without a
# deploy for the day one is needed.
_MAX_SOCKETS_PER_UIN = int(os.getenv("RCQ_MAX_SOCKETS_PER_UIN", "8"))
# Above this, every dial says how many this worker is holding.
_BUSY_ACCOUNT_HINT = 4


def _online_devs_key(uin: int) -> str:
    return f"ws:online_devs:{uin}"


# How often each worker publishes a heartbeat on the fanout channel, so that
# "heard nothing" means deaf rather than merely quiet. Costs one tiny publish
# per worker per interval.
_PUBSUB_HEALTH_INTERVAL = 15.0
# Silence longer than this, while heartbeats are going out, means this worker
# is no longer receiving. Three intervals of slack so a GC pause or a slow
# delivery never triggers a needless reconnect.
_PUBSUB_DEAF_AFTER = 3 * _PUBSUB_HEALTH_INTERVAL
# A publish→delivery step slower than this is worth a log line. Everything in
# this path is microseconds when healthy, so anything above a second is a
# stall, and the whole worker is behind the channel while it lasts.
_SLOW_STEP = 1.0


class ConnectionManager:
    """Tracks live WebSocket connections on this worker AND coordinates
    with peer workers via Redis pub/sub for cross-worker delivery.

    A single UIN may have multiple sessions (multi-device), and a
    single UIN may also have sessions split across multiple workers.
    The manager handles both cases.
    """

    def __init__(self) -> None:
        # Local-to-this-worker connection map. Other workers have
        # their own copies; we only see ours.
        self._conns: dict[int, set[WebSocket]] = defaultdict(set)
        # Per-socket device id, so a reconnect supersedes only the SAME
        # device's prior socket and DIFFERENT devices of one account
        # (e.g. phone + a connect-to-web linked browser) coexist and both
        # receive live. A regular phone session has no `dev` claim → keyed
        # "primary", which preserves the old single-device behaviour exactly.
        self._device_of: dict[WebSocket, str] = {}
        # When each socket was accepted, so the per-account ceiling can drop the
        # OLDEST rather than an arbitrary member of a set.
        self._opened_at: dict[WebSocket, float] = {}
        self._lock = asyncio.Lock()
        # Background task that subscribes to the fanout channel and
        # delivers received messages to LOCAL connections only. Started
        # lazily on first connect; survives forever per worker.
        self._pubsub_task: asyncio.Task | None = None
        self._pubsub_started = asyncio.Event()
        # Event-loop time of the last frame received on the fanout channel.
        # The watchdog compares it against the heartbeats to tell "quiet"
        # from "deaf". Zero means the loop has not started yet.
        self._pubsub_seen_at: float = 0.0
        self._watchdog_task: asyncio.Task | None = None
        # Strong refs to in-flight close tasks. A close is fire-and-forget
        # (see `_close_soon`) and asyncio only keeps a weak ref, so without
        # this the handshake can be garbage-collected half-done.
        self._closing: set[asyncio.Task] = set()

    @staticmethod
    def _envelope(**fields: Any) -> str:
        """Serialise a fanout envelope, stamped with the publish time.

        The stamp is what lets the receiving worker say whether a late
        delivery was late on the channel or late in its own dispatch — all
        workers share one clock, so the comparison is exact.
        """
        fields["ts"] = time.time()
        return json.dumps(fields)

    async def _ensure_pubsub(self) -> None:
        """Spin up the pub/sub listener once per worker. Called from
        every public method that publishes — cheap idempotent check.

        Note this check alone cannot notice a subscriber that is alive but no
        longer receiving; that is what the watchdog is for.
        """
        if self._watchdog_task is None or self._watchdog_task.done():
            self._watchdog_task = asyncio.create_task(self._pubsub_watchdog())
        if self._pubsub_task is not None and not self._pubsub_task.done():
            return
        self._pubsub_task = asyncio.create_task(self._pubsub_loop())
        # Wait for the listener to actually subscribe before returning,
        # so the very first send doesn't race the subscribe step. The
        # event is set inside the loop after `await pubsub.subscribe(...)`
        # completes.
        try:
            await asyncio.wait_for(self._pubsub_started.wait(), timeout=5.0)
        except asyncio.TimeoutError:
            log.warning(
                "Redis pub/sub did not initialise within 5s; sends may "
                "race with subscribe. Continuing anyway."
            )

    async def _pubsub_watchdog(self) -> None:
        """Restart the subscriber when this worker has gone deaf.

        The failure it exists for: Redis closes the pub/sub connection, the
        blocking read never raises, and the worker keeps its websockets while
        receiving nothing — for good, because `_ensure_pubsub` only sees a
        task that is not done. Measured on prod 2026-08-03: three subscribers
        for four workers.

        Every worker publishes a heartbeat, and every worker sees every
        publish, so on a cluster of any size the channel is never quiet for
        long. A worker that has heard nothing across several heartbeat
        intervals is not in a quiet cluster, it is deaf, and the only reliable
        cure is a fresh connection.
        """
        while True:
            await asyncio.sleep(_PUBSUB_HEALTH_INTERVAL)
            try:
                redis = await get_redis()
                await redis.publish(
                    _FANOUT_CHANNEL,
                    self._envelope(target="heartbeat", pid=os.getpid()),
                )
            except Exception:  # noqa: BLE001
                # Redis itself is unreachable; the loop's own error handling
                # will deal with it when it notices. Nothing to restart yet.
                continue

            silent_for = asyncio.get_running_loop().time() - self._pubsub_seen_at
            if silent_for < _PUBSUB_DEAF_AFTER:
                continue
            log.warning(
                "ws fanout heard nothing for %.0fs despite heartbeats; "
                "restarting the subscriber",
                silent_for,
            )
            task = self._pubsub_task
            if task is not None and not task.done():
                task.cancel()
                try:
                    await task
                except (asyncio.CancelledError, Exception):  # noqa: BLE001
                    pass
            self._pubsub_started.clear()
            self._pubsub_seen_at = asyncio.get_running_loop().time()
            self._pubsub_task = asyncio.create_task(self._pubsub_loop())

    async def _pubsub_loop(self) -> None:
        """Long-lived task that listens for fanout publishes and
        delivers them to LOCAL websockets. Reconnects on transient
        Redis failures so a worker keeps participating in the cluster
        even through a Redis blip.

        The read here is deliberately UNBOUNDED. Wrapping it in a timeout was
        tried on 2026-08-03 and made things worse: fanout carries messages of
        several hundred KB (a group snapshot for a 1750-member group is ~600
        KB), a timeout that expires while one is still arriving cancels the
        read mid-message, and the stream is then desynchronised —
        `IncompleteReadError: 513586 bytes read on a total of 600948` in the
        logs. You cannot put a stopwatch on a framed protocol stream.

        Deafness is detected out of band instead, by `_pubsub_watchdog`.
        """
        while True:
            pubsub = None
            try:
                redis = await get_redis()
                pubsub = redis.pubsub()
                await pubsub.subscribe(_FANOUT_CHANNEL)
                self._pubsub_started.set()
                self._pubsub_seen_at = asyncio.get_running_loop().time()
                async for message in pubsub.listen():
                    # Any frame at all proves we are still connected — the
                    # watchdog reads this, and it must be updated before the
                    # type filter so heartbeats count too.
                    self._pubsub_seen_at = asyncio.get_running_loop().time()
                    if message.get("type") != "message":
                        continue
                    raw = message.get("data")
                    if raw is None:
                        continue
                    try:
                        envelope = json.loads(raw)
                    except (ValueError, TypeError):
                        continue
                    target = envelope.get("target")
                    payload_text = envelope.get("payload_text")
                    # Only the delivery targets carry a payload. A supersede
                    # envelope does not, and this guard used to sit ABOVE the
                    # dispatch — so every cross-worker supersede was dropped
                    # here and eviction silently worked only within the worker
                    # that accepted the socket (one in four, at four workers).
                    # An account could therefore hold a stale socket on each of
                    # the other workers, each still fed by the `user` fanout.
                    if target in ("all", "user") and not isinstance(payload_text, str):
                        continue
                    # Split the delay into the two halves that have different
                    # cures: `transit` is publish→here (Redis and this loop
                    # getting round to the frame), `dispatch` is here→handed to
                    # every local socket. A big transit with a small dispatch
                    # means the loop was busy with the PREVIOUS frame.
                    published_at = envelope.get("ts")
                    began = time.time()
                    fanned = 0
                    if target == "all":
                        fanned = await self._deliver_all_local(payload_text)
                    elif target == "user":
                        uin = envelope.get("uin")
                        except_device = envelope.get("except_device")
                        if isinstance(uin, int):
                            fanned = await self._deliver_user_local(
                                uin,
                                payload_text,
                                except_device if isinstance(except_device, str) else None,
                            )
                    elif target == "supersede":
                        # Another worker accepted a new socket for this
                        # UIN+device — close any stale sockets WE still hold
                        # for the SAME device so a future broadcast doesn't
                        # fan out to that device's ghosts. Other devices of
                        # the account are left alone (multi-device).
                        uin = envelope.get("uin")
                        origin_pid = envelope.get("pid")
                        dev = envelope.get("device_id", "primary")
                        if isinstance(uin, int) and origin_pid != os.getpid():
                            await self._close_local_sockets_for_device(
                                uin, dev if isinstance(dev, str) else "primary"
                            )
                    ended = time.time()
                    transit = began - published_at if isinstance(published_at, (int, float)) else 0.0
                    if transit > _SLOW_STEP or ended - began > _SLOW_STEP:
                        log.warning(
                            "ws fanout slow: transit=%.2fs dispatch=%.2fs "
                            "target=%s uin=%s sockets=%d pid=%d",
                            transit,
                            ended - began,
                            target,
                            envelope.get("uin"),
                            fanned,
                            os.getpid(),
                        )
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001
                # Reconnect after a short backoff. Reset the started
                # event so callers wait for the next subscribe to land.
                log.exception("ws fanout loop hiccup; resubscribing in 2s")
            finally:
                # Drop the old subscriber explicitly. Leaving it to the garbage
                # collector leaked a Redis connection per hiccup, and a worker
                # that hiccups all day accumulates them.
                self._pubsub_started.clear()
                if pubsub is not None:
                    try:
                        await pubsub.aclose()
                    except Exception:  # noqa: BLE001
                        pass
            await asyncio.sleep(2.0)

    async def _fan_local(self, sockets: list[WebSocket], text: str, uin: Any = None) -> int:
        """Push `text` to every socket at once, and never let one of them hold
        up the rest.

        These sends used to run one after another with a bare `await`. A client
        whose TCP window is full blocks that await, and because this runs
        INSIDE the pub/sub read loop, the whole worker stops reading: every
        other socket on it goes quiet until the slow one drains. Measured on
        prod 2026-08-03 — sockets that heard nothing for two rounds and then
        received both messages at once, because they had been sitting in a
        buffer nobody was reading.

        Deliberately NO timeout around the send. Cancelling a write part-way
        through leaves the connection mid-frame, which is the same mistake that
        wrapping the Redis read in a timeout turned out to be. Concurrency
        alone already fixes the head-of-line problem: every send is in flight
        before any of them is waited on, so a stuck socket delays only the
        return to the channel, not the other deliveries.
        """
        if not sockets:
            return 0

        async def deliver(ws: WebSocket) -> None:
            began = time.time()
            try:
                await ws.send_text(text)
            except Exception:  # noqa: BLE001
                pass
            took = time.time() - began
            if took > _SLOW_STEP:
                # Names the socket that held the gather — i.e. the one that
                # kept this worker from reading the next fanout frame.
                log.warning(
                    "ws send took %.2fs uin=%s dev=%s bytes=%d pid=%d",
                    took,
                    uin,
                    self._device_of.get(ws, "?"),
                    len(text),
                    os.getpid(),
                )

        await asyncio.gather(*(deliver(ws) for ws in sockets))
        return len(sockets)

    async def _deliver_user_local(
        self, uin: int, text: str, except_device: str | None = None
    ) -> int:
        return await self._fan_local(
            [
                ws
                for ws in list(self._conns.get(uin, ()))
                if except_device is None
                or self._device_of.get(ws, "primary") != except_device
            ],
            text,
            uin,
        )

    def _close_soon(self, ws: WebSocket) -> None:
        """Start closing a superseded socket, and do NOT wait for it.

        ★ Closing a websocket is a handshake, not a hang-up: the library sends
        its close frame and then waits for the peer's answer, up to
        `close_timeout` — 10 seconds by default. A socket being superseded is
        very often a ghost (the phone that moved networks, the tab that went
        away without a FIN), and a ghost never answers, so the wait runs the
        full 10 seconds every time.

        This used to be awaited inside the pub/sub read loop. Measured on prod
        2026-08-03: 146 closes of exactly 10.00s in eight minutes, during which
        the loop read nothing — frames queued in Redis behind them and arrived
        up to 136 SECONDS late. That is the whole "delivery spikes" symptom,
        and it is also where the deaf subscribers came from: a subscriber that
        stops reading for two minutes is one Redis kills for overrunning its
        output buffer.

        The caller has already unregistered the socket, so nothing else will
        be sent to it; whether the handshake completes is of no interest to
        anyone. Its own endpoint task cleans up regardless.
        """
        task = asyncio.create_task(self._close_quietly(ws))
        self._closing.add(task)
        task.add_done_callback(self._closing.discard)

    @staticmethod
    async def _close_quietly(ws: WebSocket) -> None:
        try:
            await ws.close(code=4000, reason="superseded")
        except Exception:  # noqa: BLE001
            pass

    async def _close_local_sockets_for_device(self, uin: int, device_id: str) -> None:
        """Close only the sockets we hold for one (uin, device) — used by
        the cross-worker supersede so other devices of the account stay up."""
        old: list[WebSocket] = []
        async with self._lock:
            conns = self._conns.get(uin)
            if conns:
                for ws in list(conns):
                    if self._device_of.get(ws, "primary") == device_id:
                        old.append(ws)
                        conns.discard(ws)
                        self._device_of.pop(ws, None)
                        self._opened_at.pop(ws, None)
                if not conns:
                    self._conns.pop(uin, None)
        for ws in old:
            self._close_soon(ws)

    async def _deliver_all_local(self, text: str) -> int:
        # Same head-of-line problem as the per-user path, only worse: here one
        # stuck client would hold up every socket on the worker.
        return await self._fan_local(
            [ws for conns in list(self._conns.values()) for ws in list(conns)], text
        )

    # ── Public API ──────────────────────────────────────────────────

    async def kick_device(self, uin: int, device_id: str) -> None:
        """Drop every socket this cluster holds for one (uin, device), now.

        ⚠ Revoking a linked session used to be enforced only on the way IN:
        `authorize_session` refuses the next handshake, and the socket already
        open was left alone. A browser that never reconnects therefore went on
        receiving messages, presence and call signalling for as long as its
        socket lived — which for an idle tab is hours. The revoke has to reach
        the connection that exists, not only the one that would be made.

        Reuses the `supersede` envelope (same meaning: close stale sockets for
        this uin+device, leave the account's other devices alone). `pid` is
        omitted so the origin worker acts on it too — a supersede skips its own
        publisher because that worker just accepted the new socket, and here
        there is no new socket to spare.
        """
        await self._ensure_pubsub()
        await self._close_local_sockets_for_device(uin, device_id)
        try:
            redis = await get_redis()
            await redis.srem(_online_devs_key(uin), device_id)
            await redis.publish(
                _FANOUT_CHANNEL,
                self._envelope(target="supersede", uin=uin, device_id=device_id),
            )
        except Exception:  # noqa: BLE001 — the local close already happened
            log.warning(
                "could not fan out device kick uin=%s dev=%s", log_identity(uin), device_id
            )

    async def connect(self, uin: int, ws: WebSocket, device_id: str = "primary") -> None:
        await ws.accept()
        # Supersede only the SAME device's stale sockets — a reconnect of
        # this device (iOS reconnect cycles, a browser tab reload) replaces
        # its own old socket so a single bid isn't delivered N times to that
        # device's zombies. Sockets belonging to OTHER devices of the same
        # account (a phone + a connect-to-web linked browser) are kept, so
        # both stay live and receive. Cross-worker eviction (also device-
        # scoped) is the next paragraph.
        old_sockets: list[WebSocket] = []
        async with self._lock:
            existing = self._conns.get(uin, set())
            for old in list(existing):
                if self._device_of.get(old, "primary") == device_id:
                    old_sockets.append(old)
                    existing.discard(old)
                    self._device_of.pop(old, None)
                    self._opened_at.pop(old, None)
            existing.add(ws)
            # Ceiling on how many sockets one account may hold at once.
            #
            # The per-device supersede above assumes a device keeps its id. A
            # client that mints a fresh one on every dial supersedes nothing and
            # piles up instead: one real account reached 38 live sockets and 2.7
            # full boot chains a second, which was 73% of everything this server
            # was doing. Whatever the client is doing wrong, no account has a
            # legitimate use for dozens, and the server should not be the part
            # that falls over. Oldest go first, so the socket the person is
            # actually looking at is the one that survives.
            if len(existing) > _MAX_SOCKETS_PER_UIN:
                surplus = sorted(
                    (w for w in existing if w is not ws),
                    key=lambda w: self._opened_at.get(w, 0.0),
                )[: len(existing) - _MAX_SOCKETS_PER_UIN]
                for extra in surplus:
                    old_sockets.append(extra)
                    existing.discard(extra)
                    self._device_of.pop(extra, None)
                    self._opened_at.pop(extra, None)
                # print() and not log.warning(): the logger's output does not
                # reach the journal under the current uvicorn config, so a
                # warning here would be written and never read — which is the
                # same class of mistake as the mechanism that is never checked.
                print(
                    f"[ws] uin={uin}: {len(existing) + len(surplus)} sockets over "
                    f"the cap of {_MAX_SOCKETS_PER_UIN} — closing {len(surplus)} oldest",
                    flush=True,
                )
            self._conns[uin] = existing
            self._device_of[ws] = device_id
            self._opened_at[ws] = time.monotonic()
            held = len(existing)
        if held >= _BUSY_ACCOUNT_HINT:
            # One line per dial once an account is holding an unusual number,
            # so "is it accumulating or is it redialing?" stops being a guess.
            print(
                f"[ws] uin={log_identity(uin)} dev={device_id}: "
                f"now holding {held} sockets on this worker",
                flush=True,
            )
        for old in old_sockets:
            # Not awaited: a ghost takes the full close_timeout to answer, and
            # this runs before the new socket is marked online — waiting here
            # left a just-reconnected client looking offline (so pushed to
            # instead of delivered to) for ten seconds. See `_close_soon`.
            self._close_soon(old)
        await self._ensure_pubsub()
        # Mark UIN as online cluster-wide so APNs decisions and
        # `is_online` checks on other workers see them. Also broadcast
        # a `supersede` request so peer workers drop their stale
        # sockets for this UIN — that's the cross-worker half of the
        # deduplication above.
        try:
            from app.services.activity_rollup import bump_bg as activity_bump

            activity_bump("ws")
            redis = await get_redis()
            await redis.sadd(_ONLINE_KEY, uin)
            await redis.sadd(_online_devs_key(uin), device_id)
            await redis.expire(_online_devs_key(uin), _ONLINE_DEVS_TTL)
            envelope = self._envelope(
                target="supersede",
                uin=uin,
                device_id=device_id,
                pid=os.getpid(),
            )
            await redis.publish(_FANOUT_CHANNEL, envelope)
        except Exception:  # noqa: BLE001
            log.warning("Could not mark uin=%s online in redis", log_identity(uin))

    async def disconnect(self, uin: int, ws: WebSocket) -> None:
        async with self._lock:
            gone_device = self._device_of.pop(ws, None)
            self._opened_at.pop(ws, None)
            # Another socket of the SAME device (a reconnect racing the old
            # socket's teardown) means the device is still here — dropping it
            # from the online set would push to a device that is connected.
            device_still_local = gone_device is not None and any(
                self._device_of.get(other) == gone_device
                for other in self._conns.get(uin, ())
                if other is not ws
            )
            conns = self._conns.get(uin)
            if conns:
                conns.discard(ws)
                if not conns:
                    self._conns.pop(uin, None)
            still_local = uin in self._conns
        # Device-scoped first, and BEFORE the early return below: this device
        # left even when other devices of the account are still on this worker,
        # and that is exactly the case the per-device push decision exists for.
        if gone_device and not device_still_local:
            try:
                redis = await get_redis()
                await redis.srem(_online_devs_key(uin), gone_device)
            except Exception:  # noqa: BLE001
                pass
        if still_local:
            return
        # Last LOCAL connection for this UIN dropped. We can't tell
        # whether other workers still have a session for them — the
        # SREM is best-effort; in the multi-device-multi-worker case
        # we may briefly mark a still-connected user as offline.
        # Acceptable for v1; messages routed to them via pub/sub will
        # still be delivered if they're online elsewhere.
        try:
            redis = await get_redis()
            await redis.srem(_ONLINE_KEY, uin)
        except Exception:  # noqa: BLE001
            pass

    async def online_devices(self, uin: int) -> set[str]:
        """Device ids of `uin` with a live socket somewhere in the cluster.

        The push paths subtract this from the account's registered push tokens,
        so a device that IS connected is not also woken, while every device
        that is not connected still is. Falls back to this worker's own view if
        Redis is unreachable — worst case we wake a device that was reachable
        anyway, which is the safe direction to be wrong in.
        """
        try:
            redis = await get_redis()
            raw = await redis.smembers(_online_devs_key(uin))
            # Refresh the TTL while someone is asking: an account that is being
            # messaged is an account whose sockets are demonstrably in use.
            if raw:
                await redis.expire(_online_devs_key(uin), _ONLINE_DEVS_TTL)
            return {d.decode() if isinstance(d, bytes) else d for d in raw}
        except Exception:  # noqa: BLE001
            return {
                self._device_of.get(ws, "primary") for ws in self._conns.get(uin, ())
            }

    async def touch_device(self, uin: int, device_id: str) -> None:
        """Keep a live device's online marker from expiring. Called on every
        client frame (iOS pings ~25s), which is what makes the TTL safe to keep
        short enough that a dead worker's leftovers age out quickly."""
        try:
            redis = await get_redis()
            await redis.sadd(_online_devs_key(uin), device_id)
            await redis.expire(_online_devs_key(uin), _ONLINE_DEVS_TTL)
        except Exception:  # noqa: BLE001
            pass

    async def is_online(self, uin: int) -> bool:
        """Cross-worker online check via Redis SET. Async now (was
        synchronous on the in-memory implementation) — callers had to
        be `await`-aware anyway since they're already in async paths.
        """
        try:
            redis = await get_redis()
            return bool(await redis.sismember(_ONLINE_KEY, uin))
        except Exception:  # noqa: BLE001
            # Fall back to local-only knowledge if Redis is down.
            return uin in self._conns

    async def online_subset(self, uins: Iterable[int]) -> set[int]:
        """Which of `uins` are online right now, in ONE Redis round trip.

        `is_online` per member is fine for a single check and ruinous in a
        loop: serialising a group's roster called it once per member, so one
        `GET /groups` for an account in the 1800-member beta group cost 1800
        sequential SISMEMBERs. Measured on prod at ~6900 SISMEMBER/s against
        twenty people actually online, which was most of the box's CPU.

        The online set is bounded by concurrent users, not by roster size, so
        pulling it whole and intersecting locally is cheaper than any
        per-member query and stays cheap as groups grow.
        """
        wanted = {int(u) for u in uins}
        if not wanted:
            return set()
        try:
            redis = await get_redis()
            raw = await redis.smembers(_ONLINE_KEY)
        except Exception:  # noqa: BLE001
            # Same fallback as is_online: local knowledge beats guessing.
            return {u for u in wanted if u in self._conns}
        online: set[int] = set()
        for m in raw:
            try:
                online.add(int(m if isinstance(m, (int, str)) else m.decode()))
            except (TypeError, ValueError):
                continue
        return wanted & online

    async def send(
        self,
        uin: int,
        payload: dict[str, Any],
        except_device: str | None = None,
    ) -> bool:
        """Deliver `payload` to every WS for `uin` across the cluster.
        Returns True if the user is online (somewhere) at publish time,
        False otherwise. Note: True doesn't guarantee delivery — it
        means we asked Redis whether they're online and they were. The
        actual deliveries happen async in the receiving workers.

        `except_device` skips one device of the account. Needed for
        "this was handled on another device of yours": the device that
        handled it must not be told to undo it, and the delivery has to
        skip it on every worker, not just this one.
        """
        await self._ensure_pubsub()
        text = json.dumps(payload)
        envelope = self._envelope(
            target="user",
            uin=uin,
            payload_text=text,
            except_device=except_device,
        )
        try:
            redis = await get_redis()
            await redis.publish(_FANOUT_CHANNEL, envelope)
            online = bool(await redis.sismember(_ONLINE_KEY, uin))
        except Exception:  # noqa: BLE001
            # Redis blip: fall back to local-only delivery so at least
            # users on this worker still receive the message.
            await self._deliver_user_local(uin, text, except_device)
            return uin in self._conns
        return online

    async def broadcast(self, uins: list[int], payload: dict[str, Any]) -> None:
        if not uins:
            return
        await self._ensure_pubsub()
        text = json.dumps(payload)
        try:
            redis = await get_redis()
            # Single publish per UIN — pub/sub is cheap (~10µs RTT to
            # localhost Redis). For room broadcasts of <100 members
            # this is fine.
            for uin in uins:
                envelope = self._envelope(
                    target="user", uin=uin, payload_text=text
                )
                await redis.publish(_FANOUT_CHANNEL, envelope)
        except Exception:  # noqa: BLE001
            # Local fallback.
            for uin in uins:
                await self._deliver_user_local(uin, text)

    async def fanout(self, uins: list[int], payload: dict[str, Any]) -> set[int]:
        """Publish `payload` to the ONLINE subset of `uins` in a single
        pipelined Redis round-trip. Returns the UINs that were online at
        publish time (callers that only want the delivery may ignore it).

        The per-uin `send()` loop is O(N) round-trips (a publish + a
        sismember each) which, on a large group (1000+ members), turned a
        membership broadcast into a ~15s crawl in the request path. Offline
        users receive nothing from a publish anyway (no live socket; they
        resync on reconnect), so we filter to the online set and pipeline
        the publishes — O(1) round-trips regardless of N, and behaviourally
        identical (the same users actually get the message).
        """
        if not uins:
            return set()
        await self._ensure_pubsub()
        text = json.dumps(payload)
        try:
            redis = await get_redis()
            online_raw = await redis.smembers(_ONLINE_KEY)  # set[str] (decode_responses=True)
            targets = [u for u in uins if str(u) in online_raw]
            if not targets:
                return set()
            async with redis.pipeline(transaction=False) as pipe:
                for uin in targets:
                    pipe.publish(
                        _FANOUT_CHANNEL,
                        self._envelope(target="user", uin=uin, payload_text=text),
                    )
                await pipe.execute()
            return set(targets)
        except Exception:  # noqa: BLE001
            # Redis blip: best-effort local delivery, same fallback as send/broadcast.
            delivered: set[int] = set()
            for uin in uins:
                if uin in self._conns:
                    delivered.add(uin)
                await self._deliver_user_local(uin, text)
            return delivered

    async def fanout_each(self, items: list[tuple[int, dict[str, Any]]]) -> set[int]:
        """Publish a DIFFERENT payload per recipient in one pipelined Redis
        round-trip. Returns the subset of UINs that were online at publish
        time — i.e. exactly what a `send()` per recipient would have reported.

        `fanout` above covers the one-payload-for-everyone case. The group
        sealed-sender path can't use it: every member gets their own
        ciphertext (each envelope is sealed to one identity key), so the
        payload differs per recipient. It used a `send()` loop instead, which
        is a publish AND a sismember per member — on the 1700-member flagship
        group that's ~3400 sequential round-trips inside the sender's own
        request, and it is what put /messages/group-sealed at a 153s p95 on
        prod. Same shape as `fanout`: one smembers, one pipeline, O(1)
        round-trips regardless of N.

        Offline members get nothing here (no live socket to receive it) —
        their copy rides the offline queue, exactly as before.
        """
        if not items:
            return set()
        await self._ensure_pubsub()
        try:
            redis = await get_redis()
            online_raw = await redis.smembers(_ONLINE_KEY)  # set[str] (decode_responses=True)
            online = {uin for uin, _ in items if str(uin) in online_raw}
            targets = [(uin, payload) for uin, payload in items if uin in online]
            if targets:
                async with redis.pipeline(transaction=False) as pipe:
                    for uin, payload in targets:
                        pipe.publish(
                            _FANOUT_CHANNEL,
                            self._envelope(
                                target="user",
                                uin=uin,
                                payload_text=json.dumps(payload),
                            ),
                        )
                    await pipe.execute()
            return online
        except Exception:  # noqa: BLE001
            # Redis blip: best-effort local delivery, same fallback as send().
            delivered: set[int] = set()
            for uin, payload in items:
                if uin in self._conns:
                    await self._deliver_user_local(uin, json.dumps(payload))
                    delivered.add(uin)
            return delivered

    async def broadcast_all(self, payload: dict[str, Any]) -> None:
        """Fan out to every connected UIN across the cluster. Used by
        the Crash game's round broadcasts and the UIN auction loop.
        """
        await self._ensure_pubsub()
        text = json.dumps(payload)
        envelope = self._envelope(target="all", payload_text=text)
        try:
            redis = await get_redis()
            await redis.publish(_FANOUT_CHANNEL, envelope)
        except Exception:  # noqa: BLE001
            # Local fallback.
            await self._deliver_all_local(text)


manager = ConnectionManager()
