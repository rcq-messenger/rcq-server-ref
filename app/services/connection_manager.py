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
from collections import defaultdict
from typing import Any

from fastapi import WebSocket

from app.core.redis import get_redis

log = logging.getLogger(__name__)

# Single channel for all fanout. Envelope describes target ("user" or
# "all") and the inner payload — every worker filters on receive.
_FANOUT_CHANNEL = "ws:fanout"
# Set of UINs currently connected to ANY worker. Used by `is_online()`.
_ONLINE_KEY = "ws:online_uins"


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
        self._lock = asyncio.Lock()
        # Background task that subscribes to the fanout channel and
        # delivers received messages to LOCAL connections only. Started
        # lazily on first connect; survives forever per worker.
        self._pubsub_task: asyncio.Task | None = None
        self._pubsub_started = asyncio.Event()

    async def _ensure_pubsub(self) -> None:
        """Spin up the pub/sub listener once per worker. Called from
        every public method that publishes — cheap idempotent check."""
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

    async def _pubsub_loop(self) -> None:
        """Long-lived task that listens for fanout publishes and
        delivers them to LOCAL websockets. Reconnects on transient
        Redis failures so a worker keeps participating in the cluster
        even through a Redis blip."""
        while True:
            try:
                redis = await get_redis()
                pubsub = redis.pubsub()
                await pubsub.subscribe(_FANOUT_CHANNEL)
                self._pubsub_started.set()
                async for message in pubsub.listen():
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
                    if not isinstance(payload_text, str):
                        continue
                    if target == "all":
                        await self._deliver_all_local(payload_text)
                    elif target == "user":
                        uin = envelope.get("uin")
                        if isinstance(uin, int):
                            await self._deliver_user_local(uin, payload_text)
                    elif target == "supersede":
                        # Another worker accepted a new socket for
                        # this UIN — close any stale sockets we still
                        # hold for it so a future broadcast doesn't
                        # fan out to ghost connections.
                        uin = envelope.get("uin")
                        origin_pid = envelope.get("pid")
                        if isinstance(uin, int) and origin_pid != os.getpid():
                            await self._close_local_sockets(uin)
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001
                # Reconnect after a short backoff. Reset the started
                # event so callers wait for the next subscribe to land.
                log.exception("ws fanout loop hiccup; reconnecting in 2s")
                self._pubsub_started.clear()
                await asyncio.sleep(2.0)

    async def _deliver_user_local(self, uin: int, text: str) -> None:
        for ws in list(self._conns.get(uin, ())):
            try:
                await ws.send_text(text)
            except Exception:  # noqa: BLE001
                # Broken sockets get cleaned up by their own WS endpoint
                # task; we only need to not blow up here.
                pass

    async def _close_local_sockets(self, uin: int) -> None:
        old: list[WebSocket] = []
        async with self._lock:
            old = list(self._conns.get(uin, set()))
            self._conns.pop(uin, None)
        for ws in old:
            try:
                await ws.close(code=4000, reason="superseded")
            except Exception:  # noqa: BLE001
                pass

    async def _deliver_all_local(self, text: str) -> None:
        for conns in list(self._conns.values()):
            for ws in list(conns):
                try:
                    await ws.send_text(text)
                except Exception:  # noqa: BLE001
                    pass

    # ── Public API ──────────────────────────────────────────────────

    async def connect(self, uin: int, ws: WebSocket) -> None:
        await ws.accept()
        # Drop any stale sockets we already have for this UIN locally.
        # iOS reconnect cycles + 4-worker round-robin LB previously
        # left zombie connections on other workers: a single bid would
        # then fan out and be delivered N times because the client
        # had N parallel sockets (one per worker it had hit).
        # Cluster-wide eviction is the next paragraph; this one just
        # handles same-worker duplicates.
        old_sockets: list[WebSocket] = []
        async with self._lock:
            old_sockets = list(self._conns.get(uin, set()))
            self._conns[uin] = {ws}
        for old in old_sockets:
            try:
                await old.close(code=4000, reason="superseded")
            except Exception:  # noqa: BLE001
                pass
        await self._ensure_pubsub()
        # Mark UIN as online cluster-wide so APNs decisions and
        # `is_online` checks on other workers see them. Also broadcast
        # a `supersede` request so peer workers drop their stale
        # sockets for this UIN — that's the cross-worker half of the
        # deduplication above.
        try:
            redis = await get_redis()
            await redis.sadd(_ONLINE_KEY, uin)
            envelope = json.dumps({
                "target": "supersede",
                "uin": uin,
                "pid": os.getpid(),
            })
            await redis.publish(_FANOUT_CHANNEL, envelope)
        except Exception:  # noqa: BLE001
            log.warning("Could not mark uin=%d online in redis", uin)

    async def disconnect(self, uin: int, ws: WebSocket) -> None:
        async with self._lock:
            conns = self._conns.get(uin)
            if conns:
                conns.discard(ws)
                if not conns:
                    self._conns.pop(uin, None)
            still_local = uin in self._conns
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

    async def send(self, uin: int, payload: dict[str, Any]) -> bool:
        """Deliver `payload` to every WS for `uin` across the cluster.
        Returns True if the user is online (somewhere) at publish time,
        False otherwise. Note: True doesn't guarantee delivery — it
        means we asked Redis whether they're online and they were. The
        actual deliveries happen async in the receiving workers.
        """
        await self._ensure_pubsub()
        text = json.dumps(payload)
        envelope = json.dumps({"target": "user", "uin": uin, "payload_text": text})
        try:
            redis = await get_redis()
            await redis.publish(_FANOUT_CHANNEL, envelope)
            online = bool(await redis.sismember(_ONLINE_KEY, uin))
        except Exception:  # noqa: BLE001
            # Redis blip: fall back to local-only delivery so at least
            # users on this worker still receive the message.
            await self._deliver_user_local(uin, text)
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
                envelope = json.dumps(
                    {"target": "user", "uin": uin, "payload_text": text}
                )
                await redis.publish(_FANOUT_CHANNEL, envelope)
        except Exception:  # noqa: BLE001
            # Local fallback.
            for uin in uins:
                await self._deliver_user_local(uin, text)

    async def broadcast_all(self, payload: dict[str, Any]) -> None:
        """Fan out to every connected UIN across the cluster. Used by
        the Crash game's round broadcasts and the UIN auction loop.
        """
        await self._ensure_pubsub()
        text = json.dumps(payload)
        envelope = json.dumps({"target": "all", "payload_text": text})
        try:
            redis = await get_redis()
            await redis.publish(_FANOUT_CHANNEL, envelope)
        except Exception:  # noqa: BLE001
            # Local fallback.
            await self._deliver_all_local(text)


manager = ConnectionManager()
