"""UnifiedPush sender — wake + alert/call pushes to Android clients.

Android can't use FCM in the target region (Google services blocked), so
the Android client registers a **UnifiedPush endpoint** instead — a plain
HTTPS URL handed out by whatever distributor the user runs (ntfy.sh, a
self-hosted ntfy, NextPush, a WebPush distributor …). The server is
deliberately dumb: it just HTTP-POSTs the push payload to that URL. The
distributor's push server relays the bytes to the device, which wakes the
RCQ app's UnifiedPush receiver. There is NO provider API key or hardcoded
gateway here — the endpoint URL the app registered IS the whole address.

Privacy: the push body carries the same opaque, already-E2E-encrypted
envelope APNs carries (`env`), so the push server sees ciphertext, not
content — exactly the exposure Apple already has on the iOS path. Call
pushes carry the call payload (call_id/from/sdp) just like the iOS VoIP
push does; the push server's exposure there matches APNs VoIP.

Endpoints are stored in `device_tokens` with `platform="android-up"`
(the URL in the `token` column), so they reuse the existing registration
upsert (`POST /users/me/push-token`), the burn cascade, and the
`DELETE /users/me/push-token` cleanup. `send_to_user` / `send_call_to_user`
mirror the apns.py entrypoints so the offline-push hook sites stay
symmetric.

DELIVERY (2026-07-31, after 81% of prod sends were failing):

  * **Off the request path.** Both entrypoints schedule a background task
    and return immediately. A stalled distributor used to add up to 15s to
    the *sender's* HTTP request, and the endpoint lookup burned one of the
    (deliberately tiny) pooled DB connections while the sender waited.

  * **Retries.** ntfy.sh answers `507` when the topic has no currently
    connected subscriber, and `429` when the rate bucket is drained — and
    on ntfy that bucket is charged to the SUBSCRIBER's visitor (see
    `limitRequestsWithTopic` upstream), so a phone behind a carrier NAT
    shares one bucket with every other RCQ user on that NAT. Both states
    flap on a timescale of seconds (on prod, 37 of 59 failing endpoints
    saw both codes within the same day), so a dropped-on-first-try push
    was throwing away a wake the distributor would have accepted moments
    later. Retryable statuses get a jittered backoff; permanent ones don't.

  * **WebPush headers.** `TTL` is mandatory in RFC 8030 — Mozilla's
    autopush (the endpoint a WebPush distributor hands out) rejects a
    POST without it with `400`, which is exactly what every one of those
    endpoints was getting. ntfy ignores both headers.

  * **Health.** The final outcome per endpoint is written back to
    `device_tokens` (only when it CHANGES, to keep the write rate near
    zero) so `GET /users/me/push-health` can tell the user their
    distributor is not delivering — previously push just died silently.
"""
from __future__ import annotations

import asyncio
import json
import logging
import random
from datetime import datetime, timezone
from typing import Any

import httpx
from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import SessionLocal
from app.models.device_token import DeviceToken

log = logging.getLogger(__name__)

_PLATFORM = "android-up"

# How long the push server may hold the wake for a device that is offline
# (RFC 8030 `TTL`). A message wake is worth keeping for a while; a call wake
# is worthless the moment the caller gives up, so it expires fast.
_TTL_MESSAGE = 86400
_TTL_CALL = 60

# Statuses worth another attempt. 429 = rate bucket drained (on ntfy that is
# the *subscriber's* bucket, shared across a carrier NAT), 507 = no currently
# connected subscriber, 5xx = the push server itself is unwell. Everything
# else (400/403/413…) is a permanent rejection — retrying just burns quota.
_RETRY_STATUSES = frozenset({408, 429, 500, 502, 503, 504, 507})

# Attempt schedule: fire, then two retries with jitter. ~30s of coverage,
# which is where the observed 507/429 flaps recover, without holding a task
# alive long enough to pile up under a fan-out burst.
_RETRY_DELAYS = (6.0, 24.0)

# Ceiling on concurrent endpoint POSTs across the worker. A group fan-out can
# touch hundreds of endpoints at once; without a cap those all become live
# sockets (and, with retries, live tasks) simultaneously.
_MAX_INFLIGHT = 24

_client: httpx.AsyncClient | None = None
_sem: asyncio.Semaphore | None = None
# Strong refs to in-flight delivery tasks — asyncio only holds a weak ref, so
# a fire-and-forget task can be garbage-collected mid-await without this.
_tasks: set[asyncio.Task] = set()


async def _ensure_client() -> httpx.AsyncClient:
    global _client
    if _client is None:
        # Shorter than the old 10s: nothing awaits this any more, but a slow
        # endpoint still occupies an inflight slot, and the retry schedule
        # covers a distributor that needs a moment.
        _client = httpx.AsyncClient(timeout=8.0, follow_redirects=True)
    return _client


def _semaphore() -> asyncio.Semaphore:
    global _sem
    if _sem is None:
        _sem = asyncio.Semaphore(_MAX_INFLIGHT)
    return _sem


async def _endpoints_for(uin: int) -> list[tuple[int, str, str | None]]:
    """Read this user's Android UnifiedPush endpoints in a SHORT session,
    then release the DB connection BEFORE any network I/O — same no-DB-across-
    network rule apns.py follows to avoid pinning a pool connection across a
    stalled push. Carries the last recorded health so the writer below can
    skip the UPDATE when nothing changed."""
    async with SessionLocal() as db:  # type: AsyncSession
        rows = (
            await db.execute(
                select(DeviceToken.id, DeviceToken.token, DeviceToken.push_last_error).where(
                    DeviceToken.uin == uin, DeviceToken.platform == _PLATFORM
                )
            )
        ).all()
    return [(r[0], r[1], r[2]) for r in rows]


async def _post_once(endpoint: str, body: bytes, ttl: int) -> tuple[str, str]:
    """POST one payload to one UnifiedPush endpoint. Returns
    (outcome, detail) where outcome is "ok" | "retry" | "drop" | "fail".
    Pure network — no DB.

    A 404/410 means the distributor dropped the registration (app
    uninstalled / unregistered) so we prune it. Retryable statuses and
    transport errors come back as "retry"; anything else is a permanent
    "fail" we record but keep the endpoint for (the user may fix their
    distributor without re-registering)."""
    client = await _ensure_client()
    headers = {
        "Content-Type": "application/json",
        # RFC 8030 §5.2 — REQUIRED by WebPush servers (Mozilla autopush 400s
        # without it). ntfy ignores it.
        "TTL": str(ttl),
        "Urgency": "high",
    }
    try:
        resp = await client.post(endpoint, content=body, headers=headers)
    except (httpx.HTTPError, asyncio.TimeoutError) as exc:
        return "retry", type(exc).__name__
    if 200 <= resp.status_code < 300:
        return "ok", str(resp.status_code)
    if resp.status_code in (404, 410):
        return "drop", str(resp.status_code)
    if resp.status_code in _RETRY_STATUSES:
        return "retry", str(resp.status_code)
    return "fail", str(resp.status_code)


async def _deliver(endpoint: str, body: bytes, ttl: int) -> tuple[str, str]:
    """One endpoint, up to len(_RETRY_DELAYS)+1 attempts. Returns the final
    (outcome, detail). Jitter keeps a fan-out's retries from re-bursting in
    lockstep — which for a shared-NAT ntfy visitor is what drained the bucket
    in the first place."""
    outcome, detail = "fail", "unsent"
    for attempt, delay in enumerate((0.0, *_RETRY_DELAYS)):
        if delay:
            await asyncio.sleep(delay * (0.75 + random.random() * 0.5))
        async with _semaphore():
            outcome, detail = await _post_once(endpoint, body, ttl)
        if outcome != "retry":
            return outcome, detail
        if attempt < len(_RETRY_DELAYS):
            log.info("[up] %s for %s… — retry %d", detail, endpoint[:48], attempt + 1)
    return outcome, detail


async def _record_health(
    ok_ids: list[int], failed: list[tuple[int, str]], dead_ids: list[int]
) -> None:
    """Persist the outcome of a fan-out, AFTER the network phase. Best-effort:
    push bookkeeping must never break a send, and it must not become a write
    per push — callers pass only endpoints whose state actually CHANGED."""
    if not ok_ids and not failed and not dead_ids:
        return
    try:
        async with SessionLocal() as db:  # type: AsyncSession
            if dead_ids:
                await db.execute(delete(DeviceToken).where(DeviceToken.id.in_(dead_ids)))
            if ok_ids:
                await db.execute(
                    update(DeviceToken)
                    .where(DeviceToken.id.in_(ok_ids))
                    .values(push_last_error=None, push_last_ok=datetime.now(timezone.utc))
                )
            for token_id, detail in failed:
                await db.execute(
                    update(DeviceToken)
                    .where(DeviceToken.id == token_id)
                    .values(push_last_error=detail[:32])
                )
            await db.commit()
        if dead_ids:
            log.warning("[up] dropped %d stale endpoint(s)", len(dead_ids))
    except Exception:  # noqa: BLE001 — bookkeeping must never break a send
        log.exception("[up] failed to record push health")


async def _fan_out(uin: int, payload: dict[str, Any], ttl: int, what: str) -> None:
    """Deliver `payload` to every UnifiedPush endpoint of `uin`. Runs as a
    background task; nothing awaits the result but the log line and the
    health columns."""
    try:
        endpoints = await _endpoints_for(uin)
    except Exception:  # noqa: BLE001 — a pool timeout must not kill the task loudly
        log.exception("[up] endpoint lookup failed uin=%s", uin)
        return
    if not endpoints:
        return
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    results = await asyncio.gather(
        *(_deliver(endpoint, body, ttl) for _, endpoint, _ in endpoints),
        return_exceptions=True,
    )
    ok_ids: list[int] = []
    failed: list[tuple[int, str]] = []
    dead_ids: list[int] = []
    sent = 0
    for (token_id, endpoint, prev_error), result in zip(endpoints, results):
        if isinstance(result, BaseException):
            log.warning("[up] delivery task error for %s…: %r", endpoint[:48], result)
            continue
        outcome, detail = result
        if outcome == "ok":
            sent += 1
            # Only write when the endpoint was previously unhealthy — a
            # healthy endpoint costs zero DB writes per push.
            if prev_error is not None:
                ok_ids.append(token_id)
        elif outcome == "drop":
            dead_ids.append(token_id)
        else:
            log.warning("[up] %s giving up on %s… (%s)", detail, endpoint[:48], what)
            if prev_error != detail:
                failed.append((token_id, detail))
    log.warning("[up] %s uin=%s endpoints=%d sent=%d", what, uin, len(endpoints), sent)
    await _record_health(ok_ids, failed, dead_ids)


def _schedule(uin: int, payload: dict[str, Any], ttl: int, what: str) -> None:
    """Fire the fan-out as a background task. Deliberately NOT awaited by the
    caller: retries span ~30s and the sender's HTTP request (or the WS call
    relay) must not wait on a third-party push server."""
    task = asyncio.create_task(_fan_out(uin, payload, ttl, what))
    _tasks.add(task)
    task.add_done_callback(_tasks.discard)


async def send_to_user(
    uin: int,
    *,
    alert_title: str = "RCQ",
    alert_body: str = "New message",
    envelope_b64: str | None = None,
    envelope_type: str | None = None,
    thread_id: str | None = None,
    notif_kind: str | None = None,
    group_id: int | None = None,
    group_name: str | None = None,
) -> int:
    """Wake every Android UnifiedPush device of `uin`. No-op when the user has
    no Android endpoints (the common case for an iOS-only account). Same
    keyword signature as apns.send_to_user so the offline-push hook sites can
    fire both with parallel one-liners.

    Returns 1 once the wake is SCHEDULED (delivery happens in the background),
    not the number of devices reached — the callers only use it for a log
    counter, and waiting on a distributor is exactly what this stopped doing.

    The opaque `env` (already E2E-encrypted) is carried so the woken receiver
    can decrypt + post the real notification in-process without a queue fetch,
    exactly like the iOS NSE — the push server sees only ciphertext.
    """
    payload: dict[str, Any] = {"v": 1, "type": "msg", "to_uin": uin, "title": alert_title, "body": alert_body}
    if envelope_b64:
        payload["env"] = envelope_b64
        payload["envType"] = envelope_type or "message"
    if thread_id:
        payload["thread_id"] = thread_id
    if notif_kind:
        payload["notif_kind"] = notif_kind
    if group_id is not None:
        payload["group_id"] = group_id
    if group_name:
        payload["group_name"] = group_name
    _schedule(uin, payload, _TTL_MESSAGE, "msg")
    return 1


async def send_call_to_user(uin: int, *, payload: dict[str, Any]) -> int:
    """Wake-for-call fan-out to Android UnifiedPush devices. `payload` is the
    flat call dict (call_id, from_uin, nickname, media, sdp) — the woken
    receiver shows the full-screen incoming-call UI. Mirrors
    apns.send_voip_to_user; a `type` discriminator lets the receiver tell a
    call wake from a message wake. No-op when the user has no endpoints."""
    body = {"v": 1, "type": "call", "to_uin": uin, **payload}
    _schedule(uin, body, _TTL_CALL, "call")
    return 1
