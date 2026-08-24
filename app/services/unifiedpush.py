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

⚠ It did not match on the part that mattered until 2026-08-22: `title`
carried the PLAIN GROUP NAME and `group_name` repeated it, so the
distributor (for most Android users a third party, and for our own
`push.rcq.app` a Cloudflare edge that terminates TLS) read the room
name next to the endpoint on every post (metadata-map-2026-08-22 §1.6).
Both fields are gone and the title is a constant; see the note on
`apns._ALERT_TITLE` for what a reader on this path still sees.

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
import os
import random
from datetime import datetime, timedelta, timezone
from typing import Any, Sequence
from urllib.parse import urlparse

import httpx
from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import log_identity
from app.core.db import SessionLocal
from app.core.rate_limit import bucket_name
from app.models.device_token import DeviceToken

log = logging.getLogger(__name__)

_PLATFORM = "android-up"

# The banner title, for every wake of every kind. Spelled out here rather than
# imported from `apns` for the same reason `_UP_PLATFORM` is spelled out there:
# the two senders stay free of each other. See the note on `apns._ALERT_TITLE`
# for why this is a constant and not a parameter.
_ALERT_TITLE = "RCQ"

# How often a still-healthy endpoint re-stamps `push_last_ok`. Not per push
# (that would be a write on every wake for every device) and not never (which
# is what it was, and left the column permanently NULL for endpoints that had
# simply always worked).
_OK_STAMP_EVERY = timedelta(hours=1)

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

# OUTBOUND RELAY (2026-08-01). `ntfy.sh` stopped accepting TCP from this
# droplet's IP — v4 hangs to timeout, v6 is refused, while google/github answer
# in milliseconds from the same host; it looks like the public instance blocked
# us once the v0.76 rollout raised our POST volume. 732 of 877 Android
# endpoints on record point at ntfy.sh, so ~83% of Android devices simply
# stopped being woken ("сообщения пропускаются, когда приложение выключено",
# 2026-08-04; 10 075 ConnectTimeouts on 08-03 alone, zero before 08-01).
#
# Cloudflare's edge is not blocked, so POSTs to the blocked hosts — and only
# those — are forwarded through a narrow Worker (deploy/push-relay). Everything
# else, including our own push.rcq.app, keeps going direct. Unset
# PUSH_RELAY_URL and every push goes direct again, which is what a self-hosted
# island that nobody blocks should run.
_RELAY_URL = os.getenv("PUSH_RELAY_URL", "").strip()
_RELAY_KEY = os.getenv("PUSH_RELAY_KEY", "").strip()
_RELAY_HOSTS = frozenset(
    h.strip().lower() for h in os.getenv("PUSH_RELAY_HOSTS", "ntfy.sh").split(",") if h.strip()
)


def _endpoint_label(endpoint: str) -> str:
    """A safe name for one push endpoint in a log line.

    ⚠⚠ This replaces `endpoint[:48]`, which was a CREDENTIAL in the journal and
    the worst single line in the 2026-08-22 metadata audit. A UnifiedPush
    endpoint is `https://<host>/<topic>` and the topic IS the whole secret:
    `https://push.rcq.app/` is twenty-one characters, so forty-eight of them
    carried twenty-seven characters of topic, and an ntfy.sh endpoint fitted
    with room to spare. Anyone reading the log could then subscribe to a
    device's wakes and post fake ones at it. There is no level at which that is
    acceptable, so this is not behind RCQ_LOG_IDENTITIES: it is simply gone.

    The HOST survives, because that is the debuggable part: which distributor,
    is this the relayed one, is it our own push server. The topic becomes an
    HMAC under the same server secret the limiter buckets use, which is enough
    to tell two endpoints apart across lines (the retry line and the giving-up
    line are about the same device) and worth nothing to a reader.
    """
    try:
        host = (urlparse(endpoint).hostname or "?").lower()
    except ValueError:
        host = "?"
    return f"{host}/#{bucket_name('up-endpoint:' + endpoint)}"


def _needs_relay(endpoint: str) -> bool:
    if not _RELAY_URL or not _RELAY_KEY:
        return False
    try:
        return (urlparse(endpoint).hostname or "").lower() in _RELAY_HOSTS
    except ValueError:
        return False


# SHORTCUT TO OUR OWN PUSH SERVER (2026-08-05). Clients mint their endpoint
# from a public name, and that name now sits behind Cloudflare so that blocking
# the island's address cannot take push down with it. Delivering to it verbatim
# would send every wake out to the CF edge and straight back to this same box:
# a hop that can rate-limit us, can be down while we are up, and costs ~90ms
# against ~9ms on loopback (measured).
#
# It also silently unpicked ntfy's `visitor-request-limit-exempt-hosts`, which
# names this droplet's address — arriving from a CF edge instead, the island's
# own deliveries stopped being exempt and started spending a shared bucket.
#
# So an endpoint that names our own push host is sent to the local instance,
# with the path and query untouched. Unset PUSH_LOCAL_BASE and everything goes
# out over the public name again, which is what an island whose push server
# lives on another host should do.
_LOCAL_BASE = os.getenv("PUSH_LOCAL_BASE", "").strip().rstrip("/")
_LOCAL_HOSTS = frozenset(
    h.strip().lower()
    for h in os.getenv("PUSH_LOCAL_HOSTS", "push.rcq.app").split(",")
    if h.strip()
)


def _localize(endpoint: str) -> str | None:
    """The loopback URL for an endpoint on our own push host, else None."""
    if not _LOCAL_BASE:
        return None
    try:
        parts = urlparse(endpoint)
    except ValueError:
        return None
    if (parts.hostname or "").lower() not in _LOCAL_HOSTS:
        return None
    return f"{_LOCAL_BASE}{parts.path}" + (f"?{parts.query}" if parts.query else "")


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


# (token id, endpoint url, last error, device id, last success)
EndpointRow = tuple[int, str, str | None, str | None, datetime | None]


async def _endpoints_for(uin: int) -> list[EndpointRow]:
    """Read this user's Android UnifiedPush endpoints in a SHORT session,
    then release the DB connection BEFORE any network I/O — same no-DB-across-
    network rule apns.py follows to avoid pinning a pool connection across a
    stalled push. Carries the last recorded health so the writer below can
    skip the UPDATE when nothing changed, and the device id so the caller can
    leave a device that is already connected alone."""
    async with SessionLocal() as db:  # type: AsyncSession
        rows = (
            await db.execute(
                select(
                    DeviceToken.id,
                    DeviceToken.token,
                    DeviceToken.push_last_error,
                    DeviceToken.device_id,
                    DeviceToken.push_last_ok,
                ).where(DeviceToken.uin == uin, DeviceToken.platform == _PLATFORM)
            )
        ).all()
    return [(r[0], r[1], r[2], r[3], r[4]) for r in rows]


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
    # Our own push host is answered on loopback — checked first, because it is
    # never a host the edge relay exists for and the relay would only add the
    # trip this shortcut removes.
    #
    # A blocked host goes through the edge relay, which forwards the same body
    # and headers and hands back the upstream status verbatim — so the retry
    # rules below read the same 429/507 they would have read directly.
    url = _localize(endpoint) or endpoint
    if url == endpoint and _needs_relay(endpoint):
        url = _RELAY_URL
        headers["X-Relay-Target"] = endpoint
        headers["X-Relay-Key"] = _RELAY_KEY
    try:
        resp = await client.post(url, content=body, headers=headers)
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
            log.info("[up] %s for %s, retry %d", detail, _endpoint_label(endpoint), attempt + 1)
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


# Bookkeeping from one fan-out is one write, not one write per recipient. Each
# delivery task finishes on its own and used to open its own session for the
# stamp, so a post to the beta group asked the pool for a connection per woken
# member the moment the hourly freshness stamp came due — the same pile-up the
# batched endpoint read removes on the way in. Collect for a beat, write once.
_HEALTH_FLUSH_DELAY = 2.0
_pending_ok: set[int] = set()
_pending_failed: list[tuple[int, str]] = []
_pending_dead: set[int] = set()
_health_flush: asyncio.Task | None = None


def _queue_health(
    ok_ids: list[int], failed: list[tuple[int, str]], dead_ids: list[int]
) -> None:
    """Fold one task's outcome into the pending batch and make sure a flush is
    on its way. Never awaited by the sender."""
    global _health_flush
    if not ok_ids and not failed and not dead_ids:
        return
    _pending_ok.update(ok_ids)
    _pending_failed.extend(failed)
    _pending_dead.update(dead_ids)
    if _health_flush is None or _health_flush.done():
        _health_flush = asyncio.create_task(_flush_health())
        _tasks.add(_health_flush)
        _health_flush.add_done_callback(_tasks.discard)


async def _flush_health() -> None:
    await asyncio.sleep(_HEALTH_FLUSH_DELAY)
    # Drain under no await, so a task finishing mid-flush lands in the NEXT
    # batch rather than being written twice or dropped.
    ok, failed, dead = list(_pending_ok), list(_pending_failed), list(_pending_dead)
    _pending_ok.clear()
    _pending_failed.clear()
    _pending_dead.clear()
    await _record_health(ok, failed, dead)


async def _fan_out(
    uin: int,
    payload: dict[str, Any],
    ttl: int,
    what: str,
    exclude_tokens: frozenset[str] = frozenset(),
    skip_devices: frozenset[str] = frozenset(),
    endpoints: Sequence[EndpointRow] | None = None,
) -> None:
    """Deliver `payload` to every UnifiedPush endpoint of `uin`. Runs as a
    background task; nothing awaits the result but the log line and the
    health columns.

    `exclude_tokens` skips endpoints that are also registered by the SENDER
    of the event being pushed: on a multi-account device every local account
    registers the same endpoint, so without this the author's own phone gets
    woken about their own group post through a sibling account.

    `skip_devices` (non-empty only when some device of the account IS
    connected) narrows delivery to endpoints that can be positively placed on a
    device WITHOUT a live socket. Endpoints registered before device-aware
    registration carry no device id and are skipped in that case, because they
    might belong to the connected device — same conservative answer the old
    account-wide check gave. When nothing is connected this is empty and every
    endpoint is woken as before.

    `endpoints` given: a group fan-out already read every recipient's rows in
    one query, so this task must not open a session of its own to re-read what
    it was handed — that per-recipient session is exactly what starves the
    pool on a large group."""
    if endpoints is None:
        try:
            endpoints = await _endpoints_for(uin)
        except Exception:  # noqa: BLE001 — a pool timeout must not kill the task loudly
            log.exception("[up] endpoint lookup failed uin=%s", log_identity(uin))
            return
    endpoints = list(endpoints)
    if exclude_tokens:
        skipped = [e for _, e, _, _, _ in endpoints if e in exclude_tokens]
        if skipped:
            endpoints = [row for row in endpoints if row[1] not in exclude_tokens]
            log.info(
                "[up] %s uin=%s skipping %d sender-device endpoint(s)",
                what, log_identity(uin), len(skipped),
            )
    if skip_devices:
        before = len(endpoints)
        # Keep ONLY endpoints we can positively place on a device that is not
        # connected. An endpoint with no device id could belong to the device
        # that is online right now, and this branch runs precisely when one is
        # — so leaving it in would resurrect the double-buzz the old
        # account-wide suppression avoided.
        endpoints = [row for row in endpoints if row[3] and row[3] not in skip_devices]
        if len(endpoints) != before:
            log.info(
                "[up] %s uin=%s skipping %d connected/unattributed endpoint(s)",
                what, log_identity(uin), before - len(endpoints),
            )
    if not endpoints:
        return
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    results = await asyncio.gather(
        *(_deliver(endpoint, body, ttl) for _, endpoint, _, _, _ in endpoints),
        return_exceptions=True,
    )
    ok_ids: list[int] = []
    failed: list[tuple[int, str]] = []
    dead_ids: list[int] = []
    sent = 0
    fresh_before = datetime.now(timezone.utc) - _OK_STAMP_EVERY
    for (token_id, endpoint, prev_error, _device, prev_ok), result in zip(endpoints, results):
        if isinstance(result, BaseException):
            log.warning("[up] delivery task error for %s: %r", _endpoint_label(endpoint), result)
            continue
        outcome, detail = result
        if outcome == "ok":
            sent += 1
            # Write when the endpoint was previously unhealthy, or when the
            # last success on record is old enough to be worth refreshing.
            # ⚠ It used to be the first case ONLY, which meant an endpoint that
            # had never once failed carried `push_last_ok = NULL` forever — and
            # "never failed" and "never pushed to" were then the same row. That
            # is the state every endpoint of the tester who reported push going
            # quiet was in: nothing to look at, either way. One stamp an hour
            # answers the question and still costs nothing per push.
            if prev_error is not None or prev_ok is None or prev_ok < fresh_before:
                ok_ids.append(token_id)
        elif outcome == "drop":
            dead_ids.append(token_id)
        else:
            log.warning("[up] %s giving up on %s (%s)", detail, _endpoint_label(endpoint), what)
            if prev_error != detail:
                failed.append((token_id, detail))
    # `uin=` is the message RECIPIENT, the same delivery graph as the APNs line
    # and the [sealed] line above it, behind the same flag. The counts are the
    # operational half and they stay.
    log.warning(
        "[up] %s uin=%s endpoints=%d sent=%d", what, log_identity(uin), len(endpoints), sent
    )
    _queue_health(ok_ids, failed, dead_ids)


def _schedule(
    uin: int,
    payload: dict[str, Any],
    ttl: int,
    what: str,
    exclude_tokens: frozenset[str] = frozenset(),
    skip_devices: frozenset[str] = frozenset(),
    endpoints: Sequence[EndpointRow] | None = None,
) -> None:
    """Fire the fan-out as a background task. Deliberately NOT awaited by the
    caller: retries span ~30s and the sender's HTTP request (or the WS call
    relay) must not wait on a third-party push server."""
    task = asyncio.create_task(
        _fan_out(uin, payload, ttl, what, exclude_tokens, skip_devices, endpoints)
    )
    _tasks.add(task)
    task.add_done_callback(_tasks.discard)


async def send_to_user(
    uin: int,
    *,
    alert_body: str = "New message",
    envelope_b64: str | None = None,
    envelope_type: str | None = None,
    to_device_id: int | None = None,
    thread_id: str | None = None,
    notif_kind: str | None = None,
    group_id: int | None = None,
    exclude_tokens: frozenset[str] = frozenset(),
    skip_devices: frozenset[str] = frozenset(),
    endpoints: Sequence[EndpointRow] | None = None,
) -> int:
    """Wake every Android UnifiedPush device of `uin`. No-op when the user has
    no Android endpoints (the common case for an iOS-only account). Same
    keyword signature as apns.send_to_user so the offline-push hook sites can
    fire both with parallel one-liners.

    `exclude_tokens` = endpoints registered by the event's AUTHOR; matching
    endpoints are skipped so the sending device is never woken about its own
    action through a sibling local account (multi-account phones register one
    shared endpoint per device).

    `skip_devices` = device ids that already hold a live socket and were handed
    the envelope over it. Endpoints without a recorded device id are always
    woken (see `_fan_out`).

    Returns 1 once the wake is SCHEDULED (delivery happens in the background),
    not the number of devices reached — the callers only use it for a log
    counter, and waiting on a distributor is exactly what this stopped doing.

    The opaque `env` (already E2E-encrypted) is carried so the woken receiver
    can decrypt + post the real notification in-process without a queue fetch,
    exactly like the iOS NSE — the push server sees only ciphertext.

    ⚠ No `alert_title` and no `group_name`, same as `apns.send_to_user` and for
    the same reason: those two fields were the room name and the sender's
    nickname, handed to a third-party distributor in the clear on every wake.
    Both are gone from the SIGNATURE so no caller can put them back by
    accident. The receiver titles the banner from the envelope it opens or from
    its own group cache.
    """
    payload: dict[str, Any] = {
        "v": 1, "type": "msg", "to_uin": uin, "title": _ALERT_TITLE, "body": alert_body,
    }
    if envelope_b64:
        payload["env"] = envelope_b64
        payload["envType"] = envelope_type or "message"
        if to_device_id is not None:
            # Which of the account's libsignal devices this copy is for. A
            # fan-out message wakes every install, and only one of them holds
            # the ratchet that opens it — without this the others try, fail,
            # and raise the generic "New message" banner reserved for a real
            # decryption problem. They read it and stay quiet instead.
            payload["toDev"] = to_device_id
    if thread_id:
        payload["thread_id"] = thread_id
    if notif_kind:
        payload["notif_kind"] = notif_kind
    if group_id is not None:
        # Kept, deliberately: the receiver's mute and mentions-only gates run
        # before it opens anything and key on this id, so removing it would
        # silently break muting for a release. It is an id, not a name, and it
        # goes when group identity is sealed.
        payload["group_id"] = group_id
    _schedule(uin, payload, _TTL_MESSAGE, "msg", exclude_tokens, skip_devices, endpoints)
    return 1


async def send_call_to_user(
    uin: int, *, payload: dict[str, Any], skip_devices: frozenset[str] = frozenset()
) -> int:
    """Wake-for-call fan-out to Android UnifiedPush devices. `payload` is the
    flat call dict (call_id, from_uin, media, sdp) — the woken receiver shows
    the full-screen incoming-call UI. Mirrors apns.send_voip_to_user; a `type`
    discriminator lets the receiver tell a call wake from a message wake.
    No-op when the user has no endpoints.

    ⚠ NO `nickname`, and do not add one back. It was in this payload until
    2026-08-24, and this road is not Apple's: it is whatever distributor the
    callee installed, and for our own push.rcq.app it is a Cloudflare edge
    that terminates TLS. Either way it was learning who was calling whom, by
    name. `Push.showIncomingCall` resolves the name from the account's own
    roster off `from_uin` and `to_uin`. See the ⚠ block in `apns`'s header.

    `skip_devices` skips installs by device id — the device that ANSWERED,
    when this push is the answered-elsewhere un-ring (the fan-out already
    drops device-id-less rows whenever the set is non-empty, which is the
    safe side: an end push landing on the device that is IN the call would
    tear its own call down)."""
    body = {"v": 1, "type": "call", "to_uin": uin, **payload}
    _schedule(uin, body, _TTL_CALL, "call", skip_devices=skip_devices)
    return 1
