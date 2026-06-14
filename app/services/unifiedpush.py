"""UnifiedPush sender — wake + alert/call pushes to Android clients.

Android can't use FCM in the target region (Google services blocked), so
the Android client registers a **UnifiedPush endpoint** instead — a plain
HTTPS URL handed out by whatever distributor the user runs (ntfy.sh, a
self-hosted ntfy, NextPush, …). The server is deliberately dumb: it just
HTTP-POSTs the push payload to that URL. The distributor's push server
relays the bytes to the device, which wakes the RCQ app's UnifiedPush
receiver. There is NO provider API key or hardcoded gateway here — the
endpoint URL the app registered IS the whole address.

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
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

import httpx
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import SessionLocal
from app.models.device_token import DeviceToken

log = logging.getLogger(__name__)

_PLATFORM = "android-up"

# Shared HTTP client — endpoint POSTs are short and benefit from connection
# reuse to the common distributor hosts (ntfy.sh). Lazy so import stays cheap.
_client: httpx.AsyncClient | None = None


async def _ensure_client() -> httpx.AsyncClient:
    global _client
    if _client is None:
        _client = httpx.AsyncClient(timeout=10.0, follow_redirects=True)
    return _client


async def _endpoints_for(uin: int) -> list[tuple[int, str]]:
    """Read this user's Android UnifiedPush endpoints in a SHORT session,
    then release the DB connection BEFORE any network I/O — same no-DB-across-
    network rule apns.py follows to avoid pinning a pool connection across a
    stalled push."""
    async with SessionLocal() as db:  # type: AsyncSession
        rows = (
            await db.execute(
                select(DeviceToken.id, DeviceToken.token).where(
                    DeviceToken.uin == uin, DeviceToken.platform == _PLATFORM
                )
            )
        ).all()
    return [(r[0], r[1]) for r in rows]


async def _post_one(endpoint: str, body: bytes) -> tuple[bool, bool]:
    """POST one payload to one UnifiedPush endpoint. Returns
    (sent_ok, should_drop_endpoint). Pure network — no DB. A 404/410 means
    the distributor dropped the registration (app uninstalled / unregistered)
    so we prune it; transport errors and other statuses are non-fatal (the
    push server may be transiently down)."""
    client = await _ensure_client()
    try:
        resp = await asyncio.wait_for(
            client.post(endpoint, content=body, headers={"Content-Type": "application/json"}),
            timeout=15.0,
        )
    except (httpx.HTTPError, asyncio.TimeoutError) as exc:
        log.warning("[up] transport error for endpoint %s…: %s", endpoint[:48], exc)
        return False, False
    if 200 <= resp.status_code < 300:
        return True, False
    # A distributor returns 404/410 once the app's registration is gone.
    if resp.status_code in (404, 410):
        log.warning("[up] %s for endpoint %s… — will drop stale endpoint", resp.status_code, endpoint[:48])
        return False, True
    log.warning("[up] %s for endpoint %s… — non-fatal", resp.status_code, endpoint[:48])
    return False, False


async def _drop_dead_endpoints(token_ids: list[int]) -> None:
    """Batch-delete endpoints the distributor reported gone, AFTER the network
    phase. Best-effort — endpoint cleanup must never break a send."""
    if not token_ids:
        return
    try:
        async with SessionLocal() as db:  # type: AsyncSession
            await db.execute(delete(DeviceToken).where(DeviceToken.id.in_(token_ids)))
            await db.commit()
        log.warning("[up] dropped %d stale endpoint(s)", len(token_ids))
    except Exception:  # noqa: BLE001 — cleanup must never break a send
        log.exception("[up] failed to drop stale endpoints")


async def _fan_out(uin: int, payload: dict[str, Any]) -> int:
    endpoints = await _endpoints_for(uin)
    if not endpoints:
        return 0
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    sent = 0
    dead_ids: list[int] = []
    for token_id, endpoint in endpoints:
        ok, drop = await _post_one(endpoint, body)
        if ok:
            sent += 1
        if drop:
            dead_ids.append(token_id)
    await _drop_dead_endpoints(dead_ids)
    return sent


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
    sent = await _fan_out(uin, payload)
    log.warning("[up] send_to_user uin=%s sent=%d", uin, sent)
    return sent


async def send_call_to_user(uin: int, *, payload: dict[str, Any]) -> int:
    """Wake-for-call fan-out to Android UnifiedPush devices. `payload` is the
    flat call dict (call_id, from_uin, nickname, media, sdp) — the woken
    receiver shows the full-screen incoming-call UI. Mirrors
    apns.send_voip_to_user; a `type` discriminator lets the receiver tell a
    call wake from a message wake. No-op when the user has no endpoints."""
    body = {"v": 1, "type": "call", "to_uin": uin, **payload}
    sent = await _fan_out(uin, body)
    log.warning("[up] send_call_to_user uin=%s sent=%d", uin, sent)
    return sent
