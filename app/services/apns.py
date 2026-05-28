"""APNs sender — silent + alert pushes to iOS clients.

Apple's HTTP/2 endpoint with ES256-signed JWT auth. JWTs are valid for
~1 hour and we cache the same token across requests until it ages out;
re-signing on every request is technically allowed but burns CPU and
Apple recommends reuse.

Sealed-sender story: the push body intentionally carries NO sender info.
It's a generic "you have something to fetch" trigger. The iOS client
wakes (via content-available), fetches `/messages/queue`, decrypts each
envelope locally, and posts the resulting local notification with the
real sender info. Apple sees only "RCQ pushed an opaque payload to UIN
X's device" — not "Y messaged X."

`send_to_user(uin, ...)` is the public entrypoint. It's a no-op when
APNs config isn't populated (dev environments without a .p8 key).
"""
from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any

import httpx
from jose import jwt
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.db import SessionLocal
from app.models.device_token import DeviceToken
from app.models.user import User

log = logging.getLogger(__name__)


# Default push-preference values. Applied when a user's
# `push_preferences` row is NULL or missing the key. Keep aligned
# with the iOS Settings UI defaults so a user who hasn't visited
# Notifications settings sees the same behaviour both sides.
PUSH_PREFERENCE_DEFAULTS: dict[str, Any] = {
    "contact_requests": True,
    "trades_from_contacts": True,
    "trades_from_strangers": False,  # anti-spam
    "muted_uins": [],
    # Per-group mute. Group sealed-sender pushes skip the
    # `should_push_for` gate because the sender is hidden, but the
    # caller can still consult `is_group_muted` to suppress pushes
    # for groups the user explicitly silenced. Messages still queue
    # in OfflineGroupMessage and arrive on /queue — only the APNs
    # alert is dropped.
    "muted_group_ids": [],
}


def _pref(prefs: dict | None, key: str) -> Any:
    """Read a single preference key with default fallback. Tolerates
    NULL row (user never visited settings) and partial writes (older
    builds that didn't know about a key)."""
    if prefs is None:
        return PUSH_PREFERENCE_DEFAULTS.get(key)
    return prefs.get(key, PUSH_PREFERENCE_DEFAULTS.get(key))


async def should_push_for(
    recipient_uin: int,
    *,
    kind: str,
    sender_uin: int | None = None,
    sender_is_contact: bool | None = None,
) -> bool:
    """Decide whether to fire an APNs push for `recipient_uin` on a
    given event kind. Loads the recipient's `push_preferences` and
    matches `kind` against the toggle map. `sender_uin` is consulted
    against the muted-list AND the trades-from-contacts vs strangers
    split.

    Returns True for every kind we don't have a toggle for (sealed
    messages, calls) — those keep their existing always-push
    behaviour. The caller still decides whether to ACTUALLY push
    (e.g. `if not delivered`).
    """
    async with SessionLocal() as db:
        user = await db.get(User, recipient_uin)
        if user is None:
            return True
        prefs = user.push_preferences

    # Mute list applies to all non-sealed event types we filter
    # here. Sealed messages skip this code path entirely (the
    # caller doesn't know the sender so it doesn't pass `sender_uin`).
    muted = _pref(prefs, "muted_uins") or []
    if sender_uin is not None and sender_uin in muted:
        return False

    if kind == "contact_request":
        return bool(_pref(prefs, "contact_requests"))
    if kind == "contact_response_accepted":
        # No separate toggle — accepted-response pushes are always
        # welcome (the user requested the contact in the first
        # place; they presumably want to know when it lands).
        # Mute-list still applies via the early-return above.
        return True
    if kind == "trade_received":
        if sender_is_contact:
            return bool(_pref(prefs, "trades_from_contacts"))
        return bool(_pref(prefs, "trades_from_strangers"))
    # Unknown kind — default permissive.
    return True


async def is_group_muted(recipient_uin: int, group_id: int) -> bool:
    """True if the recipient has silenced this specific group. Used by
    the group sealed-sender fan-out, which can't go through
    `should_push_for` (sender is hidden) but still wants to honour the
    user's per-group mute toggle."""
    async with SessionLocal() as db:
        user = await db.get(User, recipient_uin)
        if user is None:
            return False
        muted = _pref(user.push_preferences, "muted_group_ids") or []
    return int(group_id) in {int(g) for g in muted}

# JWT cache. Apple's docs say tokens may be reused for up to 1 hour, but they
# rate-limit if you re-sign too often. Refresh comfortably under the limit.
_JWT_TTL_SECONDS = 50 * 60
_jwt_cache: dict[str, tuple[str, float]] = {}  # key_id → (token, expires_at)

# Module-level shared HTTP/2 client — connection reuse matters for APNs since
# every push opens a new HTTP/2 stream on the same connection. Initialized
# lazily so that env without httpx[http2] still imports the module cleanly.
_client: httpx.AsyncClient | None = None


def _apns_host() -> str:
    if settings.APNS_ENVIRONMENT == "sandbox":
        return "https://api.sandbox.push.apple.com"
    return "https://api.push.apple.com"


def _is_configured() -> bool:
    return bool(
        settings.APNS_KEY_ID
        and settings.APNS_TEAM_ID
        and settings.APNS_KEY_PATH
        and Path(settings.APNS_KEY_PATH).is_file()
    )


def _get_jwt() -> str:
    """Build (or reuse) the ES256-signed bearer token APNs wants on every
    request. Reads the .p8 file lazily — it's tiny and the JWT cache means
    it gets read once per ~50 minutes."""
    cached = _jwt_cache.get(settings.APNS_KEY_ID)
    now = time.time()
    if cached is not None and cached[1] > now:
        return cached[0]

    key_pem = Path(settings.APNS_KEY_PATH).read_text()
    payload = {"iss": settings.APNS_TEAM_ID, "iat": int(now)}
    headers = {"alg": "ES256", "kid": settings.APNS_KEY_ID}
    token = jwt.encode(payload, key_pem, algorithm="ES256", headers=headers)
    _jwt_cache[settings.APNS_KEY_ID] = (token, now + _JWT_TTL_SECONDS)
    return token


async def _ensure_client() -> httpx.AsyncClient:
    global _client
    if _client is None:
        _client = httpx.AsyncClient(http2=True, timeout=10.0)
    return _client


_APNS_PROD_HOST = "https://api.push.apple.com"
_APNS_SANDBOX_HOST = "https://api.sandbox.push.apple.com"


async def _try_send(
    token: str,
    payload: dict[str, Any],
    *,
    host: str,
    push_type: str,
    topic: str,
) -> tuple[int, str | None]:
    """One POST attempt to a specific APNs host. Returns (status, reason)
    where reason is the parsed `reason` field from Apple's JSON response
    body (or None if it can't be parsed). Doesn't touch the DB — the
    caller decides whether to drop, fall back to the other host, or
    retry.
    """
    client = await _ensure_client()
    url = f"{host}/3/device/{token}"
    headers = {
        "authorization": f"bearer {_get_jwt()}",
        "apns-push-type": push_type,
        "apns-topic": topic,
        "apns-priority": "5" if push_type == "background" else "10",
        "apns-expiration": "0",
    }
    try:
        resp = await client.post(url, headers=headers, content=json.dumps(payload))
    except httpx.HTTPError as exc:
        log.warning("APNs transport error for token %s on %s: %s", token[:12], host, exc)
        return 0, None
    body_text = (resp.text or "").strip()
    reason: str | None = None
    if body_text:
        try:
            reason = json.loads(body_text).get("reason")
        except json.JSONDecodeError:
            reason = None
    log.warning(
        "[apns] _try_send token=%s host=%s status=%s reason=%s topic=%s push_type=%s",
        token[:12], host.split("//")[-1], resp.status_code, reason, topic, push_type,
    )
    return resp.status_code, reason


async def _send_one(
    db: AsyncSession,
    token_row: DeviceToken,
    payload: dict[str, Any],
    *,
    push_type: str,
    topic: str,
) -> bool:
    """POST one push to one device. Returns True on success.

    Tries the primary APNs host first (configured via APNS_ENVIRONMENT),
    and on a `BadEnvironmentKeyInToken` 403 falls back to the OTHER
    host. This makes the backend resilient to mixed-environment tokens
    in the DB — in practice that means a dev-build install (sandbox)
    that later upgrades to TestFlight (production) without iOS issuing
    a fresh token: the old sandbox token still works through the
    sandbox host, and we don't have to wait for the user to re-register.
    Tokens that fail on BOTH hosts are genuinely dead and get dropped.

    Other dead-token codes (400 BadDeviceToken, 410 Unregistered) drop
    the row immediately — those don't have an environment angle.
    """
    primary = _apns_host()
    alternate = _APNS_SANDBOX_HOST if primary == _APNS_PROD_HOST else _APNS_PROD_HOST

    status_code, reason = await _try_send(
        token_row.token, payload, host=primary, push_type=push_type, topic=topic,
    )

    # Wrong-environment retry: same token, alternate host. Apple
    # signals an environment mismatch with TWO codes depending on
    # circumstance — `403 BadEnvironmentKeyInToken` is the formal one,
    # but `400 BadDeviceToken` also fires when a sandbox token is
    # POSTed to the production host (and vice-versa). Both should
    # trigger a fallback before we give up.
    env_mismatch = (
        (status_code == 403 and reason == "BadEnvironmentKeyInToken")
        or (status_code == 400 and reason == "BadDeviceToken")
    )
    if env_mismatch:
        status_code, reason = await _try_send(
            token_row.token, payload, host=alternate, push_type=push_type, topic=topic,
        )

    if status_code == 200:
        return True

    drop_reasons = {"BadDeviceToken", "Unregistered", "BadEnvironmentKeyInToken"}
    should_drop = status_code in (400, 410)
    if not should_drop and status_code == 403 and reason in drop_reasons:
        should_drop = True

    if should_drop:
        await db.execute(delete(DeviceToken).where(DeviceToken.id == token_row.id))
        await db.commit()
        log.warning(
            "APNs %s reason=%s for %s — dropped stale token",
            status_code, reason, token_row.token[:12],
        )
        return False

    log.warning("APNs %s reason=%s for %s — non-fatal", status_code, reason, token_row.token[:12])
    return False


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
) -> int:
    """Regular APNs push to every iOS device of `uin`. Skips VoIP tokens —
    those have a separate code path (`send_voip_to_user`) with a different
    topic and push type. No-op when APNs isn't configured.

    Always sends a `mutable-content: 1` alert so the iOS Notification
    Service Extension can intercept, decrypt the envelope, and replace
    the generic title/body with the real sender + preview before the
    user sees it. Non-envelope pushes (contact request, trade offer,
    etc.) skip the `env` field — NSE passes them through unchanged
    and iOS displays the server-set `alert_title` + `alert_body`
    directly.

    `thread_id` becomes `aps.thread-id` so iOS groups multiple pushes
    of the same kind AND so the iOS-side `RCQAppDelegate.didReceive`
    can route the user to the right surface on tap. Convention:
      - "peer-<UIN>" → 1:1 chat with that contact
      - "pending"    → pending contact requests
      - "trades"     → trades list
    """
    if not _is_configured():
        log.warning("[apns] send_to_user uin=%s skipped: APNs not configured", uin)
        return 0
    async with SessionLocal() as db:  # type: AsyncSession
        rows = (
            await db.execute(
                select(DeviceToken).where(
                    DeviceToken.uin == uin, DeviceToken.platform == "ios"
                )
            )
        ).scalars().all()
        log.warning("[apns] send_to_user uin=%s tokens=%d", uin, len(rows))
        if not rows:
            return 0
        aps: dict[str, Any] = {
            "alert": {"title": alert_title, "body": alert_body},
            "sound": "default",
            "mutable-content": 1,
        }
        if thread_id:
            aps["thread-id"] = thread_id
        payload: dict[str, Any] = {"aps": aps}
        # Recipient UIN in plain so the iOS NSE can route the push to
        # the right local account on a multi-account device. The
        # device token is per-device (not per-account), so backends
        # send one push for `uin` and APNs delivers it to every
        # account on that device — NSE then reads `to_uin` here,
        # looks up which local Account owns this UIN, swaps its
        # libsignal + Keychain stores to that account, and decrypts.
        # Without this field NSE falls back to the active account's
        # stores and fails to decrypt envelopes destined for any
        # non-active account, showing a generic "RCQ New message"
        # banner instead of the real preview.
        payload["to_uin"] = uin
        if envelope_b64:
            # Carried verbatim through APNs — the NSE pulls it out of
            # `userInfo["env"]` and runs SignalCryptoService.decrypt on
            # it locally (private keys live in the shared Keychain group).
            payload["env"] = envelope_b64
            payload["envType"] = envelope_type or "message"
        if notif_kind:
            # NSE swaps the body literal we sent for a localized
            # version keyed off this field. `alert_body` stays as
            # the fallback for clients that don't run the NSE
            # translation step (older builds, NSE crashes, etc).
            payload["notif_kind"] = notif_kind
        if group_id is not None:
            # NSE reads this to route the badge counter to the
            # `group-<id>` thread key instead of `peer-<sender>`,
            # otherwise opening the group chat can't clear the
            # bump that this push made (different keys).
            payload["group_id"] = group_id

        sent = 0
        for row in rows:
            ok = await _send_one(
                db, row, payload,
                push_type="alert",
                topic=settings.APNS_BUNDLE_ID,
            )
            if ok:
                sent += 1
        return sent


async def send_voip_to_user(uin: int, *, payload: dict[str, Any]) -> int:
    """VoIP-push fan-out for incoming-call wake-from-killed. Routes to
    `<bundle>.voip` topic with `apns-push-type: voip` so iOS treats this
    as a CallKit-bound delivery and wakes the app even from a fully
    suspended state. Looks up tokens registered as `platform="ios-voip"`
    only — regular APNs tokens won't accept a VoIP push.

    The `payload` should be a flat dict with the call info the iOS
    handler needs (call_id, from_uin, nickname, media, sdp). VoIP push
    payloads max out at 5KB — full SDPs are ~1.5KB so we fit comfortably.
    """
    if not _is_configured():
        log.info("[apns] send_voip_to_user uin=%s skipped: APNs not configured", uin)
        return 0
    async with SessionLocal() as db:  # type: AsyncSession
        rows = (
            await db.execute(
                select(DeviceToken).where(
                    DeviceToken.uin == uin, DeviceToken.platform == "ios-voip"
                )
            )
        ).scalars().all()
        log.warning("[apns] send_voip_to_user uin=%s tokens=%d", uin, len(rows))
        if not rows:
            return 0
        sent = 0
        # VoIP topic is the bundle ID with `.voip` appended — Apple's
        # convention. Push-type and priority are special too.
        voip_topic = f"{settings.APNS_BUNDLE_ID}.voip"
        for row in rows:
            ok = await _send_one(
                db, row, payload,
                push_type="voip",
                topic=voip_topic,
            )
            if ok:
                sent += 1
        return sent
