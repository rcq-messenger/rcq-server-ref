import secrets
from datetime import datetime, timedelta, timezone

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBasic, HTTPBasicCredentials, HTTPBearer
from jose import JWTError, jwt

from .config import settings

_bearer = HTTPBearer(auto_error=False)
_basic = HTTPBasic(auto_error=False)


def issue_token(uin: int, epoch: int = 0, device_id: str | None = None) -> str:
    """Mint a session token for `uin`.

    `epoch` binds the token to the current holder of the number (see
    `app.models.uin_epoch`). It is omitted from the claims when 0 so tokens for
    numbers that have never changed hands are byte-identical to the ones this
    function produced before the epoch existed.

    `device_id` names the INSTALL this token belongs to. Without it every
    install of an account keys as "primary", and since a websocket supersedes
    the one holding the same device id, two phones on one account evicted each
    other forever: the loser redialled, evicted the winner, and back around
    (measured on prod at 707 reconnects in three hours from a single address).
    The same collision made them share one offline-queue cursor, so whichever
    device drained the queue first left the other with nothing to read.

    It carries `k="phone"` next to it so `_decode_session_payload` can tell an
    install token from a linked-web guest token: those also carry `dev`, but
    they expire hard, and a phone must not be logged out for being offline.
    """
    payload = {
        "sub": str(uin),
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(seconds=settings.JWT_TTL_SECONDS),
    }
    if epoch:
        payload["ep"] = epoch
    if device_id:
        payload["dev"] = device_id
        payload["k"] = "phone"
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALG)


def issue_device_token(uin: int, device_id: str, epoch: int = 0) -> str:
    """A session token for a LINKED web device — same `sub` (uin) as the phone,
    plus a `dev` claim so the session can be revoked independently (current_uin
    checks the per-account `dev_revoked` denylist for tokens carrying a `dev`).
    Lives ~90 days, matching the device-registry TTL in routers/devices.py.

    ⚠ `epoch` is not optional in practice, only in the signature. This was the
    one token-minting function that never carried the claim, so on any number
    that has changed hands (262 of them on the flagship) `authorize_session`
    rejected a freshly linked browser's token as "stale" the moment it was
    handed over. It went unnoticed because the browser answers a 401 by minting
    its own token — which is the very behaviour report #607 is about."""
    payload = {
        "sub": str(uin),
        "dev": device_id,
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(seconds=90 * 24 * 3600),
    }
    if epoch:
        payload["ep"] = epoch
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALG)


def _decode_session_payload(token: str) -> dict:
    """Decode + verify a session token. The HMAC signature IS the credential;
    `exp` is NOT enforced for a plain phone token — a messenger must not log a
    phone out for being offline past the TTL (the 30-day exp stranded every
    long-idle native user on 401, and iOS builds up to 2026-07 reacted to that
    401 by silently re-registering a fresh UIN). Linked-web-device tokens
    (`dev` claim) keep strict expiry: they are shorter-lived, independently
    revocable guest sessions."""
    payload = jwt.decode(
        token,
        settings.JWT_SECRET,
        algorithms=[settings.JWT_ALG],
        options={"verify_exp": False},
    )
    # A linked-web guest token expires hard; an install token (`k="phone"`)
    # does not, for the same reason a plain phone token does not.
    if payload.get("dev") and payload.get("k") != "phone":
        exp = payload.get("exp")
        if exp is None or float(exp) <= datetime.now(timezone.utc).timestamp():
            raise JWTError("device token expired")
    return payload


def decode_token(token: str) -> int:
    try:
        return int(_decode_session_payload(token)["sub"])
    except (JWTError, KeyError, ValueError) as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid token") from exc


def decode_device_id(token: str) -> str:
    """The `dev` claim of a linked-web-device token, or "primary" for a
    regular (phone / direct-login) session. Used to key WS connections per
    device so a phone and a connect-to-web linked browser coexist instead
    of superseding each other. Never raises — falls back to "primary"."""
    try:
        # verify_exp off deliberately: an install token outlives its `exp` (see
        # _decode_session_payload), and reading its device id must not start
        # failing on day 31 — that would silently drop the account back to
        # "primary" and bring the mutual-eviction loop right back.
        payload = jwt.decode(
            token,
            settings.JWT_SECRET,
            algorithms=[settings.JWT_ALG],
            options={"verify_exp": False},
        )
        dev = payload.get("dev")
        return dev if isinstance(dev, str) and dev else "primary"
    except JWTError:
        return "primary"


def carry_device_id(device_id: str) -> str | None:
    """Carry an install's name onto a freshly minted token.

    Every route that RE-mints a token (session, recover, reissue, migrate, a
    number purchase) used to drop the `dev` claim, so `decode_device_id` then
    answered "primary" for that session. That is not cosmetic: the websocket
    registers under the name from the token while the push endpoint is
    registered under the install's own id, so the two stop matching and
    `skip_devices` can no longer tell that the device it is about to wake is
    the one already holding the socket. The phone then gets a push for a
    message it just received over that socket, and the same message sounds
    twice — quietly from the app, loudly from the notification ("о-оу
    несколько раз", tester report 2026-08-08).

    "primary" is the ABSENCE of a name, so it is passed on as None rather than
    pinned onto the new token.
    """
    return device_id if device_id != "primary" else None


def issue_key_challenge(signing_key: str, typ: str = "recover") -> str:
    """Short-lived signed nonce bound to a claimed signing pubkey.

    `typ` keeps the two uses apart: a challenge minted for REGISTRATION must not
    be replayable at /auth/recover and the other way round, even though both
    prove the same thing about the same key.
    """
    payload = {
        "typ": typ,
        "sk": signing_key,
        "nonce": secrets.token_urlsafe(16),
        "exp": datetime.now(timezone.utc) + timedelta(seconds=120),
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALG)


def verify_key_challenge(challenge: str, signing_key: str, typ: str = "recover") -> bool:
    """True if `challenge` is a non-expired challenge of `typ` bound to
    `signing_key` (jwt.decode enforces the signature + expiry)."""
    try:
        payload = jwt.decode(challenge, settings.JWT_SECRET, algorithms=[settings.JWT_ALG])
    except JWTError:
        return False
    return payload.get("typ") == typ and payload.get("sk") == signing_key


def issue_recover_challenge(signing_key: str) -> str:
    """The recovery flavour of [issue_key_challenge]. Stateless: the challenge
    IS the server's commitment; the client proves key ownership by signing it
    back. Reveals nothing about whether the account actually exists."""
    return issue_key_challenge(signing_key, "recover")


def verify_recover_challenge(challenge: str, signing_key: str) -> bool:
    """True if `challenge` is a non-expired RECOVER challenge for this key."""
    return verify_key_challenge(challenge, signing_key, "recover")


async def device_is_revoked(uin: int, device_id: str | None) -> bool:
    """Has this account disconnected the install named `device_id`?

    ⚠ Every place that hands out a session token for an account MUST ask this,
    not just the places that CHECK one. `authorize_session` refused a revoked
    device's bearer from the first day, and that looked like enough — but the
    web keeps no token on disk any more: it MINTS one at start-up from the
    signing key (`POST /auth/refresh`). A mint endpoint that never consulted
    the denylist simply issued the revoked browser a brand-new valid token, so
    "отключить связь с браузером" survived exactly until the next request and
    did not survive a reload at all (report #607).

    Fails CLOSED — a Redis blip makes this raise, and the callers let it: a
    mint is a rare, retryable operation, and answering "not revoked" because
    the denylist was unreachable is the one answer that cannot be taken back.
    (`authorize_session` has always had the same shape.)
    """
    if not device_id:
        return False
    from app.core.redis import get_redis  # local import avoids an import cycle

    redis = await get_redis()
    return bool(await redis.sismember(f"dev_revoked:{uin}", device_id))


async def authorize_session(token: str) -> int:
    """Everything that makes a session token still valid, in one place.

    Signature, then the two things a signature cannot express: whether this
    linked device has been revoked, and whether the number has since changed
    hands. Returns the uin or raises the usual 401/403.

    ⚠ This exists because the WEBSOCKET did none of it. `/ws/{uin}` decoded the
    token for its `sub` and checked suspension, and that was all — so revoking
    a linked web session left it able to open a socket and keep receiving
    everything, and a token minted for a previous holder of a number stayed
    good on the one channel that actually carries messages. Revocation was
    real on HTTP and cosmetic where it mattered. Any new entry point must call
    THIS, not `decode_token`.
    """
    try:
        payload = _decode_session_payload(token)
        uin = int(payload["sub"])
    except (JWTError, KeyError, ValueError) as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid token") from exc
    # Linked-web-device tokens carry a `dev` claim and are independently
    # revocable. Only THESE pay the Redis denylist lookup — a plain phone token
    # (no `dev`) skips it, so the hot path is untouched.
    dev = payload.get("dev")
    if dev and await device_is_revoked(uin, dev):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "device revoked")
    # Reject a token minted for a PREVIOUS holder of this number. Absent claim
    # and absent row both read as epoch 0, so sessions predating this check are
    # unaffected — only a number that actually changed hands invalidates.
    if int(payload.get("ep") or 0) != await uin_epoch(uin):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "stale token")
    if await is_suspended(uin):
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail={"code": "suspended"})
    return uin


async def current_uin(
    request: Request,
    creds: HTTPAuthorizationCredentials = Depends(_bearer),
) -> int:
    if creds is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing token")
    uin = await authorize_session(creds.credentials)
    # So the metrics middleware can count distinct accounts and boot chains
    # without decoding a second token of its own. Nothing else reads this.
    request.state.uin = uin
    return uin


# ── UIN recycling guard ──────────────────────────────────────────────
#
# See `app.models.uin_epoch` for the takeover primitive this closes. Cached in
# Redis because it is consulted on every authenticated request; the DB row is
# authoritative and the cache is written through on bump.
_EPOCH_KEY = "uin_epochs"
_EPOCH_LOADED_KEY = "uin_epochs:loaded"
_EPOCH_TTL_SECONDS = 300


async def _ensure_epochs_loaded(redis) -> None:
    if await redis.exists(_EPOCH_LOADED_KEY):
        return
    from sqlalchemy import select

    from app.core.db import SessionLocal
    from app.models.uin_epoch import UinEpoch

    async with SessionLocal() as db:
        rows = (
            await db.execute(select(UinEpoch.uin, UinEpoch.epoch).where(UinEpoch.epoch > 0))
        ).all()
    pipe = redis.pipeline()
    pipe.delete(_EPOCH_KEY)
    if rows:
        pipe.hset(_EPOCH_KEY, mapping={str(u): str(e) for u, e in rows})
    pipe.set(_EPOCH_LOADED_KEY, "1", ex=_EPOCH_TTL_SECONDS)
    await pipe.execute()


async def uin_epoch(uin: int) -> int:
    """Current epoch of `uin`. Falls back to the DB, then to 0.

    Unlike the suspension gate this must NOT fail open into "reject": a Redis
    outage returning 0 would refuse every token that legitimately carries an
    epoch. It therefore degrades to the database, and only to 0 if that is
    unreachable too — at which point nothing else works either.
    """
    try:
        from app.core.redis import get_redis
        redis = await get_redis()
        await _ensure_epochs_loaded(redis)
        raw = await redis.hget(_EPOCH_KEY, str(uin))
        return int(raw) if raw else 0
    except Exception:  # noqa: BLE001
        try:
            from sqlalchemy import select

            from app.core.db import SessionLocal
            from app.models.uin_epoch import UinEpoch

            async with SessionLocal() as db:
                return int(
                    await db.scalar(select(UinEpoch.epoch).where(UinEpoch.uin == uin)) or 0
                )
        except Exception:  # noqa: BLE001
            return 0


async def bump_uin_epoch(db, uin: int) -> int:
    """Called when `uin` is released (burn) so every token minted for the
    outgoing holder stops authenticating. Returns the new epoch. The caller
    owns the commit; the cache is refreshed after it."""
    from sqlalchemy import select

    from app.models.uin_epoch import UinEpoch

    row = await db.get(UinEpoch, uin)
    if row is None:
        row = UinEpoch(uin=uin, epoch=1)
        db.add(row)
    else:
        row.epoch = int(row.epoch or 0) + 1
    await db.flush()
    return int(row.epoch)


async def cache_uin_epoch(uin: int, epoch: int) -> None:
    """Write-through so a bump takes effect without waiting for the reload."""
    try:
        from app.core.redis import get_redis
        redis = await get_redis()
        await redis.hset(_EPOCH_KEY, str(uin), str(epoch))
    except Exception:  # noqa: BLE001
        pass


# ── suspension gate ──────────────────────────────────────────────────
#
# `users.is_suspended` used to be enforced in exactly ONE runtime place:
# the WebSocket handshake (`routers/ws.py`). Everything else that read the
# column was the admin UI or a public-listing filter, so a banned account
# holding a live bearer token kept working over plain HTTP — it could still
# upload media and file reports; it just could not hold a socket.
# Since phone tokens deliberately never expire, "banned" was closer
# to "logged out of the socket" than to "banned".
#
# The set is mirrored into Redis rather than read from Postgres because this
# runs on every authenticated request. Same idiom as the `dev_revoked`
# denylist above. It is a CACHE with no TTL, authoritative-on-write: the
# admin ban/unban paths update it, and a cold Redis is warmed on demand from
# the DB by `refresh_suspended`.
_SUSPENDED_KEY = "suspended_uins"
# Freshness marker for the set above. Without it, a Redis restart would drop
# the set and silently un-ban everyone until the next app restart; with it the
# set rebuilds itself from Postgres within the TTL. Costs one small query per
# worker per window, not per request.
_SUSPENDED_LOADED_KEY = "suspended_uins:loaded"
_SUSPENDED_TTL_SECONDS = 300


async def _ensure_suspended_loaded(redis) -> None:
    if await redis.exists(_SUSPENDED_LOADED_KEY):
        return
    from sqlalchemy import select

    from app.core.db import SessionLocal
    from app.models.user import User

    async with SessionLocal() as db:
        rows = (
            await db.execute(select(User.uin).where(User.is_suspended.is_(True)))
        ).scalars().all()
    pipe = redis.pipeline()
    pipe.delete(_SUSPENDED_KEY)
    if rows:
        pipe.sadd(_SUSPENDED_KEY, *[str(u) for u in rows])
    pipe.set(_SUSPENDED_LOADED_KEY, "1", ex=_SUSPENDED_TTL_SECONDS)
    await pipe.execute()


async def is_suspended(uin: int) -> bool:
    """True when `uin` is banned. Fails OPEN (returns False) if Redis is
    unreachable — consistent with the rate limiter, and preferable to
    locking every user out of the product during a Redis blip."""
    try:
        from app.core.redis import get_redis
        redis = await get_redis()
        await _ensure_suspended_loaded(redis)
        return bool(await redis.sismember(_SUSPENDED_KEY, str(uin)))
    except Exception:  # noqa: BLE001 - cache miss must not break auth
        return False


async def mark_suspended(uin: int, suspended: bool) -> None:
    """Mirror a ban/unban into the Redis set. Best-effort: the DB column
    stays the source of truth and `refresh_suspended` can rebuild from it."""
    try:
        from app.core.redis import get_redis
        redis = await get_redis()
        if suspended:
            await redis.sadd(_SUSPENDED_KEY, str(uin))
        else:
            await redis.srem(_SUSPENDED_KEY, str(uin))
    except Exception:  # noqa: BLE001
        pass


async def current_device_id(creds: HTTPAuthorizationCredentials = Depends(_bearer)) -> str:
    """The calling session's device id: "primary" for a phone / direct login, or
    the linked-web token's `dev` claim. Used to drain the offline queue PER
    DEVICE so a phone and a linked browser each receive every message instead of
    whichever drains first deleting them for the other."""
    if creds is None:
        return "primary"
    return decode_device_id(creds.credentials)


async def current_uin_optional(
    creds: HTTPAuthorizationCredentials = Depends(_bearer),
) -> int | None:
    """Like `current_uin` but lets through anonymous callers.

    Used by endpoints that are free for guests up to some boundary
    and then need to know who to bill above it — `/media/upload`
    being the canonical example. Anonymous = uin None, the endpoint
    decides whether that's allowed for the requested operation.
    """
    if creds is None:
        return None
    try:
        # Same checks as the required path, not just the signature. This
        # answers "who is this" for the owner-only gate on group posts among
        # other things, and a revoked device passing as the owner there would
        # be the revocation meaning nothing again. A token that fails simply
        # reads as anonymous, which is what every caller already handles.
        return await authorize_session(creds.credentials)
    except HTTPException:
        return None


def require_admin(creds: HTTPBasicCredentials = Depends(_basic)) -> str:
    """HTTP Basic gate for /admin/* endpoints. Compares against
    `ADMIN_USERNAME` / `ADMIN_PASSWORD` from `.env` using
    constant-time `secrets.compare_digest` so a guess-by-timing
    attack can't probe character-by-character.

    Returns the verified username on success (caller can log who
    did what — only one admin today, but the contract is ready
    for multiple). Empty config = 503 with a clear hint that the
    panel is disabled, NOT 401 — a 401 with no credentials set
    would tempt brute-force attempts against an empty password.
    """
    if not settings.ADMIN_USERNAME or not settings.ADMIN_PASSWORD:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "admin disabled (set ADMIN_USERNAME + ADMIN_PASSWORD)",
        )
    if creds is None:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "admin auth required",
            headers={"WWW-Authenticate": 'Basic realm="rcq-admin"'},
        )
    user_ok = secrets.compare_digest(
        creds.username.encode("utf-8"), settings.ADMIN_USERNAME.encode("utf-8")
    )
    pass_ok = secrets.compare_digest(
        creds.password.encode("utf-8"), settings.ADMIN_PASSWORD.encode("utf-8")
    )
    if not (user_ok and pass_ok):
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "bad credentials",
            headers={"WWW-Authenticate": 'Basic realm="rcq-admin"'},
        )
    return creds.username
