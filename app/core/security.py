import secrets
from datetime import datetime, timedelta, timezone

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBasic, HTTPBasicCredentials, HTTPBearer
from jose import JWTError, jwt

from .config import settings

_bearer = HTTPBearer(auto_error=False)
_basic = HTTPBasic(auto_error=False)


def issue_token(uin: int) -> str:
    payload = {
        "sub": str(uin),
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(seconds=settings.JWT_TTL_SECONDS),
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALG)


def issue_device_token(uin: int, device_id: str) -> str:
    """A session token for a LINKED web device — same `sub` (uin) as the phone,
    plus a `dev` claim so the session can be revoked independently (current_uin
    checks the per-account `dev_revoked` denylist for tokens carrying a `dev`).
    Lives ~90 days, matching the device-registry TTL in routers/devices.py."""
    payload = {
        "sub": str(uin),
        "dev": device_id,
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(seconds=90 * 24 * 3600),
    }
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
    if payload.get("dev"):
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
        payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALG])
        dev = payload.get("dev")
        return dev if isinstance(dev, str) and dev else "primary"
    except JWTError:
        return "primary"


def issue_recover_challenge(signing_key: str) -> str:
    """Short-lived signed nonce bound to a claimed signing pubkey, for the
    account-recovery challenge-response. Stateless: the challenge IS the
    server's commitment; the client proves key ownership by signing it back.
    Reveals nothing about whether the account actually exists."""
    payload = {
        "typ": "recover",
        "sk": signing_key,
        "nonce": secrets.token_urlsafe(16),
        "exp": datetime.now(timezone.utc) + timedelta(seconds=120),
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALG)


def verify_recover_challenge(challenge: str, signing_key: str) -> bool:
    """True if `challenge` is a non-expired recover challenge bound to
    `signing_key` (jwt.decode enforces the signature + expiry)."""
    try:
        payload = jwt.decode(challenge, settings.JWT_SECRET, algorithms=[settings.JWT_ALG])
    except JWTError:
        return False
    return payload.get("typ") == "recover" and payload.get("sk") == signing_key


async def current_uin(creds: HTTPAuthorizationCredentials = Depends(_bearer)) -> int:
    if creds is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing token")
    try:
        payload = _decode_session_payload(creds.credentials)
        uin = int(payload["sub"])
    except (JWTError, KeyError, ValueError) as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid token") from exc
    # Linked-web-device tokens carry a `dev` claim and are independently
    # revocable. Only THESE pay the Redis denylist lookup — a plain phone token
    # (no `dev`) skips it, so the hot path is untouched.
    dev = payload.get("dev")
    if dev:
        from app.core.redis import get_redis  # local import avoids an import cycle
        redis = await get_redis()
        if await redis.sismember(f"dev_revoked:{uin}", dev):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "device revoked")
    return uin


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
        return decode_token(creds.credentials)
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
