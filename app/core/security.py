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


def decode_token(token: str) -> int:
    try:
        payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALG])
        return int(payload["sub"])
    except (JWTError, KeyError, ValueError) as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid token") from exc


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
        payload = jwt.decode(creds.credentials, settings.JWT_SECRET, algorithms=[settings.JWT_ALG])
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
