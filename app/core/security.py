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


def decode_token(token: str) -> int:
    try:
        payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALG])
        return int(payload["sub"])
    except (JWTError, KeyError, ValueError) as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid token") from exc


async def current_uin(creds: HTTPAuthorizationCredentials = Depends(_bearer)) -> int:
    if creds is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing token")
    return decode_token(creds.credentials)


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
