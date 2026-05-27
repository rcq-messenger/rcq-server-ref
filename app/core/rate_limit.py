"""Sliding-window rate limiter backed by Redis.

Migrated from an in-process dict so the limit is shared across all
uvicorn workers — without this, a 60/min cap on a 4-worker box would
let a single client do 240/min, one quarter per worker.

The bucket is a Redis sorted set keyed `rl:<rule>:<identity>` where
each member is a request timestamp (epoch seconds, also used as the
score). The check-and-set Lua script runs atomically inside Redis so
two concurrent workers can't both see "below limit" and both accept.

  • Keyed by `(rule_name, identity)` where identity is the UIN for
    authenticated routes and the client IP for anonymous ones
    (sealed-sender messages, /reports without bearer token).
  • Sliding window: ZREMRANGEBYSCORE drops timestamps older than
    `window_seconds`, ZCARD counts the rest, ZADD records this one.
  • Self-pruning: each bucket gets `EXPIRE` equal to the window so
    idle keys vanish on their own — no manual cleanup loop.
  • Fail-soft: if Redis is unreachable the request is allowed
    through with a logged warning. Brief Redis outages shouldn't
    surface as 429s for legit users; spammers wouldn't notice the
    gap anyway.

Apply via `Depends(rate_limit("rule_name", limit, window_seconds))`
in any router. The dependency raises HTTPException(429) with a
`Retry-After` header pointing at when the oldest in-window request
falls out — clients can use that to back off cleanly.

Endpoints that are deliberately unauthenticated (sealed-sender
sends, anonymous `/reports`) get IP-bound limits — coarser than
per-UIN but still enough to keep one bad client from saturating
the server. NAT shared-IP false positives are accepted as the
trade for not blocking legit clients behind the same gateway.
"""

from __future__ import annotations

import logging
import time
from typing import Callable

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .redis import get_redis
from .security import decode_token

log = logging.getLogger(__name__)


# Reuse the optional bearer token reader so a route that's NOT
# `Depends(current_uin)`-gated still gets per-UIN binding when the
# client happens to send a token (e.g. /messages/sealed is
# anonymous on purpose, but the iOS client still sends its bearer —
# we'd rather count against the UIN than the IP when we can).
_bearer = HTTPBearer(auto_error=False)


# Atomic check-and-set. Returns {accepted, retry_after_seconds}.
# Doing it as one Lua script means two workers can't both observe
# "count < limit" and both accept — the entire sweep+check+insert
# runs as a single Redis op.
_LIMITER_SCRIPT = """
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local cutoff = now - window

redis.call('ZREMRANGEBYSCORE', key, '-inf', cutoff)
local count = tonumber(redis.call('ZCARD', key))

if count >= limit then
  local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
  local retry = 1
  if #oldest >= 2 then
    retry = math.max(1, math.floor(tonumber(oldest[2]) + window - now) + 1)
  end
  return {0, retry}
end

redis.call('ZADD', key, now, now)
-- TTL = window + tiny slack so a key that just got its last hit
-- still vanishes when the last in-window timestamp ages out.
redis.call('EXPIRE', key, window + 5)
return {1, 0}
"""


def _client_ip(request: Request) -> str:
    """Caddy's `header_up X-Forwarded-For {remote_host}` puts the
    original client IP first in the comma-list. Falls back to the
    direct socket peer when the header is missing (dev mode without
    a reverse proxy)."""
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _identity(request: Request, creds: HTTPAuthorizationCredentials | None) -> str:
    if creds is not None:
        try:
            return f"uin:{decode_token(creds.credentials)}"
        except HTTPException:
            # Bad token — count as IP. The auth-required routes will
            # 401 separately; for anonymous routes (sealed-sender),
            # an invalid token shouldn't be a free pass.
            pass
    return f"ip:{_client_ip(request)}"


def rate_limit(rule: str, limit: int, window_seconds: int) -> Callable:
    """Build a FastAPI dependency that enforces `limit` calls per
    `window_seconds` keyed by (rule, identity).

    Usage:
        @router.post("/something",
                     dependencies=[Depends(rate_limit("rule_name", 60, 60))])
        async def handler(...):
            ...

    Raises 429 with `Retry-After: <seconds>` once the bucket is full.
    The dependency itself returns nothing — it's a side-effect
    enforcer, not a value source.
    """

    async def _dep(
        request: Request,
        creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
    ) -> None:
        key = f"rl:{rule}:{_identity(request, creds)}"
        now = time.time()
        try:
            redis = await get_redis()
            result = await redis.eval(
                _LIMITER_SCRIPT, 1, key, now, window_seconds, limit
            )
        except Exception as exc:  # noqa: BLE001
            # Fail-soft: Redis hiccup shouldn't 429 a legit user. We
            # log loudly so the outage is visible, but let the request
            # through. Spammers won't notice the brief gap.
            log.warning("[rate_limit] redis unavailable, allowing: %s", exc)
            return

        accepted = int(result[0])
        if accepted == 1:
            return
        retry_after = int(result[1]) if len(result) > 1 else 1
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={"code": "rate_limited", "retry_after": retry_after},
            headers={"Retry-After": str(retry_after)},
        )

    return _dep


async def reset_buckets() -> None:
    """Wipe all rate-limit state. Used by tests; never called in
    production. Buckets self-prune via the cutoff sweep + key
    `EXPIRE` so memory growth is bounded by `unique_identities *
    unique_rules` and naturally fades after idle windows."""
    try:
        redis = await get_redis()
        async for key in redis.scan_iter(match="rl:*"):
            await redis.delete(key)
    except Exception:  # noqa: BLE001
        pass
