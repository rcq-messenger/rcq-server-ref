"""Sliding-window rate limiter backed by Redis.

Migrated from an in-process dict so the limit is shared across all
uvicorn workers — without this, a 60/min cap on a 4-worker box would
let a single client do 240/min, one quarter per worker.

The bucket is a Redis sorted set keyed `rl:<rule>:<bucket>` where
each member is a request timestamp (epoch seconds, also used as the
score). The check-and-set Lua script runs atomically inside Redis so
two concurrent workers can't both see "below limit" and both accept.

  • Keyed by `(rule_name, identity)` where identity is the UIN for
    authenticated routes and the client IP for anonymous ones
    (sealed-sender messages, /reports without bearer token). The
    identity never reaches Redis in the clear. See [bucket_name].
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

import hashlib
import hmac
import logging
import os
import time
from typing import Callable

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .config import settings
from .redis import get_redis
from .security import decode_token

log = logging.getLogger(__name__)


def _bucket_secret() -> bytes:
    """HMAC key for the bucket names below.

    Same derivation shape as the broker's own `_bucket_secret`
    (`routers/broker.py`): SHA-256 over a domain label and the app's JWT
    secret. That secret is read from the one `/opt/rcq/.env` all four uvicorn
    workers share and it survives a restart, which are the two properties this
    needs and the two a per-process random value would not have had. A random
    per-process salt here would give every worker its own private set of
    buckets and quietly turn every limit in the product into four times itself
    which is the exact bug the move to Redis was made to fix.

    No new environment variable: a fresh self-hosted island already has a JWT
    secret and needs no extra configuration for this to work.
    """
    return hashlib.sha256(b"rcq-rate-limit-bucket-v1:" + settings.JWT_SECRET.encode()).digest()


def bucket_name(identity: str) -> str:
    """The opaque Redis bucket name for one limiter identity.

    `identity` is what it always was: "uin:123", "ip:1.2.3.4", and for group
    slowmode a (group, member) pair. What changed on 2026-08-22 is that it is
    no longer what lands in Redis.

    WHY. `POST /messages/sealed` takes no auth on purpose: the island must not
    learn who sent an envelope, and that is the headline privacy property of
    the product. The limiter decoded the bearer token the client sends anyway
    and wrote `rl:messages_send:uin:<sender>` with a timestamp per send. So the
    sender identity we refuse to keep in Postgres was written to Redis on every
    single send, with timing, by infrastructure nobody thinks of as part of the
    message path. Group slowmode did the same for (group, member), and the IP
    branch below wrote the FULL client address that Caddy masks to /24 before
    it is allowed to touch disk (`core/transport.py`).

    What the HMAC buys, precisely, and what it does not:

      • A Redis dump, an RDB snapshot that rides along in a backup, a stray
        `KEYS *`, or anyone who reaches port 6379 and nothing else, stops
        reading as a plaintext who-talked-when list. That is the whole win and
        it is a real one.
      • It is NOT protection against seizure of the host. The secret is in
        `/opt/rcq/.env` on the same disk. Anyone holding both can hash every
        candidate uin (there are a few thousand) or every plausible IPv4
        address and match them straight back. This is not designed to survive
        that and does not.
      • It is a stable pseudonym, not an anonymiser. Within one secret's life
        the same sender always lands in the same bucket, so a dump still
        supports counting and correlation. It just cannot name anyone without
        the secret.
      • On an island still running the default JWT secret the label is public
        and this buys nothing. That island has forgeable tokens too, which is
        the larger problem and not this function's to solve.

    Rotating JWT_SECRET rotates every bucket with it, which empties the live
    limiter state. Harmless: the windows here are seconds to an hour.

    Deliberately not memoised. An `lru_cache` keyed on `identity` would be a
    live in-process table of exactly the plaintext identities this exists to
    stop writing down, and the HMAC costs a microsecond.

    64 bits of output. With a few thousand active identities the odds of two
    sharing a bucket are around 10^-12, and the consequence of one would be two
    callers sharing a limit rather than any loss of enforcement.
    """
    return hmac.new(_bucket_secret(), identity.encode("utf-8"), hashlib.sha256).hexdigest()[:16]


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
    # Whole address, because a /24 is too coarse to price abuse with. It goes
    # through [bucket_name] like every other identity, so the thing Caddy masks
    # before it reaches disk is not written to Redis in the clear either.
    return f"ip:{_client_ip(request)}"


async def enforce_rate_limit(
    identity: str, rule: str, limit: int, window_seconds: int
) -> None:
    """The limiter as a plain call, for routes whose budget depends on
    something only the handler can see (e.g. a report's `context`, which
    lives in the request body and so is not available to a dependency).

    `identity` is the already-built identity string, usually `f"uin:{uin}"`.
    Same fail-soft, same 429 shape as the dependency below.
    """
    key = f"rl:{rule}:{bucket_name(identity)}"
    now = time.time()
    try:
        redis = await get_redis()
        result = await redis.eval(_LIMITER_SCRIPT, 1, key, now, window_seconds, limit)
    except Exception as exc:  # noqa: BLE001
        log.warning("[rate_limit] redis unavailable, allowing: %s", exc)
        return
    if int(result[0]) == 1:
        return
    retry_after = int(result[1]) if len(result) > 1 else 1
    raise HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail={"code": "rate_limited", "retry_after": retry_after},
        headers={"Retry-After": str(retry_after)},
    )


# Fixed-window COST counter, for endpoints whose damage scales with the
# SIZE of the work a request asks for rather than the number of requests.
# The group fan-out endpoints turn one POST into N queue rows and N pushes,
# so a per-request cap prices them wrong: 120 requests/min against the
# ~1.9k-member flagship group is a quarter of a million rows a minute from
# a single caller, aimed at the layer that is already our bottleneck.
#
# Fixed window (INCRBY + EXPIRE) instead of the sliding set above because
# the value here is a weight, not a timestamp — there is nothing to sweep.
# A caller who goes over stays over until the window rolls, including the
# rejected requests, which is the right shape for an abuse ceiling and
# irrelevant to a real user who never approaches it.
_COST_SCRIPT = """
local key = KEYS[1]
local cost = tonumber(ARGV[1])
local limit = tonumber(ARGV[2])
local window = tonumber(ARGV[3])

local used = tonumber(redis.call('INCRBY', key, cost))
if used == cost then
  redis.call('EXPIRE', key, window)
end
if used > limit then
  local ttl = redis.call('TTL', key)
  if ttl < 0 then ttl = window end
  return {0, ttl}
end
return {1, 0}
"""


async def enforce_cost_budget(
    identity: str, rule: str, cost: int, limit: int, window_seconds: int
) -> None:
    """Charge `cost` units against `identity`'s budget for `rule`.

    Same fail-soft and same 429 shape as the request limiters. `cost` is
    whatever unit the caller is measuring — for the group endpoints it is
    the number of recipients the fan-out would actually touch, counted
    AFTER membership filtering so a request padded with non-members is
    charged for the real work and no more.
    """
    if cost <= 0:
        return
    bucket = bucket_name(identity)
    key = f"rlc:{rule}:{bucket}"
    try:
        redis = await get_redis()
        result = await redis.eval(_COST_SCRIPT, 1, key, cost, limit, window_seconds)
    except Exception as exc:  # noqa: BLE001
        log.warning("[rate_limit] redis unavailable, allowing: %s", exc)
        return
    if int(result[0]) == 1:
        return
    retry_after = int(result[1]) if len(result) > 1 else window_seconds
    # The bucket, not the identity: this line runs at WARNING and so reaches
    # journald, and `identity=uin:<sender>` here named the author of a group
    # post the endpoint above is built not to learn. The bucket still tells an
    # operator whether one caller is hitting the ceiling repeatedly or many
    # different ones are hitting it once, which is what the line is read for.
    log.warning(
        "[rate_limit] fan-out budget exhausted rule=%s bucket=%s cost=%d limit=%d",
        rule, bucket, cost, limit,
    )
    raise HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail={"code": "fanout_budget_exhausted", "retry_after": retry_after},
        headers={"Retry-After": str(retry_after)},
    )


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
        key = f"rl:{rule}:{bucket_name(_identity(request, creds))}"
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


# ── websocket connect ceiling ────────────────────────────────────────────
#
# The concurrency cap in `connection_manager` handles ACCUMULATION: an account
# that piles up live sockets loses the oldest. It does nothing about CHURN, and
# churn is what the storm actually is — measured on prod 12.08, the three worst
# accounts opened 1198, 641 and 632 sockets in an hour while never holding more
# than 7-14 at once, because each socket died after about ten seconds and was
# immediately redialled.
#
# The fixed backoff behind that was fixed in every client (Android 0.107, web,
# desktop 0.3.6, iOS build 109), but a client that never updates keeps dialling
# forever, and those are most of the traffic. So the island stops paying for
# them: over the ceiling the handshake is refused before `accept()`, which
# costs a socket setup instead of an authorised session, a queue drain, a
# presence fan-out and a boot chain.
#
# The number is deliberately far above any real client. A phone on a bad
# network with working backoff dials a handful of times a minute; three devices
# reconnecting together stay under ten. Twelve leaves room for a genuinely
# awful minute and still cuts a storming account by an order of magnitude.
WS_CONNECTS_PER_MIN = int(os.getenv("RCQ_WS_CONNECTS_PER_MIN", "12"))


async def allow_ws_connect(uin: int) -> bool:
    """May this UIN open another websocket right now?

    Fail-soft on purpose: a Redis hiccup must not lock every user out of the
    one channel that carries messages, calls and presence. Returns True when
    the ceiling is not reached, or when we cannot tell.
    """
    # Bucketed like every other limiter key. This one was never a sealed-sender
    # problem (the socket is authenticated, so the island knows who is dialling
    # anyway) but `wsrate:<uin>` in Redis is still a list of who was connecting
    # in the last minute, readable by anyone who reaches Redis alone.
    key = f"wsrate:{bucket_name(f'uin:{uin}')}"
    try:
        redis = await get_redis()
        result = await redis.eval(_COST_SCRIPT, 1, key, 1, WS_CONNECTS_PER_MIN, 60)
    except Exception as exc:  # noqa: BLE001
        log.warning("[ws_rate] redis unavailable, allowing: %s", exc)
        return True
    return int(result[0]) == 1


async def reset_buckets() -> None:
    """Wipe all rate-limit state. Used by tests; never called in
    production. Buckets self-prune via the cutoff sweep + key
    `EXPIRE` so memory growth is bounded by `unique_identities *
    unique_rules` and naturally fades after idle windows.

    All three prefixes, not just the sliding-window one: a test that resets
    only `rl:*` and then asserts against a cost budget or a socket ceiling is
    reading state the previous test left behind."""
    try:
        redis = await get_redis()
        for pattern in ("rl:*", "rlc:*", "wsrate:*"):
            async for key in redis.scan_iter(match=pattern):
                await redis.delete(key)
    except Exception:  # noqa: BLE001
        pass
