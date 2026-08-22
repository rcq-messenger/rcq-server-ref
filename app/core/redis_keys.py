"""Redis key names that used to spell out an account number.

The first strike (2026-08-22) stopped the rate limiter writing `uin:<n>` into
key names and hashed the identity into an opaque bucket instead; see
`rate_limit.bucket_name` for the derivation and, more importantly, for the
honest list of what that HMAC buys and what it does not. It left three key
families behind, all of them written by code nobody thinks of as part of the
message path:

    devices:<uin>          hash, 90 days   linked web sessions
    dev_revoked:<uin>      set,  90 days   revoked device ids
    ws:online_devs:<uin>   set,  180 s     device ids with a live socket

`KEYS *` on a box with those is a plaintext list of which accounts have a
linked browser, which ones revoked one, and which ones are connected right
now. The whole point of hashing the limiter buckets was that reaching port
6379 and nothing else should not read as a who-did-what list, and these three
undid it one prefix over.

★ One correction to the reviewer's framing, because getting the reason right
matters for what to do next. The finding was that these plaintext names are a
candidate dictionary that makes the hashed buckets grindable. They are not: the
bucket is an HMAC under the server secret, so an adversary WITHOUT the secret
cannot test a candidate at all, and one WITH it can enumerate the whole
100000..999999999 space in seconds and needs no dictionary. The real reason to
hash these is the plain one: each is a direct statement about a named account,
readable by anyone who reaches Redis alone, and that is exactly the threat
`bucket_name` exists for.

NEW PREFIXES, not the same ones. `dev:` / `devrv:` / `wsdev:` rather than
reusing `devices:` etc., because the migration below SCANs for the legacy
pattern and `devices:*` would keep matching its own output. One boot later
every key would be hashed twice.

⚠ WHAT IS DELIBERATELY NOT HASHED: `ws:online_uins`. It is one SET whose
MEMBERS are account numbers, and the admin console reads them back to render
the online roster (`admin._online_users` selects those uins out of `users` for
nickname, status and last_seen). Membership tests survive hashing fine (every
hot caller asks "is this uin in the set" and would just ask with the hash), but
the console's read is the reverse direction and an HMAC has no reverse. So
hashing the members means deleting the operator's roster, which is a product
decision and not this module's to take. Said plainly here rather than left
looking like an omission.
"""
from __future__ import annotations

import logging

from app.core.rate_limit import bucket_name
from app.core.redis import get_redis

log = logging.getLogger(__name__)

# Per-account key families. The value is the prefix; the account is the
# opaque bucket. Same derivation as every limiter key, so an island rotating
# JWT_SECRET rotates these too; see the migration note at the bottom.
DEVICES_PREFIX = "dev"
DEV_REVOKED_PREFIX = "devrv"
ONLINE_DEVS_PREFIX = "wsdev"


def account_key(prefix: str, uin: int) -> str:
    """The Redis key for one per-account thing, without the account in it.

    `uin:<n>` is the same identity string the limiter uses, so an operator who
    holds the secret can reproduce a key for one specific account when they
    genuinely need to (support, a stuck session) with the same one-liner that
    reproduces a limiter bucket. Anyone who does not hold it gets sixteen hex
    characters.
    """
    return f"{prefix}:{bucket_name(f'uin:{uin}')}"


# The legacy shapes, kept only for the one-shot migration below. Not used to
# build a key anywhere.
_LEGACY = (
    ("devices:", DEVICES_PREFIX, "hash"),
    ("dev_revoked:", DEV_REVOKED_PREFIX, "set"),
)


async def migrate_legacy_account_keys() -> int:
    """Move `devices:<uin>` and `dev_revoked:<uin>` onto the hashed names.

    Runs at boot on every worker. Idempotent: once a legacy key is folded in it
    is deleted, so the second pass finds nothing and every later boot costs one
    SCAN over a keyspace that is a few hundred keys on the flagship.

    ⚠ NOT a RENAME, and not for tidiness. Four uvicorn workers boot
    independently and there is no barrier between "worker A finished its
    lifespan and is serving requests" and "worker B is still migrating". If a
    browser links in that window, A writes the new key and B's RENAME would
    drop the legacy hash straight on top of it and lose the session that was
    just created. So each family is folded with union semantics instead,
    HSETNX per field and SADD for the set, which cannot lose either side no
    matter which order the two happen in.

    ⚠ Why this is a migration at all and not just a rename in the code. These
    two are DURABLE state on a 90-day TTL, not a cache. Orphaning
    `devices:<uin>` would make `has_linked_devices` answer False for every
    account that has a linked browser, which serves the v=2 bundle to a
    multi-device identity and silently desyncs the ratchet, and it would empty
    the device list, so the owner could not revoke the session they can no
    longer see. Orphaning `dev_revoked:<uin>` is worse: a revoked device token
    would start verifying again until its own exp, i.e. the revoke quietly
    un-revokes.

    ⚠ Rotating JWT_SECRET moves every key here, and unlike a limiter bucket
    (seconds to an hour of state) that loses 90 days of linked sessions and
    live revocations. An island that rotates its secret must expect every
    browser to re-link and must re-revoke anything it had revoked.

    Returns how many legacy keys were folded in, for the boot line.
    """
    redis = await get_redis()
    moved = 0
    for legacy_prefix, new_prefix, kind in _LEGACY:
        async for raw in redis.scan_iter(match=f"{legacy_prefix}*", count=200):
            key = raw.decode() if isinstance(raw, bytes) else str(raw)
            suffix = key[len(legacy_prefix):]
            try:
                uin = int(suffix)
            except (TypeError, ValueError):
                # Not an account number, so not ours to move. Nothing writes
                # such a key; leaving it alone is cheaper than guessing.
                continue
            target = account_key(new_prefix, uin)
            try:
                ttl = int(await redis.ttl(key) or -1)
                if kind == "hash":
                    fields = await redis.hgetall(key)
                    for field, value in (fields or {}).items():
                        # Per FIELD, so a session created on another worker in
                        # the boot window wins over the stale copy here.
                        await redis.hsetnx(target, field, value)
                else:
                    members = await redis.smembers(key)
                    if members:
                        await redis.sadd(target, *members)
                if ttl > 0:
                    current = int(await redis.ttl(target) or -1)
                    # The longer of the two. A key the running code just
                    # touched carries a freshly refreshed TTL and must not be
                    # shortened back to whatever was left on the legacy one.
                    if current < ttl:
                        await redis.expire(target, ttl)
                await redis.delete(key)
                moved += 1
            except Exception:  # noqa: BLE001, a stuck key must not block boot
                log.exception("[redis-keys] could not fold %s", legacy_prefix + "<uin>")
    if moved:
        log.warning("[redis-keys] folded %d legacy per-account key(s)", moved)
    return moved
