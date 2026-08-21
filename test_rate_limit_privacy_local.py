"""Local-only verification that the rate limiter still bites after its keys
stopped naming people.

The limiter is load-bearing DDoS protection AND, since 2026-08-22, the thing
that was quietly undoing sealed sender: `POST /messages/sealed` takes no auth
on purpose so the island cannot learn who sent an envelope, and the limiter
decoded the bearer the client sends anyway and wrote
`rl:messages_send:uin:<sender>` into Redis with a timestamp per send
(metadata-map-2026-08-22 §1.1). The fix HMACs the identity into an opaque
bucket name. The risk of a fix like that is not that it fails loudly, it is
that it silently opens the door: every identity collapsing into one bucket
would still 429 and look fine; every identity getting its own would never 429
at all and also look fine until the first flood.

So this checks the three properties that separate those cases, plus the one
piece of machinery built ON TOP of the keys that a rename could break:

  1. the same identity is still refused at exactly the configured threshold
  2. two identities do not share a bucket (and one being blocked does not
     block the other)
  3. what lands in Redis carries neither a uin nor an IP, under any prefix
  4. a dual-send's paired tail is still admitted by the one-shot slowmode
     free pass, and a second same-path post still is not

Needs a local Redis (`redis-server`, default localhost:6379). Uses db 15 so a
dev box's real keyspace is never touched.
Run: cd backend && PYTHONPATH=. .venv/bin/python test_rate_limit_privacy_local.py
"""
import asyncio
import os
import sys

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test_rate_limit_privacy.db"
os.environ["REDIS_URL"] = "redis://localhost:6379/15"
os.environ["ENV"] = "dev"
os.environ["JWT_SECRET"] = "test-secret-for-bucket-derivation"

for f in ("test_rate_limit_privacy.db",):
    try:
        os.remove(f)
    except FileNotFoundError:
        pass

from fastapi import HTTPException  # noqa: E402

from app.core.db import SessionLocal, init_db  # noqa: E402
from app.core.rate_limit import (  # noqa: E402
    bucket_name,
    enforce_cost_budget,
    enforce_rate_limit,
    reset_buckets,
)
from app.core.redis import close_redis, get_redis  # noqa: E402
from app.models.group import Group, GroupMember  # noqa: E402
from app.routers.messages import (  # noqa: E402
    _enforce_group_slowmode,
    _slowmode_free_key,
    _slowmode_identity,
)

PASS, FAIL = [], []

UIN_A = 100200300
UIN_B = 688303020
IP_A = "203.0.113.47"


def check(name: str, ok: bool, detail: str = "") -> None:
    (PASS if ok else FAIL).append(name)
    print(f"  {'ok  ' if ok else 'FAIL'} {name}{'' if ok else '  ← ' + detail}")


async def hit(identity: str, rule: str, limit: int, window: int) -> bool:
    """One request against the limiter. True = accepted, False = 429."""
    try:
        await enforce_rate_limit(identity, rule, limit, window)
        return True
    except HTTPException as exc:
        assert exc.status_code == 429, exc.status_code
        assert exc.detail["code"] == "rate_limited", exc.detail
        assert "Retry-After" in exc.headers, exc.headers
        return False


async def live_keys() -> list[str]:
    redis = await get_redis()
    out = []
    for pattern in ("rl:*", "rlc:*", "wsrate:*", "gslowfree:*"):
        async for key in redis.scan_iter(match=pattern):
            out.append(key)
    return out


async def wipe() -> None:
    await reset_buckets()
    redis = await get_redis()
    async for key in redis.scan_iter(match="gslowfree:*"):
        await redis.delete(key)


async def main() -> None:
    await init_db()
    await wipe()
    print("\nrate limiter, opaque buckets\n")

    # ── 1. the threshold has not moved ──────────────────────────────────────
    # 5/60 means five accepted and the sixth refused. Not "roughly five".
    accepted = 0
    for _ in range(8):
        if await hit(f"uin:{UIN_A}", "t_threshold", 5, 60):
            accepted += 1
    check("the same identity is accepted exactly `limit` times", accepted == 5,
          f"{accepted} accepted, expected 5")

    # The refusal has to stick for the rest of the window, not just once.
    still_refused = not await hit(f"uin:{UIN_A}", "t_threshold", 5, 60)
    check("an identity over the limit stays refused", still_refused)

    # ── 2. buckets are not shared ───────────────────────────────────────────
    # The failure this catches: a derivation that loses the identity (a
    # constant, a truncation to nothing) would still 429 and still look like a
    # working limiter, while actually rate-limiting the whole island as one.
    b_first = await hit(f"uin:{UIN_B}", "t_threshold", 5, 60)
    check("a second uin is untouched by the first one's exhausted bucket", b_first)

    ip_first = await hit(f"ip:{IP_A}", "t_threshold", 5, 60)
    check("an IP identity is untouched by the uin buckets", ip_first)

    check("two identities hash to different buckets",
          bucket_name(f"uin:{UIN_A}") != bucket_name(f"uin:{UIN_B}"))
    check("one identity hashes to a stable bucket",
          bucket_name(f"uin:{UIN_A}") == bucket_name(f"uin:{UIN_A}"))
    check("the bucket is a short opaque hex string",
          len(bucket_name(f"uin:{UIN_A}")) == 16
          and all(c in "0123456789abcdef" for c in bucket_name(f"uin:{UIN_A}")))

    # The 4-worker requirement: the secret comes from settings, not from
    # os.urandom at import, so a second process derives the SAME bucket. Proved
    # by re-deriving in a subprocess with the same JWT_SECRET in its env.
    proc = await asyncio.create_subprocess_exec(
        sys.executable, "-c",
        "import os;"
        "os.environ.setdefault('DATABASE_URL','sqlite+aiosqlite:///./test_rate_limit_privacy.db');"
        "from app.core.rate_limit import bucket_name;"
        f"print(bucket_name('uin:{UIN_A}'))",
        cwd=os.path.dirname(os.path.abspath(__file__)),
        env={**os.environ, "PYTHONPATH": "."},
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    out, err = await proc.communicate()
    check("a separate process derives the same bucket (workers share limits)",
          out.decode().strip() == bucket_name(f"uin:{UIN_A}"),
          err.decode()[-300:] or out.decode())

    # ── 3. nothing in Redis names anybody ───────────────────────────────────
    # Cover every prefix the limiter writes, not just the sliding window: the
    # cost budget (group fan-out) and the socket ceiling wrote uins too.
    await enforce_cost_budget(f"uin:{UIN_A}", "t_fanout", 10, 1000, 60)
    await enforce_cost_budget(f"ip:{IP_A}", "t_fanout", 10, 1000, 60)
    keys = await live_keys()
    check("the limiter actually wrote something (the test is not vacuous)", len(keys) >= 4,
          f"only {len(keys)} keys")
    leaks = [k for k in keys if str(UIN_A) in k or str(UIN_B) in k or IP_A in k]
    check("no key contains a uin or an IP", not leaks, f"leaked: {leaks}")
    leaks = [k for k in keys if "uin:" in k or "ip:" in k]
    check("no key carries an identity prefix either", not leaks, f"leaked: {leaks}")

    # ── 4. the dual-send handshake ──────────────────────────────────────────
    # One logical group post arrives as TWO POSTs (broadcast to the capable
    # members + the legacy sealed tail). The half that spends the slot arms a
    # one-shot 30s pass for the OTHER path. Break that and a mixed group's
    # non-capable members silently stop receiving messages.
    await wipe()
    async with SessionLocal() as db:
        db.add(Group(id=41, name="slowmode room", owner_uin=999999, slowmode_sec=60))
        db.add(GroupMember(group_id=41, uin=UIN_A, role="member", permissions=""))
        db.add(GroupMember(group_id=41, uin=UIN_B, role="member", permissions=""))
        await db.commit()
        g = await db.get(Group, 41)

        async def post(caller: int, path: str) -> bool:
            try:
                await _enforce_group_slowmode(db, g, caller, "message", path)
                return True
            except HTTPException as exc:
                assert exc.status_code == 429, exc.status_code
                return False

        first = await post(UIN_A, "broadcast")
        check("the first half of a dual-send passes", first)
        tail = await post(UIN_A, "sealed")
        check("the paired legacy tail is admitted by the free pass", tail)

        # ...and the pass was one-shot: a genuine second post on either path
        # inside the window still has to buy a slot, and there is none left.
        again = await post(UIN_A, "sealed")
        check("a second post on the freed path is refused", not again)
        same_path = await post(UIN_A, "broadcast")
        check("a second post on the original path is refused", not same_path)

        # A different member of the same room is unaffected by A's slot.
        other = await post(UIN_B, "broadcast")
        check("another member's slot is independent", other)

        keys = await live_keys()
        leaks = [k for k in keys if str(UIN_A) in k or str(UIN_B) in k or ":41:" in k]
        check("no slowmode key names the poster or the room", not leaks, f"leaked: {leaks}")
        check("the (group, member) bucket is per pair",
              _slowmode_identity(41, UIN_A) != _slowmode_identity(41, UIN_B)
              and _slowmode_identity(41, UIN_A) != _slowmode_identity(42, UIN_A))
        check("the free-pass key is per path",
              _slowmode_free_key("sealed", 41, UIN_A) != _slowmode_free_key("broadcast", 41, UIN_A))

    await wipe()
    # Close the pool rather than letting the GC do it after the loop is gone;
    # redis-py's __del__ raises "Event loop is closed" into a passing run otherwise.
    await close_redis()
    print(f"\n{len(PASS)}/{len(PASS) + len(FAIL)} pass")
    if FAIL:
        raise SystemExit("FAILED: " + ", ".join(FAIL))


asyncio.run(main())
