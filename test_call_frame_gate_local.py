#!/usr/bin/env python3
"""A call frame outside a call is not a call.

`call_offer` has always been gated: `_caller_allowed` honours the callee's
`call_policy` ("nobody" / "contacts") and refuses guest pairs. Every OTHER call
frame — answer, ICE, renegotiate, ICE restart, end — was relayed to whatever
`to_uin` said, with `sdp`, `candidate`, `media` and `reason` copied through, and
nothing asked whether a call existed. So an ordinary account could push
arbitrary strings into any other account's socket, past a "nobody" policy, past
a block, leaving no row in any queue. The comment beside the guest check said
this out loud and fixed it for guests only.

This drives `_call_pair_live`, the gate that closes it, against a real local
Redis. Touches nothing else: no island, no sockets, no database.

Run: cd backend && PYTHONPATH=. .venv/bin/python test_call_frame_gate_local.py
"""
import asyncio
import os
import sys
import time

os.environ.setdefault("REDIS_URL", "redis://localhost:6379/15")
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_call_gate.db")
os.environ.setdefault("ENV", "dev")

from app.routers.ws import _CALLS_KEY, _call_pair_live, _get_redis  # noqa: E402

CALLER, CALLEE, STRANGER = 4242001, 4242002, 4242003
CALL = "call-abc-123"
# A call that started a minute ago. The gate bounds how old an entry may be, so
# a hardcoded 2023 timestamp would read as the leak it is.
NOW = int(time.time())

failed = 0


def check(what: str, cond: bool) -> None:
    global failed
    print(f"  {'PASS' if cond else 'FAIL'}  {what}")
    if not cond:
        failed += 1


async def main() -> None:
    redis = await _get_redis()
    key = _CALLS_KEY + ":test_call_frame_gate"
    # The predicate reads the real key name, so work on it and clean up after.
    await redis.hdel(_CALLS_KEY, str(CALLER), str(CALLEE), str(STRANGER))
    try:
        print("\n-- nobody is in a call --")
        check("★ a stranger's ICE reaches nobody", not await _call_pair_live(STRANGER, CALLEE, CALL))
        check("★ nor their answer", not await _call_pair_live(STRANGER, CALLEE, ""))
        check("★ nor an 'end' for a call that never was", not await _call_pair_live(STRANGER, CALLER, "whatever"))

        print("\n-- an offer registered the pair, as it does --")
        await redis.hset(_CALLS_KEY, str(CALLER), f"{CALL}|{CALLEE}|{NOW - 60}")
        await redis.hset(_CALLS_KEY, str(CALLEE), f"{CALL}|{CALLER}|{NOW - 60}")
        check("the caller's frames pass", await _call_pair_live(CALLER, CALLEE, CALL))
        check("and the callee's do too", await _call_pair_live(CALLEE, CALLER, CALL))
        check(
            "★ a third party still cannot reach either end",
            not await _call_pair_live(STRANGER, CALLEE, CALL)
            and not await _call_pair_live(STRANGER, CALLER, CALL),
        )
        check(
            "★ and cannot borrow the live call's id to reach somebody else",
            not await _call_pair_live(CALLEE, STRANGER, CALL),
        )
        check("a frame with no call_id matches the pair it names", await _call_pair_live(CALLER, CALLEE, ""))
        check(
            "but a DIFFERENT call id does not",
            not await _call_pair_live(CALLER, CALLEE, "some-other-call"),
        )

        print("\n-- one side cleared first, which is how teardown goes --")
        await redis.hdel(_CALLS_KEY, str(CALLER))
        check(
            "★ the other end's late frame is still a real frame",
            await _call_pair_live(CALLER, CALLEE, CALL) and await _call_pair_live(CALLEE, CALLER, CALL),
        )

        print("\n-- a long call, and a third person rings one of them --")
        # `free_if_stale` in the register script treats an entry older than ten
        # minutes as a leak and DELETES it, so an offer to one of the two
        # parties mid-call clears that party's entry. The other party's entry
        # is not part of the new pair and survives, which is exactly why this
        # gate accepts EITHER side: a forty-minute call keeps renegotiating.
        await redis.hset(_CALLS_KEY, str(CALLEE), f"{CALL}|{CALLER}|{NOW - 60}")
        await redis.hset(_CALLS_KEY, str(CALLER), f"other-call|{STRANGER}|{NOW - 5}")
        check(
            "★ the long call still relays through the untouched side",
            await _call_pair_live(CALLER, CALLEE, CALL),
        )
        check(
            "and the new call relays on its own id",
            await _call_pair_live(CALLER, STRANGER, "other-call"),
        )
        await redis.hdel(_CALLS_KEY, str(CALLEE), str(CALLER))

        print("\n-- an entry from an older worker carries two fields --")
        await redis.hset(_CALLS_KEY, str(CALLER), f"{CALL}|{CALLEE}")
        await redis.hdel(_CALLS_KEY, str(CALLEE))
        check("it is still understood", await _call_pair_live(CALLER, CALLEE, CALL))

        print("\n-- an entry that leaked months ago is not a call --")
        # Nothing expires this hash, so without a bound a pair who spoke once
        # could relay frames for ever, past a `call_policy` set to "nobody" in
        # the meantime.
        from app.routers.ws import _CALL_FRAME_MAX_AGE_S
        old_ts = NOW - _CALL_FRAME_MAX_AGE_S - 60
        await redis.hset(_CALLS_KEY, str(CALLER), f"{CALL}|{CALLEE}|{old_ts}")
        await redis.hset(_CALLS_KEY, str(CALLEE), f"{CALL}|{CALLER}|{old_ts}")
        check("★ a stale entry authorises nothing", not await _call_pair_live(CALLER, CALLEE, CALL))
        fresh_ts = NOW - 3600
        await redis.hset(_CALLS_KEY, str(CALLER), f"{CALL}|{CALLEE}|{fresh_ts}")
        check(
            "but an hour-long call is still a call",
            await _call_pair_live(CALLER, CALLEE, CALL),
        )
        await redis.hdel(_CALLS_KEY, str(CALLEE))

        print("\n-- and a malformed entry is not a pass --")
        await redis.hset(_CALLS_KEY, str(CALLER), "garbage")
        check("★ garbage in the registry lets nobody through", not await _call_pair_live(CALLER, CALLEE, CALL))
    finally:
        await redis.hdel(_CALLS_KEY, str(CALLER), str(CALLEE), str(STRANGER))
        await redis.delete(key)

    print()
    if failed:
        print(f"{failed} CHECK(S) FAILED ❌")
        sys.exit(1)
    print("ALL CALL-FRAME-GATE CHECKS PASSED ✅")


asyncio.run(main())
