#!/usr/bin/env python3
"""One missed heartbeat is not somebody leaving (#1030, #1029).

Presence is DERIVED from `last_seen` freshness, and a live client refreshes it
on a ~25 second websocket ping. The window therefore has to clear several
pings: at 60 seconds it cleared two with ten to spare, so one missed ping made
a live person read offline to everyone watching and the next ping brought them
back. Every client announced both, which is why two reports in one week say the
sound fires while the contact's own flower is still green.

Pure arithmetic over the model's own constant and predicate. No island, no
database, no Redis.

Run: cd backend && PYTHONPATH=. .venv/bin/python test_presence_window_local.py
"""
import sys
from datetime import datetime, timedelta, timezone

from app.models.user import PRESENCE_FRESHNESS_SECONDS, presence_is_fresh

HEARTBEAT = 25  # seconds; ws.py:724 ("~25s from iOS")

failed = 0


def check(what: str, cond: bool) -> None:
    global failed
    print(f"  {'PASS' if cond else 'FAIL'}  {what}")
    if not cond:
        failed += 1


def seen(seconds_ago: float) -> datetime:
    return datetime.now(timezone.utc) - timedelta(seconds=seconds_ago)


print("\n-- the window against the heartbeat --")
check("a client that just pinged is online", presence_is_fresh(seen(1)))
check(
    "★ one missed ping is NOT a departure",
    presence_is_fresh(seen(2 * HEARTBEAT + 5)),
)
check(
    "★ two missed pings are still not one",
    presence_is_fresh(seen(3 * HEARTBEAT)),
)
check(
    "somebody who really stopped reads offline",
    not presence_is_fresh(seen(PRESENCE_FRESHNESS_SECONDS + 1)),
)

print("\n-- the invariant behind the number --")
check(
    "★ the window clears at least three heartbeats",
    PRESENCE_FRESHNESS_SECONDS >= 3 * HEARTBEAT,
)
check(
    "and leaves slack for jitter on top of them",
    PRESENCE_FRESHNESS_SECONDS - 3 * HEARTBEAT >= 10,
)
check(
    "but does not hold a departed person online for minutes",
    PRESENCE_FRESHNESS_SECONDS <= 120,
)

print("\n-- never trusts a missing timestamp --")
check("no last_seen is not 'fresh'", not presence_is_fresh(None))

print("\n-- the offline fan-out waits the same window --")
from app.routers.ws import _OFFLINE_DEBOUNCE_SECONDS  # noqa: E402

check(
    "★ the debounce is the freshness window, not a copy of its old value",
    _OFFLINE_DEBOUNCE_SECONDS == float(PRESENCE_FRESHNESS_SECONDS),
)

print()
if failed:
    print(f"{failed} CHECK(S) FAILED ❌")
    sys.exit(1)
print("ALL PRESENCE-WINDOW CHECKS PASSED ✅")
