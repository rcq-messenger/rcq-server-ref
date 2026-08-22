"""Expiry for the cluster-wide online set, `ws:online_uins`.

The set has no TTL and its sibling (`_online_devs_key`, one key per connected
account, its name hashed since 2026-08-22) does: 180 seconds,
refreshed on connect and on every client frame. The asymmetry was deliberate
for the devs key (`connection_manager` explains why: a device wrongly believed
online is a message the user never hears about) and simply absent for the
account set, which was maintained only by the SADD on connect and the SREM on
disconnect. A worker that dies between the two takes its SREM with it and
leaves the account marked online forever.

The one thing that pruned it was the admin console's roster read
(`admin.py`), which drops members with no `users` row. So the island cleaned up
after BURNED accounts and kept a permanent ghost for every live one, precisely
backwards, since a burned account has nothing left to leak and a live one's
ghost is a false statement that this person is here right now.

A TTL on the key itself is not available: `ws:online_uins` is one SET, so
expiring it marks the whole island offline at once. The liveness test is the
devs key instead, which is exactly the right signal: it exists only while some
device of that account has been heard from inside the last 180s, wherever in
the cluster it is connected. No devs key means no live device anywhere, which
is the definition of offline.

⚠ The ordering this depends on is enforced in `ConnectionManager.connect`: the
devs key is written BEFORE the account is added to the set, so a connecting
user is never briefly indistinguishable from a ghost.

Cost of being wrong, in the only direction it can be wrong: an account pruned a
moment before it would have refreshed reads as offline, and `manager.send`
answers False, so the message is ALSO pushed. A stale push, not a missed one:
the same trade `connection_manager`'s own docstring already takes.

Five minutes, leader-elected. `RCQ_PRESENCE_SWEEP_DRY_RUN=1` counts and logs
without removing.
"""
from __future__ import annotations

import asyncio
import logging
import os

from app.core.redis import get_redis
from app.services.connection_manager import _ONLINE_KEY, _online_devs_key
from app.services.periodic_leader import lead_this_cycle

log = logging.getLogger(__name__)

# Short relative to everything else in this directory, because the thing being
# corrected is a live-presence claim rather than stored history: at five
# minutes a ghost survives at most ~8 minutes (the devs TTL plus a cycle)
# instead of until the next restart.
SWEEP_INTERVAL_SECONDS: int = 5 * 60
# One pass. The set is bounded by concurrent users, so this is a guard against
# a pathological state rather than a real limit.
MAX_REMOVALS_PER_CYCLE: int = int(os.environ.get("RCQ_PRESENCE_SWEEP_MAX_PER_CYCLE", "5000"))
DRY_RUN: bool = os.environ.get("RCQ_PRESENCE_SWEEP_DRY_RUN", "") == "1"


async def sweep_once() -> int:
    """One pass. Returns how many ghosts were dropped (or found, dry)."""
    redis = await get_redis()
    members = await redis.smembers(_ONLINE_KEY)
    if not members:
        return 0
    ghosts: list[str] = []
    for raw in members:
        member = raw.decode() if isinstance(raw, bytes) else str(raw)
        try:
            uin = int(member)
        except (TypeError, ValueError):
            # Not a uin at all. Nothing legitimate writes one of these, and a
            # member that can never be matched is a ghost by definition.
            ghosts.append(member)
            continue
        if not await redis.exists(_online_devs_key(uin)):
            ghosts.append(member)
        if len(ghosts) >= MAX_REMOVALS_PER_CYCLE:
            break
    if not ghosts:
        return 0
    if DRY_RUN:
        log.warning("[presence-sweep] dry-run: %d ghost(s) in %s", len(ghosts), _ONLINE_KEY)
        return len(ghosts)
    removed = int(await redis.srem(_ONLINE_KEY, *ghosts) or 0)
    if removed:
        log.warning("[presence-sweep] dropped %d stale online marker(s)", removed)
    return removed


async def presence_sweep_loop() -> None:
    while True:
        try:
            # One worker per cycle (see services/periodic_leader).
            if await lead_this_cycle("presence-sweep", SWEEP_INTERVAL_SECONDS):
                await sweep_once()
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            log.exception("[presence-sweep] pass failed; retrying next cycle")
        await asyncio.sleep(SWEEP_INTERVAL_SECONDS)
