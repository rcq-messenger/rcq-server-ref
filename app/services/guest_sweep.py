"""Lifetimes of guest copies and unclaimed seats (spec 2026-09-15, 8.4).

A guest row costs the island something for as long as it exists: a number out
of circulation, a seat on every roster it sits on (keys every sender seals to),
and for a proven guest a queue of group content. Nothing about a guest makes
anyone come back to delete it, so three sweeps do:

  (a) UNCLAIMED SEATS. A member put somebody's public keys in a room and
      nobody holding the private key has opened it in `guest_added_ttl_days`
      (7). The seat never stored content (it is minted far outside the
      dormant window), so what goes is a roster entry and a number.
  (b) NEVER POLLED. A guest proved a key, got a token, and has not asked this
      island for anything in a week. That is what a script that mints and
      walks away looks like: its content was stored for about a day after the
      mint (`guest_policy.mint_backdate`) and would otherwise sit on rosters
      for 60 days more.
  (c) IDLE. A guest that has not polled for `guest_idle_days` (60). The
      person keeps their account at home; opening a room link again mints a
      new copy.

How (b) is told apart, with no extra column: a mint writes
`last_seen = guest_since - MINT_BACKDATE` (a day or more earlier), and every
event that proves somebody is there writes `last_seen >= guest_since - 1 h`
(a poll stamp, a claim, a socket ping). So "still further back than half the
backdate" can only be a row nothing has touched since it was minted.

⚠⚠ THE DELETE RE-CHECKS WITH THE ROW LOCKED. Candidates are read in one
session and deleted in another, one row at a time. In between, a seat can be
claimed and a guest can settle and become a RESIDENT. Deleting on the stale
reading would burn a person who just paid. So each purge re-reads the row
`FOR UPDATE` and re-applies its own condition before `purge_account`; a
conversion racing it waits for the lock and then finds no row, which fails
that request instead of deleting a resident.

Deletion is `services/account_delete.purge_account`, the same sequence as a
person's own burn, without the `account_burned` frame (nobody asked for this).
Each purge tells the rooms, and counts `stat:guest_swept_<a|b|c>`.

Portable SQL, like dead_account_sweep: the local tests run on SQLite, and the
one comparison between two columns (for b) is done in Python on rows the query
already narrowed.

`RCQ_GUEST_SWEEP_DRY_RUN=1` finds and logs, and deletes nothing.
"""
from __future__ import annotations

import asyncio
import logging
import os
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from app.core import guest_policy
from app.core.db import SessionLocal
from app.models.user import User
from app.services import server_settings
from app.services.account_delete import announce_rooms_after_purge, purge_account
from app.services.periodic_leader import lead_this_cycle

log = logging.getLogger("rcq.guest_sweep")

SWEEP_INTERVAL_SECONDS = int(os.environ.get("RCQ_GUEST_SWEEP_SECONDS", str(6 * 3600)))
#: Deletions per cycle across all three sweeps. Each is its own transaction
#: and its own roster broadcast, so the cap bounds a cycle's fan-out as much
#: as its database time. The next cycle takes the rest.
BATCH = int(os.environ.get("RCQ_GUEST_SWEEP_BATCH", "500"))
DRY_RUN: bool = os.environ.get("RCQ_GUEST_SWEEP_DRY_RUN", "") == "1"

#: A proven guest that has never polled is swept this long after its mint.
NEVER_POLLED_AFTER = timedelta(days=7)


def never_polled_gap() -> timedelta:
    """How far `last_seen` must sit behind `guest_since` to read as "never
    touched since the mint".

    Two days, as the spec writes it, whenever the mint backdate is at least
    four days (the default is 13). On an island that shortened DORMANT_DAYS
    the backdate can be a single day, and a fixed two-day gap would then never
    match anything; half the backdate still sits well clear of the one-hour
    lag every poll and claim writes."""
    return min(timedelta(days=2), guest_policy.mint_backdate() / 2)


def _aware(value):
    # SQLite hands timezone-aware columns back naive; Postgres does not.
    if value is None:
        return None
    if isinstance(value, str):
        value = datetime.fromisoformat(value)
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


async def _limits() -> tuple[int, int]:
    return (
        int(await server_settings.get("guest_added_ttl_days")),
        int(await server_settings.get("guest_idle_days")),
    )


def _eligible(kind: str, guest_status, guest_since, last_seen, now: datetime, ttl: int, idle: int) -> bool:
    """The one statement of each sweep's condition, used both to pick
    candidates and to re-check a locked row just before it is deleted."""
    guest_since, last_seen = _aware(guest_since), _aware(last_seen)
    if kind == "a":
        return (
            guest_status == guest_policy.STATUS_ADDED
            and guest_since is not None
            and guest_since < now - timedelta(days=ttl)
        )
    if guest_status != guest_policy.STATUS_PROVEN:
        return False
    if kind == "b":
        return (
            guest_since is not None
            and last_seen is not None
            and guest_since < now - NEVER_POLLED_AFTER
            and last_seen < guest_since - never_polled_gap()
        )
    if kind == "c":
        return last_seen is not None and last_seen < now - timedelta(days=idle)
    return False


async def find_candidates(now: datetime | None = None) -> list[tuple[int, str]]:
    """`(uin, kind)` pairs to delete this cycle, at most BATCH, each uin once
    (a row that is both never-polled and idle counts as never-polled)."""
    now = now or datetime.now(timezone.utc)
    ttl, idle = await _limits()
    cols = (User.uin, User.guest_status, User.guest_since, User.last_seen)
    async with SessionLocal() as db:
        seats = (
            await db.execute(
                select(*cols)
                .where(
                    User.guest_status == guest_policy.STATUS_ADDED,
                    User.guest_since < now - timedelta(days=ttl),
                )
                .order_by(User.guest_since)
                .limit(BATCH)
            )
        ).all()
        # (b) narrowed in SQL by what the Python condition implies on its own
        # (the mint is a week old, and last_seen is older still), so a guest
        # that polled this week is never even read. No LIMIT here: guests that
        # polled once and went quiet would otherwise fill the window ahead of
        # the rows this sweep is for, and the guest part of the table is small.
        silent = (
            await db.execute(
                select(*cols)
                .where(
                    User.guest_status == guest_policy.STATUS_PROVEN,
                    User.guest_since < now - NEVER_POLLED_AFTER,
                    User.last_seen < now - NEVER_POLLED_AFTER,
                )
                .order_by(User.guest_since)
            )
        ).all()
        idle_rows = (
            await db.execute(
                select(*cols)
                .where(
                    User.guest_status == guest_policy.STATUS_PROVEN,
                    User.last_seen < now - timedelta(days=idle),
                )
                .order_by(User.last_seen)
                .limit(BATCH)
            )
        ).all()
    out: list[tuple[int, str]] = []
    seen: set[int] = set()
    for kind, rows in (("a", seats), ("b", silent), ("c", idle_rows)):
        for r in rows:
            if len(out) >= BATCH:
                return out
            uin = int(r.uin)
            if uin in seen or not _eligible(kind, r.guest_status, r.guest_since, r.last_seen, now, ttl, idle):
                continue
            seen.add(uin)
            out.append((uin, kind))
    return out


async def purge_if_still_eligible(uin: int, kind: str, now: datetime | None = None) -> bool:
    """Delete one candidate if, with its row locked, it still meets `kind`'s
    condition. Returns whether it was (or in dry run, would be) deleted."""
    now = now or datetime.now(timezone.utc)
    ttl, idle = await _limits()
    async with SessionLocal() as db:
        # FOR UPDATE: a settle or a claim racing this waits for our commit
        # and then finds nothing to update. SQLite ignores the clause, and a
        # local test has no concurrent writer to race.
        user = await db.scalar(select(User).where(User.uin == int(uin)).with_for_update())
        if user is None or not _eligible(
            kind, user.guest_status, user.guest_since, user.last_seen, now, ttl, idle
        ):
            await db.rollback()
            return False
        if DRY_RUN:
            await db.rollback()
            return True
        result = await purge_account(db, int(uin), f"guest_swept_{kind}", announce_burn=False)
        if result is None:
            return False
        await announce_rooms_after_purge(db, result.member_rooms)
    await guest_policy.bump_stat(f"guest_swept_{kind}")
    return True


async def sweep_once(now: datetime | None = None) -> dict[str, int]:
    """One cycle of all three sweeps. Returns deletions per kind."""
    done = {"a": 0, "b": 0, "c": 0}
    for uin, kind in await find_candidates(now):
        try:
            if await purge_if_still_eligible(uin, kind, now):
                done[kind] += 1
        except Exception:  # noqa: BLE001 - one bad row must not stop the rest
            log.exception("[guest-sweep] purge failed for one row; continuing")
    return done


async def guest_sweep_loop() -> None:
    """Forever loop. Cancelled by the FastAPI lifespan on shutdown."""
    log.info(
        "[guest-sweep] starting (batch=%d, interval=%ds%s)",
        BATCH, SWEEP_INTERVAL_SECONDS, ", DRY RUN" if DRY_RUN else "",
    )
    while True:
        try:
            if not await lead_this_cycle("guest-sweep", SWEEP_INTERVAL_SECONDS):
                await asyncio.sleep(SWEEP_INTERVAL_SECONDS)
                continue
            done = await sweep_once()
            if any(done.values()):
                # warning, not info: prod runs at WARNING, and these numbers
                # are the only trace of what the sweeps removed. Counts only,
                # never a uin: a list of swept numbers is a guest register.
                log.warning(
                    "[guest-sweep] %sremoved %d unclaimed seat(s), %d never-polled "
                    "and %d idle guest(s)",
                    "dry-run: " if DRY_RUN else "", done["a"], done["b"], done["c"],
                )
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 (a sweep must not die on a transient error)
            log.exception("[guest-sweep] iteration failed; will retry")
        await asyncio.sleep(SWEEP_INTERVAL_SECONDS)
