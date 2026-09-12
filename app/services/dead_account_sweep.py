"""Delete accounts that were minted and never used.

⚠⚠ WHY THIS EXISTS. On 2026-09-01 a script created 552 accounts on the
flagship in three minutes. They were removed by hand five days later, and the
five days are the point: until then every number the island published about
itself was wrong by a factor of two (3351 accounts, of which 1369 looked like
people), and 552 numbers were out of circulation for no reason.

The research into stopping the flood at the door came back against a
proof-of-work gate: a puzzle sized so a phone takes two seconds costs an
attacker with a rented GPU $0.00003 per thousand accounts, and a second-hand
mining ASIC is 2.7 million times faster than the phone. What the caps in
`core/rate_limit` do is bound the rate; what this does is make a flood
worthless afterwards, so nobody has to notice it for it to be undone.

WHAT COUNTS AS NEVER USED, and every clause is here because leaving it out
would delete somebody real:

  * older than `DEAD_AFTER_DAYS` — a fresh account has not had time to do
    anything yet, and the flood is only interesting once it is stale;
  * never seen more than an hour after it was created — somebody who came back
    a week later is a person, whatever else they have not done;
  * the nickname the island generated, and no avatar — either is a deliberate
    act;
  * no device and no push token — a registered install is a person holding a
    phone;
  * no contact edge in either direction, no room membership, no room of their
    own, no site, no collection row, no report filed or received;
  * and never a resident. Somebody who PAID to be here is not junk however
    empty the account looks, and this is what "resident" should mean: a
    person the island keeps. A flood does not buy vouchers, so the clause
    costs the sweep nothing against the thing it was written for.

A lurker who reads a room they were added to keeps their membership row and is
therefore never touched. An account that only ever received one message is
kept too: the sender's contact edge points at it.

Deletion goes through `purge_uin_rows`, the same path a person's own "burn my
account" takes, so no orphan rows are left behind — the five stale
`group_members` rows found on 2026-09-06 were exactly that kind of leftover
from an older, blunter cleanup.
"""
from __future__ import annotations

import asyncio
import logging
import os
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, text

from app.core.db import SessionLocal
from app.models.user import User
from app.services.periodic_leader import lead_this_cycle
from app.services.uin_rows import purge_uin_rows

log = logging.getLogger(__name__)

#: How stale an unused account has to be before it is swept. Thirty days is
#: deliberately generous: the cost of keeping junk for a month is a row, and
#: the cost of deleting a real person's account is unrecoverable.
DEAD_AFTER_DAYS = int(os.environ.get("RCQ_DEAD_ACCOUNT_DAYS", "30"))

#: How long after creation a return visit still counts as "never came back".
FIRST_HOUR_SECONDS = 3600

SWEEP_INTERVAL_SECONDS = int(os.environ.get("RCQ_DEAD_ACCOUNT_SWEEP_SECONDS", str(24 * 3600)))

#: A ceiling per cycle, so a first run on an island with a large backlog cannot
#: hold a transaction open for minutes. The next cycle takes the rest.
BATCH = int(os.environ.get("RCQ_DEAD_ACCOUNT_BATCH", "500"))

# ⚠ Portable SQL on purpose. Two of the clauses have no shared spelling
# between Postgres and SQLite — `~` for the nickname and interval arithmetic
# for "came back within the hour" — and the local tests run on SQLite. Writing
# them in Postgres dialect would mean the janitor that deletes accounts is the
# one piece of code no test can execute. `LIKE` covers the generated nickname
# exactly (`user-1234`), and the hour is compared in Python below, on the two
# timestamps this already selects.
_CANDIDATES = text("""
    SELECT u.uin, u.created_at, u.last_seen
    FROM users u
    WHERE u.created_at < :cutoff
      AND u.resident_since IS NULL
      AND u.nickname LIKE 'user-%'
      AND u.avatar_media_id IS NULL
      AND NOT EXISTS (SELECT 1 FROM devices d WHERE d.uin = u.uin)
      AND NOT EXISTS (SELECT 1 FROM device_tokens t WHERE t.uin = u.uin)
      AND NOT EXISTS (SELECT 1 FROM contacts c WHERE c.owner_uin = u.uin OR c.contact_uin = u.uin)
      AND NOT EXISTS (SELECT 1 FROM group_members g WHERE g.uin = u.uin)
      AND NOT EXISTS (SELECT 1 FROM groups g WHERE g.owner_uin = u.uin)
      AND NOT EXISTS (SELECT 1 FROM sites s WHERE s.owner_uin = u.uin)
      AND NOT EXISTS (SELECT 1 FROM owned_uins o WHERE o.owner_uin = u.uin OR o.uin = u.uin)
      AND NOT EXISTS (SELECT 1 FROM reports r WHERE r.reporter_uin = u.uin OR r.target_uin = u.uin)
    ORDER BY u.created_at
    LIMIT :scan
""")


def _never_came_back(created_at, last_seen) -> bool:
    """Was this account last seen inside the first hour of its life?

    Both columns are timezone-aware on Postgres and naive on SQLite, so the
    comparison is normalised rather than assumed.
    """
    if created_at is None or last_seen is None:
        return True
    # SQLite hands these back as ISO strings when the query is raw text.
    if isinstance(created_at, str):
        created_at = datetime.fromisoformat(created_at)
    if isinstance(last_seen, str):
        last_seen = datetime.fromisoformat(last_seen)
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=timezone.utc)
    if last_seen.tzinfo is None:
        last_seen = last_seen.replace(tzinfo=timezone.utc)
    return (last_seen - created_at).total_seconds() < FIRST_HOUR_SECONDS


async def _sweep_once() -> int:
    cutoff = datetime.now(timezone.utc) - timedelta(days=DEAD_AFTER_DAYS)
    async with SessionLocal() as db:
        rows = (
            await db.execute(_CANDIDATES, {"cutoff": cutoff, "scan": BATCH * 4})
        ).all()
    uins = [int(r[0]) for r in rows if _never_came_back(r[1], r[2])][:BATCH]
    if not uins:
        return 0
    done = 0
    async with SessionLocal() as db:
        for uin in uins:
            await purge_uin_rows(db, uin)
            await db.execute(delete(User).where(User.uin == uin))
            done += 1
            if done % 100 == 0:
                await db.commit()
        await db.commit()
    return done


async def dead_account_sweep_loop() -> None:
    """Forever loop. Cancelled by the FastAPI lifespan on shutdown."""
    log.info(
        "[dead-account-sweep] starting (older than %dd, batch=%d, interval=%ds)",
        DEAD_AFTER_DAYS, BATCH, SWEEP_INTERVAL_SECONDS,
    )
    while True:
        try:
            if not await lead_this_cycle("dead-account-sweep", SWEEP_INTERVAL_SECONDS):
                await asyncio.sleep(SWEEP_INTERVAL_SECONDS)
                continue
            reaped = await _sweep_once()
            if reaped:
                # warning, not info: prod runs at WARNING, and a number here is
                # the only trace that a flood happened and was undone.
                log.warning(
                    "[dead-account-sweep] reaped %d accounts that were never used "
                    "(older than %dd)", reaped, DEAD_AFTER_DAYS,
                )
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001  (a sweep must not die on a transient error)
            log.exception("[dead-account-sweep] iteration failed; will retry")
        await asyncio.sleep(SWEEP_INTERVAL_SECONDS)
