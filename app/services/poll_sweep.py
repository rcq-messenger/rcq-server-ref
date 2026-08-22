"""Retention for polls and their ballots.

Neither table was ever swept. Only a group deletion reached them, via the FK
on `polls.group_id`. So a poll closed in May still holds its complete ballot
list, and for an ANONYMOUS poll that list is the thing the feature promises not
to keep: `models/poll.py` admits it in its own docstring ("the server still
stores `voter_uin` to enforce one-vote-per-user"), and every row carries a
`created_at`, so the island holds who voted for which option and in what order.
The API strips voter uins from anonymous responses; the database never did.

Flagship on 2026-08-22: 20 polls, 82 votes. Small, and that is fine: the shape
is the point, not the bytes. "Produce the ballots for the poll in that room" is
a question this island should not be able to answer three months later.

THE HORIZON, and what the client shows afterwards
--------------------------------------------------
Ninety days, measured from `closed_at` for a poll that was closed and from
`created_at` for one that was not. A poll left open for three months is
abandoned, not live; treating it as immortal because nobody tapped Close would
mean the ballots of every poll ever created outlive everything else on the
island.

Read the degradation before accepting it. The QUESTION and the OPTION LABELS
never touch this server (they ride the encrypted `.poll` chat envelope), so
the bubble keeps rendering in full. What the client loses is only what came
from here: `PollBubble.refreshOnAppear` calls `PollService.refresh`, that
returns nil on the 404, `state` stays nil, and the bubble draws the question,
every option and a zero next to each, no filled progress bars, no "you voted"
marks, no voter names, and no total in the footer. A tap shows the existing
`poll.error.vote` string. So an old bubble reads as a poll whose results are no
longer being counted, which is exactly what it is. No blank bubble, no spinner
that never resolves, nothing that looks like the app broke.

⚠ Votes go with the poll on `poll_votes.poll_id` ON DELETE CASCADE, so this
loop deletes parents only. `uin_rows.PER_UIN_COLUMNS` still lists both, because
a burn must reach a live poll's ballots and cannot wait ninety days.

Hourly, leader-elected, bounded per cycle.
`RCQ_POLL_SWEEP_DRY_RUN=1` counts and logs without deleting.
"""
from __future__ import annotations

import asyncio
import logging
import os
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, func, or_, select

from app.core.db import SessionLocal
from app.models.poll import Poll, PollVote
from app.services.periodic_leader import lead_this_cycle

log = logging.getLogger(__name__)

SWEEP_INTERVAL_SECONDS: int = 60 * 60

POLL_MAX_AGE_DAYS: int = int(os.environ.get("RCQ_POLL_MAX_AGE_DAYS", "90"))
MAX_DELETIONS_PER_CYCLE: int = int(os.environ.get("RCQ_POLL_SWEEP_MAX_PER_CYCLE", "500"))
DRY_RUN: bool = os.environ.get("RCQ_POLL_SWEEP_DRY_RUN", "") == "1"


def _expired(cutoff: datetime):
    return (
        or_(
            Poll.closed_at < cutoff,
            Poll.closed_at.is_(None) & (Poll.created_at < cutoff),
        ),
    )


async def sweep_once() -> int:
    """One pass. Returns how many polls went (or would have, dry). Ballots ride
    the FK cascade."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=POLL_MAX_AGE_DAYS)
    async with SessionLocal() as db:
        if DRY_RUN:
            n = int(
                (
                    await db.execute(
                        select(func.count()).select_from(Poll).where(*_expired(cutoff))
                    )
                ).scalar_one()
            )
            if n:
                log.warning("[poll-sweep] dry-run: %d poll(s) past %dd", n, POLL_MAX_AGE_DAYS)
            return n
        ids = (
            await db.scalars(
                select(Poll.id).where(*_expired(cutoff)).limit(MAX_DELETIONS_PER_CYCLE)
            )
        ).all()
        if not ids:
            return 0
        # ⚠ SQLite does not enforce the FK cascade unless `PRAGMA foreign_keys`
        # is on, and a self-host island is SQLite by default. Delete the
        # ballots explicitly so an orphaned vote list cannot be the one thing
        # this sweep leaves behind.
        await db.execute(delete(PollVote).where(PollVote.poll_id.in_(ids)))
        res = await db.execute(delete(Poll).where(Poll.id.in_(ids)))
        await db.commit()
        n = res.rowcount or 0
    if n:
        log.warning("[poll-sweep] reaped %d poll(s) and their ballots (older than %dd)",
                    n, POLL_MAX_AGE_DAYS)
    return n


async def poll_sweep_loop() -> None:
    while True:
        try:
            # One worker per cycle (see services/periodic_leader).
            if await lead_this_cycle("poll-sweep", SWEEP_INTERVAL_SECONDS):
                await sweep_once()
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            log.exception("[poll-sweep] pass failed; retrying next cycle")
        await asyncio.sleep(SWEEP_INTERVAL_SECONDS)
