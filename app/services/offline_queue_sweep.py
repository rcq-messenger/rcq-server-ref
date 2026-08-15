"""Periodically delete offline envelopes older than the configured TTL.

Background task scheduled by `app.main.lifespan`. Exists because the
ACK-mode path in `/messages/queue` (introduced alongside the bug-#2796
fix) leaves the server holding rows until the client confirms ingest —
and some clients never come back (old build with no ACK support, app
uninstalled, account dormant). Without this sweep the
`offline_messages` and `offline_group_messages` tables would grow
forever.

The TTL is intentionally long (30 days). Messages are still encrypted
in transit on the server (sealed-sender ciphertext + recipient UIN),
so retention is a storage concern, not a privacy one. 30 days matches
the lifetime users expect for "I went on holiday and want my messages
when I come back." Aggressive sweeping would be a regression for the
delivered-reliability guarantee that's the whole point of the queue.

DORMANT RECIPIENTS (added 2026-07-31). The TTL alone was not enough for the
GROUP queue, because group fan-out writes one row PER MEMBER: the "RCQ Beta"
group has 1666 members, so a single message there is 1666 rows. On prod that
table had grown to 533k rows / 3.7 GB — 96% of it addressed to people who had
not connected in over two weeks and were never going to drain it. Those rows
are pure storage cost: nobody wants three thousand backlogged group messages
on their return anyway. So group rows are also dropped once their recipient
has been away longer than DORMANT_DAYS. `users.last_seen` is refreshed on WS
connect, heartbeat and disconnect, so "away" here means the app has not
reached the island at all in that window. The 1:1 queue is deliberately NOT
subject to this — a direct message is worth holding the full TTL.
"""

from __future__ import annotations

import asyncio
import logging
import os
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, text

from app.core.db import SessionLocal
from app.models.group import OfflineGroupMessage
from app.models.message import OfflineMessage
from app.services.periodic_leader import lead_this_cycle

log = logging.getLogger(__name__)


# Configurable via env so self-hosters with tight storage can lower it,
# or chatty operators with cheap disk can raise it. Defaults to 30 days.
TTL_DAYS = int(os.environ.get("OFFLINE_QUEUE_TTL_DAYS", "30"))

# How long a recipient may be absent before we stop holding GROUP backlog for
# them (see the module docstring). 0 disables the rule entirely.
DORMANT_DAYS = int(os.environ.get("OFFLINE_GROUP_DORMANT_DAYS", "14"))

# Sender-key RECOVERY requests (`sknack`) get their own, very short TTL.
#
# A client that receives a group message under a key id it does not hold asks
# the group for that key. It cannot tell whose key id it is, so it asks EVERY
# sender-keys-capable member: on the flagship group that is ~537 queued rows to
# find one person. Measured on prod 2026-08-02, sknack was 73k of the 115k rows
# in this table, four times the volume of the actual group messages, and the
# driver is new members: 38 people joined the flagship group on 1 August and
# that day saw 137 recovery broadcasts, because each newcomer must ask once per
# distinct sender they encounter.
#
# The requests themselves are worthless once stale. The asking client re-fires
# per key id every ten minutes and again after a restart, so an hour-old copy
# will never be the one that recovers anybody — it only makes a returning
# member decrypt hundreds of envelopes addressed to a question that has already
# been asked and answered. Delivery is unaffected: anyone online gets it live,
# anyone draining within the hour still finds it.
#
# ⚠ The sweep itself only runs every SWEEP_INTERVAL_SECONDS, so in practice a
# request survives up to that long rather than exactly this TTL. That is fine
# for the purpose (retention drops from a fortnight to hours); tightening it
# further would mean a separate, faster loop for one envelope type.
#
# This does NOT fix the broadcast itself; that needs a protocol change so a
# newcomer is handed the current keys on join instead of discovering their
# absence by failing to read a message.
SKNACK_TTL_SECONDS = int(os.environ.get("OFFLINE_SKNACK_TTL_SECONDS", str(3600)))

# Rows per DELETE statement, and a ceiling per sweep. Batching keeps each
# transaction short — a single unbounded DELETE of half a million rows would
# hold locks (and one of the few pooled connections) for the whole run.
_DORMANT_BATCH = 20_000
_DORMANT_MAX_PER_SWEEP = 400_000

# Loop interval. Six hours = 4 sweeps/day; cheap for the DB and reactive
# enough that even an aggressive 1-day TTL would only over-retain by a
# few hours.
SWEEP_INTERVAL_SECONDS = int(os.environ.get("OFFLINE_QUEUE_SWEEP_INTERVAL_SECONDS", str(6 * 3600)))


# One batch of group rows addressed to someone who has not connected since
# `cutoff` (or whose account is gone). Written as SQL because the ORM's
# `delete().where(...)` cannot express a LIMIT, and the LIMIT is the point.
#
# ⚠ `skdm` is EXEMPT, and the exemption is the whole point of the write-side
# rule it mirrors (`app.routers.messages._keep_for`). A sender-key
# distribution is not backlog: it is the chain key, and a member who loses it
# cannot read a single later broadcast — no bubble, no unread, no sound, and
# no way for their client to tell "no messages" from "cannot decrypt" (#544).
# Keeping it at write time and reaping it six hours later would make that fix
# last exactly one sweep interval. A few hundred bytes per (sender, chain) is
# not what filled this table; content addressed to people who never return is,
# and that is still swept. The 30-day TTL above still bounds these rows.
#
# `sknack` is deliberately NOT exempt — it is a QUESTION, worthless once
# stale, and it has its own much shorter TTL below.
_DORMANT_SQL = text(
    """
    DELETE FROM offline_group_messages
    WHERE id IN (
        SELECT o.id FROM offline_group_messages o
        LEFT JOIN users u ON u.uin = o.to_uin
        WHERE (u.uin IS NULL OR u.last_seen < :cutoff)
          AND o.envelope_type <> 'skdm'
        LIMIT :batch
    )
    """
)


def dormant_cutoff() -> datetime | None:
    """The instant before which a recipient counts as absent for GROUP
    backlog, or None when the rule is switched off.

    Shared with the group fan-out in `app.routers.messages` so the WRITE side
    uses the same definition this sweep deletes by. Queueing a row we are
    going to reap within the hour is pure cost — the insert, the WAL, the
    index churn and the table bloat — for a copy nobody will ever drain.
    """
    if DORMANT_DAYS <= 0:
        return None
    return datetime.now(timezone.utc) - timedelta(days=DORMANT_DAYS)


async def _sweep_dormant(cutoff: datetime) -> int:
    """Drop group backlog for recipients absent since `cutoff`, in bounded
    batches. Stops at the first empty batch or the per-sweep ceiling, so a
    table that somehow grew to millions of rows gets whittled down over
    several cycles instead of in one lock-heavy pass."""
    deleted = 0
    while deleted < _DORMANT_MAX_PER_SWEEP:
        async with SessionLocal() as db:
            async with db.begin():
                result = await db.execute(
                    _DORMANT_SQL, {"cutoff": cutoff, "batch": _DORMANT_BATCH}
                )
        n = result.rowcount or 0
        deleted += n
        if n < _DORMANT_BATCH:
            break
    return deleted


async def _sweep_once() -> tuple[int, int, int, int]:
    """One pass. Returns (direct, group, dormant, sknack) deleted counts for
    the log line.

    Each table sweep runs in its own short transaction so a long-running
    DELETE on a fat table doesn't hold locks across the other.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(days=TTL_DAYS)

    direct_deleted = 0
    group_deleted = 0
    sknack_deleted = 0

    async with SessionLocal() as db:
        async with db.begin():
            result = await db.execute(
                delete(OfflineMessage).where(OfflineMessage.received_at < cutoff)
            )
            direct_deleted = result.rowcount or 0

        async with db.begin():
            result = await db.execute(
                delete(OfflineGroupMessage).where(OfflineGroupMessage.received_at < cutoff)
            )
            group_deleted = result.rowcount or 0

        if SKNACK_TTL_SECONDS > 0:
            async with db.begin():
                result = await db.execute(
                    delete(OfflineGroupMessage).where(
                        OfflineGroupMessage.envelope_type == "sknack",
                        OfflineGroupMessage.received_at
                        < datetime.now(timezone.utc) - timedelta(seconds=SKNACK_TTL_SECONDS),
                    )
                )
                sknack_deleted = result.rowcount or 0

    dormant_deleted = 0
    if DORMANT_DAYS > 0:
        dormant_deleted = await _sweep_dormant(
            datetime.now(timezone.utc) - timedelta(days=DORMANT_DAYS)
        )

    return direct_deleted, group_deleted, dormant_deleted, sknack_deleted


async def offline_queue_sweep_loop() -> None:
    """Forever loop. Cancelled by the FastAPI lifespan on shutdown."""
    log.info(
        "[offline-queue-sweep] starting (ttl=%dd, dormant=%dd, sknack=%ds, interval=%ds)",
        TTL_DAYS, DORMANT_DAYS, SKNACK_TTL_SECONDS, SWEEP_INTERVAL_SECONDS,
    )
    while True:
        try:
            # One worker per cycle — see periodic_leader's docstring. Without
            # this all four uvicorn workers ran the batched DELETEs at once.
            if not await lead_this_cycle("offline-queue-sweep", SWEEP_INTERVAL_SECONDS):
                await asyncio.sleep(SWEEP_INTERVAL_SECONDS)
                continue
            direct, group, dormant, sknack = await _sweep_once()
            if direct or group or dormant or sknack:
                # warning, not info: prod runs at WARNING and this number is
                # exactly what you want in the journal when the table grows.
                log.warning(
                    "[offline-queue-sweep] reaped direct=%d group=%d dormant=%d sknack=%d "
                    "(ttl=%dd, dormant=%dd, sknack=%ds)",
                    direct, group, dormant, sknack, TTL_DAYS, DORMANT_DAYS, SKNACK_TTL_SECONDS,
                )
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001  (sweep must not die on transient errors)
            log.exception("[offline-queue-sweep] iteration failed; will retry")
        await asyncio.sleep(SWEEP_INTERVAL_SECONDS)
