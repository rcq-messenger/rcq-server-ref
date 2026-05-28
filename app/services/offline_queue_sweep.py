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
"""

from __future__ import annotations

import asyncio
import logging
import os
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete

from app.core.db import SessionLocal
from app.models.group import OfflineGroupMessage
from app.models.message import OfflineMessage

log = logging.getLogger(__name__)


# Configurable via env so self-hosters with tight storage can lower it,
# or chatty operators with cheap disk can raise it. Defaults to 30 days.
TTL_DAYS = int(os.environ.get("OFFLINE_QUEUE_TTL_DAYS", "30"))

# Loop interval. Six hours = 4 sweeps/day; cheap for the DB and reactive
# enough that even an aggressive 1-day TTL would only over-retain by a
# few hours.
SWEEP_INTERVAL_SECONDS = int(os.environ.get("OFFLINE_QUEUE_SWEEP_INTERVAL_SECONDS", str(6 * 3600)))


async def _sweep_once() -> tuple[int, int]:
    """One pass. Returns (direct_deleted, group_deleted) for log lines.

    Each table sweep runs in its own short transaction so a long-running
    DELETE on a fat table doesn't hold locks across the other.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(days=TTL_DAYS)

    direct_deleted = 0
    group_deleted = 0

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

    return direct_deleted, group_deleted


async def offline_queue_sweep_loop() -> None:
    """Forever loop. Cancelled by the FastAPI lifespan on shutdown."""
    log.info(
        "[offline-queue-sweep] starting (ttl=%dd, interval=%ds)",
        TTL_DAYS, SWEEP_INTERVAL_SECONDS,
    )
    while True:
        try:
            direct, group = await _sweep_once()
            if direct or group:
                log.info(
                    "[offline-queue-sweep] reaped direct=%d group=%d (ttl=%dd)",
                    direct, group, TTL_DAYS,
                )
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001  (sweep must not die on transient errors)
            log.exception("[offline-queue-sweep] iteration failed; will retry")
        await asyncio.sleep(SWEEP_INTERVAL_SECONDS)
