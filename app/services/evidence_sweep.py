"""Retention for report evidence — the one place on this server that holds
DECRYPTED user media.

`POST /reports/with_evidence` exists because end-to-end encryption otherwise
makes media reports unactionable: the reporter consents, their device decrypts
the offending photo/video and uploads it in the clear so a moderator can
actually look at it. That is a deliberate, narrowly-scoped exception to "we
cannot read your content", and an exception like that needs a shelf life.

It did not have one. Files landed under `evidence/` and stayed there forever,
with no endpoint able to read them back and nothing to delete them — the worst
of both worlds: useless for moderation, and an indefinitely growing pile of
other people's decrypted pictures on a server that advertises having nothing to
hand over. This sweep supplies the missing half of the deal: evidence lives
exactly as long as it takes to moderate the report, then goes.

Rules:
- A report that has been RESOLVED (any terminal status) drops its evidence
  after `EVIDENCE_RESOLVED_GRACE_HOURS` — the moderator is done with it.
- Any evidence older than `EVIDENCE_MAX_AGE_DAYS` goes regardless of status,
  so an untriaged queue cannot become a permanent archive by neglect.
- The DB columns are cleared in the same pass, so the admin UI stops offering
  a link to a file that is gone.

Both bounds are env-tunable; an operator running their own island can shorten
them, and shortening is always the safe direction.
"""
from __future__ import annotations

import asyncio
import logging
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy import or_, select

from app.core.db import SessionLocal
from app.models.report import Report
from app.services.periodic_leader import lead_this_cycle

log = logging.getLogger(__name__)

SWEEP_INTERVAL_SECONDS: int = 60 * 60

# Mirrors `routers/reports._EVIDENCE_DIR`. Read from env as a string rather
# than imported, so this module stays import-decoupled from the router (same
# reasoning as story_sweep vs the media router).
EVIDENCE_DIR = Path(os.environ.get("RCQ_EVIDENCE_DIR", "evidence")).resolve()

EVIDENCE_MAX_AGE_DAYS: int = int(os.environ.get("RCQ_EVIDENCE_MAX_AGE_DAYS", "30"))
EVIDENCE_RESOLVED_GRACE_HOURS: int = int(
    os.environ.get("RCQ_EVIDENCE_RESOLVED_GRACE_HOURS", "48")
)


async def sweep_once() -> int:
    """One pass. Returns how many evidence files were deleted."""
    deleted = 0
    now = datetime.now(timezone.utc)
    hard_cutoff = now - timedelta(days=EVIDENCE_MAX_AGE_DAYS)
    resolved_cutoff = now - timedelta(hours=EVIDENCE_RESOLVED_GRACE_HOURS)

    async with SessionLocal() as db:
        rows = (
            await db.scalars(
                select(Report).where(
                    Report.evidence_path.isnot(None),
                    or_(
                        Report.created_at < hard_cutoff,
                        (Report.status != "open") & (Report.resolved_at < resolved_cutoff),
                    ),
                )
            )
        ).all()
        for r in rows:
            # Never let a stored path escape the evidence directory, even
            # though the write path only ever generates a bare UUID name.
            try:
                target = (EVIDENCE_DIR / Path(r.evidence_path).name).resolve()
                if target.is_relative_to(EVIDENCE_DIR) and target.exists():
                    target.unlink()
            except Exception:  # noqa: BLE001 - a stuck file must not stall the sweep
                log.warning("evidence sweep: could not unlink for report %s", r.id)
            r.evidence_path = None
            r.evidence_mime = None
            deleted += 1
        if rows:
            await db.commit()
    if deleted:
        log.info("evidence sweep: expired %d file(s)", deleted)
    return deleted


async def evidence_sweep_loop() -> None:
    while True:
        try:
            # One worker per cycle (see services/periodic_leader).
            if await lead_this_cycle("evidence-sweep", SWEEP_INTERVAL_SECONDS):
                await sweep_once()
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            log.exception("evidence sweep failed; retrying next cycle")
        await asyncio.sleep(SWEEP_INTERVAL_SECONDS)
