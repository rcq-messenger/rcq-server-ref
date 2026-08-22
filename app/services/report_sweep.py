"""Retention for closed reports.

`reports` had no sweep at all, so every row filed since April was still here,
and each closed one carried more than the complaint: `resolution_notes` is the
operator's internal free text about a named person ("why we banned X"),
`attachments` stores the AES key beside the media id so the island can decrypt
every bug-report screenshot it holds, and `reply_text` plus `report_messages`
are a full plaintext support conversation with per-turn timestamps.

⚠⚠ THE BREAKER NOBODY LISTED: the Hall of Fame reads this table live.
`services/hof_stats.bug_report_stats` counts, per account and over ALL TIME,
every `context == "bug_bounty"` report and how many reached `status ==
"resolved"`. Those two numbers drive the effort ring on the public wall
(`/public/hof`), the podium ranking, and the founder's curation list. Measured
on the flagship on 2026-08-22: 373 report rows, of which **372 are bug_bounty**.
So "delete resolved reports after N days" is, on this island, "silently deflate
every contributor's ring three months after their bug is fixed". The map's note
that "the HoF count (row itself) is unaffected" was written about the
ATTACHMENTS verdict and does not survive being applied to the row.

Hence two different terminal states, by what the row is:

* **Abuse reports** (`context != "bug_bounty"`) are a directed conflict graph:
  A complained about B, dated, with free text that usually quotes what B said.
  Nothing outside moderation reads them. Those rows are DELETED, and the
  `report_messages` turns go with them on the FK cascade.

* **Bug-bounty reports** are REDACTED IN PLACE. What survives is the skeleton
  the wall needs and nothing else: `(reporter_uin, target_uin, context, status,
  created_at, resolved_at)`. On a bug report `target_uin` is the reporter
  themselves, since `reports.create_report` permits self-target for exactly
  this context and rejects it for every other, so the skeleton is an effort tally,
  not a graph about anyone. Everything legible goes: the reporter's free text,
  the operator's notes, the reply, the conversation turns, and the attachment
  keys.

Either way the media the attachments pointed at is reaped in the same pass.
`media_sweep._referenced_ids` protects any blob a report still names, so
clearing the JSON without deleting the file would have left the blob pinned and
unreferenced, ageing out only on the 30-day mtime rule, which for a screenshot
uploaded years into a long-running ticket is not the same thing at all.

Horizon measured from RESOLUTION, never from filing. An open report is the
moderation queue and is not swept at any age: an untriaged complaint that
deletes itself is a complaint that was never handled, and the queue being
neglected is not a reason to destroy the evidence. Evidence FILES already have
their own absolute backstop in `services/evidence_sweep` (30 days regardless of
status), which is the part that genuinely must not wait for a human.

Keeping `GET /reports/mine` coherent
------------------------------------
That endpoint serves the reporter their own last 50 rows with the thread. After
a pass, an old closed ticket is simply absent (abuse) or present with an empty
reason and an empty thread (bug bounty). The second one would read as a bug, so
redaction rewrites `reason` to a short marker rather than blanking it, and the
client renders it like any other row. Nothing half-deleted, nothing that looks
like the server lost text.

Hourly, leader-elected, bounded per cycle.
`RCQ_REPORT_SWEEP_DRY_RUN=1` reports what it would do and changes nothing.
"""
from __future__ import annotations

import asyncio
import logging
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy import select

from app.core.db import SessionLocal
from app.models.report import Report
from app.models.report_message import ReportMessage
from app.services.periodic_leader import lead_this_cycle

log = logging.getLogger(__name__)

SWEEP_INTERVAL_SECONDS: int = 60 * 60

# A quarter. Long enough that "what did we do about that last month" is still
# answerable from the closed tab, and that a reporter who checks back after a
# holiday still finds their ticket; short enough that the island is not holding
# a permanent dossier of operator opinions about named people. On the flagship
# today this touches 6 rows, because the project is four months old. The point
# is what it stops accumulating, not what it clears now.
RESOLVED_MAX_AGE_DAYS: int = int(os.environ.get("RCQ_REPORT_MAX_AGE_DAYS", "90"))
MAX_PER_CYCLE: int = int(os.environ.get("RCQ_REPORT_SWEEP_MAX_PER_CYCLE", "500"))
DRY_RUN: bool = os.environ.get("RCQ_REPORT_SWEEP_DRY_RUN", "") == "1"

# Mirrors `routers/media.MEDIA_ROOT` and `media_sweep.MEDIA_ROOT`, env-read
# rather than imported, so this module stays import-decoupled from the router
# (importing it at startup is a cycle).
MEDIA_ROOT = Path(os.environ.get("RCQ_MEDIA_DIR", "./media/uploads"))

# What a redacted bug-bounty row says where the reporter's text used to be. Not
# an empty string: an empty row in MyReports reads as data loss, and every
# client already renders `reason` as plain text with no special cases.
REDACTED_REASON = "(this closed report was cleared by the island's retention policy)"

# The context that feeds the Hall of Fame. Mirrors `hof_stats` and
# `reports.create_report`. Keep the three in sync.
_BUG_CONTEXT = "bug_bounty"


def _unlink_attachment_blobs(attachments: list | None) -> int:
    """Delete the encrypted blobs a report's attachments point at.

    Resolve by NAME under the media dir, the way `routers/reports.delete_my_report`
    does: a media id is a bare hex string on the write path and must never be
    able to walk out of the directory even if a row somehow holds a path.
    """
    gone = 0
    for a in attachments or []:
        mid = (a or {}).get("media_id") if isinstance(a, dict) else None
        if not mid:
            continue
        try:
            target = (MEDIA_ROOT / f"{Path(str(mid)).name.lower()}.bin").resolve()
            if target.parent != MEDIA_ROOT.resolve():
                continue
            if target.exists():
                target.unlink()
                gone += 1
        except OSError:
            # A stuck file must not stall the pass; the row is still redacted
            # and media_sweep's age rule will reach the blob eventually.
            log.warning("[report-sweep] could not unlink media for a report attachment")
    return gone


async def sweep_once() -> tuple[int, int, int]:
    """One pass. Returns (deleted, redacted, blobs_unlinked)."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=RESOLVED_MAX_AGE_DAYS)
    deleted = redacted = blobs = 0
    async with SessionLocal() as db:
        rows = (
            await db.scalars(
                select(Report)
                .where(
                    # Terminal state only. `status` leaves "open" exactly when
                    # `resolved_at` is stamped (admin.resolve_report), so a row
                    # matching this has both.
                    Report.status != "open",
                    Report.resolved_at.is_not(None),
                    Report.resolved_at < cutoff,
                    # ⚠⚠ AND NOT ALREADY DONE. The abuse path deletes its row so
                    # it can never match twice, but the bug-bounty path REDACTS
                    # IN PLACE and the row keeps satisfying every clause above
                    # forever. Without this the pass re-selects the same rows
                    # every hour: harmless noise at six rows, and a silent
                    # failure of the whole guarantee once there are more than
                    # MAX_PER_CYCLE of them, because `order_by(resolved_at asc)
                    # limit N` would then return the same N oldest already-done
                    # rows on every pass and never reach a newly expired one.
                    # The marker in `reason` IS the redacted state, so it is
                    # also the predicate.
                    Report.reason != REDACTED_REASON,
                )
                .order_by(Report.resolved_at.asc())
                .limit(MAX_PER_CYCLE)
            )
        ).all()
        for r in rows:
            is_bug = (r.context or "") == _BUG_CONTEXT
            if DRY_RUN:
                if is_bug:
                    redacted += 1
                else:
                    deleted += 1
                continue
            blobs += _unlink_attachment_blobs(r.attachments)
            # ⚠ The conversation is deleted EXPLICITLY on both paths.
            # `report_messages.report_id` declares ON DELETE CASCADE, but
            # SQLite only enforces a foreign key when `PRAGMA foreign_keys` is
            # on and this codebase never turns it on. So on a self-host island
            # (SQLite is the default DATABASE_URL) trusting the cascade would
            # leave the full plaintext support thread behind, orphaned to a
            # report id that no longer exists and now reachable by nothing that
            # could ever clean it up. Caught by test_retention_sweeps_local.
            turns = (
                await db.scalars(
                    select(ReportMessage).where(ReportMessage.report_id == r.id)
                )
            ).all()
            for turn in turns:
                await db.delete(turn)
            if not is_bug:
                await db.delete(r)
                deleted += 1
                continue
            # Bug bounty: keep the tally, drop everything legible.
            r.reason = REDACTED_REASON
            r.resolution_notes = ""
            r.resolution_action = ""
            r.reply_text = ""
            r.replied_at = None
            r.attachments = None
            r.message_id = None
            # `evidence_path` / `evidence_mime` are already cleared by
            # services/evidence_sweep long before this horizon; clear them
            # again rather than assume the ordering of two independent loops.
            r.evidence_path = None
            r.evidence_mime = None
            redacted += 1
        if rows and not DRY_RUN:
            await db.commit()
    if deleted or redacted:
        log.warning(
            "[report-sweep] %s%d abuse report(s) deleted, %d bug report(s) redacted, "
            "%d attachment blob(s) unlinked (closed >%dd)",
            "dry-run: " if DRY_RUN else "", deleted, redacted, blobs, RESOLVED_MAX_AGE_DAYS,
        )
    return deleted, redacted, blobs


async def report_sweep_loop() -> None:
    while True:
        try:
            # One worker per cycle (see services/periodic_leader).
            if await lead_this_cycle("report-sweep", SWEEP_INTERVAL_SECONDS):
                await sweep_once()
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            log.exception("[report-sweep] pass failed; retrying next cycle")
        await asyncio.sleep(SWEEP_INTERVAL_SECONDS)
