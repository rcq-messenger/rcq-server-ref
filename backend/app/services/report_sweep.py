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
  keys. The one thing carried over from the text is the `[CRASH]` prefix, which
  is not text but the flag that keeps an auto crash dump out of the tally, see
  REDACTED_REASON_CRASH.

Either way the media the attachments pointed at is reaped in the same pass.
`media_sweep._referenced_ids` protects any blob a report still names, so
clearing the JSON without deleting the file would have left the blob pinned and
unreferenced, ageing out only on the 30-day mtime rule, which for a screenshot
uploaded years into a long-running ticket is not the same thing at all.

Horizon measured from RESOLUTION or from WITHDRAWAL, never from filing. An open
report is the moderation queue and is not swept at any age: an untriaged
complaint that deletes itself is a complaint that was never handled, and the
queue being neglected is not a reason to destroy the evidence. The one open row
that IS swept is one the reporter withdrew (`hidden_at`, see the WHERE in
sweep_once): nobody is waiting on that one, the reporter cannot read it or write
to it any more, and it is the only shape that would otherwise sit here with its
free text forever. Evidence FILES already have
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

from sqlalchemy import and_, func, or_, select

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

# ⚠⚠ The crash variant exists because `reason` is not only text, it is also a
# FLAG. `hof_stats` decides whether a bug-bounty row counts toward a
# contributor's tally by testing `reason` for the [CRASH] marker, and an auto
# crash dump is not a contributor's effort. Redacting a crash row to the plain
# marker-free string therefore did not just clear text: 90 days after the
# founder closed it, every swept crash dump silently JOINED the filer's Hall of
# Fame count, and anyone whose client crashes a lot climbed the wall for it. So
# the marker survives redaction while everything legible goes.
REDACTED_REASON_CRASH = f"[CRASH] {REDACTED_REASON}"

# Both markers are the "already redacted" predicate, see the WHERE below.
_REDACTED_REASONS = (REDACTED_REASON, REDACTED_REASON_CRASH)

# Auto-submitted crash dumps. Mirrors CRASH_MARKER in `routers/admin`,
# `routers/reports` and `_CRASH_MARKER` in `hof_stats`. Keep them in sync.
_CRASH_MARKER = "[CRASH]"

# The context that feeds the Hall of Fame. Mirrors `hof_stats` and
# `reports.create_report`. Keep the three in sync.
_BUG_CONTEXT = "bug_bounty"

# ⚠ `hidden_at` does not SHORTEN anything. A reporter hiding a report from their
# own list (DELETE /reports/mine/{id}) is not an early-deletion request: the row
# is still the operator's record and still the Hall of Fame's tally, and a
# hidden report that the operator later closes is swept on exactly the same
# 90 days from resolution as a visible one. What it does do is START a clock for
# the rows that would otherwise have none, which is every report withdrawn while
# still open (see sweep_once). Nor does this sweep defeat the soft delete, which
# is the other direction of the same question: abuse rows are deleted outright
# but never fed the wall, and bug-bounty rows, the ones that do, are redacted IN
# PLACE and keep their tally forever.


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
    # Oldest first, so a backlog bigger than MAX_PER_CYCLE drains in age order
    # instead of whatever the planner feels like. Two things can start a row's
    # clock (see the WHERE); this prefers the resolution one, which is the clock
    # almost every row is on. A row that was withdrawn and only closed later is
    # selected on the earlier of the two and ordered by the later, which costs
    # nothing: this is a batch order, not the horizon itself.
    started = func.coalesce(Report.resolved_at, Report.hidden_at)
    async with SessionLocal() as db:
        rows = (
            await db.scalars(
                select(Report)
                .where(
                    or_(
                        # Terminal state. `status` leaves "open" exactly when
                        # `resolved_at` is stamped (admin.resolve_report), so a
                        # row matching this has both.
                        and_(
                            Report.status != "open",
                            Report.resolved_at.is_not(None),
                            Report.resolved_at < cutoff,
                        ),
                        # WITHDRAWN, which is the second clock and the reason
                        # this is an OR rather than one clause. A reporter who
                        # drops a still-open report (DELETE /reports/mine/{id})
                        # used to hard-delete the row; it is a soft delete now,
                        # for the Hall of Fame reasons in the model. Without
                        # this branch that made the free text PERMANENT: the
                        # row keeps `status='open'` and a NULL `resolved_at`
                        # forever unless an operator happens to close it, which
                        # is not the normal fate of the long tail of a queue,
                        # and the reporter cannot reach it either (`hidden_at`
                        # hides it from GET /reports/mine and 404s both write
                        # paths), so they cannot even ask for it to be closed.
                        # A report nobody can read and nothing can reap is the
                        # exact shape this module exists to stop.
                        #
                        # Withdrawing is not the same event as resolving, so it
                        # does not shorten the horizon: same 90 days, measured
                        # from the drop. And a still-open row here is always
                        # self-targeted (`delete_my_report` refuses to hide an
                        # open report ABOUT somebody else), i.e. bug bounty, so
                        # it takes the REDACT path below and the wall's tally
                        # survives untouched.
                        and_(
                            Report.hidden_at.is_not(None),
                            Report.hidden_at < cutoff,
                        ),
                    ),
                    # ⚠⚠ AND NOT ALREADY DONE. The abuse path deletes its row so
                    # it can never match twice, but the bug-bounty path REDACTS
                    # IN PLACE and the row keeps satisfying every clause above
                    # forever. Without this the pass re-selects the same rows
                    # every hour: harmless noise at six rows, and a silent
                    # failure of the whole guarantee once there are more than
                    # MAX_PER_CYCLE of them, because `order_by(started asc)
                    # limit N` would then return the same N oldest already-done
                    # rows on every pass and never reach a newly expired one.
                    # The marker in `reason` IS the redacted state, so it is
                    # also the predicate. Both variants, or every redacted
                    # CRASH row (which keeps its [CRASH] prefix, see
                    # REDACTED_REASON_CRASH) matches again on the next pass.
                    Report.reason.notin_(_REDACTED_REASONS),
                )
                .order_by(started.asc())
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
            # Bug bounty: keep the tally, drop everything legible. The [CRASH]
            # prefix is not legible text, it is the flag that keeps this row
            # OUT of the tally, so it is carried over.
            r.reason = (
                REDACTED_REASON_CRASH
                if _CRASH_MARKER in (r.reason or "")
                else REDACTED_REASON
            )
            r.resolution_notes = ""
            r.resolution_action = ""
            r.reply_text = ""
            r.replied_at = None
            r.attachments = None
            r.message_id = None
            # The edit stamp goes with the text it was a trail for. What
            # survives here is meant to be an effort tally and nothing else, and
            # "this person rewrote report #412 at 14:07 on a Tuesday" is a
            # behavioural fact about them that no reader needs once the two
            # drafts it distinguished are both gone.
            r.edited_at = None
            # ⚠ `hidden_at` deliberately STAYS, and it is not the same kind of
            # stamp. It is the flag that keeps this row off `GET /reports/mine`,
            # for a row this pass keeps forever; clearing it would hand the
            # reporter back a report they dropped, now unreadable, which is a
            # worse answer than the timestamp is a leak.
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
