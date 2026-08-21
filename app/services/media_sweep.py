"""Retention for the encrypted media store (`media/uploads/*.bin`).

Until 2026-08-21 nothing ever deleted a chat/group blob: the id lives inside
the sealed envelope, the server can't correlate a blob to a message, so files
simply accumulated forever ("не хотелось бы чтобы это хранилось долго" — the
founder, deciding retention). The queue itself keeps an undelivered message
for 30 days (`offline_queue_sweep.TTL_DAYS`), so a blob must live AT LEAST
that long to serve the slowest recipient; age-by-mtime with the same 30-day
default lines the two up exactly.

What a pass never touches, regardless of age (the ids the DB still points
at):
- user avatars (`users.avatar_media_id`) and group avatars
  (`groups.avatar_media_id`) — long-lived by design, same directory;
- story blobs (`stories.media_id`) — `story_sweep` owns their 24h lifecycle
  (and a story deleted by hand leaves an unreferenced blob, which THIS sweep
  finally reaps by age — closing the leak `stories.py` used to claim a
  nonexistent orphan sweep handled);
- report evidence (`reports.attachments[*].media_id`) — few, and an open
  investigation must not lose its screenshots.

Hourly, leader-elected, deletion-capped per cycle, and one log line per pass
that did anything — silent truncation would read as "covered everything".
`RCQ_MEDIA_SWEEP_DRY_RUN=1` counts and logs without unlinking.
"""
from __future__ import annotations

import asyncio
import os
import time
from pathlib import Path

from sqlalchemy import select

from app.core.db import SessionLocal
from app.models.group import Group
from app.models.report import Report
from app.models.story import Story
from app.models.user import User
from app.services.periodic_leader import lead_this_cycle

SWEEP_INTERVAL_SECONDS: int = 60 * 60

# Mirrors `routers/media.MEDIA_ROOT` — env-read, not imported, so this module
# stays import-decoupled from the router (same reasoning as story_sweep).
MEDIA_ROOT = Path(os.environ.get("RCQ_MEDIA_DIR", "./media/uploads"))

MEDIA_MAX_AGE_DAYS: int = int(os.environ.get("RCQ_MEDIA_MAX_AGE_DAYS", "30"))
# Bounds one pass. 2000/hour clears any realistic backlog in a day while a
# runaway (or a clock jump) can't turn a single cycle into a purge.
MAX_DELETIONS_PER_CYCLE: int = int(os.environ.get("RCQ_MEDIA_SWEEP_MAX_PER_CYCLE", "2000"))
DRY_RUN: bool = os.environ.get("RCQ_MEDIA_SWEEP_DRY_RUN", "") == "1"


async def _referenced_ids() -> set[str]:
    """Every media id a DB row still points at. Lowercased — the store
    writes lowercase file names and the deposit path lowercases ids."""
    ids: set[str] = set()
    async with SessionLocal() as db:
        for col in (User.avatar_media_id, Group.avatar_media_id):
            for v in (await db.scalars(select(col).where(col.is_not(None)))).all():
                if v:
                    ids.add(v.lower())
        for v in (await db.scalars(select(Story.media_id))).all():
            if v:
                ids.add(v.lower())
        for atts in (await db.scalars(select(Report.attachments).where(Report.attachments.is_not(None)))).all():
            for a in atts or []:
                mid = (a or {}).get("media_id")
                if mid:
                    ids.add(str(mid).lower())
    return ids


async def sweep_once() -> None:
    cutoff = time.time() - MEDIA_MAX_AGE_DAYS * 24 * 3600
    # Half-written uploads a dead client left behind (`*.part`, see the
    # media router): nothing will ever finish them — a day is generous.
    try:
        for part in MEDIA_ROOT.glob("*.part"):
            try:
                if part.stat().st_mtime < time.time() - 24 * 3600 and not DRY_RUN:
                    part.unlink()
            except OSError:
                continue
        entries = list(MEDIA_ROOT.glob("*.bin"))
    except OSError:
        return
    # Age first, references second: the directory scan is cheap, the four
    # DB reads are not worth doing when nothing is old enough.
    old: list[Path] = []
    for p in entries:
        try:
            if p.stat().st_mtime < cutoff:
                old.append(p)
        except OSError:
            continue
    if not old:
        return
    referenced = await _referenced_ids()
    deleted = protected = failed = 0
    capped = False
    for p in old:
        if p.stem.lower() in referenced:
            protected += 1
            continue
        if deleted >= MAX_DELETIONS_PER_CYCLE:
            capped = True
            break
        if DRY_RUN:
            deleted += 1
            continue
        try:
            p.unlink()
            deleted += 1
        except OSError:
            failed += 1
    print(
        f"[media_sweep] scanned={len(entries)} old={len(old)} protected={protected} "
        f"deleted={deleted}{' (dry-run)' if DRY_RUN else ''}"
        f"{f' failed={failed}' if failed else ''}{' CAPPED — more next cycle' if capped else ''}"
    )


async def media_sweep_loop() -> None:
    """Forever-running task. Wired into `main.py` lifespan startup."""
    while True:
        try:
            if await lead_this_cycle("media-sweep", SWEEP_INTERVAL_SECONDS):
                await sweep_once()
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 — a bad pass must not kill the loop
            print(f"[media_sweep] {type(exc).__name__}: {exc}")
        await asyncio.sleep(SWEEP_INTERVAL_SECONDS)
