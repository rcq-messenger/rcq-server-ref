"""Periodic deletion of expired stories (24h TTL).

Runs every 5 minutes. For each `Story` row where `expires_at < now`:
- Delete the underlying media blob from `media/uploads/{media_id}.bin`.
- Delete the row (cascades to `story_views`).

The sweep is idempotent and rate-bounded — even on a heavy day it
processes maybe a few hundred rows per cycle. Wired into `main.py`'s
lifespan, sibling to `uin_auction_loop`.
"""
from __future__ import annotations

import asyncio
import os
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import select

from app.core.db import SessionLocal
from app.models.story import Story

SWEEP_INTERVAL_SECONDS: int = 5 * 60

# Mirrors `routers/media.MEDIA_ROOT`. Kept duplicated as a string env
# read so this module isn't import-coupled to the media router (which
# would create a circular-import risk during app startup).
MEDIA_ROOT = Path(os.environ.get("RCQ_MEDIA_DIR", "./media/uploads"))


async def sweep_once() -> int:
    """One pass. Returns the number of stories deleted."""
    deleted = 0
    async with SessionLocal() as db:
        now = datetime.now(timezone.utc)
        rows = (
            await db.scalars(
                select(Story).where(Story.expires_at < now)
            )
        ).all()
        for s in rows:
            blob = MEDIA_ROOT / f"{s.media_id}.bin"
            try:
                if blob.exists():
                    blob.unlink()
            except OSError:
                # If the file is locked / unreadable, the next sweep
                # will retry. Don't let one bad blob block deletion
                # of the rest.
                pass
            await db.delete(s)
            deleted += 1
        if deleted:
            await db.commit()
    return deleted


async def story_sweep_loop() -> None:
    """Forever-running task. Wired into `main.py` lifespan startup."""
    while True:
        try:
            await sweep_once()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            print(f"[story_sweep] {type(exc).__name__}: {exc}")
        await asyncio.sleep(SWEEP_INTERVAL_SECONDS)
