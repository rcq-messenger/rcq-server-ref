"""Retention for `gossip_records`: the one table the burn machinery could
not reach.

WHAT THE TABLE IS. A gossip record is a MIRROR of some identity's signed
home-island record (federation §3.3, address mobility B1). Anyone may write one
without authenticating: a client that has resolved and verified a contact's
record copies it onto its OWN island so that island can serve it to others when
the contact's island is blocked or dead. It is keyed by the global Ed25519
`sk`, not by a uin.

WHY IT NEEDED A DESIGN AND NOT A HORIZON. Because that key is not a number,
`services/uin_rows.purge_uin_rows` structurally cannot see it: a burn deletes
every row belonging to the departing UIN and leaves this one standing, so the
island kept serving "identity X lives at these islands under these numbers" for
identities that had asked to stop existing. It was the last open item in
section 2 of `docs/metadata-map-2026-08-22.md`. But the row is also a
federation mirror other islands resolve against, so the naive fix (age it out)
breaks delivery for exactly the peers it was built to rescue.

THE RULE, IN TWO PARTS.

  A. A BURN ON THIS ISLAND DELETES THE MIRROR, with no horizon at all. The
     burning account's `users.signing_key` IS the `sk` a gossip row is keyed
     by, so the burn path can reach the row even though `purge_uin_rows`
     cannot: see `uin_rows.purge_gossip_mirror`. This is the same rule §3.2
     already applies to `home_island_records` ("a record does not survive its
     UIN changing hands"), extended to the mirror.

     NOT applied on a MIGRATION. Migrating copies `signing_key` verbatim onto
     the new row: the identity continues to exist and the record continues to
     be true apart from a homes list the client republishes on next boot.
     Deleting it there would break a live peer's routing to make a number
     change look tidy.

  B. WHAT PART A CANNOT REACH, meaning mirrors of identities that live on
     OTHER islands (which is most of them), ages out on DEMAND, not on age.

     The clock is `touched_at`: the last time anyone on this island MIRRORED
     (PUT) or RESOLVED (GET) this row. Not `ts`, which is the owner's own
     issued-at and moves only when the owner republishes AND somebody
     re-mirrors the result here. An identity that never changes homes and
     whose island has gone dark has a frozen `ts` and a perfectly good record,
     so a `ts` cutoff would delete precisely the rows the mirror exists to
     hold. And not `updated_at` either: a re-PUT of a byte-identical document
     changes no column, so that clock stops at the FIRST mirror.

     `touched_at` keeps ticking in the one case that matters. When the peer's
     island is dark, nothing re-mirrors the record (a mirror requires reaching
     that island first), but the fallback GET fires, and a GET stamps the row.
     A row that goes cold is one that no contact of that identity, on this
     island, has needed for `MAX_IDLE_DAYS`.

WHAT IT COSTS, stated rather than implied. A record dropped on day
`MAX_IDLE_DAYS + 1` and wanted on day `MAX_IDLE_DAYS + 2`, at a moment when
the peer's own island is also unreachable, answers 404 instead of a homes list.
The sender does not lose the contact and does not lose the message: it falls
back to the single home it already holds, which is the pre-federation
behaviour, and the record repairs itself the first time the peer's island
answers once or the peer self-pushes a `homerec` to their contacts (which
happens on every record change, §3.3). What is bought for that is that a burned
identity's routing map stops being served by this island forever.

WHY 180 DAYS. It is six months of total silence between this island and that
identity: past the 30-day offline queue TTL, past every client-side record
cache, and the same order as the horizons already chosen for `access_tokens`
(90d) and revoked `devices` (180d). Shortening is always the safe direction for
an operator and the env var is there for it.

LEGACY ROWS ARE STAMPED, NOT DELETED. `touched_at` is NULL on every row written
before it existed, and their `updated_at` is a first-write time, not a last
touch. Measuring a horizon against a first-write clock deletes rows early,
which is the exact mistake the prekey sweep made and had to fix in
`2026.08.22.12`. So a NULL is stamped to now on the first pass and gets a full
horizon from the day this ships.

`RCQ_GOSSIP_SWEEP_DRY_RUN=1` counts and logs without deleting or stamping.
"""
from __future__ import annotations

import asyncio
import logging
import os
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, func, select, update

from app.core.db import SessionLocal
from app.models.federation import GossipRecord
from app.services.periodic_leader import lead_this_cycle

log = logging.getLogger(__name__)

# Once a day. The horizon is measured in months; there is nothing to gain from
# looking more often, and this runs on every island including small ones.
SWEEP_INTERVAL_SECONDS: int = 24 * 60 * 60

MAX_IDLE_DAYS: int = int(os.environ.get("RCQ_GOSSIP_MAX_IDLE_DAYS", "180"))

DRY_RUN: bool = os.environ.get("RCQ_GOSSIP_SWEEP_DRY_RUN", "") == "1"


async def sweep_once() -> tuple[int, int]:
    """One pass. Returns `(deleted, stamped)`.

    `stamped` is the legacy branch: rows that have never been observed being
    used get today's date instead of being judged on a clock that does not
    mean what the horizon needs it to mean.
    """
    if MAX_IDLE_DAYS <= 0:
        return (0, 0)

    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=MAX_IDLE_DAYS)

    async with SessionLocal() as db:
        # 1. Legacy rows first, and in their own statement. Doing this before
        #    the delete is what guarantees a row can never be deleted on the
        #    same pass that first stamps it.
        stamped = await db.scalar(
            select(func.count())
            .select_from(GossipRecord)
            .where(GossipRecord.touched_at.is_(None))
        ) or 0
        if stamped and not DRY_RUN:
            await db.execute(
                update(GossipRecord)
                .where(GossipRecord.touched_at.is_(None))
                .values(touched_at=now)
            )
            await db.commit()

        # 2. Cold rows. `touched_at IS NOT NULL` is redundant against a
        #    `< cutoff` comparison in SQL (NULL compares to nothing) but is
        #    stated so the intent survives a future rewrite. Deleted by the
        #    predicate rather than by a collected list of keys: the list would
        #    be an unbounded IN on the one island where this table is large.
        cold = (
            GossipRecord.touched_at.is_not(None),
            GossipRecord.touched_at < cutoff,
        )
        if DRY_RUN:
            deleted = await db.scalar(
                select(func.count()).select_from(GossipRecord).where(*cold)
            ) or 0
        else:
            res = await db.execute(delete(GossipRecord).where(*cold))
            deleted = res.rowcount or 0
            await db.commit()

    if deleted or stamped:
        log.info(
            "[gossip-sweep] %sdeleted=%d stamped=%d (idle horizon %dd)",
            "dry-run: " if DRY_RUN else "",
            deleted,
            stamped,
            MAX_IDLE_DAYS,
        )
    return (deleted, stamped)


async def gossip_sweep_loop() -> None:
    while True:
        try:
            # One worker per cycle (see services/periodic_leader).
            if await lead_this_cycle("gossip-sweep", SWEEP_INTERVAL_SECONDS):
                await sweep_once()
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            log.exception("gossip sweep failed; retrying next cycle")
        await asyncio.sleep(SWEEP_INTERVAL_SECONDS)
