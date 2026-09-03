"""Put reserved numbers that nobody is using back on the shelf.

Two kinds of stock end up out of circulation without anybody deciding it
should be:

  * PARKED — rows in ``owned_uins``. A number in a collection has no account
    behind it; it is simply held.

    ⚠⚠ This used to read "collections are closed as of 2026-09-01, so every
    remaining row is a leftover", and the code below acted on it with an
    unconditional DELETE of the whole table. Collections REOPENED on
    2026-09-03 and numbers are sold now, so the table holds paid deeds too.
    Rows with ``source='purchase'`` are property and are never reclaimed.
  * ABANDONED — a short or patterned number on an account that registered,
    did nothing at all, and never came back. "Nothing at all" is meant
    literally here: no contacts, no group memberships, no push tokens.

Parked numbers are simply released. Abandoned ones MOVE: the account is
migrated onto a fresh ordinary number by the same code path a user's own
migration uses, so the profile, the keys and anything it does own survive, and
the person can still find their way back with their recovery phrase (which
resolves by signing key, not by number). Deleting the account would free the
same number and burn the account with it, for no extra gain.

    python -m app.tools.reclaim_reserved --days 60            # dry run
    python -m app.tools.reclaim_reserved --days 60 --apply
    python -m app.tools.reclaim_reserved --days 60 --apply --parked-only

⚠ Run it from the backend root in the server's own venv (it needs
DATABASE_URL), and expect it to be slow on purpose: each migration is its own
transaction and the loop sleeps between them, because this shares a connection
pool with the live island.
"""

import argparse
import asyncio
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, func, select

from app.core.db import SessionLocal
from app.models.contact import Contact
from app.models.device_token import DeviceToken
from app.models.group import GroupMember
from app.models.owned_uin import OwnedUin
from app.models.user import User
from app.services.uin import allocate_uin, is_reserved_uin


async def _release_parked(db, apply: bool) -> int:
    rows = (await db.execute(select(OwnedUin.uin, OwnedUin.owner_uin))).all()
    if not rows:
        print("parked: none")
        return 0
    by_owner: dict[int, list[int]] = {}
    for uin, owner in rows:
        by_owner.setdefault(int(owner), []).append(int(uin))
    print(f"parked: {len(rows)} numbers held by {len(by_owner)} accounts")
    for owner, held in sorted(by_owner.items(), key=lambda kv: -len(kv[1]))[:10]:
        short = [u for u in held if is_reserved_uin(u)]
        print(f"  #{owner}: {len(held)} held, {len(short)} of them reserved")
    if apply:
        # ⚠⚠ NEVER an unconditional `delete(OwnedUin)`. It was exactly that,
        # with no WHERE at all, on the strength of a docstring saying
        # collections were closed so every row had to be a leftover. That
        # stopped being true on 2026-09-03, when collections reopened and
        # numbers went on sale: from that day the table also holds the DEEDS
        # for numbers people have paid money for, and one run of this tool
        # would have deleted every one of them, silently, with no way to tell
        # afterwards which had existed.
        #
        # A purchase is never a leftover, so it is never reclaimed here. If
        # some future rule should reclaim one, it will be written deliberately
        # and it will say so; it will not arrive as a side effect of a sweep
        # aimed at something else.
        result = await db.execute(
            delete(OwnedUin).where(OwnedUin.source != "purchase")
        )
        await db.commit()
        kept = len(rows) - (result.rowcount or 0)
        print(f"parked: released {result.rowcount or 0}, kept {kept} paid deed(s)")
    return len(rows)


async def _abandoned(db, days: int) -> list[int]:
    """Reserved numbers on accounts that have nothing and have not come back.

    The emptiness test is three LEFT JOINs rather than a subquery per account:
    on the flagship this walks 3k rows once instead of 3k times.
    """
    contacts = select(Contact.owner_uin, func.count().label("n")).group_by(Contact.owner_uin).subquery()
    groups = select(GroupMember.uin, func.count().label("n")).group_by(GroupMember.uin).subquery()
    devices = select(DeviceToken.uin, func.count().label("n")).group_by(DeviceToken.uin).subquery()
    q = (
        select(User.uin)
        .outerjoin(contacts, contacts.c.owner_uin == User.uin)
        .outerjoin(groups, groups.c.uin == User.uin)
        .outerjoin(devices, devices.c.uin == User.uin)
        .where(
            User.last_seen < datetime.now(timezone.utc) - timedelta(days=days),
            func.coalesce(contacts.c.n, 0) == 0,
            func.coalesce(groups.c.n, 0) == 0,
            func.coalesce(devices.c.n, 0) == 0,
        )
    )
    uins = [int(u) for (u,) in (await db.execute(q)).all()]
    return sorted(u for u in uins if is_reserved_uin(u))


async def _main(args) -> None:
    # Imported here: routers pull in the whole app, and a dry run should not
    # pay for that if it is only counting.
    from app.routers.migrate import _perform_migration

    async with SessionLocal() as db:
        await _release_parked(db, apply=args.apply and not args.abandoned_only)
        if args.parked_only:
            return
        targets = await _abandoned(db, args.days)

    print(f"abandoned: {len(targets)} reserved numbers on accounts silent for {args.days}+ days")
    print("  sample:", targets[:20])
    if not args.apply:
        print("dry run — nothing moved. Re-run with --apply.")
        return

    moved = 0
    for old in targets:
        # One session per account, so a failure costs one migration and not
        # the batch, and the pool never holds a long transaction open.
        async with SessionLocal() as db:
            user = await db.get(User, old)
            if user is None:
                continue
            fresh = await allocate_uin(db)
            try:
                await _perform_migration(db, user, target_uin=fresh)
            except Exception as exc:  # noqa: BLE001 — one bad row must not stop the sweep
                print(f"  #{old}: FAILED {exc!r}")
                await db.rollback()
                continue
        moved += 1
        if moved % 25 == 0:
            print(f"  moved {moved}/{len(targets)}")
        # Deliberate: this runs against a live island.
        await asyncio.sleep(0.05)
    print(f"abandoned: moved {moved} accounts off their reserved numbers")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--days", type=int, default=60, help="silence before an account counts as abandoned")
    ap.add_argument("--apply", action="store_true", help="actually do it (default is a dry run)")
    ap.add_argument("--parked-only", action="store_true", help="release collections, touch no account")
    ap.add_argument("--abandoned-only", action="store_true", help="move accounts, leave collections alone")
    asyncio.run(_main(ap.parse_args()))


if __name__ == "__main__":
    main()
