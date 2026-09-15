"""Hold every guest row before a backend DOWNGRADE (spec 2026-09-15, section 17).

⚠⚠ WHY THIS EXISTS. Guest restrictions live in code, not in the data: a row
with `guest_status` set is restricted to rooms only because this backend reads
that column on every request. A backend older than guest copies ignores the
column, so after a downgrade every guest is a full account on a paid island
(contacts, calls, numbers, search) and every unclaimed seat is an account
anybody holding the key can recover into. A rollback of the code is therefore
NOT neutral, and a forward fix is the better answer whenever there is one.

When there is not, the order is:

  1. set `guest_admission=off` in the console, so no new guest or seat is
     made while this runs (the script refuses to apply otherwise);
  2. run this with `--apply`:
       * every UNCLAIMED SEAT is deleted exactly as a burn deletes an account
         (`services/account_delete.purge_account`), and its rooms are told;
       * every PROVEN GUEST is SUSPENDED. ⚠ That also stops them posting in
         their rooms: a suspended account cannot authenticate at all. There is
         no narrower lever an older backend understands;
  3. downgrade.

After a forward fix, `--release` lifts exactly the suspensions this script
made, using the list `--apply` wrote. Suspensions an operator made for other
reasons are not in the list and stay.

⚠ The list is a list of which numbers on this island are guests. Keep it off
shared storage and delete it after `--release`. Nothing else in the codebase
keeps such a list; it exists here only because the alternative is lifting
every suspended guest's ban, including bans for abuse.

Usage on the island (the app's own environment, so DATABASE_URL and REDIS_URL
are the ones the server uses):

    python tools/guest_rows_hold.py                          # dry run, counts only
    python tools/guest_rows_hold.py --apply --list /root/guest-hold.txt
    python tools/guest_rows_hold.py --release --list /root/guest-hold.txt
"""
from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path

# Run as a plain script from anywhere: the app package is the repo root.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

POSTING_WARNING = (
    "⚠ Suspending a guest also stops them posting in their rooms: a suspended "
    "account cannot authenticate at all."
)


class HoldRefused(RuntimeError):
    """The hold would not be safe to apply right now."""


async def hold(apply: bool, list_path: str | None) -> dict:
    """Count, and with `apply` delete seats and suspend guests. Returns a
    report dict. Raises HoldRefused when admission is still open or no list
    path was given for an apply."""
    from sqlalchemy import select, update

    from app.core import guest_policy
    from app.core.db import SessionLocal
    from app.core.security import mark_suspended
    from app.models.user import User
    from app.services.account_delete import announce_rooms_after_purge, purge_account

    async with SessionLocal() as db:
        seats = [
            int(u)
            for u in (
                await db.execute(
                    select(User.uin).where(User.guest_status == guest_policy.STATUS_ADDED)
                )
            ).scalars().all()
        ]
        guests = [
            int(u)
            for u in (
                await db.execute(
                    select(User.uin).where(
                        User.guest_status == guest_policy.STATUS_PROVEN,
                        User.is_suspended.is_(False),
                    )
                )
            ).scalars().all()
        ]
    report = {"seats": len(seats), "guests": len(guests), "purged": 0, "suspended": 0}
    if not apply:
        return report

    # Admission must be closed first, or seats and guests keep arriving behind
    # the hold and the downgrade frees them. `admission_open` is what both
    # `/auth/guest` and owner-add ask, so False here means neither mints.
    if await guest_policy.admission_open():
        raise HoldRefused(
            "guest admission is still open on this island: set guest_admission=off "
            "in the console first"
        )
    if not list_path:
        raise HoldRefused("--apply needs --list PATH, so --release can undo exactly this hold")
    # Opened BEFORE anything changes: a list that cannot be written after the
    # suspensions are committed would leave nothing to release them by.
    with open(list_path, "a", encoding="utf-8") as fh:
        for uin in seats:
            async with SessionLocal() as db:
                # Re-read locked: a seat claimed since the count is a proven
                # guest now and gets the suspension below instead.
                row = await db.scalar(
                    select(User)
                    .where(User.uin == uin, User.guest_status == guest_policy.STATUS_ADDED)
                    .with_for_update()
                )
                if row is None:
                    await db.rollback()
                    continue
                result = await purge_account(db, uin, "guest_hold", announce_burn=False)
                if result is not None:
                    report["purged"] += 1
                    await announce_rooms_after_purge(db, result.member_rooms)

        async with SessionLocal() as db:
            # Re-selected, so a seat claimed during the loop above is held too.
            targets = [
                int(u)
                for u in (
                    await db.execute(
                        select(User.uin).where(
                            User.guest_status == guest_policy.STATUS_PROVEN,
                            User.is_suspended.is_(False),
                        )
                    )
                ).scalars().all()
            ]
            if targets:
                await db.execute(
                    update(User)
                    .where(
                        User.uin.in_(targets),
                        User.guest_status == guest_policy.STATUS_PROVEN,
                        User.is_suspended.is_(False),
                    )
                    .values(is_suspended=True)
                    .execution_options(synchronize_session=False)
                )
            fh.writelines(f"{uin}\n" for uin in targets)
            fh.flush()
            os.fsync(fh.fileno())
            await db.commit()
        for uin in targets:
            await mark_suspended(uin, True)
        report["suspended"] = len(targets)
    return report


async def release(list_path: str) -> dict:
    """Lift the suspensions a previous `--apply` made, for rows that are still
    guests. A row that was converted or deleted since is left alone."""
    from sqlalchemy import select, update

    from app.core.db import SessionLocal
    from app.core.security import mark_suspended
    from app.models.user import User

    with open(list_path, encoding="utf-8") as fh:
        listed = sorted({int(line) for line in fh if line.strip().isdigit()})
    released: list[int] = []
    async with SessionLocal() as db:
        if listed:
            released = [
                int(u)
                for u in (
                    await db.execute(
                        select(User.uin).where(
                            User.uin.in_(listed),
                            User.guest_status.is_not(None),
                            User.is_suspended.is_(True),
                        )
                    )
                ).scalars().all()
            ]
        if released:
            await db.execute(
                update(User)
                .where(User.uin.in_(released))
                .values(is_suspended=False)
                .execution_options(synchronize_session=False)
            )
        await db.commit()
    for uin in released:
        await mark_suspended(uin, False)
    return {"listed": len(listed), "released": len(released)}


async def _main(args: argparse.Namespace) -> int:
    from app.core.db import engine
    from app.core.redis import close_redis
    from app.services.connection_manager import manager

    try:
        if args.release:
            if not args.list:
                print("--release needs --list PATH")
                return 2
            report = await release(args.list)
            print(f"listed: {report['listed']}, suspensions lifted: {report['released']}")
            return 0
        print(POSTING_WARNING)
        try:
            report = await hold(args.apply, args.list)
        except HoldRefused as exc:
            print(f"refused: {exc}")
            return 2
        if args.apply:
            print(
                f"unclaimed seats deleted: {report['purged']} of {report['seats']}; "
                f"guests suspended: {report['suspended']}. List written to {args.list}."
            )
        else:
            print(
                f"dry run: {report['seats']} unclaimed seat(s) would be deleted, "
                f"{report['guests']} guest(s) would be suspended. Nothing changed."
            )
        return 0
    finally:
        await manager.shutdown()
        await close_redis()
        await engine.dispose()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--apply", action="store_true", help="delete seats and suspend guests")
    mode.add_argument("--release", action="store_true", help="lift the suspensions in --list")
    parser.add_argument("--list", help="file of suspended uins, written by --apply, read by --release")
    raise SystemExit(asyncio.run(_main(parser.parse_args())))
