"""One-off backfill: move accounts still sitting on the old open privacy
defaults onto the private ones (2026-08-11).

Why this exists as a script and not a schema migration: the `DEFAULT` clause
in `app/core/db.py` only applies to rows inserted after it changes, so an
island that has been running keeps every existing account on `everyone`. On
prod that was 2801 accounts out of 2923, i.e. 96% of the base, which is the
whole point — a privacy setting people have to find is a privacy setting
almost nobody has.

⚠ This cannot distinguish "never touched the setting" from "deliberately
chose everyone", so it moves both. The move is strictly towards less
exposure and every account can flip it back in Settings, which is why that
is acceptable; the reverse default would not be.

`profile_visibility` is deliberately NOT touched: adding a contact starts
with looking somebody up by number, and closing the profile card to
strangers breaks that path.

Usage on a droplet:

    /opt/rcq/venv/bin/python tools/backfill_privacy_defaults.py --dry-run
    /opt/rcq/venv/bin/python tools/backfill_privacy_defaults.py --apply
"""

from __future__ import annotations

import argparse
import asyncio
import os
import ssl
import sys

import asyncpg

# (column, old value we replace, new value)
MOVES = [
    ("last_seen_visibility", "everyone", "contacts"),
    ("group_invite_policy", "everyone", "contacts"),
    ("call_policy", "everyone", "contacts"),
    ("read_receipts_visibility", "everyone", "contacts"),
]


def _env(path: str = "/opt/rcq/.env") -> dict[str, str]:
    out: dict[str, str] = {}
    if not os.path.exists(path):
        return out
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                out[k] = v.strip().strip('"').strip("'")
    return out


def _dsn() -> str:
    raw = os.environ.get("DATABASE_URL") or _env().get("DATABASE_URL")
    if not raw:
        sys.exit("DATABASE_URL not found in env or /opt/rcq/.env")
    # asyncpg speaks plain postgres URLs and rejects the SQLAlchemy driver
    # prefix; the `?ssl=require` tail is passed through as a startup param
    # and trips ProtocolViolationError, so it goes too (TLS is set up below).
    return raw.replace("postgresql+asyncpg://", "postgresql://").split("?")[0]


async def main(apply: bool) -> None:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    # statement_cache_size=0 is mandatory behind PgBouncer in transaction mode.
    conn = await asyncpg.connect(_dsn(), ssl=ctx, statement_cache_size=0)
    try:
        total = await conn.fetchval("select count(*) from users")
        print(f"accounts: {total}")
        for column, old, new in MOVES:
            n = await conn.fetchval(
                f"select count(*) from users where {column} = $1", old
            )
            print(f"  {column}: {n} on '{old}' -> '{new}'")
            if apply and n:
                await conn.execute(
                    f"update users set {column} = $1 where {column} = $2", new, old
                )
        print("applied" if apply else "dry run, nothing written")
    finally:
        await conn.close()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true", help="write the changes")
    ap.add_argument("--dry-run", action="store_true", help="count only (default)")
    args = ap.parse_args()
    asyncio.run(main(apply=args.apply))
