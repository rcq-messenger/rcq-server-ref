"""Does this account look like a person, or like a script's leftovers?

One question, asked by the free invite drip (routers/invites.py) before it
hands an entry credential to an account that never paid for one. It is the
INVERSE of `dead_account_sweep._CANDIDATES`, clause for clause, plus one rule
the sweep does not need: the two must agree, or the island would be handing
invites to rows it is about to delete.

⚠⚠ WHY THE BAR IS HERE AT ALL. On 2026-09-01 a script opened 552 accounts on
the flagship in three minutes. Every one of them predates the day entry went
on sale, so every one of them is "legacy" by the only fact the drip can read
off the row, and three free invites each is 1,656 entry credentials minted
for the cost of one evening. A person, by contrast, does at least one of the
things below within a month, and comes back the next day. The rule is cheap
to state and expensive to fake at scale, which is the whole design of the
sweep and is reused here for the same reason.

The extra rule is the day. The sweep spares anybody seen more than an hour
after creation, because deleting a person is unrecoverable and an hour is
enough to avoid it. Handing out invites is the other direction: a mistake
costs an entry credential, so the bar is higher, twenty-four hours between
the first and the last time the account was seen. A script that registers
and leaves never clears it; a person who installed the app and opened it
the next morning does.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

#: How long the account has to have been in use, first sighting to last, before
#: it is taken for a person. See the module docstring for why it is a day and
#: not the sweep's hour.
MIN_LIFETIME = timedelta(hours=24)

# ⚠ Portable SQL, for the same reason the sweep's query is: the local tests
# run on SQLite, and a rule that decides who gets an entry credential must be
# one the tests can execute. Every EXISTS here is the negation of a NOT EXISTS
# in `dead_account_sweep._CANDIDATES`; the two lists are meant to be read side
# by side, and a table added to one belongs in the other.
#
# ONE query, one row, and no ORM entities loaded: this runs on every GET
# /invites for a legacy account, and hydrating the contact graph to answer
# "has any edge" would be the N+1 the sweep was written to avoid.
_SIGNAL = text("""
    SELECT u.created_at, u.last_seen,
           CASE WHEN (
                   u.nickname NOT LIKE 'user-%'
                OR u.avatar_media_id IS NOT NULL
                OR EXISTS (SELECT 1 FROM devices d WHERE d.uin = u.uin)
                OR EXISTS (SELECT 1 FROM device_tokens t WHERE t.uin = u.uin)
                OR EXISTS (SELECT 1 FROM contacts c WHERE c.owner_uin = u.uin OR c.contact_uin = u.uin)
                OR EXISTS (SELECT 1 FROM group_members g WHERE g.uin = u.uin)
                OR EXISTS (SELECT 1 FROM groups g WHERE g.owner_uin = u.uin)
                OR EXISTS (SELECT 1 FROM sites s WHERE s.owner_uin = u.uin)
                OR EXISTS (SELECT 1 FROM owned_uins o WHERE o.owner_uin = u.uin OR o.uin = u.uin)
                OR EXISTS (SELECT 1 FROM reports r WHERE r.reporter_uin = u.uin OR r.target_uin = u.uin)
           ) THEN 1 ELSE 0 END AS acted
    FROM users u
    WHERE u.uin = :uin
""")


def _as_utc(value) -> datetime | None:
    """Both timestamp columns come back tz-aware on Postgres, naive on SQLite,
    and as ISO strings when the query is raw text. Same normalisation as
    `dead_account_sweep._never_came_back`, for the same three shapes."""
    if value is None:
        return None
    if isinstance(value, str):
        value = datetime.fromisoformat(value)
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value


async def looks_like_a_person(db: AsyncSession, uin: int) -> bool:
    """True when `uin` has done at least one deliberate thing AND has been
    around for a day. False for a row the sweep would reap, and for a row that
    does not exist."""
    row = (await db.execute(_SIGNAL, {"uin": uin})).first()
    if row is None:
        return False
    created_at, last_seen, acted = _as_utc(row[0]), _as_utc(row[1]), int(row[2] or 0)
    if not acted or created_at is None or last_seen is None:
        return False
    return (last_seen - created_at) >= MIN_LIFETIME
