"""Guest copies: who is one, and whether this island admits new ones.

Spec 2026-09-15 (guest copies through a paid or invite door), sections 2.4 and
3.2. A guest copy is an account row whose owner lives on another island and
holds a seat in a room here without having come through the door. The row
carries `users.guest_status` ("added" for a seat nobody has claimed, "proven"
for a guest whose key was proven); NULL is every native account.

This module is the shared foundation the rest of the guest work stands on:

  * `is_guest` / `mark_guest` / `unmark_guest`, a Redis mirror of the set of
    guest rows, because the answer is needed on every authenticated request;
  * `admission_open`, the ONE place the admission settings are combined;
  * `shares_room`, the relationship the island can see between a guest and
    anybody else.

⚠⚠ THE FAILURE DIRECTIONS ARE THE REVERSE OF THE SUSPENDED SET's, and on
purpose. `security.is_suspended` fails OPEN on a Redis error, because locking
every user out during a blip is worse than letting a banned one through for a
minute. Here the harm runs the other way: a guest read as native for a minute
is a free account on a paid island with contacts, calls and numbers, and a
native read as a guest for a minute is a refused request they retry. So:

  * `is_guest` never answers from nothing. A Redis error reads the row.
  * `mark_guest` runs BEFORE the commit that creates or claims a guest, and
    raises if it cannot mark; the caller rolls back and answers 503. A mark
    whose commit then fails restricts a number nobody holds yet.
  * `unmark_guest` runs AFTER the commit that converts or deletes, and is best
    effort. A stale mark restricts a former guest for a few minutes.
"""
from __future__ import annotations

import logging
import secrets

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import aliased

log = logging.getLogger(__name__)

#: The set of guest uins, as strings. A CACHE, authoritative on write: the
#: create, claim, convert and delete paths keep it in step, and a cold or
#: flushed Redis rebuilds it from the table.
GUEST_KEY = "guest_uins"
#: Freshness marker for the set. While it exists the set is trusted; when it
#: expires the next reader rebuilds from `users`. One small query per worker
#: per window, never per request.
GUEST_LOADED_KEY = "guest_uins:loaded"
GUEST_TTL_SECONDS = 300
#: Marks made recently, kept beside the set so a rebuild cannot erase them.
#:
#: ⚠⚠ WHY THIS EXISTS. A mark is written before its row is committed. A rebuild
#: that runs in between reads a table without the row and, if it simply
#: replaced the set, would drop the mark: the row then commits as a guest that
#: the cache calls native until the next rebuild, which is up to five minutes
#: of a free full account. The suspended set has exactly that race and gets
#: away with it because it fails open anyway. So every mark also lands here
#: with a short TTL, and a rebuild is `table UNION pending`, never the table
#: alone.
GUEST_PENDING_KEY = "guest_uins:pending"
#: Far longer than any request spends between its mark and its commit. The TTL
#: is refreshed by every mark, so under steady minting an entry can outlive
#: it; that only keeps a number restricted, which is the safe direction, and
#: `unmark_guest` removes an entry whose commit failed.
GUEST_PENDING_TTL_SECONDS = 120

STATUS_ADDED = "added"
STATUS_PROVEN = "proven"

#: How long the daily guest counters (`stat:guest_*:<YYYYMMDD>`) live. 40 days,
#: like the reissue counters, so a month of them can be read straight off
#: Redis. No uin is ever part of the key: they count how guests arrive, and a
#: per-account tally would be a guest register.
STAT_TTL_SECONDS = 40 * 24 * 60 * 60


async def bump_stat(name: str) -> None:
    """INCR `stat:<name>:<YYYYMMDD>` (UTC). Best effort: a counter never fails
    the request it counts."""
    try:
        from datetime import datetime, timezone

        redis = await _redis()
        key = f"stat:{name}:{datetime.now(timezone.utc):%Y%m%d}"
        pipe = redis.pipeline()
        pipe.incr(key)
        pipe.expire(key, STAT_TTL_SECONDS)
        await pipe.execute()
    except Exception:  # noqa: BLE001
        pass


def _dormant_days() -> int:
    # Read from the sweep that owns the number, lazily: that module imports the
    # database layer, and this one is imported from the auth layer, which is
    # how import cycles start.
    from app.services.offline_queue_sweep import DORMANT_DAYS

    return int(DORMANT_DAYS)


def mint_backdate():
    """How far in the past a freshly minted guest's `last_seen` is written
    (spec 2026-09-15, 8.3).

    Group content is queued only for members seen inside DORMANT_DAYS
    (`_queueable` in messages.py). One day short of that window means a
    self-joined guest has about a day of content stored before its first poll,
    and a script that mints and never polls stops costing storage after that
    day. `last_seen` is non-nullable, so a backdate is how a row starts dormant
    without an ALTER.
    """
    from datetime import timedelta

    days = _dormant_days()
    return timedelta(days=max(days - 1, 1)) if days > 0 else timedelta(days=13)


def added_backdate():
    """`last_seen` backdate for an unclaimed seat (spec 2026-09-15, 8.3).

    Well past the dormant window, so a seat nobody has opened stores no group
    content at all. It still receives sender-key material, because `_keep_for`
    keeps class 2 for every recipient: a seat that is claimed later is not left
    unable to read what arrives after the claim.
    """
    from datetime import timedelta

    return timedelta(days=max(_dormant_days(), 0) + 16)


def __getattr__(name: str):
    # `MINT_BACKDATE` / `ADDED_BACKDATE` as the spec names them, computed on
    # first read for the import-cycle reason in `_dormant_days`.
    if name == "MINT_BACKDATE":
        return mint_backdate()
    if name == "ADDED_BACKDATE":
        return added_backdate()
    raise AttributeError(name)


class GuestCacheUnavailable(RuntimeError):
    """The guest set could not be written. Raised by `mark_guest` only; the
    caller rolls back and answers `guest_unavailable_error()`."""


def guest_unavailable_error() -> HTTPException:
    """The 503 every guest path answers when it cannot mark, lock or read what
    it needs. `retry_after` is advisory: nothing here knows how long an outage
    lasts, and a client retries once rather than looping."""
    return HTTPException(
        status.HTTP_503_SERVICE_UNAVAILABLE,
        detail={"code": "guest_unavailable"},
        headers={"Retry-After": "30"},
    )


async def _redis():
    # Imported per call, like `security.is_suspended` does: this module is
    # imported from the auth layer, and a module-level import of the Redis
    # client is how import cycles start. It also leaves `app.core.redis` as
    # the one patch point a test needs to take Redis away.
    from app.core.redis import get_redis

    return await get_redis()


async def _rebuild(redis) -> None:
    """Replace the set with `guest rows UNION pending marks`, and arm the
    marker. The union is done by Redis inside one MULTI, so a reader never
    sees a half-built set and two workers rebuilding at once both finish with
    a correct one."""
    from app.core.db import SessionLocal
    from app.models.user import User

    async with SessionLocal() as db:
        rows = (
            await db.execute(select(User.uin).where(User.guest_status.is_not(None)))
        ).scalars().all()
    # A private scratch key per rebuild, so concurrent rebuilds cannot read
    # each other's half-filled sets.
    scratch = f"{GUEST_KEY}:build:{secrets.token_hex(8)}"
    pipe = redis.pipeline(transaction=True)
    if rows:
        pipe.sadd(scratch, *[str(u) for u in rows])
        pipe.expire(scratch, 60)
    # SUNIONSTORE overwrites the destination atomically, treats a missing key
    # as empty, and deletes the destination when the union is empty. An island
    # with no guests therefore ends with no set and a live marker, which reads
    # as "nobody is a guest" until the marker expires.
    pipe.sunionstore(GUEST_KEY, [scratch, GUEST_PENDING_KEY])
    pipe.delete(scratch)
    pipe.set(GUEST_LOADED_KEY, "1", ex=GUEST_TTL_SECONDS)
    await pipe.execute()


async def _is_guest_from_row(uin: int) -> bool:
    from app.core.db import SessionLocal
    from app.models.user import User

    async with SessionLocal() as db:
        value = await db.scalar(select(User.guest_status).where(User.uin == int(uin)))
    return value is not None


async def is_guest(uin: int) -> bool:
    """True when `uin` is a guest copy or an unclaimed seat.

    Redis first (marker, rebuild if it is missing, then SISMEMBER). On ANY
    Redis error the row is read instead. If the database is unreachable as
    well, the exception propagates and the request fails; it is never answered
    as "native".
    """
    try:
        redis = await _redis()
        if not await redis.exists(GUEST_LOADED_KEY):
            await _rebuild(redis)
        return bool(await redis.sismember(GUEST_KEY, str(int(uin))))
    except Exception as exc:  # noqa: BLE001 - any cache failure reads the row
        log.warning("[guest] cache unavailable, reading the row: %s", exc)
    return await _is_guest_from_row(uin)


async def mark_guest(uin: int) -> None:
    """Put `uin` in the guest set BEFORE the commit that makes it a guest.

    Raises `GuestCacheUnavailable` when Redis cannot take the write. The caller
    must then roll back and answer `guest_unavailable_error()`: committing a
    guest row the cache does not know about is exactly the fail-open this
    module exists to prevent. On a failed commit afterwards, call
    `unmark_guest`.
    """
    try:
        redis = await _redis()
        pipe = redis.pipeline(transaction=True)
        pipe.sadd(GUEST_KEY, str(int(uin)))
        pipe.sadd(GUEST_PENDING_KEY, str(int(uin)))
        pipe.expire(GUEST_PENDING_KEY, GUEST_PENDING_TTL_SECONDS)
        await pipe.execute()
    except Exception as exc:  # noqa: BLE001
        raise GuestCacheUnavailable(str(exc)) from exc


async def unmark_guest(uin: int) -> None:
    """Take `uin` out of the guest set AFTER the commit that converted it to a
    resident, deleted it, or failed to create it. Best effort, never raises.

    If the removal cannot be written, the marker is dropped instead so the next
    reader rebuilds from the table. Should that fail too, the stale entry
    restricts the former guest until the marker expires on its own (300 s,
    plus up to the pending TTL if the uin was marked in the last two minutes).
    That is the safe direction, and the reason this may be best effort while
    `mark_guest` may not.
    """
    try:
        redis = await _redis()
        pipe = redis.pipeline(transaction=True)
        pipe.srem(GUEST_KEY, str(int(uin)))
        pipe.srem(GUEST_PENDING_KEY, str(int(uin)))
        await pipe.execute()
        return
    except Exception as exc:  # noqa: BLE001
        log.warning("[guest] unmark failed, dropping the marker: %s", exc)
    try:
        redis = await _redis()
        await redis.delete(GUEST_LOADED_KEY)
    except Exception:  # noqa: BLE001
        pass


async def shares_room(db, a: int, b: int) -> bool:
    """True when `a` and `b` are both members of at least one room here.

    The one relationship this island can see between a guest and anybody else:
    a guest has no contact edges here, and a shared room is what already hands
    both of them each other's keys and nicknames in the roster. `a == b` is
    not special-cased; a caller that allows self-lookups says so itself.
    """
    from app.models.group import GroupMember

    other = aliased(GroupMember)
    hit = await db.scalar(
        select(GroupMember.id)
        .join(other, other.group_id == GroupMember.group_id)
        .where(GroupMember.uin == int(a), other.uin == int(b))
        .limit(1)
    )
    return hit is not None


async def admission_open() -> bool:
    """Whether this island admits NEW guests right now (spec 2026-09-15, 3.2).

    The only function that combines the settings, and what `/server/info`
    serves as `guest_accounts_v1`. It governs minting and owner-add only:
    existing guests keep their tokens and their restrictions whatever it says.

      * an open island: False. Anyone may register natively, so "guest" means
        nothing there and clients keep today's path.
      * a closed island that refuses strangers entirely: False, even with
        `guest_admission=on`. That operator asked to be off the network.
      * `guest_admission=off`: False. `on`: True.
      * `auto`: True only on a paid island that is not closed. An invite or
        closed island admits guests only when its operator says `on`
        (founder, 2026-09-15), so an auto-updated company island does not
        start letting outsiders into its rooms without anyone deciding it.

    ⚠ It fails CLOSED on a worker that has never read the settings. The code
    defaults (`registration_policy` from the environment, `guest_admission`
    auto) would give False on a stock island anyway, but an island whose
    environment says "paid" and whose console says "closed" would read as
    open-for-guests from defaults alone, so the policy is read strictly.
    """
    from app.services import server_settings

    try:
        policy = await server_settings.get_strict("registration_policy")
    except server_settings.SettingsUnavailable:
        return False
    if policy == "open":
        return False
    closed = bool(await server_settings.get("closed_island"))
    if closed and bool(await server_settings.get("federation_refuse_strangers")):
        return False
    mode = await server_settings.get("guest_admission")
    if mode == "off":
        return False
    if mode == "on":
        return True
    # "auto", and anything a hand-edited row might carry, which reads as auto.
    return policy == "paid" and not closed


# ── route policy (spec 2026-09-15, section 6.1) ─────────────────────────────
#
# Every route that takes an account session states what a GUEST may do there,
# with a marker on the endpoint:
#
#   * no marker: DENIED. A guest token gets 403 `guest_restricted` before the
#     handler runs. This is the default on purpose, so a route added next
#     month is closed to guests until somebody decides otherwise;
#   * `@guest(ALLOW)`: the route behaves for a guest exactly as for anyone;
#   * `@guest(RULE)`: the route is let through, and the HANDLER applies the
#     guest rule itself (`is_guest`, `shares_room`). Also used for "EMPTY"
#     routes, directories that answer a guest with an empty list rather than a
#     403 because shipped clients call them from a copy signed in as an
#     account.
#
# `current_uin` and `current_uin_optional` call `enforce` on every request.
# `test_guest_policy_local.py` walks the app's routes and fails when a session
# route has no entry in its table, so the default cannot be forgotten
# silently: a new route is denied AND the test names it.

ALLOW = "allow"
RULE = "rule"


def guest(policy: str):
    """Mark a route's decision for guest callers. No marker = denied to guests.

    Sits directly above `async def`, under the `@router` decorator, so the
    function object the router registers is the one carrying the attribute.
    """
    if policy not in (ALLOW, RULE):
        raise ValueError(f"unknown guest policy {policy!r}")

    def deco(fn):
        fn.__guest_policy__ = policy
        return fn

    return deco


def route_policy(endpoint) -> str:
    """"allow", "rule", or "deny" for an endpoint function. The test's reading
    of a marker, kept next to the code that writes it."""
    value = getattr(endpoint, "__guest_policy__", None)
    return value if value in (ALLOW, RULE) else "deny"


def restricted_error() -> HTTPException:
    """The 403 a guest gets on a route closed to it. Shipped clients show one
    sentence for it and never retry (spec 2026-09-15, 12.1)."""
    return HTTPException(status.HTTP_403_FORBIDDEN, detail={"code": "guest_restricted"})


async def refuse_guest(uin: int) -> None:
    """Raise `restricted_error()` when `uin` is a guest, counting the refusal.
    For RULE handlers whose rule is "this part is not for guests"."""
    if await is_guest(uin):
        await bump_stat("guest_restricted")
        raise restricted_error()


async def enforce(request, uin: int) -> None:
    """Refuse a guest session on a route without an ALLOW or RULE marker.

    Starlette writes the matched endpoint into the scope when the route
    matches, before FastAPI resolves any dependency, so the marker is known
    here. ALLOW and RULE routes pay no lookup at all; every other route pays
    one `is_guest`, which is a Redis set read.

    ⚠ Fails CLOSED like `is_guest`: if neither Redis nor the database can
    answer, the request fails rather than letting a possible guest through.
    """
    endpoint = request.scope.get("endpoint") if request is not None else None
    if route_policy(endpoint) != "deny":
        return
    await refuse_guest(uin)


# ── poll stamp (spec 2026-09-15, section 8.3) ───────────────────────────────

#: One stamp per guest per this many seconds, whatever the poll rate.
POLL_STAMP_WINDOW_SECONDS = 6 * 60 * 60


async def touch_poll(db, uin: int) -> None:
    """Keep a polling guest inside the dormant window. Best effort, never
    raises.

    Group content is queued only for members whose `last_seen` is recent
    (`_queueable` in messages.py), and a guest copy that is only ever polled
    (no socket, so no WS ping) would otherwise age out of its own rooms. The
    stamp is written one hour in the past, so presence never reads a guest as
    online, and at most once per window per guest, so a client that polls
    every few seconds costs one UPDATE a quarter of a day.

    `db` is accepted for the call shape the spec names and is NOT used: the
    stamp commits on its own session, because `get_db` never commits and a
    read handler like `GET /messages/queue` may finish without committing, which
    would silently drop a stamp written on the request's session.
    """
    del db
    try:
        if not await is_guest(uin):
            return
        from datetime import datetime, timezone

        from sqlalchemy import update

        from app.core.db import SessionLocal
        from app.core.rate_limit import bucket_name
        from app.models.user import User
        from app.services.guest_accounts import POLL_STAMP_LAG

        redis = await _redis()
        # Keyed by the HMAC'd bucket name, never the raw uin: a Redis dump
        # should not be a list of which numbers are guests that polled today.
        key = f"gpoll:{bucket_name('uin:' + str(int(uin)))}"
        if not await redis.set(key, "1", nx=True, ex=POLL_STAMP_WINDOW_SECONDS):
            return
        stamp = datetime.now(timezone.utc) - POLL_STAMP_LAG
        async with SessionLocal() as own:
            await own.execute(
                update(User)
                .where(
                    User.uin == int(uin),
                    User.guest_status == STATUS_PROVEN,
                    User.last_seen < stamp,
                )
                .values(last_seen=stamp)
            )
            await own.commit()
    except Exception as exc:  # noqa: BLE001 - a stamp never fails a poll
        log.warning("[guest] poll stamp skipped: %s", exc)
