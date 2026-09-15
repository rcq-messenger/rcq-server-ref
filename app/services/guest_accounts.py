"""Guest copies: the database and Redis steps the guest routes share.

Spec 2026-09-15, sections 4, 4.5, 5 and 9. Three routes create or claim guest
rows (`POST /auth/guest`, `POST /groups/{id}/guests`, and the seat claim inside
`/auth/recover` and `/auth/refresh`), and four paths turn a guest into a
resident (`POST /auth/guest/settle`, a door registration by the same key,
`/residency/redeem`, and the operator). Every one of them has to resolve a key
to the SAME row, refuse a room for the SAME reasons with the SAME codes, and
convert a row the SAME way, or the paths drift apart and a person ends up with
two rows their phrase cannot both reach. So those steps live here, once.

`app/core/guest_policy.py` answers "is this uin a guest" and "does the island
admit guests"; this module does the writing around those answers.

⚠⚠ ONE ROW PER KEY. Both mint paths resolve the signing key over both base64
spellings, in `first_claim_order`, and only insert under a per-key create lock
after resolving again. Recover and uin-for-key use the same order, so the row a
guest proof lands on is the row the person's phrase recovers into. A second row
for the same key would lose recovery to the older one, which is why a
conversion always rewrites the existing row (section 9).
"""
from __future__ import annotations

import base64
import hashlib
import logging
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, status
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import guest_policy
from app.core.rate_limit import enforce_rate_limit
from app.core.security import bump_uin_epoch, cache_uin_epoch
from app.models.group import Group, GroupMember
from app.models.user import User
from app.services import server_settings
from app.services.key_owner import first_claim_order

log = logging.getLogger(__name__)

#: `gch:<hash>`: a guest challenge that has been spent. Longer than the
#: challenge's own 120 s life, so a challenge cannot be spent twice while it
#: still verifies.
CHALLENGE_GUARD_TTL_SECONDS = 300
#: `gmk:<hash>`: somebody is creating a guest row for this key right now. Far
#: longer than an insert takes; it only has to outlive one request.
CREATE_LOCK_TTL_SECONDS = 30
#: Rooms an unclaimed seat may be put in. Nobody holding the key has said
#: anything yet, so the number is small and not an operator setting.
SEAT_MAX_ROOMS = 3
#: Seats members of one room may mint in a day (section 5, step 6).
GROUP_ADD_MINTS_PER_DAY = 100
#: A claim or a poll stamps `last_seen` this far in the past, so presence never
#: reads a guest as online (`presence_is_fresh`) while the group queue still
#: counts it as active (section 8.3).
POLL_STAMP_LAG = timedelta(hours=1)


def refusal(http_status: int, code: str, *, headers: dict | None = None, **extra) -> HTTPException:
    """The `detail: {"code": ...}` shape every guest refusal uses (section 11)."""
    return HTTPException(http_status, detail={"code": code, **extra}, headers=headers)


# ── resolving a key ────────────────────────────────────────────────────────


@dataclass(frozen=True)
class KeyRow:
    uin: int
    guest_status: str | None
    identity_key: str | None


def key_spellings(raw: bytes) -> tuple[str, str]:
    """Padded and unpadded standard base64 of a key. Both sit in the live
    table, and a lookup on one spelling lets the other through."""
    padded = base64.b64encode(raw).decode("ascii")
    return padded, padded.rstrip("=")


async def row_for_key(
    db: AsyncSession, sk_raw: bytes, *, guests_only: bool = False
) -> KeyRow | None:
    """The row this signing key resolves to, first claim first, or None.

    `guests_only` narrows the candidates to guest rows, for the one caller that
    asks "does this key hold a guest row" rather than "where does this key
    land": a door registration deciding whether to convert (section 9.2).
    """
    q = select(User.uin, User.guest_status, User.identity_key).where(
        User.signing_key.in_(key_spellings(sk_raw))
    )
    if guests_only:
        q = q.where(User.guest_status.is_not(None))
    row = (await db.execute(q.order_by(*first_claim_order()).limit(1))).first()
    if row is None:
        return None
    return KeyRow(uin=int(row.uin), guest_status=row.guest_status, identity_key=row.identity_key)


async def claim_seat(db: AsyncSession, uin: int, *, identity_key: str | None = None) -> bool:
    """Turn an unclaimed seat into a proven guest. The caller owns the commit.

    One conditional UPDATE, so two proofs racing for one seat both succeed as
    far as the person is concerned and exactly one of them writes. Returns
    whether THIS call wrote.

    `identity_key` is set only by `POST /auth/guest`, whose proof covers it.
    Recover and refresh prove the signing key alone, so they leave whatever
    identity key the adder supplied (section 4.5): a wrong one decrypts
    nothing until the person's client runs `/auth/guest`, which repairs it.
    """
    now = datetime.now(timezone.utc)
    values: dict = {
        "guest_status": guest_policy.STATUS_PROVEN,
        "guest_since": now,
        "last_seen": now - POLL_STAMP_LAG,
    }
    if identity_key is not None:
        values["identity_key"] = identity_key
    result = await db.execute(
        update(User)
        .where(User.uin == int(uin), User.guest_status == guest_policy.STATUS_ADDED)
        .values(**values)
        .execution_options(synchronize_session=False)
    )
    return (result.rowcount or 0) == 1


# ── room admission ─────────────────────────────────────────────────────────


async def rooms_held(db: AsyncSession, uin: int) -> int:
    return int(
        await db.scalar(
            select(func.count()).select_from(GroupMember).where(GroupMember.uin == int(uin))
        )
        or 0
    )


async def member_count(db: AsyncSession, group_id: int) -> int:
    return int(
        await db.scalar(
            select(func.count()).select_from(GroupMember).where(GroupMember.group_id == int(group_id))
        )
        or 0
    )


async def refuse_full_room(db: AsyncSession, g: Group) -> None:
    """403 `guest_room_full` for a room at or above the guest member ceiling.

    The ceiling keeps headroom under the per-post payload cap (4096 sealed
    copies, messages.py): a room pushed past it stops working for everybody in
    it, residents included.
    """
    ceiling = int(await server_settings.get("guest_room_member_ceiling"))
    if await member_count(db, g.id) >= ceiling:
        raise refusal(status.HTTP_403_FORBIDDEN, "guest_room_full")


async def refuse_group_limit(db: AsyncSession, uin: int) -> None:
    """403 `guest_group_limit` for a guest already in `guest_max_groups` rooms."""
    if await rooms_held(db, uin) >= int(await server_settings.get("guest_max_groups")):
        raise refusal(status.HTTP_403_FORBIDDEN, "guest_group_limit")


def _retry_after(exc: HTTPException) -> dict:
    retry = (exc.headers or {}).get("Retry-After")
    return {"Retry-After": str(retry)} if retry else {}


async def spend_room_budget(group_id: int) -> None:
    """Count one new guest into this room's day, or 429 `guest_room_limit`.

    Spent LAST, after every refusal that costs nothing, so a request refused
    for another reason does not use up a room's allowance. Fail-closed: a
    budget that switches itself off when Redis blinks is no budget.
    """
    per_day = int(await server_settings.get("guest_room_joins_per_day"))
    try:
        await enforce_rate_limit(
            f"grp:{int(group_id)}", "guest_room_join", per_day, 86400, fail_closed=True
        )
    except HTTPException as exc:
        if exc.status_code != status.HTTP_429_TOO_MANY_REQUESTS:
            raise
        raise refusal(
            status.HTTP_429_TOO_MANY_REQUESTS, "guest_room_limit", headers=_retry_after(exc)
        ) from None


async def spend_group_add_budget(group_id: int) -> None:
    """Count one seat minted by members of this room, or 429 `guest_add_limit`
    with `scope: "group"` (section 5, step 6)."""
    try:
        await enforce_rate_limit(
            f"grp:{int(group_id)}", "guest_add_group", GROUP_ADD_MINTS_PER_DAY, 86400,
            fail_closed=True,
        )
    except HTTPException as exc:
        if exc.status_code != status.HTTP_429_TOO_MANY_REQUESTS:
            raise
        raise refusal(
            status.HTTP_429_TOO_MANY_REQUESTS, "guest_add_limit",
            headers=_retry_after(exc), scope="group",
        ) from None


# ── single use and the create lock ─────────────────────────────────────────


async def _set_nx(key: str, value: str, ttl: int) -> bool:
    # Imported per call so `app.core.redis.get_redis` stays the one patch
    # point a test needs to take Redis away, as in guest_policy.
    from app.core.redis import get_redis

    redis = await get_redis()
    return bool(await redis.set(key, value, nx=True, ex=ttl))


def challenge_guard_key(challenge: str) -> str:
    return "gch:" + hashlib.sha256(challenge.encode("utf-8")).hexdigest()[:32]


async def claim_challenge(challenge: str) -> str:
    """Spend a guest challenge, or refuse: 409 `guest_replayed` when it was
    spent already, 503 `guest_unavailable` when Redis cannot say.

    ⚠ Not best effort, and claimed BEFORE any token is minted, including the
    token for an existing row. Without it a proof seen once (a log, a
    misbehaving front) mints a session for somebody's copy for as long as the
    challenge verifies. Returns the key so the caller can give it back when
    its commit fails.
    """
    key = challenge_guard_key(challenge)
    try:
        fresh = await _set_nx(key, "1", CHALLENGE_GUARD_TTL_SECONDS)
    except Exception:  # noqa: BLE001
        raise guest_policy.guest_unavailable_error() from None
    if not fresh:
        raise refusal(status.HTTP_409_CONFLICT, "guest_replayed")
    return key


async def release_key(key: str | None) -> None:
    """Give back a spent challenge whose change did not commit. Best effort:
    the worst case is a client told `guest_replayed` for a change that never
    happened, and its next attempt uses a fresh challenge anyway."""
    if not key:
        return
    try:
        from app.core.redis import get_redis

        await (await get_redis()).delete(key)
    except Exception:  # noqa: BLE001
        pass


@dataclass(frozen=True)
class CreateLock:
    key: str
    token: str


async def acquire_create_lock(sk_raw: bytes) -> CreateLock:
    """The per-key lock around "no row exists, insert one": 409 `guest_busy`
    when another request holds it, 503 `guest_unavailable` when Redis cannot
    say. The caller resolves the key AGAIN under the lock before inserting."""
    key = "gmk:" + hashlib.sha256(sk_raw).hexdigest()[:32]
    token = secrets.token_hex(8)
    try:
        got = await _set_nx(key, token, CREATE_LOCK_TTL_SECONDS)
    except Exception:  # noqa: BLE001
        raise guest_policy.guest_unavailable_error() from None
    if not got:
        raise refusal(status.HTTP_409_CONFLICT, "guest_busy")
    return CreateLock(key=key, token=token)


# Delete only our own lock: a request that outlived its 30 s must not release
# the lock a later request now holds.
_RELEASE_LOCK_SCRIPT = (
    "if redis.call('get', KEYS[1]) == ARGV[1] then "
    "return redis.call('del', KEYS[1]) end return 0"
)


async def release_create_lock(lock: CreateLock | None) -> None:
    if lock is None:
        return
    try:
        from app.core.redis import get_redis

        await (await get_redis()).eval(_RELEASE_LOCK_SCRIPT, 1, lock.key, lock.token)
    except Exception:  # noqa: BLE001
        # It expires on its own in CREATE_LOCK_TTL_SECONDS.
        pass


# ── a key that arrived by rotation ─────────────────────────────────────────


async def retire_bearers_before_proof(
    db: AsyncSession, uin: int, *, always: bool = False
) -> int | None:
    """A request has just proven the private key of this row's CURRENT signing
    key and is about to hand out a session: kill every bearer minted before it,
    if the key reached the row by a rotation nobody has proven since. The
    caller owns the commit and then calls `bearers_retired`. Returns the new
    epoch, or None when nothing was bumped.

    ⚠⚠ THE ATTACK THIS CLOSES (review 2026-09-15). `/auth/reissue` lets a bearer
    move its row onto any signing key no other row here holds, and proves at
    most the OLD key. A free guest copy rotated onto a stranger's public key
    (their home card hands it out) sat waiting. When the stranger later proved
    the key (recover, refresh, `/auth/guest`) they landed in that row with the
    rotator still signed in beside them; a paid registration even converted it
    into a resident the rotator could read, act as, or burn. The rotator holds
    no private key, so once its bearers die it has no way back in.

    One-shot through `users.key_unproven_since`, and one conditional UPDATE, so
    two proofs racing each other bump once. An honest rotation pays one extra
    401-and-refresh on the rotating device, and nothing after that.

    `always` is for a conversion to resident by a door registration: that
    request hands a resident's session to whoever proved the key, and nobody
    showed the island a bearer, so every earlier one dies whatever the flag
    says.
    """
    result = await db.execute(
        update(User)
        .where(User.uin == int(uin), User.key_unproven_since.is_not(None))
        .values(key_unproven_since=None)
        .execution_options(synchronize_session=False)
    )
    if (result.rowcount or 0) != 1 and not always:
        return None
    return await bump_uin_epoch(db, int(uin))


async def bearers_retired(uin: int, epoch: int | None) -> None:
    """After the commit of `retire_bearers_before_proof`: publish the epoch so
    the stale bearers stop at once, and close the sockets they opened. The
    epoch is checked only at a socket's handshake, so without the kick a socket
    the rotator already held would keep receiving the account's frames (the
    same reason a signed reissue kicks)."""
    if epoch is None:
        return
    from app.services.connection_manager import manager  # local: heavy import, used rarely

    await cache_uin_epoch(int(uin), epoch)
    await manager.kick_uin(int(uin))


# ── conversion to resident (section 9) ─────────────────────────────────────


def clear_guest_columns(user: User) -> bool:
    """Make a guest row native, in place. The caller owns the commit and then
    calls `after_conversion`. Returns whether the row was a guest.

    `entered_via` is left as it is: "guest" is how the person got in, and
    paying later does not rewrite history (the same rule `/residency/redeem`
    follows for every other value).
    """
    was_guest = user.guest_status is not None
    user.guest_status = None
    user.guest_since = None
    return was_guest


async def announce_rooms(db: AsyncSession, uin: int) -> None:
    """Tell every room this row is in that its roster changed (the `guest` or
    `invited` flag, or the identity key). Best effort: the change is already
    committed, and clients pick the roster up on their next refresh anyway.

    Reuses the migration's roster broadcast, which already prices the fan-out
    across many rooms (snapshot for small rooms, the id alone above the limit).
    """
    from app.routers.groups import broadcast_roster_rekey  # local: groups imports this module

    try:
        await broadcast_roster_rekey(db, uin)
    except Exception:  # noqa: BLE001
        log.warning("[guest] roster broadcast failed after a guest change", exc_info=True)


async def after_conversion(db: AsyncSession, uin: int) -> None:
    """Everything that follows the COMMIT of a conversion, in the order the
    cache rules need: unmark (best effort, a stale mark only restricts), then
    the roster broadcast, then the counter."""
    await guest_policy.unmark_guest(uin)
    await announce_rooms(db, uin)
    await guest_policy.bump_stat("guest_settle")
