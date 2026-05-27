"""Random Chat — anonymous, time-boxed 1:1 sessions between strangers.

The server matches two willing-to-chat users from a Redis-backed
queue. Once matched, both sides receive a `random_match` WS event
with the peer's identity_key (so they can encrypt messages to each
other) and a pair_id (opaque session token). Actual chat traffic
still rides on the regular `/messages/sealed` endpoint — sealed-
sender already gives us anonymity at the server level. Random Chat
just decides *who* gets paired with *whom*.

State (Redis-backed, multi-worker safe)
---------------------------------------
- `random:queue` — Redis LIST, FIFO of UINs waiting for a match.
- `random:pair:{pair_id}` — Redis HASH per active session
  (uin_a, uin_b, started_at_iso, expires_at_iso).
- `random:pair_by_uin` — Redis HASH, reverse index uin → pair_id.
- `random:active_pairs` — Redis ZSET, score=expires_at unix epoch,
  member=pair_id. Drives the expire sweeper without scanning all
  pairs.
- `random:daily:{YYYY-MM-DD}` — Redis HASH, uin → today's count.
  TTL 48h so the bucket auto-cleans without explicit rollover.

Each worker can read/write all of the above; `expire_loop` is
leader-elected via Redis SETNX so only one worker actually runs the
sweeper, but any worker handles a /queue or /skip request.
"""
from __future__ import annotations

import asyncio
import os
import secrets
import uuid as _uuid
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import get_db
from app.core.redis import (
    LEADER_RENEW_SECONDS,
    acquire_leadership,
    get_redis,
    renew_leadership,
)
from app.core.security import current_uin
from app.models.contact import Contact
from app.models.user import User
from app.services.connection_manager import manager

router = APIRouter(prefix="/random", tags=["random"])

# Length of a single random session. Roadmap calls for 5 minutes; the last
# 60s gets a "fade" warning client-side (handled in the iOS layer).
PAIR_DURATION_SECONDS = 5 * 60
# Per-day cap on how many strangers a single UIN can be matched with. Keeps
# trolls from spamming the queue. 50 feels generous for genuine use.
DAILY_MATCH_LIMIT = 50

# Redis keys / prefixes.
_QUEUE_KEY = "random:queue"
_PAIR_BY_UIN_KEY = "random:pair_by_uin"
_ACTIVE_PAIRS_KEY = "random:active_pairs"
_PAIR_KEY_PREFIX = "random:pair:"
_DAILY_KEY_PREFIX = "random:daily:"
# Leader role for `expire_loop`.
_EXPIRE_LEADER_ROLE = "random_expire_loop"
# Stable per-worker identity for leader election. Combines pid +
# random uuid so two workers (or two restarts) never collide.
_WORKER_IDENTITY = f"{os.getpid()}-{_uuid.uuid4()}"


@dataclass
class _Pair:
    """Active random-chat session — one Redis hash, materialised here
    for typed convenience when reading. The canonical source is
    `random:pair:{pair_id}` in Redis; this dataclass is just a
    de-serialised view used by the matchmaker / expire-sweeper."""
    pair_id: str
    uin_a: int
    uin_b: int
    started_at: datetime
    expires_at: datetime

    def peer_of(self, uin: int) -> int:
        return self.uin_b if uin == self.uin_a else self.uin_a


def _today_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _pair_key(pair_id: str) -> str:
    return _PAIR_KEY_PREFIX + pair_id


async def _bump_daily(uin: int) -> int:
    """Increment today's match counter for `uin` and return the new
    value. Bucket auto-rolls at UTC midnight (key carries the date;
    48h TTL ensures yesterday's hash gets purged automatically)."""
    redis = await get_redis()
    key = _DAILY_KEY_PREFIX + _today_utc()
    new_value = await redis.hincrby(key, str(uin), 1)
    # Set TTL only on first hit — HINCRBY auto-creates the hash, but
    # doesn't touch TTL. Idempotent EXPIRE; calling repeatedly is fine.
    await redis.expire(key, 48 * 3600)
    return int(new_value)


async def _get_daily_count(uin: int) -> int:
    redis = await get_redis()
    key = _DAILY_KEY_PREFIX + _today_utc()
    raw = await redis.hget(key, str(uin))
    return int(raw) if raw else 0


class _PeerInfo(BaseModel):
    uin: int
    nickname: str
    identity_key: str
    signing_key: str


class QueueOut(BaseModel):
    status: str  # "queued" | "matched"
    pair_id: str | None = None
    peer: _PeerInfo | None = None
    expires_at: datetime | None = None


class LeaveOut(BaseModel):
    left: bool


async def _fetch_peer(db: AsyncSession, uin: int) -> _PeerInfo | None:
    user = await db.get(User, uin)
    if user is None:
        return None
    return _PeerInfo(
        uin=user.uin,
        nickname=user.nickname,
        identity_key=user.identity_key,
        signing_key=user.signing_key,
    )


async def _are_already_connected(db: AsyncSession, a: int, b: int) -> bool:
    """We don't pair users who already know each other — random chat is for
    strangers. A single Contact row in either direction counts as 'connected'."""
    row = (
        await db.execute(
            select(Contact).where(
                ((Contact.owner_uin == a) & (Contact.contact_uin == b))
                | ((Contact.owner_uin == b) & (Contact.contact_uin == a))
            ).limit(1)
        )
    ).scalar_one_or_none()
    return row is not None


async def _is_uin_paired(uin: int) -> str | None:
    """Returns active pair_id for `uin` or None. Cluster-wide via Redis."""
    redis = await get_redis()
    return await redis.hget(_PAIR_BY_UIN_KEY, str(uin))


async def _try_match(uin: int, db: AsyncSession) -> _Pair | None:
    """Walk the queue looking for a peer for `uin`. The peer must (a) still
    be online, and (b) not already be a contact of `uin`. Skipped candidates
    are pushed back to the queue tail. Returns the new pair on success, or
    None if nobody suitable is waiting.

    Operates against Redis directly — every dequeue is `LPOP random:queue`,
    every re-queue is `RPUSH random:queue` (FIFO preservation).
    """
    redis = await get_redis()
    skipped: list[int] = []
    pair: _Pair | None = None
    while True:
        raw = await redis.lpop(_QUEUE_KEY)
        if raw is None:
            break  # queue empty
        try:
            candidate = int(raw)
        except (ValueError, TypeError):
            continue
        if candidate == uin:
            continue
        # is_online is async (Redis-backed cross-worker visibility).
        if not await manager.is_online(candidate):
            # Stale entry — they disconnected without leaving. Drop silently.
            continue
        if await _is_uin_paired(candidate):
            # Edge: somehow already paired (shouldn't happen, but defensively skip).
            continue
        if await _are_already_connected(db, uin, candidate):
            skipped.append(candidate)
            continue
        # Found one.
        now = datetime.now(timezone.utc)
        pair = _Pair(
            pair_id=secrets.token_urlsafe(16),
            uin_a=candidate,
            uin_b=uin,
            started_at=now,
            expires_at=now + timedelta(seconds=PAIR_DURATION_SECONDS),
        )
        # Persist the pair across workers. HSET serialises the dataclass
        # by hand; ZADD scores by expiry-epoch so the sweeper can scan
        # in O(log n).
        pipe = redis.pipeline(transaction=True)
        pipe.hset(_pair_key(pair.pair_id), mapping={
            "uin_a": str(pair.uin_a),
            "uin_b": str(pair.uin_b),
            "started_at": pair.started_at.isoformat(),
            "expires_at": pair.expires_at.isoformat(),
        })
        pipe.expire(_pair_key(pair.pair_id), PAIR_DURATION_SECONDS + 60)
        pipe.zadd(_ACTIVE_PAIRS_KEY, {pair.pair_id: pair.expires_at.timestamp()})
        pipe.hset(_PAIR_BY_UIN_KEY, mapping={
            str(pair.uin_a): pair.pair_id,
            str(pair.uin_b): pair.pair_id,
        })
        await pipe.execute()
        break
    # Re-queue anyone we skipped (still want them matched, just not with this caller).
    if skipped:
        await redis.rpush(_QUEUE_KEY, *[str(s) for s in skipped])
    return pair


async def _notify_match(pair: _Pair, db: AsyncSession) -> None:
    """Fan out `random_match` to both sides with the *other* user's info.
    Each side gets the peer's identity_key so they can encrypt messages."""
    a_info = await _fetch_peer(db, pair.uin_a)
    b_info = await _fetch_peer(db, pair.uin_b)
    if a_info is None or b_info is None:
        return
    expires_iso = pair.expires_at.isoformat()
    await manager.send(pair.uin_a, {
        "type": "random_match",
        "pair_id": pair.pair_id,
        "peer": b_info.model_dump(),
        "expires_at": expires_iso,
    })
    await manager.send(pair.uin_b, {
        "type": "random_match",
        "pair_id": pair.pair_id,
        "peer": a_info.model_dump(),
        "expires_at": expires_iso,
    })


async def _load_pair(pair_id: str) -> _Pair | None:
    redis = await get_redis()
    raw = await redis.hgetall(_pair_key(pair_id))
    if not raw:
        return None
    try:
        return _Pair(
            pair_id=pair_id,
            uin_a=int(raw["uin_a"]),
            uin_b=int(raw["uin_b"]),
            started_at=datetime.fromisoformat(raw["started_at"]),
            expires_at=datetime.fromisoformat(raw["expires_at"]),
        )
    except (KeyError, ValueError):
        return None


async def _end_pair(pair_id: str, reason: str) -> None:
    """Tear down a pair and notify both sides. Idempotent — safe to call
    twice (e.g. both peers leave simultaneously). Cleans up Redis state
    atomically via a pipeline so we never leave dangling pair_by_uin
    entries pointing at a deleted pair."""
    pair = await _load_pair(pair_id)
    if pair is None:
        return
    redis = await get_redis()
    pipe = redis.pipeline(transaction=True)
    pipe.delete(_pair_key(pair_id))
    pipe.zrem(_ACTIVE_PAIRS_KEY, pair_id)
    pipe.hdel(_PAIR_BY_UIN_KEY, str(pair.uin_a), str(pair.uin_b))
    await pipe.execute()
    payload = {"type": "random_end", "pair_id": pair_id, "reason": reason}
    await manager.send(pair.uin_a, payload)
    await manager.send(pair.uin_b, payload)


@router.post("/queue", response_model=QueueOut)
async def queue(
    uin: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> QueueOut:
    """Opt in to random matching. If somebody else is already waiting, we
    match instantly and return the pair; otherwise the caller is parked in
    the queue and will receive a `random_match` WS event when somebody else
    queues up."""
    # Age gate. Stranger Mode pairs the caller with an anonymous adult —
    # we won't put a minor in that conversation, and we won't pair an
    # adult with someone whose age we don't know.
    #
    # Server-side enforcement is the contract: the iOS layer also gates
    # the entry tile so users see a friendly modal, but the backend
    # check is the one that matters for App Review (Guideline 1.2 —
    # UGC moderation, with anonymous matching specifically called out
    # in Apple's Feb 2026 update).
    user = await db.get(User, uin)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found")
    if user.age is None:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            detail={"code": "age_required"},
        )
    if user.age < 18:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            detail={"code": "under_18"},
        )

    redis = await get_redis()

    # Daily cap. Counted at queue time so spamming /queue counts too.
    if await _get_daily_count(uin) >= DAILY_MATCH_LIMIT:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "daily random-chat limit reached")

    # Already in a pair? Reject — caller should /leave first.
    if await _is_uin_paired(uin):
        raise HTTPException(status.HTTP_409_CONFLICT, "already in an active random session")

    # Already in the queue? Idempotent — return queued.
    # LPOS returns the index or None — we just need existence.
    if await redis.lpos(_QUEUE_KEY, str(uin)) is not None:
        return QueueOut(status="queued")

    pair = await _try_match(uin, db)
    if pair is None:
        await redis.rpush(_QUEUE_KEY, str(uin))
        await _bump_daily(uin)
        return QueueOut(status="queued")

    await _bump_daily(uin)
    # Fan out match event to both sides.
    await _notify_match(pair, db)
    peer_uin = pair.peer_of(uin)
    peer_info = await _fetch_peer(db, peer_uin)
    return QueueOut(
        status="matched",
        pair_id=pair.pair_id,
        peer=peer_info,
        expires_at=pair.expires_at,
    )


@router.post("/leave", response_model=LeaveOut)
async def leave(uin: int = Depends(current_uin)) -> LeaveOut:
    """Cancel queueing OR end the active pair (whichever applies). Notifies
    the peer with `random_end` so their UI can fade out cleanly."""
    redis = await get_redis()
    # Try removing from queue first (no-op if not in queue).
    removed = await redis.lrem(_QUEUE_KEY, 0, str(uin))
    if removed:
        return LeaveOut(left=True)
    pair_id = await _is_uin_paired(uin)
    if pair_id is None:
        return LeaveOut(left=False)
    await _end_pair(pair_id, reason="peer_left")
    return LeaveOut(left=True)


@router.post("/skip", response_model=QueueOut)
async def skip(
    uin: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> QueueOut:
    """Atomic 'leave + queue': end the current pair (if any) and immediately
    look for a fresh stranger. Heart of the roulette UX — one tap, new face."""
    # Same age gate as /queue — `skip` is functionally a re-queue, so
    # bypassing the gate here would defeat the protection on the main
    # entry point. Cheap to re-check (single User SELECT).
    user = await db.get(User, uin)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found")
    if user.age is None:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            detail={"code": "age_required"},
        )
    if user.age < 18:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            detail={"code": "under_18"},
        )

    redis = await get_redis()
    pair_id = await _is_uin_paired(uin)
    if pair_id is not None:
        await _end_pair(pair_id, reason="peer_skipped")
    if await _get_daily_count(uin) >= DAILY_MATCH_LIMIT:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "daily random-chat limit reached")
    if await redis.lpos(_QUEUE_KEY, str(uin)) is not None:
        return QueueOut(status="queued")
    pair = await _try_match(uin, db)
    if pair is None:
        await redis.rpush(_QUEUE_KEY, str(uin))
        await _bump_daily(uin)
        return QueueOut(status="queued")
    await _bump_daily(uin)
    await _notify_match(pair, db)
    peer_uin = pair.peer_of(uin)
    peer_info = await _fetch_peer(db, peer_uin)
    return QueueOut(
        status="matched",
        pair_id=pair.pair_id,
        peer=peer_info,
        expires_at=pair.expires_at,
    )


async def on_disconnect(uin: int) -> None:
    """Called from the WS endpoint when a user's last socket goes away. Pulls
    them out of the matching queue and tears down any active pair so the peer
    isn't stuck talking to nobody for the next 5 minutes."""
    redis = await get_redis()
    await redis.lrem(_QUEUE_KEY, 0, str(uin))
    pair_id = await _is_uin_paired(uin)
    if pair_id is not None:
        await _end_pair(pair_id, reason="peer_disconnected")


async def expire_loop() -> None:
    """Background task — sweeps expired pairs every 30s. Leader-elected
    via Redis SETNX so only one worker per cluster runs the sweep at a
    time. Followers idle quietly until they win the lock (i.e. the
    leader dies / restarts).

    Sweep is O(log n + k) — ZRANGEBYSCORE with score ≤ now returns
    only the expired pair_ids; we don't scan the full active set.
    """
    is_leader = False
    while True:
        try:
            if not is_leader:
                # Try to claim the leader lock. If we win, run the sweep
                # this tick. If we lose, idle for the renew window then
                # try again — the eventual winner will take over within
                # ~LEADER_TTL_SECONDS of the previous leader dying.
                is_leader = await acquire_leadership(_EXPIRE_LEADER_ROLE, _WORKER_IDENTITY)
                if not is_leader:
                    await asyncio.sleep(LEADER_RENEW_SECONDS)
                    continue
            else:
                # Refresh our claim so it doesn't expire while we work.
                is_leader = await renew_leadership(_EXPIRE_LEADER_ROLE, _WORKER_IDENTITY)
                if not is_leader:
                    # We lost the lock (could happen if we paused past
                    # the TTL). Skip this tick and re-acquire next.
                    continue

            redis = await get_redis()
            now_ts = datetime.now(timezone.utc).timestamp()
            # Expired pair_ids — score <= now means expires_at has passed.
            expired_ids = await redis.zrangebyscore(_ACTIVE_PAIRS_KEY, "-inf", now_ts)
            for pair_id in expired_ids:
                await _end_pair(pair_id, reason="expired")
        except Exception:  # noqa: BLE001
            # Never let a transient exception kill the sweeper.
            pass
        await asyncio.sleep(30)
