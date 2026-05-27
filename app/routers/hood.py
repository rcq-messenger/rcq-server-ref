"""Hood — geohash-bucket public chat.

Sealed-sender deliberately not used: bucket chat is a public surface
(anonymous handle of the sender's choice; server sees `owner_uin`
for moderation, hides it from the response when the sender posts
anonymously). iOS surfaces a permanent "unencrypted" banner in
HoodChatView so the user can't mistake this for a private chat.

Subscription is driven from the WS channel — clients send
`hood_subscribe` + `hood_unsubscribe` payloads to ws.py. This
router owns the in-memory subscriber set + the broadcast helpers
that ws.py calls when handling those events.
"""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import get_db
from app.core.rate_limit import rate_limit
from app.core.redis import get_redis
from app.core.security import current_uin
from app.models.hood_message import HoodMessage
from app.services.connection_manager import manager

router = APIRouter(prefix="/hood", tags=["hood"])

# Hard caps. Each bucket renders the most recent N messages — older
# rows persist in the DB (for moderation / future infinite scroll)
# but don't ship over the wire on /messages.
MAX_FETCH: int = 200
MAX_BODY_LEN: int = 500

# Subscriber state lives in Redis so a user can WS-subscribe on
# worker A and POST /hood/send on worker B without the bucket
# membership going missing. Two keys per user:
#
#   hood:bucket:<bucket>  → Redis SET of subscribed UINs
#   hood:uin:<uin>        → STRING with the bucket the UIN is in
#                           (used by `_bucket_for` + clean-up so
#                            switching buckets removes the old one)
#
# add_subscriber atomically moves the user from any old bucket to
# the new one inside a single MULTI/EXEC; subscribers_for / count
# read SMEMBERS / SCARD directly.

_BUCKET_KEY_PREFIX = "hood:bucket:"
_UIN_KEY_PREFIX = "hood:uin:"


def _bucket_key(bucket: str) -> str:
    return f"{_BUCKET_KEY_PREFIX}{bucket}"


def _uin_key(uin: int) -> str:
    return f"{_UIN_KEY_PREFIX}{uin}"


# ── Subscribe helpers (called from ws.py) ───────────────────────────


async def add_subscriber(uin: int, bucket: str) -> int:
    """Register the UIN as a subscriber for `bucket`. Returns the
    new total count of subscribers. Caller (ws.py) broadcasts a
    `hood_count` event to peers."""
    redis = await get_redis()
    uin_key = _uin_key(uin)
    prev_bucket = await redis.get(uin_key)
    # `redis.get` may return bytes depending on the client decode
    # setting; normalise to str.
    if isinstance(prev_bucket, bytes):
        prev_bucket = prev_bucket.decode()
    pipe = redis.pipeline()
    if prev_bucket and prev_bucket != bucket:
        pipe.srem(_bucket_key(prev_bucket), str(uin))
    pipe.sadd(_bucket_key(bucket), str(uin))
    pipe.set(uin_key, bucket)
    pipe.scard(_bucket_key(bucket))
    results = await pipe.execute()
    count = int(results[-1] or 0)
    return count


async def remove_subscriber(uin: int) -> tuple[str | None, int]:
    """Remove the UIN from whichever bucket it was subscribed to.
    Returns (bucket_id, new_count)."""
    redis = await get_redis()
    uin_key = _uin_key(uin)
    bucket = await redis.get(uin_key)
    if isinstance(bucket, bytes):
        bucket = bucket.decode()
    if not bucket:
        return None, 0
    pipe = redis.pipeline()
    pipe.srem(_bucket_key(bucket), str(uin))
    pipe.delete(uin_key)
    pipe.scard(_bucket_key(bucket))
    results = await pipe.execute()
    count = int(results[-1] or 0)
    return bucket, count


async def subscribers_for(bucket: str) -> list[int]:
    redis = await get_redis()
    members = await redis.smembers(_bucket_key(bucket)) or set()
    out: list[int] = []
    for m in members:
        if isinstance(m, bytes):
            m = m.decode()
        try:
            out.append(int(m))
        except (TypeError, ValueError):
            continue
    return out


# ── DTOs ────────────────────────────────────────────────────────────


class HoodMessageOut(BaseModel):
    id: int
    bucket_id: str
    nickname: str
    owner_uin: int | None
    body: str
    anonymous: bool
    reply_to_id: int | None
    reply_to_nickname: str | None
    reply_to_body: str | None
    deleted: bool
    reactions: dict[str, str]
    created_at: datetime


class HoodListResponse(BaseModel):
    messages: list[HoodMessageOut]
    bucket_count: int


class HoodSendIn(BaseModel):
    body: str = Field(min_length=1, max_length=MAX_BODY_LEN)
    nickname: str = Field(min_length=1, max_length=64)
    anonymous: bool = True
    reply_to_id: int | None = None
    reply_to_nickname: str | None = Field(default=None, max_length=64)
    reply_to_body: str | None = Field(default=None, max_length=160)


class HoodReactIn(BaseModel):
    emoji: str = Field(min_length=1, max_length=8)


# ── Routes ──────────────────────────────────────────────────────────


def _serialize(m: HoodMessage) -> HoodMessageOut:
    reactions = m.reactions if isinstance(m.reactions, dict) else {}
    return HoodMessageOut(
        id=m.id,
        bucket_id=m.bucket_id,
        nickname=m.nickname,
        owner_uin=None if m.anonymous else m.owner_uin,
        body="" if m.deleted_at is not None else m.body,
        anonymous=m.anonymous,
        reply_to_id=m.reply_to_id,
        reply_to_nickname=m.reply_to_nickname,
        reply_to_body=m.reply_to_body,
        deleted=m.deleted_at is not None,
        reactions={k: v for k, v in reactions.items()},
        created_at=m.created_at,
    )


@router.get("/messages", response_model=HoodListResponse)
async def list_messages(
    bucket: str = Query(min_length=1, max_length=64),
    _me: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> HoodListResponse:
    rows = (await db.execute(
        select(HoodMessage)
        .where(HoodMessage.bucket_id == bucket)
        .order_by(HoodMessage.created_at.desc())
        .limit(MAX_FETCH)
    )).scalars().all()
    rows.reverse()  # client wants oldest → newest
    return HoodListResponse(
        messages=[_serialize(m) for m in rows],
        bucket_count=len(await subscribers_for(bucket)),
    )


@router.post(
    "/send",
    response_model=HoodMessageOut,
    dependencies=[Depends(rate_limit("hood_send", 60, 60))],
)
async def send_message(
    body: HoodSendIn,
    me: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> HoodMessageOut:
    """Insert a message and fan out to every subscriber of the bucket
    the sender is currently checked into."""
    bucket = await _bucket_for(me)
    if bucket is None:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail={"code": "not_subscribed"})
    msg = HoodMessage(
        bucket_id=bucket,
        owner_uin=me,
        nickname=body.nickname.strip(),
        body=body.body.strip(),
        anonymous=body.anonymous,
        reply_to_id=body.reply_to_id,
        reply_to_nickname=(body.reply_to_nickname or None),
        reply_to_body=(body.reply_to_body or None),
        reactions={},
    )
    db.add(msg)
    await db.commit()
    await db.refresh(msg)

    payload = _serialize(msg).model_dump(mode="json")
    recipients = await subscribers_for(bucket)
    if recipients:
        count = len(recipients)
        await manager.broadcast(recipients, {
            "type": "hood_message",
            "message": payload,
            "bucket_count": count,
        })
    return _serialize(msg)


@router.delete("/messages/{message_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_message(
    message_id: int,
    me: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
):
    msg = await db.get(HoodMessage, message_id)
    if msg is None or msg.deleted_at is not None:
        return
    if msg.owner_uin != me:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "not yours")
    msg.deleted_at = datetime.now(timezone.utc)
    await db.commit()
    recipients = await subscribers_for(msg.bucket_id)
    if recipients:
        await manager.broadcast(recipients, {
            "type": "hood_delete",
            "bucket_id": msg.bucket_id,
            "message_id": msg.id,
        })


@router.post("/messages/{message_id}/react", status_code=status.HTTP_204_NO_CONTENT)
async def react_to_message(
    message_id: int,
    body: HoodReactIn,
    me: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
):
    """Toggle the caller's UIN in the reaction map for `emoji`. Server
    is the source of truth — the broadcast tells every subscriber the
    new full map so clients converge without local merge logic."""
    msg = await db.get(HoodMessage, message_id)
    if msg is None or msg.deleted_at is not None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such message")
    reactions = dict(msg.reactions) if isinstance(msg.reactions, dict) else {}
    existing = reactions.get(body.emoji, "")
    uins = set(filter(None, existing.split(",")))
    me_str = str(me)
    if me_str in uins:
        uins.discard(me_str)
    else:
        uins.add(me_str)
    if uins:
        reactions[body.emoji] = ",".join(sorted(uins))
    else:
        reactions.pop(body.emoji, None)
    await db.execute(
        update(HoodMessage)
        .where(HoodMessage.id == message_id)
        .values(reactions=reactions)
    )
    await db.commit()
    recipients = await subscribers_for(msg.bucket_id)
    if recipients:
        await manager.broadcast(recipients, {
            "type": "hood_reaction",
            "bucket_id": msg.bucket_id,
            "message_id": message_id,
            "reactions": reactions,
        })


# ── Helpers ─────────────────────────────────────────────────────────


async def _bucket_for(uin: int) -> str | None:
    """Find which bucket `uin` is currently subscribed to (returns
    None if they aren't subscribed anywhere). Reads the Redis
    `hood:uin:<uin>` key, set by `add_subscriber`."""
    redis = await get_redis()
    bucket = await redis.get(_uin_key(uin))
    if isinstance(bucket, bytes):
        bucket = bucket.decode()
    return bucket or None
