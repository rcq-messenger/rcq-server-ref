from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import get_db
from app.core.security import current_uin
from app.models.nearby import NearbyCheckin
from app.models.user import User

router = APIRouter(prefix="/nearby", tags=["nearby"])

# Reasonable TTL bounds for a check-in. Anything below 5 min is too
# short to be useful (network jitter alone would expire it); anything
# above 4 h drifts into "always-on geofence" territory which the
# privacy model deliberately rules out — opt-in must mean *for this
# little while*, not "until I remember".
MIN_TTL = 5 * 60
MAX_TTL = 4 * 60 * 60


class CheckinIn(BaseModel):
    """Body for `POST /nearby/checkin`. The client computes a
    geohash level-6 (~1.2km × 0.6km tile) for its current location
    and sends only that bucket string. Server never sees raw
    coordinates.

    `display_name` is the anonymous label the client picked for
    this Nearby session (e.g. "Wandering Stranger #4982"). It's
    what every other client will see in `/nearby/list` and Hood
    Chat — the user's real nickname is deliberately not
    surfaced. Optional for clients on older builds; the read path
    falls back to the real nickname when null."""

    bucket_id: str = Field(min_length=1, max_length=16)
    ttl_seconds: int = Field(ge=MIN_TTL, le=MAX_TTL)
    display_name: str | None = Field(default=None, max_length=64)


class CheckinOut(BaseModel):
    """Echoed expiry so the client UI can show a countdown without
    having to track the local TTL itself."""

    expires_at: datetime


class NearbyUser(BaseModel):
    """One row in the `/nearby/list` response. Privacy posture:
    when `anonymous` is true the `nickname` field is the
    minted display name (e.g. "Wandering Stranger #4982") and
    the iOS client hides the UIN entirely; when false, the
    user explicitly opted out of anonymous mode and `nickname`
    holds their real account nickname — UIN is fine to surface
    too in that mode. Status icon is always returned. Status
    message / photo / bio / city / age are not — the contract is
    "you see a stranger near you, you can offer to add them,
    beyond that nothing leaks"."""

    uin: int
    nickname: str
    anonymous: bool
    status: str
    # Gender icon hint. Included only when the user's
    # `gender_visibility = "everyone"` — anonymous mode doesn't
    # suppress this on its own; the user explicitly chose to make
    # gender public, so it stays visible in Nearby too. "contacts"
    # and "nobody" visibilities never appear here.
    gender: str | None = None
    bucket_id: str
    expires_at: datetime


@router.post("/checkin", response_model=CheckinOut)
async def checkin(
    body: CheckinIn,
    uin: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> CheckinOut:
    """Register the caller as "looking for nearby people" in the
    given bucket for `ttl_seconds`. Replaces any prior checkin for
    the same uin — moving between cities or extending the timer is
    a single POST, not delete + post.

    Uses Postgres `INSERT ... ON CONFLICT DO UPDATE` rather than
    delete-then-add: with the ORM's deferred unit-of-work, the
    INSERT was being flushed before the DELETE actually hit the
    DB, which raised `UniqueViolationError` on
    `nearby_checkins_uin_key` for any user re-checking-in (e.g.
    moving cities mid-session, or the iOS app's normal "extend
    TTL" cycle). Symptom on the client was a 500 every refresh
    after the first one. Upsert is atomic on a single statement
    so there's no window for the unique constraint to fire."""
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=body.ttl_seconds)
    stmt = (
        pg_insert(NearbyCheckin)
        .values(
            uin=uin,
            bucket_id=body.bucket_id,
            display_name=body.display_name,
            expires_at=expires_at,
        )
        .on_conflict_do_update(
            index_elements=[NearbyCheckin.uin],
            set_={
                "bucket_id": body.bucket_id,
                "display_name": body.display_name,
                "expires_at": expires_at,
            },
        )
    )
    await db.execute(stmt)
    await db.commit()
    # Surface inbound checkins in journalctl so cross-device tests
    # can correlate "uin A is in bucket X" with "uin B is in bucket
    # Y" without us having to ssh in and SELECT * every time.
    print(f"[Nearby] checkin uin={uin} bucket={body.bucket_id} ttl={body.ttl_seconds}s")
    return CheckinOut(expires_at=expires_at)


@router.delete("/checkin", status_code=status.HTTP_204_NO_CONTENT)
async def end_checkin(
    uin: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Pull the caller's checkin row immediately. Used by the iOS
    "I'm done looking" toggle and by the burn-account flow."""
    await db.execute(delete(NearbyCheckin).where(NearbyCheckin.uin == uin))
    await db.commit()


@router.get("/list", response_model=list[NearbyUser])
async def list_nearby(
    bucket: str = Query(min_length=1, max_length=160),
    me: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> list[NearbyUser]:
    """Fetch other users currently checked in to any of the
    given buckets.

    Accepts a comma-separated bucket list: clients ship their own
    geohash plus its eight neighbours so two devices on different
    sides of a tile boundary still find each other (common in
    dense cities — a 1km level-6 tile boundary cuts neighbourhoods
    in half otherwise). Single-bucket queries still work, the
    query just contains one entry.

    Mutual-visibility rule: the caller must themselves have an
    active checkin (anywhere — we don't require they be in the
    bucket they're querying). This blocks a passive sweeper from
    enumerating user lists while invisible — discovery requires
    being discoverable yourself, same trade-off Tinder/Bumble use."""
    now = datetime.now(timezone.utc)
    my_checkin = (
        await db.execute(
            select(NearbyCheckin)
            .where(NearbyCheckin.uin == me)
            .where(NearbyCheckin.expires_at > now)
        )
    ).scalar_one_or_none()
    if my_checkin is None:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "you must be checked in yourself to see nearby users",
        )

    bucket_list = [b.strip() for b in bucket.split(",") if b.strip()]
    if not bucket_list:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, "bucket list is empty"
        )

    rows = (
        await db.execute(
            select(NearbyCheckin, User)
            .join(User, User.uin == NearbyCheckin.uin)
            .where(NearbyCheckin.bucket_id.in_(bucket_list))
            .where(NearbyCheckin.expires_at > now)
            .where(NearbyCheckin.uin != me)
            # Hide users who set themselves to "offline" / invisible.
            # They keep their checkin row (so they can still post in
            # Hood Chat — that's the asymmetric "I want to read/say
            # things but not be on a list" affordance) but they
            # don't appear in anyone's Nearby roster.
            .where(User.status != "offline")
        )
    ).all()
    # Visibility-debug log so the operator can trace why two
    # devices that "should" see each other don't. Compare the
    # caller's bucket list against any concurrent checkins.
    print(
        f"[Nearby] list uin={me} buckets={bucket_list} "
        f"hits={len(rows)} ({[u.uin for _, u in rows]})"
    )
    return [
        NearbyUser(
            uin=u.uin,
            # Anonymous nickname wins when set; null `display_name`
            # means the user opted out of anonymous mode and we
            # surface their real nickname.
            nickname=c.display_name or u.nickname,
            anonymous=c.display_name is not None,
            status=u.status,
            gender=(
                u.gender
                if u.gender and (u.gender_visibility or "nobody") == "everyone"
                else None
            ),
            bucket_id=c.bucket_id,
            expires_at=c.expires_at,
        )
        for c, u in rows
    ]
