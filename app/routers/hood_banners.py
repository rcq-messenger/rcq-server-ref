"""District banner board.

Geohash-level-6 buckets (same key the `/nearby` surface uses). A
banner is a short text + optional encrypted blob image, paid for
through a mock IAP receipt and lives for `duration` (1h / 6h / 24h
/ 7d). The list endpoint filters by `expires_at > now` so callers
never see stale rows.

Pricing tiers (USD cents, surface to iOS via /hood/banners/pricing):
    1h  → $0.99
    6h  → $1.99
    24h → $4.99
    7d  → $14.99

`iap_receipt` is currently mocked — any non-empty string is
accepted. Wire StoreKit receipt verification here when launch IAP
config is ready.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import get_db
from app.core.rate_limit import rate_limit
from app.core.security import current_uin
from app.models.hood_banner import HoodBanner
from app.models.user import User

router = APIRouter(prefix="/hood", tags=["hood_banners"])

# Allowed `duration` strings + their TTL.
_DURATIONS: dict[str, timedelta] = {
    "1h": timedelta(hours=1),
    "6h": timedelta(hours=6),
    "24h": timedelta(hours=24),
    "7d": timedelta(days=7),
}

# Display price cents per duration. Kept in sync with the iOS-side
# table so the buy sheet renders the same number the server enforces
# when StoreKit lands. UI fetches this via /hood/banners/pricing.
_PRICES_CENTS: dict[str, int] = {
    "1h": 99,
    "6h": 199,
    "24h": 499,
    "7d": 1499,
}

# Hard ceiling on banners visible in one bucket. Past this we 409 the
# create — keeps the carousel readable.
MAX_BANNERS_PER_BUCKET: int = 5
# Cap on text length. Matches iOS composer enforcement.
MAX_TEXT_LEN: int = 500


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _price_display(cents: int) -> str:
    return f"${cents / 100:.2f}"


class BannerOut(BaseModel):
    id: int
    bucket_id: str
    text: str
    image_url: str | None
    image_thumb_url: str | None
    is_anonymous: bool
    is_mine: bool
    owner_nickname: str | None
    owner_uin: int | None
    duration: str
    created_at: datetime
    expires_at: datetime


class BannerListOut(BaseModel):
    items: list[BannerOut]
    total_active: int
    can_post: bool


class PricingOut(BaseModel):
    duration: str
    label: str
    price_cents: int
    price_display: str


@router.get("/banners/pricing", response_model=list[PricingOut])
async def pricing() -> list[PricingOut]:
    """Static IAP-tier table for the composer. Surfaces the same
    cents the server will validate against the StoreKit receipt
    when that wiring lands."""
    labels = {"1h": "1 hour", "6h": "6 hours", "24h": "24 hours", "7d": "7 days"}
    return [
        PricingOut(
            duration=d,
            label=labels[d],
            price_cents=_PRICES_CENTS[d],
            price_display=_price_display(_PRICES_CENTS[d]),
        )
        for d in ("1h", "6h", "24h", "7d")
    ]


@router.get("/banners/{bucket_id}", response_model=BannerListOut)
async def list_banners(
    bucket_id: str,
    me: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> BannerListOut:
    """Active banners in this bucket, newest first."""
    if not bucket_id or len(bucket_id) > 64:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "bad bucket")
    rows = (await db.execute(
        select(HoodBanner)
        .where(HoodBanner.bucket_id == bucket_id, HoodBanner.expires_at > _now())
        .order_by(HoodBanner.created_at.desc())
        .limit(100)
    )).scalars().all()

    nick_lookup: dict[int, str] = {}
    if rows:
        owners = {r.owner_uin for r in rows if not r.is_anonymous}
        if owners:
            user_rows = (await db.execute(
                select(User.uin, User.nickname).where(User.uin.in_(list(owners)))
            )).all()
            nick_lookup = {int(u.uin): u.nickname for u in user_rows}

    items = [
        BannerOut(
            id=r.id,
            bucket_id=r.bucket_id,
            text=r.text,
            image_url=r.image_url,
            image_thumb_url=r.image_thumb_url,
            is_anonymous=r.is_anonymous,
            is_mine=(r.owner_uin == me),
            owner_nickname=None if r.is_anonymous else nick_lookup.get(r.owner_uin),
            owner_uin=None if r.is_anonymous else r.owner_uin,
            duration=r.duration,
            created_at=r.created_at,
            expires_at=r.expires_at,
        )
        for r in rows
    ]
    return BannerListOut(
        items=items,
        total_active=len(items),
        can_post=len(items) < MAX_BANNERS_PER_BUCKET,
    )


class CreateBannerIn(BaseModel):
    bucket_id: str = Field(min_length=1, max_length=64)
    text: str = Field(min_length=1, max_length=MAX_TEXT_LEN)
    image_url: str | None = Field(default=None, max_length=255)
    image_thumb_url: str | None = Field(default=None, max_length=255)
    is_anonymous: bool = False
    duration: str = Field(min_length=1, max_length=8)
    # Mock IAP receipt — any non-empty string passes today. StoreKit
    # validation slots in here.
    receipt: str = Field(min_length=1)


class CreateBannerOut(BaseModel):
    banner: BannerOut


@router.post(
    "/banners",
    response_model=CreateBannerOut,
    status_code=status.HTTP_201_CREATED,
    # Anti-spam: per-UIN cap. A single account can't carpet-bomb
    # bucket boards even with valid IAP receipts.
    dependencies=[Depends(rate_limit("hood_banner_create", 30, 3600))],
)
async def create_banner(
    body: CreateBannerIn,
    me: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> CreateBannerOut:
    duration = body.duration.strip().lower()
    if duration not in _DURATIONS:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            detail={"code": "bad_duration", "allowed": list(_DURATIONS.keys())},
        )

    # Bucket capacity check.
    active_count = await db.scalar(
        select(HoodBanner.id)
        .where(HoodBanner.bucket_id == body.bucket_id, HoodBanner.expires_at > _now())
        .order_by(HoodBanner.id.desc())
    )
    # active_count is just a probe; count() is the count.
    active_count_full = (await db.execute(
        select(HoodBanner)
        .where(HoodBanner.bucket_id == body.bucket_id, HoodBanner.expires_at > _now())
    )).scalars().all()
    if len(active_count_full) >= MAX_BANNERS_PER_BUCKET:
        raise HTTPException(status.HTTP_409_CONFLICT, detail={"code": "bucket_full"})

    now = _now()
    banner = HoodBanner(
        bucket_id=body.bucket_id,
        owner_uin=me,
        text=body.text.strip(),
        image_url=body.image_url,
        image_thumb_url=body.image_thumb_url,
        is_anonymous=body.is_anonymous,
        duration=duration,
        created_at=now,
        expires_at=now + _DURATIONS[duration],
        iap_receipt=body.receipt,
    )
    db.add(banner)
    await db.commit()
    await db.refresh(banner)

    nick: str | None = None
    if not banner.is_anonymous:
        u = await db.get(User, me)
        nick = u.nickname if u else None

    return CreateBannerOut(
        banner=BannerOut(
            id=banner.id,
            bucket_id=banner.bucket_id,
            text=banner.text,
            image_url=banner.image_url,
            image_thumb_url=banner.image_thumb_url,
            is_anonymous=banner.is_anonymous,
            is_mine=True,
            owner_nickname=nick,
            owner_uin=None if banner.is_anonymous else banner.owner_uin,
            duration=banner.duration,
            created_at=banner.created_at,
            expires_at=banner.expires_at,
        )
    )


@router.delete("/banners/{banner_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_banner(
    banner_id: int,
    me: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
):
    banner = await db.get(HoodBanner, banner_id)
    if banner is None:
        return
    if banner.owner_uin != me:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "not yours")
    await db.execute(delete(HoodBanner).where(HoodBanner.id == banner_id))
    await db.commit()
