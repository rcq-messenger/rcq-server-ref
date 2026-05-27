"""24h ephemeral stories.

The flow:
- Poster: client encrypts media → uploads via `/media/upload` →
  POSTs `/stories` with the resulting `media_id`, key, kind, caption,
  is_anonymous, duration_sec.
- Reader: pulls `/stories/feed` — returns groups of active stories
  for everyone in the reader's contacts list. Within a group,
  stories are ordered oldest → newest. Each story carries a
  `viewed: bool` flag for the reader so the iOS ring can render
  watched vs unwatched segments.
- Reader marks a story watched via `POST /stories/{id}/view` —
  idempotent, bumps `view_count` once.
- Poster sees viewer list via `GET /stories/{id}/viewers` (only the
  owner is allowed; everyone else gets 403).
- Poster deletes a story early via `DELETE /stories/{id}`.

Visibility model: a story is visible to anyone the poster has in
their contacts (i.e. mutual / one-way "Add as contact" already
ran). Anonymous mode hides the byline at the wire level —
`owner_uin` and `owner_nickname` are nulled out for non-owner
viewers when `is_anonymous=true`.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import get_db
from app.core.security import current_uin
from app.models.contact import Contact
from app.models.story import Story, StoryView
from app.models.user import User
from app.services.connection_manager import manager

router = APIRouter(prefix="/stories", tags=["stories"])

# How long a story is visible. Standard 24h.
STORY_TTL_SECONDS = 24 * 60 * 60
# Max active stories per user. Prevents one account from flooding
# every contact's feed. Picked to comfortably cover a heavy-poster
# day (a story every ~80min) without enabling abuse.
STORIES_PER_USER_CAP = 18
# Caption length cap mirroring the column type.
CAPTION_MAX = 280


# ------------------------------------------------------------------
# Pydantic schemas
# ------------------------------------------------------------------


class PostStoryIn(BaseModel):
    media_id: str = Field(..., min_length=1, max_length=64)
    media_kind: str  # "photo" | "video"
    media_key_b64: str = Field(..., min_length=1, max_length=96)
    caption: str | None = Field(default=None, max_length=CAPTION_MAX)
    is_anonymous: bool = False
    duration_sec: int | None = None


class StoryOut(BaseModel):
    """Wire shape. `owner_uin` / `owner_nickname` are nulled for
    non-owner viewers of an anonymous story."""

    id: str
    owner_uin: int | None
    owner_nickname: str | None
    media_id: str
    media_kind: str
    media_key_b64: str
    caption: str | None
    is_anonymous: bool
    duration_sec: int | None
    posted_at: datetime
    expires_at: datetime
    view_count: int
    viewed: bool


class StoryGroupOut(BaseModel):
    """One contact's active stories, ordered oldest → newest."""

    owner_uin: int | None
    owner_nickname: str | None
    is_anonymous: bool  # whether this group is anonymous (per-story honest)
    stories: list[StoryOut]


class FeedOut(BaseModel):
    groups: list[StoryGroupOut]


class ViewerOut(BaseModel):
    viewer_uin: int
    viewer_nickname: str
    viewed_at: datetime


class ViewersOut(BaseModel):
    viewers: list[ViewerOut]


class PostedOut(BaseModel):
    story: StoryOut


# ------------------------------------------------------------------
# Endpoints
# ------------------------------------------------------------------


@router.post("", response_model=PostedOut, status_code=status.HTTP_201_CREATED)
async def post_story(
    body: PostStoryIn,
    db: AsyncSession = Depends(get_db),
    uin: int = Depends(current_uin),
) -> PostedOut:
    if body.media_kind not in ("photo", "video"):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, "media_kind must be photo or video"
        )
    # Per-user cap so a single account can't flood every contact's feed.
    active_count = await db.scalar(
        select(func.count(Story.id))
        .where(Story.owner_uin == uin)
        .where(Story.expires_at > datetime.now(timezone.utc))
    )
    if (active_count or 0) >= STORIES_PER_USER_CAP:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            f"max {STORIES_PER_USER_CAP} active stories per user",
        )
    now = datetime.now(timezone.utc)
    story = Story(
        id=uuid.uuid4().hex,
        owner_uin=uin,
        media_id=body.media_id,
        media_kind=body.media_kind,
        media_key_b64=body.media_key_b64,
        caption=(body.caption or None),
        is_anonymous=body.is_anonymous,
        duration_sec=body.duration_sec,
        posted_at=now,
        expires_at=now + timedelta(seconds=STORY_TTL_SECONDS),
        view_count=0,
    )
    db.add(story)
    await db.commit()
    await db.refresh(story)

    me = await db.get(User, uin)
    out = StoryOut(
        id=story.id,
        owner_uin=uin,
        owner_nickname=me.nickname if me else None,
        media_id=story.media_id,
        media_kind=story.media_kind,
        media_key_b64=story.media_key_b64,
        caption=story.caption,
        is_anonymous=story.is_anonymous,
        duration_sec=story.duration_sec,
        posted_at=story.posted_at,
        expires_at=story.expires_at,
        view_count=story.view_count,
        viewed=True,  # owner has implicitly seen their own
    )
    # Push a WS nudge to every contact so their feed picks up the
    # new story without requiring a foreground refresh. Anonymous
    # stories still nudge — they'd otherwise sit invisible until the
    # next pull.
    await _broadcast_to_contacts(db, uin, {
        "type": "story_posted",
        "story_id": story.id,
        "owner_uin": uin if not story.is_anonymous else None,
    })
    return PostedOut(story=out)


@router.get("/feed", response_model=FeedOut)
async def feed(
    db: AsyncSession = Depends(get_db),
    uin: int = Depends(current_uin),
) -> FeedOut:
    now = datetime.now(timezone.utc)
    # Pull contacts I have. Stories from these UINs are eligible.
    contact_uins = (
        await db.scalars(
            select(Contact.contact_uin)
            .where(Contact.owner_uin == uin)
            .where(Contact.blocked == False)  # noqa: E712
        )
    ).all()
    if not contact_uins:
        return FeedOut(groups=[])
    # Pull active stories from those contacts + the viewer's own.
    eligible = list(contact_uins) + [uin]
    rows = (
        await db.scalars(
            select(Story)
            .where(Story.owner_uin.in_(eligible))
            .where(Story.expires_at > now)
            .order_by(Story.owner_uin, Story.posted_at)
        )
    ).all()
    if not rows:
        return FeedOut(groups=[])
    # Resolve viewed-by-me set in one shot.
    seen_ids = set(
        (
            await db.scalars(
                select(StoryView.story_id)
                .where(StoryView.viewer_uin == uin)
                .where(StoryView.story_id.in_([s.id for s in rows]))
            )
        ).all()
    )
    # Resolve nicknames in one shot.
    user_uins = list({s.owner_uin for s in rows})
    user_rows = (
        await db.scalars(select(User).where(User.uin.in_(user_uins)))
    ).all()
    nick_by_uin = {u.uin: u.nickname for u in user_rows}
    # Group + shape. Anonymous stories from non-owners hide the
    # byline; the viewer themselves always sees their own UIN.
    groups: dict[int, StoryGroupOut] = {}
    for s in rows:
        is_owner = s.owner_uin == uin
        hide = s.is_anonymous and not is_owner
        owner_uin = None if hide else s.owner_uin
        owner_nickname = None if hide else nick_by_uin.get(s.owner_uin)
        # Group key: real UIN for own-or-non-anonymous; per-story id
        # for anonymous-from-others, so each anonymous story gets its
        # own ring (we don't want to bundle multiple anonymous stories
        # from the same poster — that would re-leak the identity).
        key: int = s.owner_uin if not hide else -hash(s.id) & 0x7FFFFFFFFFFFFFFF
        viewed_flag = is_owner or (s.id in seen_ids)
        story_out = StoryOut(
            id=s.id,
            owner_uin=owner_uin,
            owner_nickname=owner_nickname,
            media_id=s.media_id,
            media_kind=s.media_kind,
            media_key_b64=s.media_key_b64,
            caption=s.caption,
            is_anonymous=s.is_anonymous,
            duration_sec=s.duration_sec,
            posted_at=s.posted_at,
            expires_at=s.expires_at,
            view_count=s.view_count,
            viewed=viewed_flag,
        )
        if key not in groups:
            groups[key] = StoryGroupOut(
                owner_uin=owner_uin,
                owner_nickname=owner_nickname,
                is_anonymous=hide,
                stories=[],
            )
        groups[key].stories.append(story_out)
    # Stable order: own group first, then by oldest-unviewed story
    # so contacts with new stories float to the top of the feed.
    def _group_sort_key(g: StoryGroupOut) -> tuple[int, datetime]:
        is_self = g.owner_uin == uin
        unviewed = [s for s in g.stories if not s.viewed]
        first_ts = (
            min(s.posted_at for s in unviewed)
            if unviewed
            else max(s.posted_at for s in g.stories)
        )
        # Self → first, then unviewed-having groups, then fully-viewed.
        bucket = 0 if is_self else (1 if unviewed else 2)
        return (bucket, first_ts)

    ordered = sorted(groups.values(), key=_group_sort_key)
    return FeedOut(groups=ordered)


@router.post("/{story_id}/view")
async def mark_viewed(
    story_id: str,
    db: AsyncSession = Depends(get_db),
    uin: int = Depends(current_uin),
) -> dict:
    s = await db.get(Story, story_id)
    if s is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such story")
    if s.expires_at <= datetime.now(timezone.utc):
        raise HTTPException(status.HTTP_410_GONE, "story expired")
    # Owner views don't bump the count — feels weird to count yourself.
    if s.owner_uin == uin:
        return {"ok": True}
    existing = await db.get(StoryView, (story_id, uin))
    if existing is not None:
        return {"ok": True}  # idempotent
    db.add(StoryView(story_id=story_id, viewer_uin=uin))
    s.view_count = (s.view_count or 0) + 1
    await db.commit()
    return {"ok": True}


@router.get("/{story_id}/viewers", response_model=ViewersOut)
async def list_viewers(
    story_id: str,
    db: AsyncSession = Depends(get_db),
    uin: int = Depends(current_uin),
) -> ViewersOut:
    s = await db.get(Story, story_id)
    if s is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such story")
    if s.owner_uin != uin:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "not your story")
    rows = (
        await db.scalars(
            select(StoryView)
            .where(StoryView.story_id == story_id)
            .order_by(StoryView.viewed_at.desc())
        )
    ).all()
    if not rows:
        return ViewersOut(viewers=[])
    user_rows = (
        await db.scalars(
            select(User).where(User.uin.in_([r.viewer_uin for r in rows]))
        )
    ).all()
    nick_by = {u.uin: u.nickname for u in user_rows}
    return ViewersOut(viewers=[
        ViewerOut(
            viewer_uin=r.viewer_uin,
            viewer_nickname=nick_by.get(r.viewer_uin, str(r.viewer_uin)),
            viewed_at=r.viewed_at,
        )
        for r in rows
    ])


@router.delete("/{story_id}")
async def delete_story(
    story_id: str,
    db: AsyncSession = Depends(get_db),
    uin: int = Depends(current_uin),
) -> dict:
    s = await db.get(Story, story_id)
    if s is None:
        return {"ok": True}  # idempotent
    if s.owner_uin != uin:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "not your story")
    # Cascade kills story_views via FK ON DELETE CASCADE. The blob
    # itself stays on disk — the 24h sweep would have GC'd it on
    # expiry anyway, and a hard sweep here would race with any
    # in-flight readers. The sweep loop also removes orphan blobs.
    await db.delete(s)
    await db.commit()
    await _broadcast_to_contacts(db, uin, {
        "type": "story_deleted",
        "story_id": story_id,
        "owner_uin": uin if not s.is_anonymous else None,
    })
    return {"ok": True}


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------


async def _broadcast_to_contacts(db: AsyncSession, uin: int, packet: dict) -> None:
    """Fan out a WS packet to every UIN that has `uin` in their
    contact list. Used for `story_posted` / `story_deleted` nudges.
    Best-effort — offline contacts will see the change on next
    `/stories/feed` pull anyway."""
    contact_owners = (
        await db.scalars(
            select(Contact.owner_uin)
            .where(Contact.contact_uin == uin)
            .where(Contact.blocked == False)  # noqa: E712
        )
    ).all()
    seen: set[int] = set()
    for owner_uin in contact_owners:
        if owner_uin in seen:
            continue
        seen.add(owner_uin)
        await manager.send(owner_uin, packet)
    # Also self-notify so the poster's own feed refreshes immediately.
    await manager.send(uin, packet)
