"""News broadcasts.

Admin-only write surface (`POST /admin/news`, `POST /admin/news/upload`,
`DELETE /admin/news/{id}`) + a single public read endpoint
(`GET /news`) that every iOS client polls for unread badge state.

Media is stored UNENCRYPTED under `news_media/`. Different model from
chat / story media — those are encrypted per-recipient via the
sealed-sender lane, but news posts are a public broadcast: every user
gets the same bytes, so there's no per-recipient key to escrow.
Served via `GET /news/media/{id}` with no auth.
"""

from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile, status
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import get_db
from app.core.security import require_admin
from app.models.news import NewsPost

public_router = APIRouter(prefix="/news", tags=["news"])
admin_router = APIRouter(prefix="/admin/news", tags=["news"], dependencies=[Depends(require_admin)])

# Filesystem location for news media. Public-readable; served via
# `GET /news/media/{id}`. Created at import so the first post on a
# fresh deploy doesn't crash on the missing directory.
_NEWS_MEDIA_DIR = Path(os.environ.get("RCQ_NEWS_MEDIA_DIR", "news_media")).resolve()
_NEWS_MEDIA_DIR.mkdir(parents=True, exist_ok=True)

# Generous body cap — news posts are typically patch notes, longer
# than a chat message but bounded enough to fit in one screen.
MAX_BODY_LEN: int = 4000
# Single attachment cap. News media is broadcast unencrypted from
# the droplet, so anything past this hits bandwidth-per-user pain
# fast. 50 MB matches the chat free-tier ceiling.
MAX_ATTACHMENT_BYTES: int = 50 * 1024 * 1024
# Up to 4 attachments per post. Past that the feed scrolls.
MAX_ATTACHMENTS: int = 4

ALLOWED_NEWS_MIMES: dict[str, str] = {
    "image/jpeg": ".jpg",
    "image/png": ".png",
    "image/gif": ".gif",
    "image/webp": ".webp",
    "image/heic": ".heic",
    "video/mp4": ".mp4",
    "video/quicktime": ".mov",
    "video/x-m4v": ".m4v",
}


def _kind_for_mime(mime: str) -> str:
    if mime == "image/gif":
        return "gif"
    if mime.startswith("video/"):
        return "video"
    return "image"


# ── DTOs ────────────────────────────────────────────────────────────


class NewsAttachmentIn(BaseModel):
    media_id: str = Field(..., min_length=1, max_length=64)
    mime: str = Field(..., min_length=1, max_length=64)


class NewsAttachmentOut(BaseModel):
    media_id: str
    mime: str
    kind: str  # "image" | "video" | "gif"


class NewsPostOut(BaseModel):
    id: int
    body: str
    attachments: list[NewsAttachmentOut]
    author_label: str
    published_at: datetime


class NewsListOut(BaseModel):
    items: list[NewsPostOut]
    # Server-supplied `latest_id` so the iOS client can compare
    # against its locally-stored `lastReadNewsID` without scanning
    # the list itself. Zero when there are no posts yet.
    latest_id: int


class CreateNewsIn(BaseModel):
    body: str = Field(..., min_length=1, max_length=MAX_BODY_LEN)
    attachments: list[NewsAttachmentIn] = Field(default_factory=list)
    author_label: str | None = Field(default=None, max_length=64)


class UploadMediaOut(BaseModel):
    media_id: str
    mime: str
    kind: str


# ── public read ─────────────────────────────────────────────────────


@public_router.get("", response_model=NewsListOut)
async def list_news(
    limit: int = Query(50, ge=1, le=200),
    since: int = Query(0, ge=0, description="Return posts with id > `since`. 0 = full list."),
    db: AsyncSession = Depends(get_db),
) -> NewsListOut:
    """Public news feed. iOS hits this on app boot + periodically
    via `NewsService` to detect unread posts. The `since` filter
    lets the client request only-new-posts cheaply once it knows
    its last-seen id, though `latest_id` is the authoritative
    badge state."""
    query = select(NewsPost).order_by(NewsPost.published_at.desc()).limit(limit)
    if since > 0:
        query = query.where(NewsPost.id > since)
    rows = (await db.execute(query)).scalars().all()
    latest = (await db.execute(
        select(NewsPost.id).order_by(NewsPost.id.desc()).limit(1)
    )).scalar_one_or_none() or 0
    items = [
        NewsPostOut(
            id=r.id,
            body=r.body,
            attachments=_coerce_attachments(r.attachments),
            author_label=r.author_label,
            published_at=r.published_at,
        )
        for r in rows
    ]
    return NewsListOut(items=items, latest_id=int(latest))


@public_router.get("/media/{media_id}")
async def fetch_news_media(media_id: str) -> FileResponse:
    """Serve a news attachment. No auth — news media is broadcast
    to every user. Path-traversal guard via uuid hex check."""
    try:
        uuid.UUID(hex=media_id)
    except ValueError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such blob")
    # Find file with any allowed extension.
    for ext in ALLOWED_NEWS_MIMES.values():
        target = _NEWS_MEDIA_DIR / f"{media_id}{ext}"
        if target.exists():
            return FileResponse(
                path=target,
                # FastAPI infers media_type from extension; pinning
                # it would require us to track mime separately on
                # the FS, which is cheap to skip.
            )
    raise HTTPException(status.HTTP_404_NOT_FOUND, "no such blob")


# ── admin write ─────────────────────────────────────────────────────


@admin_router.post("/upload", response_model=UploadMediaOut, status_code=status.HTTP_201_CREATED)
async def upload_news_media(
    blob: UploadFile = File(...),
) -> UploadMediaOut:
    """Admin uploads a single attachment. Returns the `media_id` to
    paste into `POST /admin/news`'s attachments array. Files are
    stored unencrypted under `news_media/`."""
    mime = blob.content_type or "application/octet-stream"
    if mime not in ALLOWED_NEWS_MIMES:
        raise HTTPException(
            status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail={"code": "unsupported_mime", "mime": mime},
        )
    ext = ALLOWED_NEWS_MIMES[mime]

    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = await blob.read(256 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > MAX_ATTACHMENT_BYTES:
            raise HTTPException(
                status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail={"code": "too_large", "max_bytes": MAX_ATTACHMENT_BYTES},
            )
        chunks.append(chunk)
    payload = b"".join(chunks)
    if not payload:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "empty upload")

    file_id = str(uuid.uuid4())
    target = _NEWS_MEDIA_DIR / f"{file_id}{ext}"
    try:
        target.write_bytes(payload)
    except OSError as exc:
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"code": "write_failed", "error": str(exc)},
        )
    return UploadMediaOut(media_id=file_id, mime=mime, kind=_kind_for_mime(mime))


@admin_router.post("", response_model=NewsPostOut, status_code=status.HTTP_201_CREATED)
async def create_news_post(
    body: CreateNewsIn,
    db: AsyncSession = Depends(get_db),
) -> NewsPostOut:
    if len(body.attachments) > MAX_ATTACHMENTS:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            detail={"code": "too_many_attachments", "max": MAX_ATTACHMENTS},
        )
    attachments_payload = [
        {"media_id": a.media_id, "mime": a.mime, "kind": _kind_for_mime(a.mime)}
        for a in body.attachments
    ]
    post = NewsPost(
        body=body.body.strip(),
        attachments=attachments_payload or None,
        author_label=(body.author_label or "RCQ Team").strip() or "RCQ Team",
    )
    db.add(post)
    await db.commit()
    await db.refresh(post)
    return NewsPostOut(
        id=post.id,
        body=post.body,
        attachments=_coerce_attachments(post.attachments),
        author_label=post.author_label,
        published_at=post.published_at,
    )


@admin_router.get("", response_model=NewsListOut)
async def admin_list_news(
    limit: int = Query(100, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
) -> NewsListOut:
    rows = (await db.execute(
        select(NewsPost).order_by(NewsPost.published_at.desc()).limit(limit)
    )).scalars().all()
    latest = (await db.execute(
        select(NewsPost.id).order_by(NewsPost.id.desc()).limit(1)
    )).scalar_one_or_none() or 0
    items = [
        NewsPostOut(
            id=r.id,
            body=r.body,
            attachments=_coerce_attachments(r.attachments),
            author_label=r.author_label,
            published_at=r.published_at,
        )
        for r in rows
    ]
    return NewsListOut(items=items, latest_id=int(latest))


@admin_router.delete("/{post_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_news_post(
    post_id: int,
    db: AsyncSession = Depends(get_db),
):
    post = await db.get(NewsPost, post_id)
    if post is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such post")
    # Unlink attachment files alongside the row delete. Best-effort:
    # a stray FS file outliving its row is harmless (404 on fetch).
    for att in _coerce_attachments(post.attachments):
        for ext in ALLOWED_NEWS_MIMES.values():
            target = _NEWS_MEDIA_DIR / f"{att.media_id}{ext}"
            if target.exists():
                try:
                    target.unlink()
                except OSError:
                    pass
    await db.delete(post)
    await db.commit()


# ── helpers ─────────────────────────────────────────────────────────


def _coerce_attachments(raw) -> list[NewsAttachmentOut]:
    if not raw or not isinstance(raw, list):
        return []
    out: list[NewsAttachmentOut] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        media_id = item.get("media_id")
        mime = item.get("mime") or ""
        if not isinstance(media_id, str) or not isinstance(mime, str):
            continue
        out.append(NewsAttachmentOut(
            media_id=media_id,
            mime=mime,
            kind=item.get("kind") or _kind_for_mime(mime),
        ))
    return out
