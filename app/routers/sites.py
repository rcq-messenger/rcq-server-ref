"""`.rcq` sites — static bundles this island hosts and serves by name.

Design: `docs/rcq-sites-design.md` (decisions taken 2026-09-01). The short of
it, because it decides everything in this file:

* A site is a **static bundle**. No server-side code, ever - the island stores
  and serves bytes, which is the only shape that keeps a hosting feature from
  becoming an execution feature.
* Reads are **unauthenticated** on purpose. The island must not be able to
  build a "who read what" journal, and asking for a token would be exactly
  that journal. Anonymous reads are why this endpoint has no `current_uin`.
* Writes are authenticated and quota'd, and the operator can freeze a site
  without deleting it, because a complaint arrives before the answer does.
* The name is unique on THIS island only. `blog.is2.rcq` is is2's `blog`, and
  `blog` is free on every other island: there is no registry above the
  islands, and there is deliberately no DNS anywhere.

⚠⚠ This is the first OPEN content we store. Everything else on the island is
sealed and unreadable to it; these bytes are public by definition, and the
operator tools ship with the feature rather than after it.
"""

from __future__ import annotations

import json
import os
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from fastapi.responses import FileResponse, Response
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import get_db
from app.core.rate_limit import rate_limit
from app.core.security import current_uin, require_admin
from app.models.site import Site

router = APIRouter(prefix="/sites", tags=["sites"])
admin_router = APIRouter(prefix="/admin/sites", tags=["sites"], dependencies=[Depends(require_admin)])

#: Where bundles live. Same disk as media, one directory per site.
SITES_ROOT = Path(os.environ.get("RCQ_SITES_DIR", "sites")).resolve()
SITES_ROOT.mkdir(parents=True, exist_ok=True)

#: The free tier from the design doc.
MAX_SITES_PER_UIN = 1
MAX_BUNDLE_BYTES = 20 * 1024 * 1024
MAX_FILE_BYTES = 5 * 1024 * 1024
MAX_FILES = 64

#: Lowercase letters, digits and dashes. Short on purpose: the address is read
#: aloud and typed by hand.
_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")

#: What a bundle may contain. No fonts (an outside font is a fingerprint), no
#: scripts (there is no JS at all), no video (the traffic is somebody else's
#: relay). Everything is served with the type this table says, never with a
#: type the uploader claims.
_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".webp": "image/webp",
    ".svg": "image/svg+xml",
    ".txt": "text/plain; charset=utf-8",
    ".json": "application/json",
}


def _site_dir(name: str) -> Path:
    return SITES_ROOT / name


def _safe_rel(path: str) -> str:
    """A path inside the bundle, or a refusal.

    ⚠ The whole traversal question lives here: `..`, absolute paths, backslash
    tricks and empty segments are refused rather than normalised, because a
    normaliser that is wrong once serves `/etc/passwd`.
    """
    if not path or path.startswith("/") or "\\" in path or ".." in path.split("/"):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail={"code": "bad_path"})
    if len(path) > 200 or any(not seg for seg in path.split("/")):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail={"code": "bad_path"})
    return path


class SiteOut(BaseModel):
    name: str
    owner_uin: int
    version: int
    title: str | None
    size_bytes: int
    listed: bool
    frozen: bool
    updated_at: datetime


class AvailabilityOut(BaseModel):
    name: str
    available: bool
    #: "taken" | "invalid" | "reserved" — never who holds it. A name lookup
    #: must not become a directory of who owns what (design §3.6).
    reason: str | None = None


@router.get("/available/{name}", response_model=AvailabilityOut,
            dependencies=[Depends(rate_limit("site_available", 30, 60))])
async def availability(name: str, db: AsyncSession = Depends(get_db)) -> AvailabilityOut:
    """Is this name free here? Yes/no, and never the owner.

    ⚠ There is deliberately no endpoint that lists every name on the island. A
    site that stayed out of the catalogue is reachable by its exact name and
    listed nowhere - that is its property, and an enumeration would take it
    away. This answers one name at a time, rate-limited, like the UIN check.
    """
    lower = name.strip().lower()
    if not _NAME_RE.match(lower):
        return AvailabilityOut(name=lower, available=False, reason="invalid")
    row = await db.get(Site, lower)
    return AvailabilityOut(name=lower, available=row is None, reason="taken" if row else None)


@router.get("/{name}/manifest.json")
async def manifest(name: str, db: AsyncSession = Depends(get_db)) -> Response:
    """The manifest exactly as the owner signed it.

    Served verbatim - re-serialising it here would change the bytes the
    signature covers, and the reader verifies the signature over exactly what
    the owner produced.
    """
    site = await _live(db, name)
    return Response(content=site.manifest, media_type="application/json")


@router.get("/{name}")
async def index(name: str, db: AsyncSession = Depends(get_db)) -> FileResponse:
    return await file(name, "index.html", db)


@router.get("/{name}/{path:path}")
async def file(name: str, path: str, db: AsyncSession = Depends(get_db)) -> FileResponse:
    """Serve one file. No authentication, by design (see the module docstring).

    ⚠ The Content-Type comes from OUR table, never from the uploader: a bundle
    that could name its own type could serve JavaScript as an image, and the
    whole no-scripts rule rests on the reader trusting what it is handed. The
    CSP header is a second lock on the same door, for readers that open a site
    in an ordinary browser through a gateway.
    """
    site = await _live(db, name)
    rel = _safe_rel(path)
    target = (_site_dir(site.name) / rel).resolve()
    root = _site_dir(site.name).resolve()
    if root not in target.parents and target != root:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail={"code": "bad_path"})
    if not target.is_file():
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail={"code": "no_file"})
    media_type = _TYPES.get(target.suffix.lower())
    if media_type is None:
        raise HTTPException(status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, detail={"code": "bad_type"})
    return FileResponse(
        target,
        media_type=media_type,
        headers={
            "Content-Security-Policy":
                "default-src 'none'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
                "font-src 'none'; script-src 'none'; frame-ancestors *; sandbox",
            "X-Content-Type-Options": "nosniff",
            # The version is in the manifest; a bundle is replaced whole, so a
            # short cache is safe and saves the island the repeat traffic.
            "Cache-Control": "public, max-age=300",
        },
    )


async def _live(db: AsyncSession, name: str) -> Site:
    site = await db.get(Site, name.strip().lower())
    if site is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail={"code": "no_site"})
    if site.frozen:
        # 410, not 404: the reader is told the site exists and is held, which
        # is the honest answer while a complaint is looked at.
        raise HTTPException(status.HTTP_410_GONE, detail={"code": "frozen"})
    return site


@router.put("/{name}", response_model=SiteOut,
            dependencies=[Depends(rate_limit("site_put", 10, 3600))])
async def put_site(
    name: str,
    manifest: str = Form(...),
    owner_key: str = Form(...),
    title: str | None = Form(None),
    listed: bool = Form(False),
    files: list[UploadFile] = File(...),
    me: int = Depends(current_uin),
    db: AsyncSession = Depends(get_db),
) -> SiteOut:
    """Publish a version of a site, whole.

    Atomic by construction: the new bundle is written beside the old one and
    swapped, so a reader never sees half a version and a rollback is a rename.
    """
    lower = name.strip().lower()
    if not _NAME_RE.match(lower):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail={"code": "invalid_name"})
    # ⚠ A name of digits only belongs to the holder of that number. `123456.rcq`
    # is indistinguishable from "the official page of #123456", and that is the
    # one impersonation worth closing with a single line. Letter names stay a
    # common pool - reserving those would be a squatting market.
    if lower.isdigit() and int(lower) != me:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail={"code": "reserved_for_uin"})
    try:
        parsed = json.loads(manifest)
        if not isinstance(parsed, dict):
            raise ValueError
    except ValueError:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail={"code": "bad_manifest"})

    existing = await db.get(Site, lower)
    if existing is not None and int(existing.owner_uin) != me:
        raise HTTPException(status.HTTP_409_CONFLICT, detail={"code": "taken"})
    if existing is not None and existing.frozen:
        raise HTTPException(status.HTTP_410_GONE, detail={"code": "frozen"})
    if existing is None:
        held = await db.scalar(
            select(func.count()).select_from(Site).where(Site.owner_uin == me)
        )
        if (held or 0) >= MAX_SITES_PER_UIN:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                detail={"code": "too_many_sites", "max": MAX_SITES_PER_UIN},
            )
    # ⚠ The key may not change under an existing name. The reader pinned it on
    # their first visit, so a new key is a different site wearing this name -
    # the exact substitution the signature exists to make visible.
    if existing is not None and existing.owner_key != owner_key:
        raise HTTPException(status.HTTP_409_CONFLICT, detail={"code": "key_changed"})
    if len(files) > MAX_FILES:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail={"code": "too_many_files"})

    staging = SITES_ROOT / f".staging-{lower}"
    if staging.exists():
        shutil.rmtree(staging, ignore_errors=True)
    staging.mkdir(parents=True)
    total = 0
    try:
        for f in files:
            rel = _safe_rel((f.filename or "").strip())
            if Path(rel).suffix.lower() not in _TYPES:
                raise HTTPException(status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                                    detail={"code": "bad_type", "file": rel})
            body = await f.read()
            if len(body) > MAX_FILE_BYTES:
                raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                                    detail={"code": "file_too_large", "file": rel})
            total += len(body)
            if total > MAX_BUNDLE_BYTES:
                raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                                    detail={"code": "bundle_too_large", "max": MAX_BUNDLE_BYTES})
            dest = staging / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(body)
        if not (staging / "index.html").is_file():
            raise HTTPException(status.HTTP_400_BAD_REQUEST, detail={"code": "no_index"})
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise

    live = _site_dir(lower)
    previous = SITES_ROOT / f".previous-{lower}"
    shutil.rmtree(previous, ignore_errors=True)
    if live.exists():
        live.rename(previous)
    staging.rename(live)
    shutil.rmtree(previous, ignore_errors=True)

    now = datetime.now(timezone.utc)
    if existing is None:
        site = Site(
            name=lower, owner_uin=me, owner_key=owner_key, version=1,
            manifest=manifest, size_bytes=total, title=title, listed=bool(listed),
            created_at=now, updated_at=now,
        )
        db.add(site)
    else:
        site = existing
        site.version += 1
        site.manifest = manifest
        site.size_bytes = total
        site.title = title
        site.listed = bool(listed)
        site.updated_at = now
    await db.commit()
    await db.refresh(site)
    return SiteOut(
        name=site.name, owner_uin=site.owner_uin, version=site.version, title=site.title,
        size_bytes=site.size_bytes, listed=site.listed, frozen=site.frozen, updated_at=site.updated_at,
    )


@router.get("", response_model=list[SiteOut])
async def catalogue(db: AsyncSession = Depends(get_db)) -> list[SiteOut]:
    """The catalogue: only sites that ASKED to be in it.

    ⚠ Not "every site on the island" - see `availability` for why that list
    does not exist.
    """
    rows = (
        await db.execute(
            select(Site).where(Site.listed.is_(True), Site.frozen.is_(False))
            .order_by(Site.updated_at.desc()).limit(200)
        )
    ).scalars().all()
    return [
        SiteOut(name=s.name, owner_uin=s.owner_uin, version=s.version, title=s.title,
                size_bytes=s.size_bytes, listed=s.listed, frozen=s.frozen, updated_at=s.updated_at)
        for s in rows
    ]


@router.delete("/{name}")
async def delete_site(
    name: str, me: int = Depends(current_uin), db: AsyncSession = Depends(get_db)
) -> dict:
    """The owner takes their own site down.

    ⚠ Honest wording for the caller: this removes it from THIS island. Readers
    who already have it keep their cached copy, and no server can reach into
    that (design §5).
    """
    site = await db.get(Site, name.strip().lower())
    if site is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail={"code": "no_site"})
    if int(site.owner_uin) != me:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail={"code": "not_owner"})
    shutil.rmtree(_site_dir(site.name), ignore_errors=True)
    await db.delete(site)
    await db.commit()
    return {"ok": True}


@admin_router.get("", response_model=list[SiteOut])
async def admin_list(db: AsyncSession = Depends(get_db)) -> list[SiteOut]:
    """Everything the island hosts, for the person answering for it."""
    rows = (await db.execute(select(Site).order_by(Site.updated_at.desc()))).scalars().all()
    return [
        SiteOut(name=s.name, owner_uin=s.owner_uin, version=s.version, title=s.title,
                size_bytes=s.size_bytes, listed=s.listed, frozen=s.frozen, updated_at=s.updated_at)
        for s in rows
    ]


@admin_router.post("/{name}/freeze", response_model=SiteOut)
async def admin_freeze(name: str, frozen: bool = True, db: AsyncSession = Depends(get_db)) -> SiteOut:
    """Hold a site while a complaint is looked at. Reversible on purpose:
    deleting first and asking later is how an operator loses somebody's work
    over a report that turns out to be wrong."""
    site = await db.get(Site, name.strip().lower())
    if site is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail={"code": "no_site"})
    site.frozen = bool(frozen)
    if site.frozen:
        site.listed = False
    site.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(site)
    return SiteOut(name=site.name, owner_uin=site.owner_uin, version=site.version, title=site.title,
                   size_bytes=site.size_bytes, listed=site.listed, frozen=site.frozen,
                   updated_at=site.updated_at)
