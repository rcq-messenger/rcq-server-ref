"""Encrypted blob storage. The client encrypts media before upload, so the server
sees only opaque bytes — content type, dimensions, anything visual is invisible to us.

Storage: local filesystem under `./media/uploads/{uuid}.bin`. Production migration to
R2/S3 is straightforward — swap the file open/read for an S3 client. Marked TODO.
"""
from __future__ import annotations

import os
import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from fastapi.responses import FileResponse
from pydantic import BaseModel

router = APIRouter(prefix="/media", tags=["media"])

# TODO(prod): swap to R2/S3 with presigned PUT/GET. For dev, local fs is fine.
MEDIA_ROOT = Path(os.environ.get("RCQ_MEDIA_DIR", "./media/uploads"))
MEDIA_ROOT.mkdir(parents=True, exist_ok=True)

# Absolute safety cap. Hard disk / bandwidth backstop so a single
# request can't take the host out.
MAX_BLOB_SIZE = 2 * 1024 * 1024 * 1024


class UploadOut(BaseModel):
    media_id: str
    size: int


@router.post("/upload", response_model=UploadOut, status_code=status.HTTP_201_CREATED)
async def upload(
    blob: UploadFile = File(...),
) -> UploadOut:
    """Encrypted blob upload. The blob must already be encrypted client-side;
    the server never decrypts."""
    contents = await blob.read()
    size = len(contents)

    if size > MAX_BLOB_SIZE:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "blob too large")

    media_id = uuid.uuid4().hex
    target = MEDIA_ROOT / f"{media_id}.bin"
    with open(target, "wb") as f:
        f.write(contents)
    return UploadOut(media_id=media_id, size=size)


@router.put("/{media_id}", response_model=UploadOut, status_code=status.HTTP_201_CREATED)
async def deposit(
    media_id: str,
    blob: UploadFile = File(...),
) -> UploadOut:
    """Cross-island blob deposit (federation): the CLIENT supplies the id, so
    one envelope's media reference resolves on every island the sender deposits
    the blob to (own island for carbons + the recipient's island). Same trust
    model as the open envelope deposit — the blob is client-side encrypted.

    First write wins: re-depositing an existing id is an idempotent success,
    never an overwrite (ids are uuid4 hex, unguessable)."""
    try:
        uuid.UUID(hex=media_id)
    except ValueError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "bad media id")
    contents = await blob.read()
    size = len(contents)
    if size > MAX_BLOB_SIZE:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "blob too large")

    target = MEDIA_ROOT / f"{media_id.lower()}.bin"
    if target.exists():
        return UploadOut(media_id=media_id.lower(), size=target.stat().st_size)
    with open(target, "wb") as f:
        f.write(contents)
    return UploadOut(media_id=media_id.lower(), size=size)


@router.get("/{media_id}")
async def fetch(media_id: str) -> FileResponse:
    # Reject anything that doesn't look like a uuid hex. Avoids path traversal.
    try:
        uuid.UUID(hex=media_id)
    except ValueError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such blob")
    target = MEDIA_ROOT / f"{media_id}.bin"
    if not target.exists():
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such blob")
    return FileResponse(
        path=target,
        media_type="application/octet-stream",
        filename=f"{media_id}.bin",
    )
