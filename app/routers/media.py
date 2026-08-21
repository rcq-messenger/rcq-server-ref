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

from app.core.rate_limit import rate_limit

router = APIRouter(prefix="/media", tags=["media"])

# TODO(prod): swap to R2/S3 with presigned PUT/GET. For dev, local fs is fine.
MEDIA_ROOT = Path(os.environ.get("RCQ_MEDIA_DIR", "./media/uploads"))
MEDIA_ROOT.mkdir(parents=True, exist_ok=True)

# Per-request cap. 512 MB is 5x the biggest thing any shipped client will
# send (the web caps documents at 100 MB); the old 2 GB "backstop" was a
# free disk-fill lever on an unauthenticated endpoint. Env-tunable for a
# self-host that wants different economics.
MAX_BLOB_SIZE = int(os.environ.get("RCQ_MEDIA_MAX_BLOB_MB", "512")) * 1024 * 1024

_CHUNK = 1024 * 1024

# Uploads stay tokenless (sealed sender: the blob must not be attributable
# to an account), so the limiter binds per-UIN only when a client happens to
# attach a token and per-IP otherwise. The ceiling is set for a HUMAN burst
# (an album, a voice-note streak) with carrier CGNAT sharing one IP in
# mind — it exists to stop scripted flooding, not to meter people.
_UPLOAD_RATE = rate_limit("media_upload", 240, 600)


async def _stream_to(target: Path, blob: UploadFile) -> int:
    """Stream the body to `target` in chunks, enforcing MAX_BLOB_SIZE while
    reading. The old `await blob.read()` slurped the whole body into RAM
    BEFORE checking the cap — a 2 GB request was a 2 GB allocation, times
    four workers. Writes to a temp path and renames so a client that dies
    mid-upload never leaves a half blob under a servable name."""
    # Unique per request: two concurrent deposits of the SAME id must not
    # interleave into one temp file. The winner's rename lands last; the
    # bytes are identical by contract either way.
    tmp = target.with_suffix(f".{uuid.uuid4().hex[:8]}.part")
    size = 0
    try:
        with open(tmp, "wb") as f:
            while chunk := await blob.read(_CHUNK):
                size += len(chunk)
                if size > MAX_BLOB_SIZE:
                    raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "blob too large")
                f.write(chunk)
        os.replace(tmp, target)
    finally:
        tmp.unlink(missing_ok=True)
    return size


class UploadOut(BaseModel):
    media_id: str
    size: int


@router.post(
    "/upload",
    response_model=UploadOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(_UPLOAD_RATE)],
)
async def upload(
    blob: UploadFile = File(...),
) -> UploadOut:
    """Encrypted blob upload. The blob must already be encrypted client-side;
    the server never decrypts."""
    media_id = uuid.uuid4().hex
    size = await _stream_to(MEDIA_ROOT / f"{media_id}.bin", blob)
    return UploadOut(media_id=media_id, size=size)


@router.put(
    "/{media_id}",
    response_model=UploadOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(_UPLOAD_RATE)],
)
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
    target = MEDIA_ROOT / f"{media_id.lower()}.bin"
    if target.exists():
        return UploadOut(media_id=media_id.lower(), size=target.stat().st_size)
    size = await _stream_to(target, blob)
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
