"""Encrypted blob storage. The client encrypts media before upload, so the server
sees only opaque bytes — content type, dimensions, anything visual is invisible to us.

Storage: local filesystem under `./media/uploads/{uuid}.bin`. Production migration to
R2/S3 is straightforward — swap the file open/read for an S3 client. Marked TODO.
"""
from __future__ import annotations

import errno
import hashlib
import os
import re
import uuid
from email.utils import formatdate
from pathlib import Path
from typing import Callable, Mapping

import anyio
from fastapi import APIRouter, Depends, File, HTTPException, Request, Response, UploadFile, status
from fastapi.responses import FileResponse
from fastapi.routing import APIRoute
from pydantic import BaseModel
from starlette.types import Receive, Scope, Send

from app.core.rate_limit import rate_limit

# TODO(prod): swap to R2/S3 with presigned PUT/GET. For dev, local fs is fine.
MEDIA_ROOT = Path(os.environ.get("RCQ_MEDIA_DIR", "./media/uploads"))
MEDIA_ROOT.mkdir(parents=True, exist_ok=True)

# Per-request cap. 512 MB is 5x the biggest thing any shipped client will
# send (the web caps documents at 100 MB); the old 2 GB "backstop" was a
# free disk-fill lever on an unauthenticated endpoint. Env-tunable for a
# self-host that wants different economics.
MAX_BLOB_SIZE = int(os.environ.get("RCQ_MEDIA_MAX_BLOB_MB", "512")) * 1024 * 1024

_CHUNK = 1024 * 1024

# What an upload body may carry on top of the blob: the multipart boundary
# lines and the part's own headers, a few hundred bytes from every shipped
# client. Generous on purpose, because the early refusal below must never be
# the one that turns away a blob of exactly MAX_BLOB_SIZE; `_stream_to` still
# holds the blob itself to the exact cap.
_FORM_SLACK = 64 * 1024

# Uploads stay tokenless (sealed sender: the blob must not be attributable
# to an account), so the limiter binds per-UIN only when a client happens to
# attach a token and per-IP otherwise. The ceiling is set for a HUMAN burst
# (an album, a voice-note streak) with carrier CGNAT sharing one IP in
# mind — it exists to stop scripted flooding, not to meter people.
_UPLOAD_RATE = rate_limit("media_upload", 240, 600)


def _body_ceiling() -> int:
    # Read per request rather than frozen at import, like every other use of
    # MAX_BLOB_SIZE here.
    return MAX_BLOB_SIZE + _FORM_SLACK


def _too_large() -> HTTPException:
    # `Connection: close` so the server stops taking the rest of a body it has
    # already refused. Without it uvicorn keeps the connection for reuse and
    # first reads the remainder off the socket, so a 2 GB upload still crossed
    # the wire in full only to be thrown away.
    return HTTPException(
        status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "blob too large", headers={"Connection": "close"}
    )


class _CappedRequest(Request):
    """A request whose body stops at `_body_ceiling()`.

    For a body that declares no length (chunked), counting it is the only
    early answer there is. FastAPI hands the whole stream to the multipart
    parser, which spools it to a temp file, and nothing the endpoint does can
    run before that has finished."""

    async def stream(self):  # type: ignore[override]
        seen = 0
        ceiling = _body_ceiling()
        async for chunk in super().stream():
            seen += len(chunk)
            if seen > ceiling:
                raise _too_large()
            yield chunk


class _CappedBodyRoute(APIRoute):
    """The early 413 on the two upload routes (`/media` is the only router
    that takes a body this large, and its GET has none to cap).

    ⚠ It cannot be a dependency. FastAPI parses a form body, spooling the file
    part to disk, BEFORE it solves a single dependency (the rate limiter
    included), so a check written as one runs once the whole body has already
    arrived, which is what the size check in `_stream_to` always did. A route
    class runs before FastAPI touches the body: a declared Content-Length over
    the ceiling is refused without reading a byte of it, and a body without
    one is counted as it streams (`_CappedRequest`)."""

    def get_route_handler(self) -> Callable:
        handler = super().get_route_handler()

        async def capped(request: Request) -> Response:
            try:
                declared = int(request.headers.get("content-length", ""))
            except ValueError:
                declared = None
            if declared is not None and declared > _body_ceiling():
                raise _too_large()
            return await handler(_CappedRequest(request.scope, request.receive))

        return capped


router = APIRouter(prefix="/media", tags=["media"], route_class=_CappedBodyRoute)

# `link` refusing on a filesystem that has no hard links at all, as opposed
# to refusing because the name exists. Linux says EPERM (vfat), the rest of
# the list is what FUSE and network mounts answer.
_NO_HARD_LINKS = {errno.EPERM, errno.ENOTSUP, errno.EOPNOTSUPP, errno.ENOSYS}


async def _stream_to(target: Path, blob: UploadFile) -> int:
    """Copy the form's file part to `target` in chunks, holding it to
    MAX_BLOB_SIZE. The old `await blob.read()` slurped the whole blob into RAM
    BEFORE checking the cap — a 2 GB request was a 2 GB allocation, times four
    workers.

    ⚠ This is NOT where an oversize upload is first refused, whatever this
    comment used to say about enforcing the cap while the body streamed: by
    the time an endpoint runs, FastAPI has already received the whole body
    and spooled the part to a temp file. `_CappedBodyRoute` refuses early;
    this check is the exact one, on the blob's own bytes without the form
    framing.

    Writes to a temp path and LINKS it into place, so a client that dies
    mid-upload never leaves a half blob under a servable name, and the first
    complete copy of an id wins: `os.link` refuses a name that exists, where
    the old `os.replace` overwrote it. That matters on PUT, whose id the
    client picks. Two deposits of one id are NOT byte-identical (an RCQM1
    re-send seals under a fresh nonce prefix, at the same size), so last
    write wins swapped the blob under a reader, and a download resumed with
    Range could splice the head of one copy onto the tail of the other."""
    # Unique per request: two concurrent deposits of the SAME id must not
    # interleave into one temp file.
    tmp = target.with_suffix(f".{uuid.uuid4().hex[:8]}.part")
    size = 0
    try:
        with open(tmp, "wb") as f:
            while chunk := await blob.read(_CHUNK):
                size += len(chunk)
                if size > MAX_BLOB_SIZE:
                    raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "blob too large")
                f.write(chunk)
        try:
            os.link(tmp, target)
        except FileExistsError:
            # A concurrent deposit of this id finished first and its bytes
            # stand. Answer with what is stored, not with what this one sent.
            size = target.stat().st_size
        except OSError as exc:
            if exc.errno not in _NO_HARD_LINKS:
                raise
            # A mount without hard links (some FUSE and network filesystems a
            # self-hoster may keep media on): the old rename, last write wins,
            # rather than every upload failing on such a mount.
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
    never an overwrite (ids are uuid4 hex, unguessable), and since
    `_stream_to` links rather than renames that holds for two deposits racing
    each other too."""
    try:
        uuid.UUID(hex=media_id)
    except ValueError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "bad media id")
    target = MEDIA_ROOT / f"{media_id.lower()}.bin"
    if target.exists():
        return UploadOut(media_id=media_id.lower(), size=target.stat().st_size)
    size = await _stream_to(target, blob)
    return UploadOut(media_id=media_id.lower(), size=size)


# One range: `bytes=S-E`, `bytes=S-` or the suffix `bytes=-N`. A list of
# ranges is served whole: nothing RCQ ships asks for one, and multipart/
# byteranges would be a second response format with no reader. 19 digits is
# as far as a file offset goes; anything longer is not a range, it is noise.
_RANGE_RE = re.compile(r"(?i)bytes=(\d{1,19})?-(\d{1,19})?")
_UNSATISFIABLE = (-1, -1)


def _requested_range(value: str, size: int) -> tuple[int, int] | None:
    """The byte range a `Range` header asks for as (first, last), inclusive,
    clamped to the blob; `_UNSATISFIABLE` when it starts at or past the end;
    None for anything to ignore and answer with the whole blob (malformed,
    several ranges, a last byte before the first), which RFC 9110 allows."""
    m = _RANGE_RE.fullmatch(value.strip())
    if m is None or (m.group(1) is None and m.group(2) is None):
        return None
    if m.group(1) is None:
        n = int(m.group(2))
        if n == 0 or size == 0:
            return _UNSATISFIABLE
        return (max(0, size - n), size - 1)
    first = int(m.group(1))
    last = None if m.group(2) is None else int(m.group(2))
    if last is not None and last < first:
        return None
    if first >= size:
        return _UNSATISFIABLE
    return (first, size - 1 if last is None else min(last, size - 1))


def _etag(st: os.stat_result) -> str:
    """A strong validator for exactly these bytes: inode, size and mtime to
    the nanosecond, hashed. ⚠ Not the id and the size: two encodings of one
    id have the same size (an RCQM1 re-send differs in its nonce prefix
    only), so a resume keyed on those could splice two different blobs.
    Hashed so the header carries neither an inode number nor a nanosecond
    clock reading."""
    raw = f"{st.st_ino}:{st.st_size}:{st.st_mtime_ns}".encode()
    return '"' + hashlib.blake2b(raw, digest_size=12).hexdigest() + '"'


class _RangeResponse(Response):
    """206 Partial Content: bytes [first, last] of a file, read from an offset
    in 64 KiB pieces. Built like Starlette's own FileResponse, which in the
    Starlette this island pins (0.38, under fastapi 0.115) always starts at
    byte 0 and never reads Range; Range arrived in 0.39."""

    chunk_size = 64 * 1024

    def __init__(self, path: Path, first: int, last: int, size: int, headers: Mapping[str, str]) -> None:
        self.path = path
        self.first = first
        self.length = last - first + 1
        self.status_code = status.HTTP_206_PARTIAL_CONTENT
        self.media_type = "application/octet-stream"
        self.background = None
        self.init_headers({
            **headers,
            "content-range": f"bytes {first}-{last}/{size}",
            "content-length": str(self.length),
        })

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        await send({"type": "http.response.start", "status": self.status_code, "headers": self.raw_headers})
        async with await anyio.open_file(self.path, mode="rb") as f:
            await f.seek(self.first)
            left = self.length
            while left > 0:
                chunk = await f.read(min(self.chunk_size, left))
                if not chunk:
                    # Shorter than its stat said, which a blob linked into
                    # place never becomes. Stop short: the server closes the
                    # connection on the missing bytes and the reader retries.
                    return
                left -= len(chunk)
                await send({"type": "http.response.body", "body": chunk, "more_body": left > 0})


@router.get("/{media_id}")
async def fetch(media_id: str, request: Request) -> Response:
    """The blob, verbatim, or one byte range of it (spec §9.3).

    A download cut at byte N used to cost the whole file again: this answered
    `Range` with a 200 and every byte from the start, so a 105 MB file on a
    shaky network was 105 MB per attempt (report 1080). Now a single range
    gets 206 with `Content-Range`, a range starting past the end gets 416,
    and `If-Range` holding anything but the current ETag gets the whole blob,
    so a reader can never stitch two different blobs together. Every answer
    says `Accept-Ranges: bytes` and carries the ETag. A plain GET is still a
    FileResponse, byte for byte what it always was."""
    # Reject anything that doesn't look like a uuid hex. Avoids path traversal.
    try:
        uuid.UUID(hex=media_id)
    except ValueError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such blob")
    target = MEDIA_ROOT / f"{media_id}.bin"
    try:
        st = target.stat()
    except FileNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such blob")
    etag = _etag(st)
    headers = {
        "accept-ranges": "bytes",
        "etag": etag,
        "last-modified": formatdate(st.st_mtime, usegmt=True),
    }
    wanted = None
    if (rng := request.headers.get("range")) is not None:
        # Only the strong tag itself matches. A weak tag or a date names
        # "about this version", and a resume needs these exact bytes.
        if_range = request.headers.get("if-range")
        if if_range is None or if_range.strip() == etag:
            wanted = _requested_range(rng, st.st_size)
    if wanted is None:
        return FileResponse(
            path=target,
            media_type="application/octet-stream",
            filename=f"{media_id}.bin",
            stat_result=st,
            headers=headers,
        )
    if wanted == _UNSATISFIABLE:
        return Response(
            status_code=status.HTTP_416_REQUESTED_RANGE_NOT_SATISFIABLE,
            headers={**headers, "content-range": f"bytes */{st.st_size}"},
        )
    return _RangeResponse(
        target, wanted[0], wanted[1], st.st_size,
        headers={**headers, "content-disposition": f'attachment; filename="{media_id}.bin"'},
    )
