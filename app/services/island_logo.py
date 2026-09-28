"""The island's logo: validation, storage and the run-hot read.

One picture per island, set by its operator from the admin console (Features →
Branding, next to the island's name and welcome text). Clients draw it wherever
they name the island and fall back to the lettered tile they already draw when
there is none.

⚠ THE SIZE CAP IS 64 KB of image, and it is a real refusal, not a truncation.
Where it comes from:

  * the biggest slot any client draws this in is about 96 px (the iOS switcher
    pill is 28 pt, an Android switcher row 30 dp, the island card in Settings
    40 px). A 256x256 PNG of a flat mark is 10-20 KB; 64 KB leaves room for a
    photographic JPEG or a small animated GIF at that size and still refuses a
    camera original;
  * every uvicorn worker holds the current logo in memory (see the cache
    below), so the cap is also a per-worker RAM figure: 4 workers x 64 KB is a
    quarter of a megabyte, and a megabyte cap would have been four;
  * it is served once per client per change and then cached for a day, so the
    bytes are a one-off cost, not a per-connect one.

Above the cap the admin endpoint refuses with 400 and stores nothing: the
island keeps whatever logo it already had, and the operator is told the limit
and the size they sent. Nothing is scaled or cropped server-side and nothing
is truncated -- a truncated data URI is an unopenable image, which is exactly
the broken picture this feature is not allowed to produce. The admin console
downscales to 256x256 in the browser before it sends, so a normal file never
reaches the cap in the first place.

⚠ THE BYTES DO NOT RIDE ON `/server/info`. That reply is fetched on every
connect, by every client, for every account, AND by the cross-island paths
before a key lookup or a call (see `services/crossisland*` on the clients, and
the note in web-chat's signal-device.ts about awaiting it under the
provisioning lock). What rides there is `logo_version`, a 12-character digest;
the picture itself is one unauthenticated `GET /server/logo` that the client
caches by that version. See routers/server.py.
"""
import hashlib
import asyncio
import time as _time
from base64 import b64decode
from typing import Optional

from sqlalchemy import delete, select

from app.core import db_nesting
from app.core.db import SessionLocal
from app.core.single_flight import SingleFlight
from app.models.island_logo import IslandLogo

# The only row this table ever has.
ROW_ID = 1

#: Hard ceiling on the decoded image, in bytes. See the module docstring.
MAX_LOGO_BYTES = 64 * 1024

#: What a client can actually draw on all four platforms. GIF is in because an
#: operator may well want an animated mark and the web/desktop render it
#: natively; the phones fall back to its first frame, which they already do for
#: an animated account avatar.
ALLOWED_MIMES = ("image/png", "image/jpeg", "image/webp", "image/gif")

#: Generous ceiling on the *encoded* form, checked before base64 is decoded so
#: a multi-megabyte body is refused without allocating its decoded twin.
#: base64 costs 4/3 plus the `data:image/webp;base64,` preamble.
_MAX_DATA_URI_CHARS = (MAX_LOGO_BYTES * 4) // 3 + 64


class LogoTooLarge(ValueError):
    """The image is over `MAX_LOGO_BYTES`. Carries the size so the operator is
    told what they sent, not just what the limit is."""

    def __init__(self, size: int) -> None:
        super().__init__(
            f"logo is {size} bytes; this island accepts up to {MAX_LOGO_BYTES}"
        )
        self.size = size


def parse_data_uri(raw: str) -> tuple[str, bytes]:
    """`data:image/png;base64,<b64>` -> (mime, bytes), or ValueError.

    Same shape as `_validate_hof_avatar` in routers/users.py, which is the
    other place this codebase takes a picture as a data URI from a browser.
    The mime is taken from the URI and checked against the allow-list rather
    than sniffed: it is echoed back as the Content-Type of a public endpoint,
    so it must be a value we chose, never one the caller did.
    """
    raw = (raw or "").strip()
    if len(raw) > _MAX_DATA_URI_CHARS:
        # Refused on the encoded length so we never decode a body that cannot
        # possibly fit. The reported size is the decoded one it would have had.
        raise LogoTooLarge((len(raw) * 3) // 4)
    if not raw.startswith("data:") or ";base64," not in raw:
        raise ValueError("logo must be a base64 image data URI")
    header, b64 = raw.split(";base64,", 1)
    mime = header[len("data:"):].strip().lower()
    if mime not in ALLOWED_MIMES:
        raise ValueError(
            "unsupported image type; use " + ", ".join(ALLOWED_MIMES)
        )
    try:
        blob = b64decode(b64, validate=True)
    except Exception:  # noqa: BLE001
        raise ValueError("logo is not valid base64")
    if not blob:
        raise ValueError("logo is empty")
    if len(blob) > MAX_LOGO_BYTES:
        raise LogoTooLarge(len(blob))
    return mime, blob


def version_of(mime: str, blob: bytes) -> str:
    """Short digest that identifies this exact picture. Rides on
    `/server/info` and doubles as the ETag, so it has to change whenever a
    single byte does -- and whenever the mime does, which is why it is in the
    hash even though a change of type without a change of bytes is not a thing
    that happens in practice."""
    h = hashlib.sha256()
    h.update(mime.encode())
    h.update(b"\x00")
    h.update(blob)
    return h.hexdigest()[:12]


class _Cache:
    """The current logo, held per worker.

    Same shape and the same reasoning as `services/server_settings._Cache`: a
    write on one worker is visible everywhere within about `_TTL` (the
    lifespan ticker re-reads it on a clock), and the writing worker sees it at
    once (`reload()` after the admin's commit). A logo is the definition of a
    value that tolerates a few seconds of lag, and `/server/info` must not pay
    a DB read for it.

    `at` is when the last successful load started (`<= 0`: never read, or
    invalidated by a test; the next reader waits for a fresh one); `row` is
    `(mime, blob, version)` or None for "this island has no logo", which is a
    real answer and is cached like any other. There is no hard age cap here
    as there is for the settings: a stale logo decides nothing.

    ⚠ `loaded` is what tells that real answer apart from "never read". Both
    have `row` None, and before this flag a cold worker whose first read
    failed published `logo_version: ""`, which every client caches as "this
    island has no logo" and draws the lettered tile for, on an island that
    has one. /server/info now refuses (503) until the logo is loaded.
    """

    row: Optional[tuple[str, bytes, str]] = None
    at: float = -1e9
    loaded: bool = False
    #: Bumped by `store`, `clear` and `reload`; see server_settings._Cache.gen.
    gen: int = 0
    #: See server_settings._Cache.retry_at: counted from the failure.
    retry_at: float = 0.0
    failing: bool = False


_cache = _Cache()
_TTL = 5.0  # seconds
_RETRY_AFTER = 2.0
# A read's own deadline, see server_settings._READ_DEADLINE.
_READ_DEADLINE = 10.0
#: See server_settings._COLD_WAIT.
_COLD_WAIT = 2.0
_flight = SingleFlight("island-logo")


def _bust() -> None:
    """A write is on its way (`store`, `clear`): a refresh already in flight
    may have read the table before it, so its answer is thrown away. Not an
    invalidation, for the reason in server_settings.apply; `reload()` after
    the commit is what publishes the new logo."""
    _cache.gen += 1


async def _read_row(known_version: Optional[str]) -> tuple[bool, Optional[tuple[str, bytes, str]]]:
    """`(changed, row)`. Reads the 12-character version first and the picture
    only when that differs from what this worker holds, so the refresh every
    `_TTL` seconds moves a dozen bytes instead of up to 64 KB per worker."""
    async with SessionLocal() as db:
        version = await db.scalar(select(IslandLogo.version).where(IslandLogo.id == ROW_ID))
        if version is not None and version == known_version:
            return False, None
        if version is None:
            return True, None
        row = (
            await db.execute(
                select(IslandLogo.mime, IslandLogo.data, IslandLogo.version).where(
                    IslandLogo.id == ROW_ID
                )
            )
        ).first()
    return True, ((row[0], bytes(row[1]), row[2]) if row else None)


async def _refresh() -> bool:
    started = _time.monotonic()
    gen = _cache.gen
    known = _cache.row[2] if (_cache.loaded and _cache.row) else None
    try:
        changed, row = await asyncio.wait_for(_read_row(known), _READ_DEADLINE)
    except Exception:
        _cache.retry_at = _time.monotonic() + _RETRY_AFTER
        _cache.failing = True
        raise
    _cache.failing = False
    _cache.retry_at = 0.0
    if _cache.gen != gen:
        return False
    if changed:
        _cache.row = row
    _cache.at = started
    _cache.loaded = True
    return True


async def current() -> Optional[tuple[str, bytes, str]]:
    """`(mime, bytes, version)`, or None when this island has no logo -- or
    when it has never been read on this worker, which `is_loaded()` tells
    apart.

    Never raises, and never makes a request wait on the pool once loaded: a
    stale logo is served while ONE background refresh per worker reads the
    table (services/server_settings.py explains why a request must not reload
    a cache inline). Only a cold or invalidated cache waits for that shared
    read, and for at most `_COLD_WAIT` per attempt.
    """
    now = _time.monotonic()
    at = _cache.at
    if at > 0:
        if now - at >= _TTL and _flight.current() is None and now >= _cache.retry_at:
            _flight.start(_refresh)
        return _cache.row
    db_nesting.note_wait("island_logo")
    for _ in range(2):
        task = _flight.start(_refresh)
        await _flight.wait_for_attempt(task, _COLD_WAIT)
        if _cache.at > 0 or _cache.failing or not task.done():
            break
    return _cache.row


def is_loaded() -> bool:
    return _cache.loaded


async def wait_loaded(timeout: float) -> bool:
    """See server_settings.wait_loaded."""
    if _cache.loaded:
        return True
    deadline = _time.monotonic() + timeout
    for _ in range(2):
        left = deadline - _time.monotonic()
        if left <= 0:
            break
        await _flight.wait(_flight.start(_refresh), left)
        if _cache.loaded:
            break
    return _cache.loaded


async def warm(timeout: float) -> bool:
    """For the lifespan, before the worker takes traffic."""
    await _flight.wait(_flight.start(_refresh), timeout)
    return _cache.loaded


def tick() -> None:
    """For the lifespan ticker; see server_settings.tick."""
    now = _time.monotonic()
    at = _cache.at
    if at > 0 and now - at < _TTL:
        return
    if now < _cache.retry_at:
        return
    _flight.start(_refresh)


async def reload() -> bool:
    """Re-read NOW, for the admin path right after `store`/`clear` committed.
    Same reasoning as `server_settings.reload`, failure included: the old
    logo stays with the back-off, and the ticker publishes the new one when
    the database answers."""
    _cache.gen += 1
    try:
        return await _refresh()
    except Exception:  # noqa: BLE001
        return False


async def version() -> str:
    """The digest for `/server/info`; "" when the island has no logo. The one
    cheap thing a client needs to know: whether there is a picture, and whether
    it is the one already cached."""
    row = await current()
    return row[2] if row else ""


async def store(db, mime: str, blob: bytes) -> str:
    """Upsert the single row on the caller's session and return the new
    version. The caller commits, then calls `reload()`."""
    ver = version_of(mime, blob)
    row = await db.get(IslandLogo, ROW_ID)
    if row is None:
        db.add(IslandLogo(id=ROW_ID, mime=mime, data=blob, version=ver))
    else:
        row.mime = mime
        row.data = blob
        row.version = ver
    await db.flush()
    _bust()
    return ver


async def clear(db) -> None:
    """Remove the logo. Idempotent: an island that never had one is unchanged,
    and clients go back to the lettered tile. The caller commits, then calls
    `reload()`."""
    await db.execute(delete(IslandLogo).where(IslandLogo.id == ROW_ID))
    _bust()
