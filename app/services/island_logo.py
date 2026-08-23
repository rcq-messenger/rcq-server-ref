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
import time as _time
from base64 import b64decode
from typing import Optional

from sqlalchemy import delete, select

from app.core.db import SessionLocal
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
    write on one worker is visible everywhere within `_TTL`, and the writing
    worker sees it at once. A logo is the definition of a value that tolerates
    a few seconds of lag, and `/server/info` must not pay a DB read for it.

    `at` is the last successful load; `row` is `(mime, blob, version)` or None
    for "this island has no logo", which is a real answer and is cached like
    any other.
    """

    row: Optional[tuple[str, bytes, str]] = None
    at: float = -1e9


_cache = _Cache()
_TTL = 5.0  # seconds


def _bust() -> None:
    _cache.at = -1e9


async def current() -> Optional[tuple[str, bytes, str]]:
    """`(mime, bytes, version)`, or None when this island has no logo.

    Never raises. A DB blip must not take down `/server/info` (unauthenticated
    and polled on every connect) nor `/server/logo`: on failure the last known
    answer is kept and `at` is left alone so the next call retries.
    """
    now = _time.monotonic()
    if now - _cache.at < _TTL:
        return _cache.row
    try:
        async with SessionLocal() as db:
            row = (
                await db.execute(
                    select(IslandLogo.mime, IslandLogo.data, IslandLogo.version).where(
                        IslandLogo.id == ROW_ID
                    )
                )
            ).first()
    except Exception:  # noqa: BLE001
        return _cache.row
    _cache.row = (row[0], bytes(row[1]), row[2]) if row else None
    _cache.at = now
    return _cache.row


async def version() -> str:
    """The digest for `/server/info`; "" when the island has no logo. The one
    cheap thing a client needs to know: whether there is a picture, and whether
    it is the one already cached."""
    row = await current()
    return row[2] if row else ""


async def store(db, mime: str, blob: bytes) -> str:
    """Upsert the single row on the caller's session and return the new
    version. The caller commits."""
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
    and clients go back to the lettered tile. The caller commits."""
    await db.execute(delete(IslandLogo).where(IslandLogo.id == ROW_ID))
    _bust()
