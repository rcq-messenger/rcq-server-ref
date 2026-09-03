"""The island's own picture: one logo per island, set by its operator.

Until this existed an island was drawn as a lettered tile everywhere a client
names it (the account switcher, the join confirm, the island card in Settings).
The name and the welcome text have been operator-settable since islands
existed; the face was the one part of an island's identity that was generated
rather than chosen.

⚠ WHY A TABLE OF ITS OWN, and not the two obvious alternatives:

  * `server_settings`: the natural home, since the name and the welcome text
    live there, and it was the first thing tried. Its `value` column is
    `String(2048)`, which is about 1.5 KB of image, and the startup migrator in
    `core/db.py` can only ADD COLUMN: there is no path in this codebase that
    widens an existing column's type on a live island. On top of that the
    generic admin PATCH truncates any string to 2048 characters (which for a
    data URI means a silently unopenable image, the exact "broken picture" this
    feature must never produce), and `describe()` hands EVERY setting back to
    the admin console on every poll, so the blob would ride along each time.

  * a file under `RCQ_MEDIA_DIR`, where `/media` keeps blobs. Two reasons not
    to. The contract of that directory is "the server never sees content": every
    blob in it is client-encrypted, and a plaintext PNG under a uuid name in the
    middle of it is a lie about the store. And it is a different durability
    class from the database: a self-hoster who redeploys the container keeps
    their Postgres and loses that volume, so the island's face would quietly
    disappear on an upgrade while its name survived.

A new table rides `create_all` on every island (flagship, is2 and every
self-hoster) on a plain restart, exactly like `user_capabilities` and `devices`
before it. No ALTER, nothing to go wrong on an old deployment.

The bytes are stored raw, not base64: the one endpoint that reads them
(`GET /server/logo`) hands them straight to the wire, so a base64 round trip
would cost 33% of the row and a decode per request for nothing. The admin
endpoint takes a data URI (which is what a browser file picker can produce
without an upload form) and decodes it once, on the way in.
"""
from datetime import datetime, timezone

from sqlalchemy import DateTime, Integer, LargeBinary, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class IslandLogo(Base):
    """The island's logo. At most one row, always `id = 1`.

    A single-row table rather than a key/value pair so the mime, the bytes and
    the version cannot drift apart: they are set and cleared together, in one
    statement, and a half-written logo is not representable.
    """

    __tablename__ = "island_logo"

    # Fixed at 1 by the service. `autoincrement=False` for the same reason
    # models/user.py gives: an Integer primary key without it becomes a SERIAL
    # on Postgres, and then a forgotten column mints a number of its own.
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=False)
    # "image/png" | "image/jpeg" | "image/webp" | "image/gif". Echoed back as
    # the Content-Type; never derived from a filename.
    mime: Mapped[str] = mapped_column(String(32), nullable=False)
    data: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    # Short digest of the bytes. This, and NOT the image, is what rides on
    # `/server/info`: it is the whole reason that reply stays as cheap as it was
    # (see routers/server.py). Doubles as the ETag.
    version: Mapped[str] = mapped_column(String(16), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )
