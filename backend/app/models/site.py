from datetime import datetime, timezone

from sqlalchemy import BigInteger, Boolean, DateTime, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class Site(Base):
    """One `.rcq` site: a static bundle this island hosts and serves by name.

    ⚠⚠ This is the FIRST open content on our servers. Everything else the
    island stores is sealed and unreadable to it; a site is public bytes by
    definition, which is a different kind of responsibility (see
    `docs/rcq-sites-design.md` §5) and the reason the operator tools ship with
    the feature rather than after it.

    The name is unique on THIS island only, which is the whole addressing
    model: `blog.is2.rcq` is the site `blog` in is2's zone, and `blog` is free
    on every other island. There is no registry above the islands, and there is
    deliberately no DNS anywhere: the client parses the name itself and asks
    the island the suffix names.

    `owner_key` is what makes a site more than a folder on somebody's server:
    every bundle is signed by the owner's key, the reader pins that key on
    first visit, and the island can serve different bytes but cannot pass them
    off as the same site. It is also what lets a name MOVE - the same key
    answering from another island, published through the signed federation
    record accounts already use - so that a dead island does not mean a dead
    address.
    """

    __tablename__ = "sites"
    __table_args__ = (
        Index("ix_sites_owner", "owner_uin"),
        Index("ix_sites_listed", "listed"),
    )

    #: Lowercase, `[a-z0-9-]{1,32}`, unique on this island. A name of digits
    #: only belongs to the holder of that UIN (see routers/sites).
    name: Mapped[str] = mapped_column(String(32), primary_key=True)
    owner_uin: Mapped[int] = mapped_column(BigInteger, nullable=False)
    #: Ed25519 public key (base64) the bundles are signed under. The reader
    #: pins this; changing it is a different site wearing the same name, and
    #: every client says so.
    owner_key: Mapped[str] = mapped_column(Text, nullable=False)
    #: Monotonic, bumped by each upload. The client caches by it and a
    #: re-visit costs the island nothing.
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    #: The manifest as the owner signed it: file list with hashes, version,
    #: key, signature. Served verbatim - re-serialising it would break the
    #: signature over the exact bytes.
    manifest: Mapped[str] = mapped_column(Text, nullable=False)
    #: Bytes on disk, for the quota and for the operator's list.
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    #: One line the catalogue shows. Not the page title: the author writes it
    #: for the list, and it is public.
    title: Mapped[str | None] = mapped_column(String(80), nullable=True)
    #: Show WHO published this in the public catalogue. Opt-in, and off by
    #: default (2026-09-02, founder): the island knows the owner because it
    #: must, but publishing a page is not a decision to publish the number
    #: that receives your messages. The operator still sees it - they answer
    #: for what their island hosts - and `/admin/sites` is where that lives.
    show_owner: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    #: In the catalogue. Opt-in, and the operator's to withdraw: a site that
    #: is not listed still opens by its exact name, which is the point of a
    #: catalogue being a shop window rather than a permission to exist.
    listed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    #: Pinned to the top of the catalogue by the OPERATOR (2026-09-02, founder:
    #: the network's own page sits in its own section above recents and the
    #: catalogue in every client). The owner cannot ask for it - a self-service
    #: flag would be the shop window's front row for sale - and it never
    #: outlives `listed`: a site that leaves the catalogue, by anyone's hand,
    #: leaves the top of it too.
    featured: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    #: Frozen by the operator: reads answer 410 and uploads are refused. Not a
    #: delete - the bytes stay while a complaint is looked at.
    frozen: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc)
    )
