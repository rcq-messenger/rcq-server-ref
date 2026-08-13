from datetime import datetime, timezone

from sqlalchemy import BigInteger, DateTime, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class HomeIslandRecord(Base):
    """A user's self-signed "home-island list" (federation Layer B, F1).

    One row per local UIN on this island. `doc` is the opaque, client-produced
    JSON document specified in `docs/federation-protocol.md` §2.3: the identity
    key, the list of `(host, uin)` homes this identity is reachable on, an
    issued-at `ts`, and a signature made with the owner's libsignal identity key.

    The server is NOT the trust root and does not verify the signature (it has no
    libsignal in-process). Authentication on the write path proves the writer owns
    this UIN on this island; clients verify the signature on read against the
    identity key they anchor by safety number. The server only enforces
    anti-rollback (`ts` must not go backwards) and a size bound, then serves the
    blob to anyone — it is public routing data that reveals only where a key is
    reachable, which a sender must know to deliver anyway.
    """
    __tablename__ = "home_island_records"

    # Local handle on THIS island. Not a global identity (there is none); the
    # identity lives inside `doc` as `ik`. No FK to users.uin so a self-host
    # island can serve records without coupling to the user table's lifecycle.
    # See the note in models/user.py: an integer PK without this becomes a
    # BIGSERIAL, and a forgotten column then mints a trophy number silently.
    uin: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=False)
    # The full §2.3 served object verbatim, as the client signed it. Stored as
    # text (not parsed JSON) so the canonical bytes the client signed are never
    # mutated by a JSON round-trip on the server.
    doc: Mapped[str] = mapped_column(Text, nullable=False)
    # Extracted issued-at (Unix seconds) for cheap anti-rollback checks without
    # re-parsing `doc`. Mirrors `doc`'s `ts`.
    ts: Mapped[int] = mapped_column(BigInteger, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False,
    )


class GossipRecord(Base):
    """A MIRROR of some identity's signed home-island record (Layer B gossip /
    address-mobility B1).

    Unlike `HomeIslandRecord` (keyed by a LOCAL uin, written only by its
    authenticated owner), a gossip record is keyed by the GLOBAL identity — the
    base64 Ed25519 `signing_key` (`sk`) inside the document — and may be written
    by ANYONE: a client that has resolved + verified a contact's record mirrors
    it here so this island can serve it to others. A peer's routing record thus
    becomes reachable from *any* honest island a contact uses, not only the
    peer's own island, so a blocked/dead island no longer hides where its
    residents moved.

    Because the write path is unauthenticated, the server VERIFIES the Ed25519
    signature over the canonical signed bytes before storing, so a row can only
    exist under an `sk` for a document that key actually signed — the store is
    self-authenticating, and `ts` anti-rollback stops a replay of an older
    island list. Verification is repeated client-side on read (redundancy, not
    added trust).
    """
    __tablename__ = "gossip_records"

    # The base64 Ed25519 signing key (`sk`) — the global identity the record
    # belongs to, independent of any local uin (44 base64 chars for 32 bytes).
    sk: Mapped[str] = mapped_column(Text, primary_key=True)
    # The full §2.3 signed object verbatim, exactly as the owner signed it.
    doc: Mapped[str] = mapped_column(Text, nullable=False)
    # Extracted issued-at for anti-rollback without re-parsing `doc`.
    ts: Mapped[int] = mapped_column(BigInteger, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False,
    )
