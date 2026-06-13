from datetime import datetime, timezone

from sqlalchemy import BigInteger, Boolean, DateTime, Integer, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class BrokerRelay(Base):
    """A relay distributed by the BROKER (relay-transport Phase 2 / гидра prereq).

    Unlike the signed relay-config (GitHub-raw + CF KV) which publishes the FULL
    relay list to everyone — and is therefore scrapable + blockable wholesale,
    the Tor-BridgeDB problem — the broker hands out relays a FEW-PER-REQUEST in a
    deterministic per-requester bucket, so no single actor learns the whole pool
    without controlling many buckets (slow + detectable). See
    `RCQ/docs/relay-broker-design.md`.

    A row is created by an OPERATOR via `POST /broker/register`, which carries an
    Ed25519 signature over the descriptor — self-authenticating, like the gossip
    record: the server verifies it before storing, so a stranger cannot poison a
    descriptor, and a tag is derived from the operator key (un-squattable: a
    different key can never overwrite another operator's row). The descriptor is
    opaque relay-connection params (proto/server/port/sni/… — exactly the shape
    clients already parse for in-chat bridge sharing). The server is NOT a trust
    root: a hostile relay's max exposure is metadata + DoS, healed by multi-relay
    + onion; the signature is accountability, not safety.
    """
    __tablename__ = "broker_relays"

    # Server-derived stable id: sha256(operator_key : server : port). Keying on a
    # key-derived id makes a tag un-squattable — a different operator key yields a
    # different row, so no one can overwrite another's registration.
    tag: Mapped[str] = mapped_column(Text, primary_key=True)
    # Opaque relay descriptor JSON verbatim as the operator signed it (the
    # connection params the client builds a sing-box outbound from).
    descriptor: Mapped[str] = mapped_column(Text, nullable=False)
    # Base64 Ed25519 public key of the registering operator (re-registration auth
    # + accountability). Not a trust grant.
    operator_key: Mapped[str] = mapped_column(Text, nullable=False)
    # "community" (default, anyone) | "trusted" (ours / long-honest, set by admin).
    tier: Mapped[str] = mapped_column(Text, nullable=False, default="community")
    # Admin kill switch — a disabled relay is never distributed.
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    # Issued-at (Unix seconds) from the signed registration, for anti-rollback.
    ts: Mapped[int] = mapped_column(BigInteger, nullable=False)
    # Liveness, updated out-of-band (canary / health task). NULL = never probed;
    # clients tolerate a dead relay via urltest, so this only refines selection.
    last_ok: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    fail_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False,
    )
