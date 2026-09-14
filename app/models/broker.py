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
    # A PAID tenant's endpoint. NULL is the public pool and everything below
    # behaves as it always has.
    #
    # ⚠⚠ A row with this set is NEVER served to the public bucket — not
    # "ranked lower", never. The entire thing being sold is that the address is
    # not in the public list, so leaking it once through the ordinary
    # distribution path would sell the product and destroy it in the same
    # request. See `_serve` in routers/broker.py.
    tenant_id: Mapped[str | None] = mapped_column(Text, nullable=True, index=True)
    # The POOL this endpoint belongs to: `shared` (every Personal buyer) or
    # `team-<id>` (one organisation's own nodes). NULL, like tenant_id NULL,
    # is the public pool. A tenant reaches these rows through its own
    # `pool_id` rather than a per-row assignment, so filling a pool is one
    # assign per node instead of one per customer.
    #
    # ⚠⚠ Same rule as tenant_id, for the same reason: a row with a pool is
    # NEVER in the public answer, whatever its tier or liveness. `_serve` in
    # routers/broker.py denies on either column.
    #
    # `index=True` only shapes a fresh database (create_all). Production got
    # this as a plain nullable column through the add-list in core/db.py,
    # and a handful of rows do not need an index anyway.
    pool_id: Mapped[str | None] = mapped_column(Text, nullable=True, index=True)
    # Admin kill switch — a disabled relay is never distributed. Also how a
    # node registered with `private: true` waits: parked dark until the
    # founder assigns it to a pool, so it is never served publicly even once.
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


class RelayTenant(Base):
    """Somebody who pays for private relay endpoints.

    Deliberately here, in the island's own database, and not in the console's
    D1. The check runs on every `GET /broker/bridges`, in `broker.py`, and a
    per-request round trip to a Worker to ask "is this key good" would put a
    third party on the path of the one feature people buy to stay reachable.
    The console brokers tenants the same way it already brokers invites.

    What is sold is NOT a dedicated machine (see private-relays-design.md): it
    is a small pool whose addresses are absent from the published config. One
    tenant with a machine to themselves is a machine that identifies them.
    """

    __tablename__ = "relay_tenants"

    # rt_<hex>
    id: Mapped[str] = mapped_column(Text, primary_key=True)
    # sha256 of the tenant key, hex. The key itself is shown once, at issue,
    # and never stored — same rule as the island owner token.
    key_hash: Mapped[str] = mapped_column(Text, nullable=False, unique=True, index=True)
    name: Mapped[str | None] = mapped_column(Text, nullable=True)
    # active | disabled. Revoking is setting this, and it takes effect on the
    # tenant's next poll rather than instantly — the client holds its endpoint
    # list until it asks again, which is the same shape as every other relay
    # source and not worth a push channel.
    status: Mapped[str] = mapped_column(Text, nullable=False, default="active")
    # Unix seconds. Past this the endpoints stop being served, without the row
    # or the endpoints being touched: a lapsed customer who pays again keeps
    # the same key and the same nodes.
    paid_until: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    # Which pool of endpoints this tenant is served, as a label rather than a
    # foreign key: there is no pools table, a pool exists the moment a relay
    # row carries the label. `shared` is the one pool every Personal buyer
    # shares; `team-<tnt_id>` is a Team's own pool, named by the console's
    # tenant id so the cabinet and the island agree without a lookup; NULL is
    # no relays at all (a Supporter, or a legacy tenant with direct rows
    # only). A Team rides `shared` until its own pool has an enabled node.
    pool_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    # The console's `tnt_` id. The cron and the cabinet can both try to mint
    # the same customer in the same second; this is what lets the second
    # caller be refused instead of a second key being issued. Also what
    # matches this row to its invoices in the console.
    ext_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False,
    )
