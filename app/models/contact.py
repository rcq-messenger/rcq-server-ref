from datetime import datetime, timezone

from sqlalchemy import BigInteger, Boolean, DateTime, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class Contact(Base):
    __tablename__ = "contacts"
    __table_args__ = (UniqueConstraint("owner_uin", "contact_uin", name="uq_owner_contact"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    owner_uin: Mapped[int] = mapped_column(BigInteger, index=True)
    contact_uin: Mapped[int] = mapped_column(BigInteger, index=True)
    blocked: Mapped[bool] = mapped_column(Boolean, default=False)
    # (`created_at` was unmapped on 2026-08-22. Nothing read it: not a query,
    # not an ordering, not a served field. It was a relationship-start ledger
    # the island kept for itself, one dated edge per friendship, and the whole
    # social graph is already the thing stage 4 wants off the island.)


class ContactRequest(Base):
    __tablename__ = "contact_requests"
    __table_args__ = (UniqueConstraint("from_uin", "to_uin", name="uq_request_pair"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    from_uin: Mapped[int] = mapped_column(BigInteger, index=True)
    to_uin: Mapped[int] = mapped_column(BigInteger, index=True)
    state: Mapped[str] = mapped_column(String(16), default="pending")  # pending|accepted|declined
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    # When the request left `pending`. NOT the same clock as created_at, which
    # is why the retention sweep needs its own column: a request raised a week
    # ago and accepted a minute ago must be measured from the acceptance, or
    # the sweep would delete it out from under a client still retrying.
    # Nullable: every row that predates the column is still pending or was
    # resolved before any of this existed.
    resolved_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, default=None
    )


class ContactVaultDevice(Base):
    """One row per (account, device) whose client keeps the contact list in
    the vault (SPEC 4.9) instead of reading it out of `contacts`.

    Stage 4b of the core-metadata plan, and a MEASUREMENT: it answers how
    much of the island still needs the `contacts` table, which is the number
    the drop waits on. Nothing about it changes what any endpoint writes or
    serves today -- the island records both directed rows for every accepted
    pair exactly as before, because the five server-side rules that read them
    move at the drop and not one pair at a time (`services/contact_source`
    says why at length).

    Per DEVICE, not per account, and for the same reason `group_log_readers`
    is (stage 5): an account whose phone updated first does not speak for its
    still-old desktop. An account counts as moved only when every device that
    drains its legacy queue (every `queue_cursors` row) is also marked here,
    so an abandoned install stops holding the account back when its cursor is
    reaped as stale.

    ⚠ `last_seen` is what makes the mark expire. Clients re-advertise on
    every app start, so a live install refreshes it daily and a downgrade to
    a build that has never heard of the field ages out after
    `VAULT_MARK_TTL_DAYS` instead of counting as moved forever. Stage 5's
    reader mark is refreshed by the BEHAVIOUR itself (a fetch); this one is
    an assertion, so it needs a clock.

    ⚠ A device can UNMARK itself (`{"vault_contacts": false}` on
    SPEC 2.12), which `group_log_readers` cannot. A client that has to roll
    a release back must be able to put its account back on the server list,
    and a mark that only ever went one way would strand it.

    ⚠ "primary" is the ABSENCE of an install name, not a device (SPEC 2.11),
    so two unnamed installs of one account share one row here exactly as
    they share one `queue_cursors` row. A new unnamed install therefore
    marks the account as moved on behalf of an old unnamed one. Same
    exposure stage 5 shipped with, and the same answer: name the install.
    """

    __tablename__ = "contact_vault_devices"

    uin: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=False)
    device_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
