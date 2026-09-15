from datetime import datetime, timezone

from sqlalchemy import BigInteger, DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class RetiredSigningKey(Base):
    """A signing key this island's accounts USED to carry, and whose account it was.

    ⚠⚠ WHY IT EXISTS. `/auth/reissue` rewrites an account's keys in place, and
    every other install of that account still holds the old private key. When
    one of them next proves it at `/auth/refresh` or `/auth/recover` the key
    matches no row, and the only answer the island had was `identity_not_found`,
    which every shipped client reads as "the account was burned, wipe the local
    copy". So a rotation on one phone erased the account's history on the
    user's other phone. This table is what lets those two endpoints say
    `identity_rotated` instead: the account is alive, under a new key, and the
    device should ask its owner for the new phrase.

    A DATABASE ROW, NOT A REDIS KEY (spec F3, critic 7). A Redis marker with a
    TTL was the first design, and it failed in both directions: nothing cleared
    it on a burn, so for its whole lifetime an old-seed holder kept hearing
    "this account exists and rotated" about an account its owner had deleted;
    and a Redis flush or eviction silently turned the answer back into the
    wiping one. Here the row is in `uin_rows.PER_UIN_COLUMNS`, so a burn purges
    it (a later recover then answers `identity_not_found`, which is now true)
    and a number move carries it to the new number.

    What it holds is new metadata and is kept small on purpose: a HASH of the
    old key (the key itself is public, but there is no reason to keep a list of
    them), the number, and when. `services/retired_key_sweep` ages rows out;
    the horizon is the founder's open question (f) in the spec.

    The answer it enables reaches only a holder of the OLD private key: both
    endpoints verify a signature under the presented key before they ever look
    here.
    """

    __tablename__ = "retired_signing_keys"

    #: sha256 hex of the 32 raw bytes of the retired Ed25519 public key. Hashed
    #: from the DECODED bytes, so padded, unpadded and re-encoded spellings of
    #: one key land on one row.
    sk_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    #: The account that carried the key when it was retired. BigInteger like
    #: every other uin column (the spec sketch said Integer; the island's
    #: convention wins, see models/uin_epoch.py for why an integer uin column
    #: must never turn into a serial).
    uin: Mapped[int] = mapped_column(BigInteger, index=True, autoincrement=False)
    rotated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
