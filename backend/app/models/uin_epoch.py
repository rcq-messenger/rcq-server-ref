from sqlalchemy import BigInteger, Integer
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class UinEpoch(Base):
    """How many times a UIN has changed hands.

    A UIN is not an identity — the key is — and numbers are deliberately
    recyclable: a burned account frees its number, and the vanity flow sells a
    specific one to a new holder. That recycling is what makes bearer tokens
    dangerous, because `current_uin` binds a session to `sub` (the UIN) and
    phone tokens deliberately never expire (an `exp` on them stranded long-idle
    native clients on 401, which older iOS builds answered by silently
    re-registering).

    Concretely, the primitive this table closes: register a chosen number, keep
    the bearer, delete the account to release the number, wait for it to be
    handed to somebody else, and the saved token still authenticates — now as
    THEM. That is one HTTP request from account takeover, and selling vanity
    UINs is exactly the flow that makes step three happen on purpose.

    So the counter lives HERE and not on `users`: it has to outlive the user row
    it belonged to. Tokens carry the epoch they were minted under as `ep`, and a
    token whose `ep` no longer matches the number's current epoch is refused.

    Backwards compatible by construction: an untouched number has no row here
    (epoch 0) and a pre-existing token carries no `ep` claim (read as 0), so
    every session issued before this table existed keeps working. Only a number
    that actually changes hands invalidates its old tokens.
    """

    __tablename__ = "uin_epochs"

    # See the note in models/user.py: an integer PK without this becomes a
    # BIGSERIAL, and a forgotten column then mints a trophy number silently.
    uin: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=False)
    epoch: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
