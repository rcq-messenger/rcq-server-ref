"""Stage 4a of the core-metadata plan: the vault.

A small set of opaque slots per account. A slot holds ciphertext the client
sealed under a key derived from the account's long-term identity, plus a
version. The island holds no key and no schema for the contents: it cannot
tell a contact list from a room key from anything else, and it is not meant
to.

What the vault is for. Stage 4 moves the contact list off the island and
onto the person's devices; stage 7 makes a room reachable only by a key the
client holds. Both need a copy that survives a reinstall, and the vault is
that copy, and also the way the account's own devices converge: every write
nudges the account's other sessions over the socket (slot and version, no
blob), they re-read, merge and carry on.

⚠⚠ Per entry, with a version, never whole-list. The #605 lesson from 17.08:
two devices each published their own half of the backup-island list and each
silently un-published the other's, because the island refused only writes
with an OLDER timestamp and a write carried no notion of what it was based
on. Here a write names the version it read; the island advances it by one
or refuses with 409 and the current version. A device that lost the race
re-reads, merges, retries. There is no path by which a write lands on top of
a version its author never saw.

The slot name is 32 hex characters the client chooses. Clients derive it from
the same identity secret as the key (so a reinstall finds its slots again
without any local state), which also means the island sees a random-looking
name rather than "contacts".

No `updated_at`: it would be a per-account clock of "when did this person
last change their contacts", and nothing on the island reads it. The sweep
has no business here either; the slots live exactly as long as the account
(uin_rows: moved on a migration, removed on a burn, emptied on a key reissue).

(Naming: `owned_uins` is called "the UIN vault" in uin_shop.py. That is the
collection of numbers an account holds; this is the sealed-blob store. Two
vaults, different tables, and each comment names its table.)
"""
from sqlalchemy import BigInteger, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class VaultSlot(Base):
    __tablename__ = "vault_slots"

    # See the note in models/user.py: an integer PK without autoincrement=False
    # becomes a BIGSERIAL on Postgres, and a forgotten column then mints a
    # number silently.
    uin: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=False)
    slot: Mapped[str] = mapped_column(String(32), primary_key=True)
    # Base64 of the client's sealed blob. Text rather than bytes for the same
    # reason every other payload on the island is: one shape on SQLite and
    # Postgres, no driver-specific binary handling.
    # NULL = a tombstone: the slot was deleted and keeps its row so the
    # version can never run backwards or repeat (see routers/vault.py).
    blob: Mapped[str | None] = mapped_column(Text, nullable=True)
    # 1 on the first write, +1 per accepted write or delete. A write must
    # name the version it was based on (0 only for a slot that never existed).
    version: Mapped[int] = mapped_column(BigInteger, nullable=False, default=1)
