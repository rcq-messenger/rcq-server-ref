"""Is this account a person, or somebody's backup mailbox? (#1054)

Multihoming (federation §5a) registers a person's EXISTING keys on a second
island so a dead island is invisible to them. On that island the result is an
ordinary `users` row with its own number and the person's nickname: nothing in
the row says "I am a copy". It turns up in search like anyone else, and a
resident who presses Add writes a `contact_requests` row that nobody will ever
read. The copy's owner drains only `/messages/queue` there (§5a.3); nothing
polls `/contacts/pending` on a backup, it holds no socket and no push token.
The request sits at "pending" forever. Every pending request on is2 on
2026-09-27 was of this kind.

The island CAN tell, from the one document the owner writes about it: the
signed home-island record (§2.3) the client PUTs to every home, primary first
(§5a.1 step 4). If the record names THIS mailbox and names somewhere else
before it, the owner has said in their own signature that this is a backup and
where they actually live.

What is and is not checked, and why that is enough:

  * the record's `sk` is the row's signing key and its signature verifies. A
    record written under a session is the owner's claim about their own
    mailbox; the signature makes it the KEY's claim too, so a stale record
    left over from before a key change does not count;
  * the record must name this mailbox by one of this island's names. When it
    does not (an island reached under an old name, an unset `island_host`),
    the answer is "don't know" and the request behaves as it always did.
    Misreading a person as a copy would turn away people who are really here;
    missing a copy only leaves today's behaviour;
  * ⚠ the record does NOT prove that the home account consents to being named.
    Anybody can sign "my primary is 134@api" with their own key. That sends
    requests meant for them to somebody else, which harms nobody but them, and
    the client closes it: it adds the home address only if that island's key
    card carries the same signing key as the copy.

Privacy: the answer reveals `homes[0]` of a record that
`GET /federation/island-record/{uin}` already serves to anybody, unauthenticated.
Nothing here is new information, only a sensible place to say it.
"""
from __future__ import annotations

import json
import re

from fastapi import Request
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.federation import HomeIslandRecord
from app.models.user import User
from app.services import reissue_proof
from app.services.island_hosts import island_hosts

#: A bare host with an optional port, the only shape a home may be answered in.
#: Whatever the owner wrote goes back to a client that will dial it, so nothing
#: with a scheme, a path or a space is repeated.
_HOST = re.compile(r"[a-z0-9.\-]{1,253}(:[0-9]{1,5})?")

#: The refusal on `POST /contacts/request`: 403 with this code.
#:
#: ⚠ 403 and not 409, on purpose. The shipped web and iOS clients read ANY 409
#: from this endpoint as "already in your contact list" and would say so, which
#: is false. On any other status they print the body (web add screen, iOS) or a
#: generic "could not send" (Android, web profile), and the body carries a
#: sentence that is true.
CODE = "backup_copy"


class HomeRef(BaseModel):
    """Where the person behind a backup copy actually lives. Carried as `home`
    on a search row, a profile and an outgoing request, absent everywhere else,
    so every client that predates it reads the row exactly as before."""
    host: str
    uin: int


def home_ref(home: tuple[str, int] | None) -> HomeRef | None:
    return HomeRef(host=home[0], uin=home[1]) if home is not None else None


async def own_hosts(request: Request) -> set[str]:
    """This island's names, for reading a record.

    `island_hosts` (the configured name, else the Host header, plus the CDN
    fronts) and the Host header on top. Not a security binding like the proofs
    that function exists for: a caller who writes a false Host header only
    changes how THEIR OWN request is classified, and at worst gets today's
    behaviour back.
    """
    allowed, _ = await island_hosts(request)
    header = reissue_proof.canonical_host(request.headers.get("host", ""))
    if header:
        allowed.add(header)
    return allowed


def home_from_doc(raw: str | None, user: User, own: set[str]) -> tuple[str, int] | None:
    """`(host, uin)` of the person `user` is a backup copy of, or None.

    None means "a person here, or can't tell", and the caller then does exactly
    what it did before this module existed.
    """
    if not raw or not user.signing_key:
        return None
    try:
        doc = json.loads(raw)
    except (ValueError, TypeError):
        return None
    if not isinstance(doc, dict) or doc.get("sk") != user.signing_key:
        return None
    homes = doc.get("homes")
    if not isinstance(homes, list) or len(homes) < 2:
        return None
    parsed: list[tuple[str, int]] = []
    for h in homes:
        if not isinstance(h, dict):
            return None
        host, uin = h.get("host"), h.get("uin")
        if not isinstance(host, str) or not isinstance(uin, int) or isinstance(uin, bool):
            return None
        parsed.append((reissue_proof.canonical_host(host), uin))
    mine = [i for i, (host, uin) in enumerate(parsed) if host in own and uin == user.uin]
    if not mine or mine[0] == 0:
        return None
    home_host, home_uin = parsed[0]
    # A primary on THIS island under another number is two accounts for one
    # key here, not a backup. Leave it alone.
    if home_host in own or home_uin <= 0 or not _HOST.fullmatch(home_host):
        return None
    # Last, because it is the only step that costs anything.
    from app.routers.federation import _verify_record_sig
    if not _verify_record_sig(doc):
        return None
    return home_host, home_uin


async def home_of(db: AsyncSession, user: User, own: set[str]) -> tuple[str, int] | None:
    """`home_from_doc` for one account, reading its record."""
    raw = await db.scalar(select(HomeIslandRecord.doc).where(HomeIslandRecord.uin == user.uin))
    return home_from_doc(raw, user, own)


async def homes_of(
    db: AsyncSession, users: list[User], own: set[str]
) -> dict[int, tuple[str, int]]:
    """The same for a page of accounts, in one query. Only copies are keyed."""
    if not users:
        return {}
    rows = (
        await db.execute(
            select(HomeIslandRecord.uin, HomeIslandRecord.doc).where(
                HomeIslandRecord.uin.in_([u.uin for u in users])
            )
        )
    ).all()
    docs = {uin: doc for uin, doc in rows}
    out: dict[int, tuple[str, int]] = {}
    for u in users:
        home = home_from_doc(docs.get(u.uin), u, own)
        if home is not None:
            out[u.uin] = home
    return out


def refusal(home: tuple[str, int]) -> dict:
    """The `detail` of the refusal. New clients read `code`, `home_host` and
    `home_uin`; `message` is for the ones that predate the code and print the
    body they get (the web add screen, iOS), so what they print is true.

    ⚠ Short, and the code first. Android keeps the first 200 characters of an
    error body, so a longer one stops being parseable JSON on a client that
    reads the code out of the exception text.
    """
    host, uin = home
    return {
        "code": CODE,
        "home_host": host,
        "home_uin": uin,
        "message": f"Backup copy of {uin}@{host}. Add that address instead.",
    }
