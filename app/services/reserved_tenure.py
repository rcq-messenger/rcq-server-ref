"""May this identity take a SCARCE number here through `desired_uin`?

Multihoming (federation §5a) asks a backup island for the number the person
already has at home, and for an ordinary number that is granted on proof of the
signing key alone. A reserved number (short or patterned, `uin.is_reserved_uin`)
needs more: the caller must already answer to it on another island.

⚠⚠ Until 2026-10-01 "already answers to it" was read off a self-signed record:
the one the caller offered as `home_record`, or the one this island mirrors for
the key (`gossip_records`, written by anybody through the open
`PUT /federation/gossip-record`). A record is signed by its OWN `sk`, so it
proves who wrote it and nothing about what it says: anyone through the door
could sign `{homes: [{host: "anywhere", uin: 777}]}` with their own key, offer
it, and leave with #777. Found while investigating report 1069.

What counts now:

  * the record (offered or mirrored) is only a POINTER. It must verify under the
    caller's key and name the number on an island in `TENURE_TRUSTED_ISLANDS`,
    and that only decides where to ask;
  * that island is then asked over HTTPS for two things it holds about the
    number: the record its holder published there
    (`GET /federation/island-record/{uin}`), which must verify, carry the same
    `sk` and name the number on that island; and its key card
    (`GET /federation/keys/{uin}`), which must carry the same signing key.
    The card is the island's own answer from its `users` row. The record
    alone is not: `PUT /federation/island-record` stores whatever its
    authenticated writer sends, so the holder of #777 there could publish
    somebody else's signed record and hand them #777 here;
  * anything else (no pointer, an island not on the list, a timeout, a
    redirect, a refusal, a mismatch) is "no", and the registration carries on
    with a fresh number. Never an error: the person still gets their backup.

Why a list an operator writes rather than "the island the record names":
self-hosting is a supported feature, so an island the caller chooses is an
island the caller may run, and it will say whatever they like. A catalogue of
public islands is no better, because the chain is then as weak as the weakest
build in it. The default is the two islands this project runs, which both
apply this same rule, and an island never trusts itself: a free number that a
record claims is held HERE is a stale or false record.

⚠ The network wait happens before the registration's own session takes a
connection, and the one read it needs (the mirror row, plus a cheap "is the
number free at all") runs on a short session of its own that is closed before
the request goes out. Holding a pooled connection across an outbound call to
another island is the 11.09-28.09 stall pattern (core/db_nesting.py).
"""
from __future__ import annotations

import asyncio
import json
import logging
import re

import httpx
from fastapi import Request
from sqlalchemy import select

from app.core.config import settings
from app.core.db import SessionLocal
from app.models.federation import GossipRecord
from app.services import reissue_proof
from app.services.backup_copy import own_hosts
from app.services.uin import uin_is_taken

log = logging.getLogger(__name__)

#: Budget for one trusted island to answer both reads, end to end. A backup
#: registration is a person waiting on a spinner, and a "no" costs them only a
#: different number on the backup, so this stays short.
_FETCH_SECONDS = 4.0
#: The same bound `routers/federation` puts on a stored record. A key card is
#: far smaller. Anything over it is not something this module asked for.
_MAX_BODY = 8 * 1024
#: How many trusted islands one registration may ask. The default list has two
#: and an island drops itself, so this only matters for a long operator list.
_MAX_ISLANDS = 3
#: A bare host with an optional port. The URL is built from the operator's
#: list, never from a record, but the list is still a string in a file.
_HOST = re.compile(r"[a-z0-9.\-]{1,253}(:[0-9]{1,5})?")


def trusted_islands(own: set[str]) -> list[str]:
    """`TENURE_TRUSTED_ISLANDS`, canonical, without this island's own names."""
    out: list[str] = []
    for raw in settings.TENURE_TRUSTED_ISLANDS.split(","):
        host = reissue_proof.canonical_host(raw)
        if host and host not in own and host not in out and _HOST.fullmatch(host):
            out.append(host)
    return out


def _same_key(a: object, b: object) -> bool:
    """Two wire spellings of one 32-byte key (padded and unpadded base64 both
    occur in the wild)."""
    if not isinstance(a, str) or not isinstance(b, str):
        return False
    try:
        return reissue_proof.decode_key32(a) == reissue_proof.decode_key32(b)
    except (ValueError, TypeError):
        return False


def _islands_naming(doc: object, uin: int, signing_key: str, trusted: list[str]) -> list[str]:
    """The trusted islands on which this record, signed by `signing_key`, says
    the identity holds `uin`. Empty when it is not such a record."""
    if not isinstance(doc, dict) or not _same_key(doc.get("sk"), signing_key):
        return []
    homes = doc.get("homes")
    if not isinstance(homes, list):
        return []
    named: list[str] = []
    for h in homes:
        if not isinstance(h, dict):
            continue
        host, n = h.get("host"), h.get("uin")
        if not isinstance(host, str) or isinstance(n, bool) or n != uin:
            continue
        host = reissue_proof.canonical_host(host)
        if host in trusted and host not in named:
            named.append(host)
    if not named:
        return []
    # Last, because it is the only step that costs anything.
    from app.routers.federation import _verify_record_sig

    return named if _verify_record_sig(doc) else []


async def _get_json(client: httpx.AsyncClient, url: str) -> dict | None:
    """A JSON object from a 200, or None. Redirects are not followed (the
    client is built with `follow_redirects=False`, so a 3xx is just "not 200"),
    and the body is cut off at `_MAX_BODY` instead of being read to the end."""
    async with client.stream("GET", url) as r:
        if r.status_code != 200:
            return None
        body = b""
        async for chunk in r.aiter_bytes():
            body += chunk
            if len(body) > _MAX_BODY:
                return None
    try:
        doc = json.loads(body)
    except ValueError:
        return None
    return doc if isinstance(doc, dict) else None


async def _island_confirms(host: str, uin: int, signing_key: str) -> bool:
    """Does `host` itself say that its #`uin` is this signing key?"""
    base = f"https://{host}"
    async with httpx.AsyncClient(
        # Per phase; `holds_elsewhere` puts the whole exchange under
        # `_FETCH_SECONDS` on top, so a server that drips bytes cannot stretch it.
        timeout=httpx.Timeout(_FETCH_SECONDS - 1.0),
        follow_redirects=False,
        headers={"accept": "application/json"},
    ) as client:
        # Both reads finish (or fail) before the client closes under them.
        results = await asyncio.gather(
            _get_json(client, f"{base}/federation/island-record/{uin}"),
            _get_json(client, f"{base}/federation/keys/{uin}"),
            return_exceptions=True,
        )
    for res in results:
        if isinstance(res, BaseException):
            raise res
    record, card = results
    if record is None or card is None:
        return False
    if card.get("uin") != uin or not _same_key(card.get("signing_key"), signing_key):
        return False
    # Same key, signature verified, and it names #uin on THIS island.
    return _islands_naming(record, uin, signing_key, [host]) == [host]


async def holds_elsewhere(
    request: Request, uin: int, signing_key: str, offered: dict | None
) -> bool:
    """True only when a trusted island confirms that `signing_key` holds `uin`
    there. Call it BEFORE the request's own session runs its first statement.

    Never raises: every failure is a "no", and the caller then grants a fresh
    number exactly as it does for anybody without a claim.
    """
    try:
        trusted = trusted_islands(await own_hosts(request))
        if not trusted:
            return False
        pointers: list[str] = []
        # The offered record is attacker-shaped input on an unauthenticated
        # endpoint; the store's own size bound applies before anything else.
        if isinstance(offered, dict):
            try:
                small = len(json.dumps(offered).encode("utf-8")) <= _MAX_BODY
            except (TypeError, ValueError):
                small = False
            if small:
                pointers += _islands_naming(offered, uin, signing_key, trusted)
        async with SessionLocal() as s:
            # Checked again at the grant; here it only saves a pointless trip
            # to another island for a number that is gone anyway.
            if await uin_is_taken(s, uin):
                return False
            # `sk` IS the primary key of the mirror table.
            raw = await s.scalar(select(GossipRecord.doc).where(GossipRecord.sk == signing_key))
        if raw:
            try:
                mirrored = json.loads(raw)
            except (ValueError, TypeError):
                mirrored = None
            pointers += [h for h in _islands_naming(mirrored, uin, signing_key, trusted)
                         if h not in pointers]
        for host in pointers[:_MAX_ISLANDS]:
            try:
                if await asyncio.wait_for(
                    _island_confirms(host, uin, signing_key), _FETCH_SECONDS
                ):
                    return True
            except (httpx.HTTPError, OSError, asyncio.TimeoutError) as exc:
                # The trusted island's name is the operator's own config and
                # names nobody; the number and key stay out of the line.
                log.warning("[tenure] %s did not answer: %s", host, type(exc).__name__)
        return False
    except Exception as exc:  # noqa: BLE001 — a failed lookup must cost a number, never the sign-up
        # The type only: a database error's text carries its bound parameters,
        # which here are the number and the key being asked about.
        log.warning("[tenure] lookup failed: %s", type(exc).__name__)
        return False
