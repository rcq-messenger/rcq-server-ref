"""Which host names a signed proof may be bound to on THIS island.

Two proofs bind the island they were made for: `rcq-reissue-v1` (a key
rotation, routers/auth.py `reissue`) and `rcq-guest-v1` (a guest copy,
routers/auth.py `guest_join`). Both must accept exactly the same set of names,
or a client that works for one would be told `*_wrong_host` by the other while
talking to the same island through the same front. So the set is computed here
and nowhere else. (It was `auth._reissue_hosts` until the guest proof needed
it too, spec 2026-09-15 section 4.4 step 3.)
"""
from __future__ import annotations

from fastapi import Request

from app.core.config import settings
from app.services import reissue_proof, server_settings


async def island_hosts(request: Request) -> tuple[set[str], bool]:
    """The hosts a proof may be bound to on THIS island, and whether the set had
    to come from the request's Host header.

    The island's own name (`island_host`) plus the fronts that proxy to it
    (FRONT_ALIAS_HOSTS: a client reaching the flagship through cdn.rcq.app
    signs the host it dialled). When `island_host` is empty, which is the
    default on a self-hosted island, the Host header is used instead of
    skipping the check (critic 11): skipping made a proof for island A good on
    any island C where the same key happened to sit on the same number. A
    header is written by the caller, so this is weaker than a configured name,
    and callers count it so an operator can see it happening.
    """
    own = reissue_proof.canonical_host(str(await server_settings.get("island_host") or ""))
    from_header = False
    if not own:
        own = reissue_proof.canonical_host(request.headers.get("host", ""))
        from_header = True
    allowed = {own} if own else set()
    allowed |= {
        reissue_proof.canonical_host(h) for h in settings.FRONT_ALIAS_HOSTS.split(",") if h.strip()
    }
    return allowed, from_header
