"""Retention for spent entry credentials: `invites` and `access_tokens`.

One loop for two tables because they are the same object on two different
islands. An invite admits somebody to an island running
`REGISTRATION_POLICY=invite`; an access token admits somebody through the
network gate of a CLOSED (masquerade) island. Neither had a sweep, so both
accumulated a permanent alumni roster: a revoked or exhausted row keeps its
operator-written `label` (typically a person's or an organisation's name), its
`device_id`, and its whole lifespan, long after it stops admitting anyone.

⚠ WHO THIS IS ABOUT. `access_tokens` only has rows on an island running the
masquerade Caddyfile, and an operator runs masquerade because their community
is under enough pressure to need a decoy. So the population whose names sit in
that column forever is precisely the population for whom a seized disk is worst.
That is the argument for a horizon; it is not an argument for a short one,
because the same operator needs to answer "who did we admit last quarter". A
quarter is the compromise, and shortening it is always the safe direction.

Flagship on 2026-08-22: zero rows in both tables (it is an open island and does
not run the gate). This is entirely for is2 and for self-hosters.

⚠⚠ THE CASCADE, which is the trap here. `access_tokens.parent_id` points a
`device` row at the `invite` row it was redeemed from, and
`gate.revoke_token(invite_id)` uses it to revoke every device minted from that
invite in one action. An exhausted invite whose device is still LIVE is the
NORMAL state of a redeemed one-time invite, so a naive "delete exhausted rows"
would quietly destroy the operator's ability to cut off everyone admitted by a
leaked code, which is the single most important thing that endpoint does. So an
invite-kind row with any un-revoked child is never swept, whatever its age.

Deleting a gate row is not the same as revoking it and does not widen access:
`gate_check` fails CLOSED on a row it cannot find, so a missing row denies
exactly like a revoked one. Only already-dead rows are touched here anyway.

Hourly, leader-elected, bounded per cycle.
`RCQ_CREDENTIAL_SWEEP_DRY_RUN=1` reports and changes nothing.
"""
from __future__ import annotations

import asyncio
import logging
import os
from datetime import datetime, timedelta, timezone

from sqlalchemy import and_, delete, func, or_, select

from app.core.db import SessionLocal
from app.models.access_token import AccessToken
from app.models.invite import Invite
from app.services.periodic_leader import lead_this_cycle

log = logging.getLogger(__name__)

SWEEP_INTERVAL_SECONDS: int = 60 * 60

CREDENTIAL_MAX_AGE_DAYS: int = int(os.environ.get("RCQ_CREDENTIAL_MAX_AGE_DAYS", "90"))
MAX_PER_CYCLE: int = int(os.environ.get("RCQ_CREDENTIAL_SWEEP_MAX_PER_CYCLE", "500"))
DRY_RUN: bool = os.environ.get("RCQ_CREDENTIAL_SWEEP_DRY_RUN", "") == "1"


def _dead_invites(cutoff: datetime):
    """Invites that stopped admitting anyone before `cutoff`.

    Two ways to die and they have different clocks. An EXHAUSTED invite is
    stamped `spent_at` by the last registration that used it. An EXPIRED one
    needs no stamp: `expires_at` already is the moment it died, so the horizon
    runs from there.

    A row spent before `spent_at` existed has a NULL stamp and is left to the
    `created_at` arm, which is the invite's own minting clock. That is safe in a
    way the declined-contact-request fallback was not: an exhausted invite has
    no reader at all, so an early delete costs nothing but the admin list entry.
    """
    return or_(
        and_(Invite.used_count >= Invite.max_uses, Invite.spent_at < cutoff),
        and_(
            Invite.used_count >= Invite.max_uses,
            Invite.spent_at.is_(None),
            Invite.created_at < cutoff,
        ),
        and_(Invite.expires_at.is_not(None), Invite.expires_at < cutoff),
    )


def _dead_tokens(cutoff: datetime):
    """Gate tokens that can no longer let anybody in, older than `cutoff`.

    The activity clock is `last_used_at`, falling back to `created_at` for a
    token nobody ever presented. Three terminal states, matching `gate._active`
    exactly so this can never sweep something the gate would still admit:
    revoked, expired, or use-exhausted. A `standing` token has `max_uses` NULL
    (unlimited) and so is only ever reachable through the revoked or expired
    arms, and that is correct: an operator's bridge-bot token must not evaporate
    because it went quiet over the summer.
    """
    activity = func.coalesce(AccessToken.last_used_at, AccessToken.created_at)
    return and_(
        or_(
            AccessToken.revoked.is_(True),
            and_(AccessToken.expires_at.is_not(None), AccessToken.expires_at < cutoff),
            and_(
                AccessToken.max_uses.is_not(None),
                AccessToken.uses >= AccessToken.max_uses,
            ),
        ),
        activity < cutoff,
    )


async def sweep_once() -> tuple[int, int]:
    """One pass. Returns (invites, access tokens) removed."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=CREDENTIAL_MAX_AGE_DAYS)
    async with SessionLocal() as db:
        invite_codes = list(
            (
                await db.scalars(
                    select(Invite.code).where(_dead_invites(cutoff)).limit(MAX_PER_CYCLE)
                )
            ).all()
        )
        token_ids = list(
            (
                await db.scalars(
                    select(AccessToken.id).where(_dead_tokens(cutoff)).limit(MAX_PER_CYCLE)
                )
            ).all()
        )
        # ⚠⚠ See the module docstring: an invite-kind row that still has a live
        # child is the revocation handle for that child and is never swept.
        if token_ids:
            live_parents = set(
                (
                    await db.scalars(
                        select(AccessToken.parent_id).where(
                            AccessToken.parent_id.in_(token_ids),
                            AccessToken.revoked.is_(False),
                        )
                    )
                ).all()
            )
            if live_parents:
                token_ids = [t for t in token_ids if t not in live_parents]
        if DRY_RUN:
            if invite_codes or token_ids:
                log.warning(
                    "[credential-sweep] dry-run: %d invite(s) and %d gate token(s) past %dd",
                    len(invite_codes), len(token_ids), CREDENTIAL_MAX_AGE_DAYS,
                )
            return len(invite_codes), len(token_ids)
        n_inv = n_tok = 0
        if invite_codes:
            n_inv = (
                await db.execute(delete(Invite).where(Invite.code.in_(invite_codes)))
            ).rowcount or 0
        if token_ids:
            n_tok = (
                await db.execute(delete(AccessToken).where(AccessToken.id.in_(token_ids)))
            ).rowcount or 0
        if n_inv or n_tok:
            await db.commit()
    if n_inv or n_tok:
        log.warning(
            "[credential-sweep] reaped %d spent invite(s) and %d dead gate token(s) (>%dd)",
            n_inv, n_tok, CREDENTIAL_MAX_AGE_DAYS,
        )
    return n_inv, n_tok


async def credential_sweep_loop() -> None:
    while True:
        try:
            # One worker per cycle (see services/periodic_leader).
            if await lead_this_cycle("credential-sweep", SWEEP_INTERVAL_SECONDS):
                await sweep_once()
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            log.exception("[credential-sweep] pass failed; retrying next cycle")
        await asyncio.sleep(SWEEP_INTERVAL_SECONDS)
