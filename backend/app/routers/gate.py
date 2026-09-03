"""Closed-island network gate — per-user access tokens for a masquerade island.

Only exercised when the operator runs the masquerade Caddyfile, which sends a
GET subrequest to `/gate/check` on every request and serves a decoy on anything
but a 2xx. See docs/closed-island-access-design.md.

Security rules baked in here (from the design review):
  * /gate/check FAILS CLOSED: a Redis blip falls through to the DB; only a real
    deny (or DB also unreachable) returns non-2xx. Never `return 200` in except.
  * Redis is a 45s metadata CACHE, not the source of truth; the predicate
    (revoked / expiry / uses<max_uses) is re-evaluated in-process every request.
  * Responses are content-free (status only) so even an authed observer learns
    nothing; the raw token / X-RCQ-Auth is NEVER logged.
  * /gate/redeem mints a device row ONLY from an unexhausted invite, inserts the
    device row ON CONFLICT FIRST and consumes the invite only if a new row was
    created (kills the double-consume race + the unbounded-mint hole).
  * Revoking an invite cascades to its device children.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import secrets
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Header, Request, Response
from pydantic import BaseModel
from sqlalchemy import literal_column, or_, select, text, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.db import get_db
from app.core.rate_limit import rate_limit
from app.core.security import require_admin
from app.models.access_token import AccessToken

router = APIRouter(tags=["gate"])
log = logging.getLogger("rcq")

_CACHE_TTL = 45          # seconds; bounds worst-case revoke latency
_LRU_THROTTLE = 300      # seconds between last_used_at writes per token


def _hash(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _env_master_matches(raw: str) -> bool:
    master = settings.RCQ_AUTH_TOKEN or ""
    # compare_digest on the raw low-entropy operator secret (timing oracle with ==).
    return bool(master) and secrets.compare_digest(raw, master)


def _active(meta: dict) -> bool:
    """Predicate re-evaluated in-process every request."""
    if meta.get("revoked"):
        return False
    exp = meta.get("expires_at")
    if exp is not None:
        try:
            if datetime.fromisoformat(exp) <= _now():
                return False
        except ValueError:
            return False
    mu = meta.get("max_uses")
    if mu is not None and meta.get("uses", 0) >= mu:
        return False
    return True


def _meta_from_row(row: AccessToken) -> dict:
    return {
        "kind": row.kind,
        "revoked": bool(row.revoked),
        "expires_at": row.expires_at.isoformat() if row.expires_at else None,
        "max_uses": row.max_uses,
        "uses": row.uses,
    }


async def _deny() -> Response:
    # Small jitter so a Redis-hit deny and a DB-miss deny aren't a clean
    # token-existence timing oracle. The host-level subrequest tell is
    # irreducible (documented); this only blunts the per-token delta.
    await asyncio.sleep(0.002 + secrets.randbelow(3) / 1000.0)
    return Response(status_code=401)


@router.get("/gate/check", dependencies=[Depends(rate_limit("gate_check", 1200, 60))])
async def gate_check(
    x_rcq_auth: str | None = Header(default=None),
    db: AsyncSession = Depends(get_db),
) -> Response:
    """Caddy forward-style subrequest. 2xx = let the real request through; any
    non-2xx = Caddy serves the decoy. Hot path: DB-read at worst, never a write
    on the decision path."""
    raw = (x_rcq_auth or "").strip()
    if not raw:
        return await _deny()
    if _env_master_matches(raw):
        return Response(status_code=200)

    h = _hash(raw)

    # 1) Redis metadata cache — but NEVER let a Redis failure grant access.
    meta: dict | None = None
    try:
        from app.core.redis import get_redis
        redis = await get_redis()
        cached = await redis.get(f"gate:meta:{h}")
        if cached:
            meta = json.loads(cached)
    except Exception:
        meta = None  # fall through to DB (fail-closed: a blip never grants)

    # 2) DB fallback (authoritative). FAIL-CLOSED: any error -> deny.
    if meta is None:
        try:
            row = (await db.execute(
                select(AccessToken).where(AccessToken.token_hash == h)
            )).scalar_one_or_none()
        except Exception:
            log.warning("[gate] DB lookup failed on /gate/check")
            return await _deny()
        if row is None:
            return await _deny()
        meta = _meta_from_row(row)
        # populate the positive cache (best-effort)
        try:
            from app.core.redis import get_redis
            redis = await get_redis()
            await redis.set(f"gate:meta:{h}", json.dumps(meta), ex=_CACHE_TTL)
        except Exception:
            pass

    if not _active(meta):
        return await _deny()

    # last_used_at — telemetry only, never on the auth decision. NX-gated so it
    # writes at most ~1/token/5min (a per-request write would saturate the pool).
    try:
        from app.core.redis import get_redis
        redis = await get_redis()
        if await redis.set(f"gate:lru:{h}", "1", nx=True, ex=_LRU_THROTTLE):
            await db.execute(
                update(AccessToken).where(AccessToken.token_hash == h)
                .values(last_used_at=_now())
            )
            await db.commit()
    except Exception:
        pass

    return Response(status_code=200)


class RedeemIn(BaseModel):
    device_id: str


class RedeemOut(BaseModel):
    token: str


@router.post("/gate/redeem", dependencies=[Depends(rate_limit("gate_redeem", 20, 60))])
async def gate_redeem(
    body: RedeemIn,
    x_rcq_auth: str | None = Header(default=None),
    db: AsyncSession = Depends(get_db),
):
    """Exchange a one-time invite for a durable device token. Idempotent-ish:
    a device/standing/master token is returned verbatim (no mint); a re-redeem
    from the same device_id re-issues a fresh device token without re-consuming
    the invite (the raw device token is not recoverable from its hash)."""
    raw = (x_rcq_auth or "").strip()
    dev = (body.device_id or "").strip()
    if not raw or not (16 <= len(dev) <= 64) or not all(c in "0123456789abcdefABCDEF" for c in dev):
        return await _deny()

    # Master / non-invite tokens: return verbatim, never mint or mutate.
    if _env_master_matches(raw):
        return RedeemOut(token=raw)

    h = _hash(raw)
    row = (await db.execute(
        select(AccessToken).where(AccessToken.token_hash == h)
    )).scalar_one_or_none()
    if row is None:
        return await _deny()
    meta = _meta_from_row(row)
    if row.kind in ("device", "standing"):
        return RedeemOut(token=raw) if _active(meta) else await _deny()
    if row.kind != "invite":
        return await _deny()
    # An invite is redeemable while NOT revoked/expired. We deliberately do NOT
    # block on exhaustion (uses>=max_uses) here: a FRESH device is stopped by the
    # conditional consume below, while a device that ALREADY redeemed this invite
    # (a retry after a lost response) re-mints via ON CONFLICT without consuming —
    # so idempotent retry works without re-opening a spent invite to new devices.
    if meta.get("revoked"):
        return await _deny()
    _exp = meta.get("expires_at")
    if _exp is not None:
        try:
            if datetime.fromisoformat(_exp) <= _now():
                return await _deny()
        except ValueError:
            return await _deny()

    # Invite -> device. INSERT the device row ON CONFLICT FIRST; consume only if
    # a NEW row was created (xmax=0). Postgres-only path (matches the codebase's
    # existing pg_insert usage); the masquerade is a prod/self-host feature.
    new_raw = secrets.token_urlsafe(32)
    new_hash = _hash(new_raw)
    now = _now()
    ins = (
        pg_insert(AccessToken)
        .values(
            token_hash=new_hash, kind="device", label=row.label,
            device_id=dev, parent_id=row.id, max_uses=None, uses=0,
            revoked=False, created_at=now,
        )
        .on_conflict_do_update(
            index_elements=["device_id"],
            index_where=text("device_id IS NOT NULL"),
            set_={"token_hash": new_hash, "created_at": now},
        )
        .returning(literal_column("(xmax = 0)"))
    )
    inserted = bool((await db.execute(ins)).scalar())
    if inserted:
        # Fresh device row -> consume one invite use atomically. If the invite
        # got exhausted/revoked in the race, roll the whole thing back -> deny.
        cons = await db.execute(
            update(AccessToken)
            .where(
                AccessToken.token_hash == h,
                AccessToken.kind == "invite",
                AccessToken.revoked.is_(False),
                AccessToken.uses < AccessToken.max_uses,
                or_(AccessToken.expires_at.is_(None), AccessToken.expires_at > now),
            )
            .values(uses=AccessToken.uses + 1)
        )
        if cons.rowcount != 1:
            await db.rollback()
            return await _deny()
    await db.commit()

    # Cache the new device token as active AFTER commit (a Redis failure here
    # must not undo a committed consume).
    try:
        from app.core.redis import get_redis
        redis = await get_redis()
        await redis.set(
            f"gate:meta:{new_hash}",
            json.dumps({"kind": "device", "revoked": False, "expires_at": None,
                        "max_uses": None, "uses": 0}),
            ex=_CACHE_TTL,
        )
    except Exception:
        pass
    return RedeemOut(token=new_raw)


# ---------------------------------------------------------------------------
# Admin: generate / list / revoke access tokens (operator-only).
# ---------------------------------------------------------------------------

class CreateTokenIn(BaseModel):
    kind: str = "invite"            # invite | standing
    label: str | None = None
    max_uses: int | None = None     # invite defaults to 1; standing stays None
    expires_in_days: int | None = None


async def _evict(hashes: list[str]) -> None:
    if not hashes:
        return
    try:
        from app.core.redis import get_redis
        redis = await get_redis()
        await redis.delete(*[f"gate:meta:{h}" for h in hashes])
    except Exception:
        pass


@router.post("/admin/access-tokens")
async def admin_create_token(
    body: CreateTokenIn,
    _: str = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    kind = body.kind if body.kind in ("invite", "standing") else "invite"
    max_uses = 1 if kind == "invite" else body.max_uses  # standing: None = unlimited
    expires_at = None
    if body.expires_in_days and body.expires_in_days > 0:
        from datetime import timedelta
        expires_at = _now() + timedelta(days=body.expires_in_days)
    raw = secrets.token_urlsafe(32)
    h = _hash(raw)
    row = AccessToken(
        token_hash=h, kind=kind, label=body.label, max_uses=max_uses,
        uses=0, revoked=False, expires_at=expires_at, created_at=_now(),
    )
    db.add(row)
    await db.commit()
    await db.refresh(row)
    # The raw token is returned ONCE here and never stored or logged.
    return {"id": row.id, "kind": kind, "token": raw, "label": body.label,
            "max_uses": max_uses, "expires_at": expires_at.isoformat() if expires_at else None}


@router.get("/admin/access-tokens")
async def admin_list_tokens(
    _: str = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    rows = (await db.execute(
        select(AccessToken).order_by(AccessToken.created_at.desc()).limit(500)
    )).scalars().all()
    return [
        {
            "id": r.id, "kind": r.kind, "label": r.label,
            "token_prefix": r.token_hash[:8],  # display only; full hash is the credential
            "device_id": r.device_id, "parent_id": r.parent_id,
            "uses": r.uses, "max_uses": r.max_uses,
            "revoked": r.revoked,
            "expires_at": r.expires_at.isoformat() if r.expires_at else None,
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "last_used_at": r.last_used_at.isoformat() if r.last_used_at else None,
        }
        for r in rows
    ]


@router.post("/admin/access-tokens/{token_id}/revoke")
async def admin_revoke_token(
    token_id: int,
    _: str = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    row = (await db.execute(
        select(AccessToken).where(AccessToken.id == token_id)
    )).scalar_one_or_none()
    if row is None:
        return Response(status_code=404)
    affected = [row.token_hash]
    await db.execute(
        update(AccessToken).where(AccessToken.id == token_id).values(revoked=True)
    )
    # Revoking an invite cascades to the device tokens it minted, else "revoke
    # Alice's invite" would leave Alice's redeemed device working.
    if row.kind == "invite":
        children = (await db.execute(
            select(AccessToken.token_hash).where(AccessToken.parent_id == token_id)
        )).scalars().all()
        affected.extend(children)
        await db.execute(
            update(AccessToken).where(AccessToken.parent_id == token_id).values(revoked=True)
        )
    await db.commit()
    await _evict(affected)
    return {"revoked": True, "id": token_id, "cascaded": len(affected) - 1}
