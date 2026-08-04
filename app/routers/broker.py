"""Relay broker (relay-transport Phase 2 / гидра prerequisite).

The signed relay-config (GitHub-raw + CF KV) publishes the WHOLE relay list to
everyone, so a censor scrapes it and blocks the pool wholesale (the Tor-BridgeDB
problem). The broker is a SECOND, additive distribution channel that hands out
relays a FEW-PER-REQUEST in a deterministic per-NETWORK bucket, so no single
actor learns the whole pool without controlling many networks (slow + costly).

  POST /broker/register     (open, self-authenticating) operator adds a relay
  GET  /broker/bridges       (open, IP-bucketed)         client pulls a few relays
  GET  /broker/admin/list    (admin)                      full pool
  POST /broker/admin/set     (admin)                      set tier / enabled
  DELETE /broker/admin/{tag} (admin)                      remove a relay

Anti-enumeration is enforced SERVER-SIDE (security review 2026-06-13): the bucket
is derived from the requester IP block + a daily epoch + a server secret (NOT a
client-chosen param), so a single IP sees one stable subset it cannot vary, and
the per-relay score is HMAC'd with a server secret so an attacker can't grind
which relay lands in which bucket offline. Selection is trusted-preferred so a
community flood can't displace vetted relays, community registrations land ENABLED
(self-serve гидра — no manual approval) but are SERVED only once the canary has
verified them e2e (recent last_ok), and registration is capped per-key + globally.

Fully decoupled from send/queue/bundle. The server is NOT a trust root: a hostile
relay's max exposure is metadata + DoS, healed by multi-relay + onion. The
registration signature is accountability + anti-poisoning, not a safety grant.
See `RCQ/docs/relay-broker-design.md`.
"""
import base64
import binascii
import hashlib
import hmac
import ipaddress
import json
import re
import time

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.db import get_db
from app.core.rate_limit import _client_ip, rate_limit
from app.core.redis import get_redis
from app.core.security import require_admin
from app.models.broker import BrokerRelay
from app.services.geoip import country_of

router = APIRouter(prefix="/broker", tags=["broker"])

_MAX_DESCRIPTOR_BYTES = 2 * 1024
_MAX_TS_SKEW = 300              # ts must not be future-dated past this (clock-skew slack)
_MAX_ROWS_PER_KEY = 8          # one operator key can list at most this many relays
_MAX_TOTAL_ROWS = 1000         # global pool cap (DB-bloat floor)
_BUCKET_PERIOD = 86400         # ring reshuffles daily
_LIVENESS_WINDOW = 2700        # a community relay is served only if probed-alive within this many seconds (canary runs ~every 10 min)
# Region-scoped liveness (the FRA canary is single-vantage: it wrongly drops a
# relay reachable from a censored region but not FRA, and wrongly serves one
# reachable from FRA but blocked in-region). Clients report reachability; a relay
# counts as alive/dead IN A REGION only when QUORUM distinct networks there agree
# within the window. Distinct-/24 quorum over the OBSERVED source IP is the sybil
# resistance — no client signature needed (a client can't forge N real networks).
_REACH_WINDOW = 7200           # a region report stays fresh this long (client reports are sparser than the canary)
_REACH_QUORUM = 2              # distinct reporter /24s in a region needed to flip its in-region liveness
_MAX_REACH_REPORTS = 25        # per request body

# Per-proto descriptor schema: required + optional keys, each with a charset.
_RE = {
    "server": re.compile(r"^[A-Za-z0-9.\-:\[\]]{1,255}$"),
    "sni": re.compile(r"^[A-Za-z0-9.\-]{1,255}$"),
    "uuid": re.compile(r"^[0-9a-fA-F\-]{1,64}$"),
    "pbk": re.compile(r"^[A-Za-z0-9_\-+/=]{1,128}$"),
    "sid": re.compile(r"^[A-Za-z0-9_\-+/=]{1,64}$"),
    "pw": re.compile(r"^[A-Za-z0-9_\-+/=.]{1,128}$"),
    "obfs": re.compile(r"^[A-Za-z0-9_\-+/=.]{1,128}$"),
    "flow": re.compile(r"^[a-z\-]{1,32}$"),
    "label": re.compile(r"^[^\x00-\x1f\x7f]{1,64}$"),
}
_PROTO_KEYS = {
    "vless": ({"uuid", "pbk", "sid"}, {"flow", "label"}),
    "hysteria2": ({"pw"}, {"obfs", "label"}),
}
_BASE_KEYS = {"proto", "server", "port", "sni"}


def _bucket_secret() -> bytes:
    """Stable, non-public HMAC key derived from the app JWT secret (shared across
    workers + restarts, never exposed). Makes the per-bucket relay score
    un-grindable offline."""
    return hashlib.sha256(b"rcq-broker-bucket-v1:" + settings.JWT_SECRET.encode()).digest()


def _canon_key(b64: str) -> str | None:
    """Decode an Ed25519 pubkey STRICTLY (no junk/whitespace leniency) and
    re-encode to a canonical string, so every textual variant of the same key
    collapses to one identity (one row, one tag). None if not a valid 32-byte key."""
    try:
        raw = base64.b64decode(b64, validate=True)
    except (binascii.Error, ValueError):
        return None
    if len(raw) != 32:
        return None
    return base64.b64encode(raw).decode()


def _server_routable(server: str) -> bool:
    """Reject loopback / link-local / private / reserved / metadata targets so a
    descriptor can't point clients (or a future liveness probe) at an internal
    address. Hostnames pass here (a future probe MUST re-resolve + re-check)."""
    host = server.strip()
    low = host.lower()
    if low == "localhost" or low.endswith(".localhost"):
        return False
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return True  # hostname — allowed at registration time
    return not (
        ip.is_private or ip.is_loopback or ip.is_link_local
        or ip.is_reserved or ip.is_multicast or ip.is_unspecified
    )


def _validate_descriptor(d: object) -> dict:
    """Type/shape/charset-check a relay descriptor. Allows ONLY the keys valid for
    its proto (so what the operator signs == what we store == what we serve, with
    no cross-proto or unknown fields), enforces per-proto required fields + a
    charset allow-list, rejects internal `server` targets, and bounds size."""
    if not isinstance(d, dict):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "descriptor must be an object")
    proto = d.get("proto")
    if proto not in _PROTO_KEYS:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "proto must be vless or hysteria2")
    required, optional = _PROTO_KEYS[proto]
    allowed = _BASE_KEYS | required | optional
    extra = set(d.keys()) - allowed
    if extra:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"unknown/cross-proto keys: {sorted(extra)}")

    def field(key: str, *, required: bool) -> None:
        v = d.get(key)
        if v is None:
            if required:
                raise HTTPException(status.HTTP_400_BAD_REQUEST, f"missing {key}")
            return
        if not isinstance(v, str) or not _RE[key].match(v):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, f"invalid {key}")

    if not isinstance(d.get("server"), str) or not _RE["server"].match(d["server"]):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid server")
    if not _server_routable(d["server"]):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "server must be a public address")
    field("sni", required=True)
    port = d.get("port")
    if not isinstance(port, int) or isinstance(port, bool) or not (1 <= port <= 65535):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid port")
    for k in required:
        field(k, required=True)
    for k in optional:
        field(k, required=False)

    raw = json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    if len(raw.encode("utf-8")) > _MAX_DESCRIPTOR_BYTES:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "descriptor too large")
    return d


def _reg_signed_bytes(descriptor: dict, ts: int) -> bytes:
    """The EXACT bytes an operator signs to register: canonical JSON of
    {descriptor, ts}, keys sorted recursively, compact, UTF-8."""
    return json.dumps(
        {"descriptor": descriptor, "ts": ts},
        sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")


def _verify_reg_sig(descriptor: dict, ts: int, canon_key_b64: str, sig_b64: str) -> bool:
    """True iff `sig` is a valid Ed25519 signature over the canonical registration
    bytes under the (already-canonicalized) operator key."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        sig = base64.b64decode(sig_b64, validate=True)
        pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(canon_key_b64))
        pub.verify(sig, _reg_signed_bytes(descriptor, ts))
        return True
    except (InvalidSignature, ValueError, TypeError, binascii.Error):
        return False


def _status_signed_bytes(ts: int) -> bytes:
    """Bytes an operator signs to query THEIR OWN relay status: canonical JSON of
    {action:"status", ts}. A DISTINCT payload from registration, so a register
    signature can't be replayed against /status (and vice-versa)."""
    return json.dumps(
        {"action": "status", "ts": ts},
        sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")


def _verify_status_sig(ts: int, canon_key_b64: str, sig_b64: str) -> bool:
    """True iff `sig` is a valid Ed25519 signature over the status bytes under the
    (already-canonicalized) operator key."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        sig = base64.b64decode(sig_b64, validate=True)
        pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(canon_key_b64))
        pub.verify(sig, _status_signed_bytes(ts))
        return True
    except (InvalidSignature, ValueError, TypeError, binascii.Error):
        return False


def _relay_tag(canon_key_b64: str, server: str, port: int) -> str:
    """Stable, un-squattable id from the CANONICAL operator key + endpoint. A
    different key yields a different row; the same operator re-registering the
    same endpoint updates their own row."""
    h = hashlib.sha256(f"{canon_key_b64}:{server}:{port}".encode("utf-8")).hexdigest()
    return f"br-{h[:16]}"


def _ip_block(ip: str) -> str:
    """The requester's network block (v4 /24, v6 /48) — the anti-enumeration
    bucket. One network sees one stable subset; it cannot be varied per request."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return ip or "unknown"
    prefix = 24 if a.version == 4 else 48
    return str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False).network_address)


@router.post(
    "/register",
    dependencies=[Depends(rate_limit("broker_register", 10, 60))],
)
async def register_relay(
    body: dict = Body(...),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Register (or refresh) a relay. Body:
    `{descriptor:{proto,server,port,sni,…}, key:<b64 ed25519 pub>, sig:<b64>, ts:int}`.
    The server canonicalizes the key, VERIFIES the signature before storing (a
    stranger cannot poison a descriptor), bounds `ts` to a sane window, and caps
    rows per-key + globally. New relays land ENABLED (self-serve гидра — no manual
    approval); the safety net is in /bridges, which SERVES a community relay only
    after the canary has verified it e2e (recent last_ok), so a dead/junk
    self-registration is never handed to a client."""
    raw_key = body.get("key")
    sig_b64 = body.get("sig")
    ts = body.get("ts")
    if not isinstance(raw_key, str) or not isinstance(sig_b64, str):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "missing key or sig")
    if not isinstance(ts, int) or isinstance(ts, bool) or ts <= 0 or ts > int(time.time()) + _MAX_TS_SKEW:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "missing or invalid ts")
    key_b64 = _canon_key(raw_key)
    if key_b64 is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid operator key")
    descriptor = _validate_descriptor(body.get("descriptor"))
    if not _verify_reg_sig(descriptor, ts, key_b64, sig_b64):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "bad signature")

    tag = _relay_tag(key_b64, descriptor["server"], descriptor["port"])
    raw = json.dumps(descriptor, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    existing = (
        await db.execute(select(BrokerRelay).where(BrokerRelay.tag == tag))
    ).scalar_one_or_none()
    if existing is not None:
        if existing.operator_key != key_b64:  # unreachable (tag is key-derived); defend anyway
            raise HTTPException(status.HTTP_403_FORBIDDEN, "tag owned by another key")
        if ts < existing.ts:
            raise HTTPException(status.HTTP_409_CONFLICT, "stale ts")
        existing.descriptor = raw
        existing.ts = ts
        await db.commit()
        return {"ok": True, "tag": tag, "enabled": existing.enabled}

    # New row — enforce caps (refreshes above are exempt).
    per_key = (
        await db.execute(select(func.count()).select_from(BrokerRelay).where(BrokerRelay.operator_key == key_b64))
    ).scalar_one()
    if per_key >= _MAX_ROWS_PER_KEY:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "per-key relay limit reached")
    total = (await db.execute(select(func.count()).select_from(BrokerRelay))).scalar_one()
    if total >= _MAX_TOTAL_ROWS:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "broker pool full")
    # Self-serve гидра: a community relay lands ENABLED (no founder approval). The
    # brakes are (a) /bridges' liveness gate — a community relay isn't SERVED until
    # the canary verifies it e2e — plus (b) the admin kill switch (enabled=False)
    # and (c) the per-key (8) + global (1000) registration caps above.
    db.add(BrokerRelay(tag=tag, descriptor=raw, operator_key=key_b64, tier="community", enabled=True, ts=ts))
    await db.commit()
    return {"ok": True, "tag": tag, "enabled": True}


@router.get(
    "/bridges",
    dependencies=[Depends(rate_limit("broker_bridges", 30, 60))],
)
async def get_bridges(
    request: Request,
    db: AsyncSession = Depends(get_db),
    n: int = Query(3, ge=1, le=5),
) -> dict:
    """Return up to `n` ENABLED, LIVE relays for this requester's NETWORK bucket.
    The bucket is the requester IP block + a daily epoch (NOT client-chosen), and
    the per-relay score is HMAC'd with a server secret, so the subset can be
    neither cycled from one IP nor ground offline. Trusted relays fill first so a
    community flood can't displace them. No stable `tag` is returned — clients
    dedup locally by proto:server:port.

    Liveness gate (the safety net for self-serve auto-enable): a COMMUNITY relay is
    served only once the canary has verified it e2e recently (last_ok within
    _LIVENESS_WINDOW), so a never-probed or gone-dead self-registration never
    reaches a client. TRUSTED relays (admin-set, and independently monitored by the
    signed-config canary) are exempt — promoting one is instant, with no gap."""
    now = int(time.time())
    client_ip = _client_ip(request)
    region = country_of(client_ip)
    all_rows = (
        await db.execute(select(BrokerRelay).where(BrokerRelay.enabled.is_(True)))
    ).scalars().all()

    # Region quorum (best-effort): count DISTINCT reporter /24s in THIS requester's
    # region that recently called each community relay reachable / unreachable.
    community_all = [r for r in all_rows if r.tier != "trusted"]
    sp_of: dict[str, str] = {}
    for r in community_all:
        try:
            d = json.loads(r.descriptor)
        except ValueError:
            continue
        if d.get("server") and d.get("port") is not None:
            sp_of[r.tag] = f"{d['server']}:{d['port']}"
    ok_count: dict[str, int] = {}
    fail_count: dict[str, int] = {}
    try:
        redis = await get_redis()
        min_score = now - _REACH_WINDOW
        probed = [r for r in community_all if r.tag in sp_of]
        async with redis.pipeline(transaction=False) as pipe:
            for r in probed:
                sp = sp_of[r.tag]
                pipe.zcount(f"broker:reach:ok:{sp}:{region}", min_score, "+inf")
                pipe.zcount(f"broker:reach:fail:{sp}:{region}", min_score, "+inf")
            res = await pipe.execute()
        for idx, r in enumerate(probed):
            ok_count[r.tag] = int(res[2 * idx] or 0)
            fail_count[r.tag] = int(res[2 * idx + 1] or 0)
    except Exception:
        pass  # Redis hiccup: fall back to the canary-only gate below.

    def _serve(r: BrokerRelay) -> bool:
        # Trusted (admin-set, signed-config canary-monitored): always served.
        if r.tier == "trusted":
            return True
        canary_alive = r.last_ok is not None and now - r.last_ok <= _LIVENESS_WINDOW
        region_ok = ok_count.get(r.tag, 0) >= _REACH_QUORUM
        region_fail = fail_count.get(r.tag, 0) >= _REACH_QUORUM
        # In-region reachability (quorum) is the strongest signal: it rescues a
        # relay the FRA canary can't reach but a censored region can, and it
        # overrides region-fail noise. Otherwise fall back to the canary, unless
        # the region quorum says it's blocked here.
        return region_ok or (canary_alive and not region_fail)

    rows = [r for r in all_rows if _serve(r)]
    if not rows:
        return {"relays": [], "ts": now}
    bucket = f"{_ip_block(client_ip)}:{now // _BUCKET_PERIOD}"
    secret = _bucket_secret()

    def score(r: BrokerRelay) -> str:
        return hmac.new(secret, f"{bucket}:{r.tag}".encode("utf-8"), hashlib.sha256).hexdigest()

    trusted = sorted((r for r in rows if r.tier == "trusted"), key=score)
    community = sorted((r for r in rows if r.tier != "trusted"), key=score)
    chosen = (trusted + community)[:n]
    out = []
    for r in chosen:
        try:
            d = json.loads(r.descriptor)
        except ValueError:
            continue
        d["tier"] = r.tier
        out.append(d)
    # Best-effort reach telemetry: bump a rolling ~24h served-count per relay so an
    # operator can confirm via /broker/status that their relay is actually being
    # handed out. Per-relay aggregate only (no requester identity), and fully
    # swallowed — a redis hiccup must NEVER break relay distribution.
    try:
        redis = await get_redis()
        async with redis.pipeline(transaction=False) as pipe:
            for r in chosen:
                k = f"broker:served:{r.tag}"
                pipe.incr(k)
                pipe.expire(k, 86400)
            await pipe.execute()
    except Exception:
        pass
    return {"relays": out, "ts": now}


@router.post(
    "/reachability",
    dependencies=[Depends(rate_limit("broker_reachability", 30, 60))],
)
async def report_reachability(
    request: Request,
    body: dict = Body(...),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Client reachability reports for region-scoped liveness. Body:
    `{reports: [{server, port, ok}, …]}`. The server derives the reporter's REGION
    (country, from its source IP) and NETWORK (/24) and records a fresh OK/FAIL
    vote in a rolling per-(relay, region) set. /bridges then serves a community
    relay in region R once QUORUM distinct networks there recently reported it
    reachable — so a relay raised in a censored country reaches users there even
    when the FRA canary can't — and suppresses a canary-alive community relay in R
    once a quorum reports it UNREACHABLE there.

    No client signature: the trust anchor is the OBSERVED source IP (a client can't
    forge being on many distinct real /24s in a region), so quorum over distinct
    networks IS the sybil resistance. Reports for relays not in the pool are ignored
    (bounds the Redis keyspace to real relays × regions). Fully best-effort — a
    Redis hiccup never errors the client, and distribution keeps working."""
    reports = body.get("reports")
    if not isinstance(reports, list) or not reports:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "reports must be a non-empty list")
    if len(reports) > _MAX_REACH_REPORTS:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "too many reports")

    ip = _client_ip(request)
    region = country_of(ip)
    net = _ip_block(ip)
    now = int(time.time())

    # Accept reports ONLY for relays actually in the pool (keyed by server:port),
    # so a client can't mint arbitrary Redis keys.
    known: set[str] = set()
    for r in (await db.execute(select(BrokerRelay).where(BrokerRelay.enabled.is_(True)))).scalars().all():
        try:
            d = json.loads(r.descriptor)
        except ValueError:
            continue
        if d.get("server") and d.get("port") is not None:
            known.add(f"{d['server']}:{d['port']}")

    accepted = 0
    try:
        redis = await get_redis()
        async with redis.pipeline(transaction=False) as pipe:
            for rep in reports:
                if not isinstance(rep, dict):
                    continue
                server, port, ok = rep.get("server"), rep.get("port"), rep.get("ok")
                if (not isinstance(server, str) or not isinstance(port, int)
                        or isinstance(port, bool) or not isinstance(ok, bool)):
                    continue
                sp = f"{server}:{port}"
                if sp not in known:
                    continue
                key = f"broker:reach:{'ok' if ok else 'fail'}:{sp}:{region}"
                pipe.zadd(key, {net: now})
                pipe.zremrangebyscore(key, 0, now - _REACH_WINDOW)
                pipe.expire(key, _REACH_WINDOW)
                accepted += 1
            await pipe.execute()
    except Exception:
        pass
    return {"ok": True, "accepted": accepted, "region": region, "ts": now}


@router.post(
    "/status",
    dependencies=[Depends(rate_limit("broker_status", 30, 60))],
)
async def operator_status(
    body: dict = Body(...),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Let an OPERATOR see the status of THEIR OWN relays — is each one being
    served to users right now, when the canary last verified it alive, how many
    times it's been handed out lately. Auth is the SAME Ed25519 operator key used
    at /register: the body `{key, sig, ts}` signs `{action:"status", ts}`, and the
    server returns ONLY rows whose operator_key matches the verified key.

    NB the broker distributes DESCRIPTORS, not traffic, so it cannot report actual
    end-user connection counts (those never touch the broker — the relay's own
    sing-box sees them). `serving` answers the real question ("is my relay live and
    being handed to clients"); `served_recent` is how many times it was handed out
    in the last ~24h (a reach proxy, best-effort)."""
    raw_key = body.get("key")
    sig_b64 = body.get("sig")
    ts = body.get("ts")
    if not isinstance(raw_key, str) or not isinstance(sig_b64, str):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "missing key or sig")
    # Bound ts BOTH directions (anti-replay) — tighter than register's future-only check.
    if not isinstance(ts, int) or isinstance(ts, bool) or ts <= 0 or abs(int(time.time()) - ts) > _MAX_TS_SKEW:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "missing or invalid ts")
    key_b64 = _canon_key(raw_key)
    if key_b64 is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid operator key")
    if not _verify_status_sig(ts, key_b64, sig_b64):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "bad signature")

    now = int(time.time())
    rows = (
        await db.execute(select(BrokerRelay).where(BrokerRelay.operator_key == key_b64))
    ).scalars().all()

    # Best-effort reach counts (never fail the status read on a redis hiccup).
    served: dict[str, int] = {}
    try:
        redis = await get_redis()
        for r in rows:
            v = await redis.get(f"broker:served:{r.tag}")
            served[r.tag] = int(v) if v is not None else 0
    except Exception:
        served = {}

    relays = []
    for r in rows:
        try:
            d = json.loads(r.descriptor)
        except ValueError:
            d = {}
        is_serving = bool(r.enabled) and (
            r.tier == "trusted" or (r.last_ok is not None and now - r.last_ok <= _LIVENESS_WINDOW)
        )
        relays.append({
            "tag": r.tag,
            "proto": d.get("proto"),
            "server": d.get("server"),
            "port": d.get("port"),
            "tier": r.tier,
            "enabled": bool(r.enabled),
            "serving": is_serving,
            "last_ok": r.last_ok,
            "last_ok_age_sec": (now - r.last_ok) if r.last_ok is not None else None,
            "fail_count": r.fail_count,
            "served_recent": served.get(r.tag, 0),
        })
    return {"relays": relays, "ts": now, "liveness_window_sec": _LIVENESS_WINDOW}


# ── admin (HTTP Basic) ────────────────────────────────────────────────────────
@router.get("/admin/list", dependencies=[Depends(require_admin)])
async def admin_list(db: AsyncSession = Depends(get_db)) -> dict:
    rows = (await db.execute(select(BrokerRelay))).scalars().all()
    out = []
    for r in rows:
        try:
            desc = json.loads(r.descriptor)
        except ValueError:
            desc = {"_corrupt": True}
        out.append({
            "tag": r.tag,
            "tier": r.tier,
            "enabled": r.enabled,
            "ts": r.ts,
            "last_ok": r.last_ok,
            "fail_count": r.fail_count,
            "operator_key": (r.operator_key or "")[:12] + "…",
            # Server-side registration time, in unix seconds like last_ok. The
            # canary's prune step needs it to judge a row that has NEVER
            # answered, where last_ok gives it nothing to measure from.
            "created_at": int(r.created_at.timestamp()) if r.created_at else None,
            "descriptor": desc,
        })
    return {"relays": out}


class AdminSet(BaseModel):
    tag: str
    tier: str | None = None
    enabled: bool | None = None


@router.post("/admin/set", dependencies=[Depends(require_admin)])
async def admin_set(body: AdminSet, db: AsyncSession = Depends(get_db)) -> dict:
    row = (
        await db.execute(select(BrokerRelay).where(BrokerRelay.tag == body.tag))
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such relay")
    if body.tier is not None:
        if body.tier not in ("community", "trusted"):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "tier must be community or trusted")
        row.tier = body.tier
    if body.enabled is not None:
        row.enabled = body.enabled
    await db.commit()
    return {"ok": True, "tag": row.tag, "tier": row.tier, "enabled": row.enabled}


class LivenessResult(BaseModel):
    tag: str
    ok: bool


class LivenessReport(BaseModel):
    results: list[LivenessResult]


@router.post("/admin/liveness", dependencies=[Depends(require_admin)])
async def admin_liveness(body: LivenessReport, db: AsyncSession = Depends(get_db)) -> dict:
    """Liveness report from the out-of-band prober (the prod relay canary, which
    e2e-probes each ENABLED broker relay every cycle). For each {tag, ok}: a
    success stamps last_ok=now + resets fail_count; a failure bumps fail_count and
    leaves last_ok untouched, so a relay ages out of /bridges' liveness window once
    it stops passing. Unknown tags are ignored. This is the ONLY writer of
    last_ok/fail_count — the serving path (/bridges) only reads them."""
    now = int(time.time())
    updated = 0
    for res in body.results:
        row = (
            await db.execute(select(BrokerRelay).where(BrokerRelay.tag == res.tag))
        ).scalar_one_or_none()
        if row is None:
            continue
        if res.ok:
            row.last_ok = now
            row.fail_count = 0
        else:
            row.fail_count = (row.fail_count or 0) + 1
        updated += 1
    await db.commit()
    return {"ok": True, "updated": updated, "ts": now}


@router.delete("/admin/{tag}", dependencies=[Depends(require_admin)])
async def admin_delete(tag: str, db: AsyncSession = Depends(get_db)) -> dict:
    await db.execute(delete(BrokerRelay).where(BrokerRelay.tag == tag))
    await db.commit()
    return {"ok": True}
