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
  POST /broker/admin/tenants[/set|/rotate|/assign] (admin) paid tenancy + pools

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
import secrets
import hmac
import ipaddress
import json
import logging
import re
import time
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import delete, func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.db import engine, get_db
from app.core.rate_limit import _client_ip, rate_limit
from app.core.redis import get_redis
from app.core.security import require_admin
# ⚠ relay_addresses is cached for the life of the process (transport.py): a
# node added to the signed config after boot is not refused by `assign` until
# the next restart. Acceptable, since assigning a fleet node is a founder
# mistake, not an attack, and the fleet changes by deploy anyway.
from app.core.transport import fleet_endpoints, relay_addresses, set_broker_addresses
from app.models.broker import BrokerRelay, RelayTenant
from app.models.relay_inquiry import RelayInquiry
from app.services.geoip import country_of

router = APIRouter(prefix="/broker", tags=["broker"])

_MAX_DESCRIPTOR_BYTES = 2 * 1024
_MAX_TS_SKEW = 300              # ts must not be future-dated past this (clock-skew slack)
_MAX_ROWS_PER_KEY = 8          # one operator key can list at most this many relays
_MAX_TOTAL_ROWS = 1000         # global pool cap (DB-bloat floor)
_BUCKET_PERIOD = 86400         # ring reshuffles daily
# Failures before a never-live community row is swept. The canary runs about
# every 10 minutes, so this is roughly a day: long enough for somebody who
# registered a relay in the evening and fixes it in the morning, short enough
# that a wrong (or someone else's) address is not probed forever.
_DEAD_AFTER_FAILS = 144
# Parked rows (registered `private`, never assigned) are the one kind of row
# the island neither probes nor sweeps on its own: the canary skips disabled
# rows, and the liveness sweep above only sees reported failures. Left
# uncapped, one IP at the register rate limit could fill the whole pool with
# parked junk in about two hours and hold it for a week, refusing every real
# operator's registration without costing the canary a single probe. Parked
# rows are the founder's own nodes, raised a couple at a time, so the caps
# are small: a stranger who fills them blocks parking only, never public
# registration, and the rows are one DELETE each in the admin.
_MAX_PARKED_ROWS = 16          # parked, never assigned, island-wide
_MAX_PARKED_PER_KEY = 2        # one bootstrap key parks one node; two allows a port change
# A parked row nobody assigned within this long is deleted by the liveness
# call, so the island does not depend on the canary's 30-day prune to shed
# junk. The runbook assigns a node in the same sitting it is raised; a week
# is generous for that, and a node raised and forgotten re-registers in one
# command.
_PARKED_TTL = 7 * 86400
log = logging.getLogger(__name__)

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

# What a client can say about the route it ended up on. Deliberately a closed
# set: it is a counter key, and an open string would let a client mint Redis
# keys. `tunnel_ok` is the only good outcome; the other three are the shapes of
# failure we cannot currently tell apart from the traffic mix alone.
_TRANSPORT_OUTCOMES = frozenset({
    "tunnel_ok",       # engaged and the route carried traffic
    "tunnel_dead",     # engaged, carried nothing, no fallback taken
    "fell_to_direct",  # tunnel carried nothing, direct worked
    "fell_to_front",   # tunnel AND direct dead, went out through the CF front
    "direct_ok",       # never needed the tunnel
})
_TRANSPORT_RETENTION = 45 * 86400

# A pool label: `shared`, `team-<tnt id>`. Lowercase, digits, dashes, and
# short, because it is written by the console worker from its tenant id and
# read back in the admin and the canary line; nothing else is ever a valid
# pool and a typo must not create one.
#
# No underscore, on purpose. A console id is `tnt_<hex>`, and the worker
# spells its pool with the underscore as a dash (`team-tnt-<hex>`, `poolFor`
# in console-worker/tenants.js, pinned by its own test against this exact
# grammar). Admitting the underscore here would give every Team pool two
# spellings: the founder assigns nodes to `team-tnt_x` off the cabinet id,
# the minute sync keeps offering `team-tnt-x`, and the pool never applies
# with nothing saying why. One spelling, and the other one is a 400 the
# founder sees at once. The inquiry names the pool as the worker spelled it.
_POOL_RE = re.compile(r"^[a-z0-9\-]{1,64}$")
# The label of every Personal buyer's pool. A Team rides it until its own
# `team-<id>` pool has an enabled node.
_SHARED_POOL = "shared"
# The inquiry tier the island writes for itself when a PAID team has no pool
# yet. Counted by /admin/stats as `pools_needing_nodes` and mailed by the
# monitor; closed by the founder or by the island once the pool applies.
_TEAM_PAID_TIER = "team-paid"

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


def _parked_where():
    """The WHERE of a parked row still waiting for the founder: registered
    `private` (so disabled and never probed) and assigned to nobody. One
    definition for the register caps, the sweep and the assign guard, so the
    three cannot drift apart. A row the founder disabled after it was live
    has a `last_ok` and is not parked; a parked row given a pool is a
    customer's node and is not parked either."""
    return (
        BrokerRelay.enabled.is_(False),
        BrokerRelay.tenant_id.is_(None),
        BrokerRelay.pool_id.is_(None),
        BrokerRelay.last_ok.is_(None),
    )


async def _sweep_stale_parked(db: AsyncSession) -> int:
    """Delete parked rows nobody assigned within _PARKED_TTL, by created_at:
    a parked row never answers a probe, so `last_ok` gives nothing to
    measure from. Never a pool's or a tenant's row (`_parked_where` excludes
    both), never a row that was live once. Returns how many went; the caller
    commits."""
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=_PARKED_TTL)
    where = (*_parked_where(), BrokerRelay.created_at < cutoff)
    n = int(await db.scalar(select(func.count()).select_from(BrokerRelay).where(*where)) or 0)
    if n:
        # `fetch`, not the default `evaluate`: that one re-runs the WHERE in
        # Python against rows already loaded in this session (a liveness
        # report can name a parked row), and on SQLite those come back with
        # a naive `created_at` that cannot be compared to the aware cutoff.
        await db.execute(
            delete(BrokerRelay).where(*where).execution_options(synchronize_session="fetch")
        )
        log.warning("[broker] swept %d parked relay(s) nobody assigned in %d days", n, _PARKED_TTL // 86400)
    return n


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


# ⏭ MISSING, and operators ask for it: a way to find out whether YOUR relay is
# being handed out right now. The broker knows; the person running the box has
# no way to ask, so a healthy relay that has been disabled server-side, or one
# the canary dropped, looks exactly like a working one from the operator's
# side. Today the only self-service answer is the end-to-end dial in
# docs/relay-operator-guide.md, which proves the relay works and says nothing
# about whether it is in rotation.
#
# The shape is already here and needs no new secret: `/register` below is
# authenticated by an Ed25519 signature over the descriptor, so
# `POST /broker/status` with the same `{key, sig, ts}` envelope would answer
# "enabled / live / last probed / tier" for that one key and nothing else.
# ⚠ It must answer for ONE key at a time and never list, or it becomes the
# relay enumeration that `/bridges` exists to prevent.
#
# Not critical: a dead relay costs the network nothing by design, which is why
# this has waited (founder, 09.09: "write it down, we will do it later").
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
    # A node meant for a paid pool. It lands PARKED (enabled=False): dark to
    # /bridges, to the canary and to every public answer, until the founder
    # assigns it to a pool. The alternative, landing it enabled and hoping to
    # assign it within the ten minutes before the canary's first OK gets it
    # served, would burn the address on a slow morning. Outside the signed
    # envelope on purpose: it changes only where the operator's OWN row
    # starts, never what it says, and a stranger sending it parks nothing but
    # their own relay.
    private = body.get("private", False)
    if not isinstance(private, bool):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "private must be a boolean")
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
    if private:
        # The parked caps (see _MAX_PARKED_ROWS). Only rows still waiting for
        # an assignment count: a parked node the founder has pooled is a
        # customer's node, not a slot, and leaves the count the moment it is
        # assigned, whether or not it is lit yet.
        parked_key = (
            await db.execute(
                select(func.count()).select_from(BrokerRelay)
                .where(*_parked_where(), BrokerRelay.operator_key == key_b64)
            )
        ).scalar_one()
        if parked_key >= _MAX_PARKED_PER_KEY:
            raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "per-key parked limit reached")
        parked_total = (
            await db.execute(select(func.count()).select_from(BrokerRelay).where(*_parked_where()))
        ).scalar_one()
        if parked_total >= _MAX_PARKED_ROWS:
            raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "parked pool full")
    # Self-serve гидра: a community relay lands ENABLED (no founder approval). The
    # brakes are (a) /bridges' liveness gate — a community relay isn't SERVED until
    # the canary verifies it e2e — plus (b) the admin kill switch (enabled=False)
    # and (c) the per-key (8) + global (1000) registration caps above.
    # A `private` registration is the one exception: it lands parked, and the
    # refresh path above leaves `enabled` alone, so re-running bootstrap
    # neither parks nor un-parks a row.
    db.add(BrokerRelay(
        tag=tag, descriptor=raw, operator_key=key_b64, tier="community", enabled=not private, ts=ts,
    ))
    await db.commit()
    return {"ok": True, "tag": tag, "enabled": not private}


def _disclosure_cap(pool: int, requested: int) -> int:
    """How many relays one network may learn, given how many exist.

    The bucket is deterministic per (IP block, day), so a censor's cost is
    counted in distinct network vantage points, not requests — the per-IP rate
    limit does not touch them. Each vantage point yields a k-subset of the pool
    of N, so the expected number of relays still unseen after t of them is
    N(1-k/N)^t, and full enumeration costs roughly (N/k)·ln(N) networks.

    That ratio is the whole game, and `n` was chosen when the pool was expected
    to be large. Measured against what actually exists:

        pool  k=1  k=2  k=3  k=5      (networks needed to see everything)
           6   10    5    3    1
          10   22   11    7    4
          20   59   29   19   11

    Six relays with the old ceiling of five meant ONE network learned the entire
    fleet. Holding k at about N/5 keeps the cost near ten networks or more,
    which is where it stops being a single curl.

    Two things this deliberately does not claim. A state censor has effectively
    unlimited vantage points, so this raises the cost of casual scraping and
    makes enumeration a visible pattern; it does not stop ТСПУ. And while the
    signed config still publishes the whole fleet to anyone who asks, none of it
    binds at all — the broker only starts mattering once that list degrades to a
    minimal seed. Tuning it now is free and sets the right default for then.
    """
    if pool <= 0:
        return 0
    return max(1, min(requested, pool // 5))


# ── paid tenancy ─────────────────────────────────────────────────────────
#
# A tenant proves itself with one bearer key and gets their own endpoints added
# to the ordinary answer. Without a key nothing about this endpoint changes by
# a single byte, which is the property that lets it ship before anyone has
# bought anything.

def _tenant_key(request: Request) -> str | None:
    """The tenant key from `Authorization: Bearer …`.

    ⚠ A header, deliberately, and this one because proxies redact it. The
    obvious alternative was a query parameter, and a query parameter is exactly
    how 990 session tokens ended up written to disk in this project — the
    websocket has no choice but to use one, this does.
    """
    raw = request.headers.get("authorization") or ""
    parts = raw.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    key = parts[1].strip()
    # A logged-in client sends its own session JWT here on other endpoints, and
    # some will send it to this one too. A JWT is three dot-separated parts; a
    # tenant key is not. Cheap way to skip the pointless hash + query.
    return None if (not key or key.count(".") == 2) else key


async def _tenant_from_request(request: Request, db: AsyncSession, now: int):
    """The active, paid-up tenant behind this request, plus WHY when there
    isn't one: `(tenant | None, state)` where state is None (no key offered),
    "ok", "unknown" or "expired".

    ⚠ This used to answer None to everything, deliberately, so that no key, a
    wrong key, a revoked key and a lapsed subscription were indistinguishable
    and the endpoint could not be used as an oracle for guessing keys. That
    property is given up here on purpose, and it is worth saying why.

    It was never fully true: a real key adds the tenant's own endpoints to the
    answer, so anybody guessing could already tell a hit from a miss by
    counting relays. What the silence did cost was real, though. A client had
    no way to distinguish "your key is good and quiet" from "you mistyped it",
    so it reported every string the user pasted as accepted, including
    nonsense. That was reported from the outside within a day of the first key
    being issued.

    What is actually protecting the keys is their size (32 characters of
    base64url) against a 30-per-minute rate limit, and no amount of silence
    here moves that needle.
    """
    key = _tenant_key(request)
    if not key:
        return None, None
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
    tenant = (
        await db.execute(select(RelayTenant).where(RelayTenant.key_hash == digest))
    ).scalar_one_or_none()
    if tenant is None or tenant.status != "active":
        return None, "unknown"
    if tenant.paid_until is not None and tenant.paid_until < now:
        return None, "expired"
    return tenant, "ok"


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
    tenant, key_state = await _tenant_from_request(request, db, now)
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
        # ⚠⚠ A tenant's OR a pool's endpoint is never in the public answer.
        # Not ranked lower, not "only to trusted buckets" — never. What is
        # sold is that the address is absent from the public list, so handing
        # it out here once would sell the product and destroy it in the same
        # request. These rows are added below, and only for the key that
        # owns them, whether by direct assignment or by pool membership.
        if r.tenant_id or r.pool_id:
            return False
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

    # Theirs, in full and unbucketed. Bucketing exists so no single requester
    # learns the whole PUBLIC pool; a tenant is supposed to know their own
    # endpoints, and there are three of them. Two ways to own a row: the
    # legacy direct assignment (`tenant_id`), and membership of the tenant's
    # pool. A tenant with no pool (Supporter) gets only its direct rows, which
    # for a Supporter is none.
    mine = [
        r for r in all_rows
        if r.tenant_id == tenant.id
        or (tenant.pool_id is not None and r.pool_id == tenant.pool_id)
    ] if tenant is not None else []

    rows = [r for r in all_rows if _serve(r)]
    if not rows and not mine:
        # The empty answer carries the verdict too, otherwise a good key on an
        # island with nothing to hand out looks exactly like a bad one, which
        # is the case this whole field exists for.
        return {"relays": [], "ts": now, "key": key_state, "private_count": 0}
    bucket = f"{_ip_block(client_ip)}:{now // _BUCKET_PERIOD}"
    secret = _bucket_secret()

    def score(r: BrokerRelay) -> str:
        return hmac.new(secret, f"{bucket}:{r.tag}".encode("utf-8"), hashlib.sha256).hexdigest()

    trusted = sorted((r for r in rows if r.tier == "trusted"), key=score)
    community = sorted((r for r in rows if r.tier != "trusted"), key=score)
    # A tenant gets their own endpoints IN ADDITION to the normal public set,
    # never instead of it: private nodes are the thing that keeps working when
    # the public pool is blocked, and the public pool is what keeps working
    # when a private node is. Neither is a replacement for the other.
    chosen = mine + (trusted + community)[:_disclosure_cap(len(rows), n)]
    out = []
    mine_tags = {r.tag for r in mine}
    for r in chosen:
        try:
            d = json.loads(r.descriptor)
        except ValueError:
            continue
        d["tier"] = r.tier
        # Which of these are THEIRS. Without it the client cannot tell a node
        # somebody paid for from one of the fourteen everybody has, so it threw
        # both into one latency race and a paying customer spent most of their
        # time on the public pool. The paid nodes are supposed to be the route;
        # the public ones are supposed to be the parachute.
        if r.tag in mine_tags:
            d["private"] = True
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
    # `key` is null when none was offered, else ok | unknown | expired. See
    # _tenant_from_request for why this is said out loud now.
    return {"relays": out, "ts": now, "key": key_state, "private_count": len(mine)}


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
    # ...and for the SIGNED-CONFIG fleet, which the clients have been probing
    # and reporting all along — the reports were silently dropped here because
    # those relays are not broker rows. That left the seven machines carrying
    # most of the bypass with no in-region signal at all, while their share of
    # traffic fell from 68% to 20% and nobody could see whether they were
    # blocked or merely unused (18.08). The canary probes from Frankfurt and
    # cannot answer that question by construction.
    known |= fleet_endpoints()

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
                # ⚠ Counted BEFORE the pool check, so `accepted` says "well
                # formed", not "matched". The pool now holds private
                # addresses, and a reply that counted matches would confirm
                # any of them at 25 guesses per unauthenticated request.
                # Votes for a private node are still recorded: they are the
                # founder's only in-region view of it (/admin/reachability).
                accepted += 1
                sp = f"{server}:{port}"
                if sp not in known:
                    continue
                key = f"broker:reach:{'ok' if ok else 'fail'}:{sp}:{region}"
                pipe.zadd(key, {net: now})
                pipe.zremrangebyscore(key, 0, now - _REACH_WINDOW)
                pipe.expire(key, _REACH_WINDOW)
            await pipe.execute()
    except Exception:
        pass

    # ── did the tunnel actually CARRY anything ──────────────────────────────
    #
    # The per-relay votes above are a TCP connect: they answer "does the port
    # answer", which is not the same question as "does the tunnel work". DPI
    # commonly lets the TCP handshake through and kills the connection at the
    # TLS/Reality stage — so a fleet can read 100% reachable while nobody can
    # actually use it. That gap is what left us unable to explain the relay
    # share falling from 68% to 20% while every probe said the machines were
    # fine (18.08).
    #
    # The client already computes the answer for its own routing (`routeOk`,
    # and the fallbacks that follow it). This just lets the island hear it:
    # one counted outcome per report, per region, per hour. No identifiers —
    # a counter per (region, outcome), nothing per account.
    outcome = body.get("transport")
    if isinstance(outcome, str) and outcome in _TRANSPORT_OUTCOMES:
        try:
            redis = await get_redis()
            hour = time.strftime("%Y%m%d%H", time.gmtime(now))
            key = f"transport:outcome:{hour}:{region}"
            pipe = redis.pipeline(transaction=False)
            pipe.hincrby(key, outcome, 1)
            pipe.expire(key, _TRANSPORT_RETENTION)
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
            # Whose it is. A node assigned to a paying tenant is not part of
            # the public pool at all and must not read as one in the admin: it
            # is never handed to anybody but that customer, and "Promote to
            # trusted" on it would be a category error rather than an action.
            "tenant_id": r.tenant_id,
            # Which pool, if any. The canary reads it to skip these rows in
            # its prune and to alert on them by name; the admin pill reads it
            # to show a pooled node as not-public.
            "pool_id": r.pool_id,
            # Server-side registration time, in unix seconds like last_ok. The
            # canary's prune step needs it to judge a row that has NEVER
            # answered, where last_ok gives it nothing to measure from.
            "created_at": int(r.created_at.timestamp()) if r.created_at else None,
            "descriptor": desc,
        })
    return {"relays": out}


@router.get("/admin/reachability", dependencies=[Depends(require_admin)])
async def admin_reachability(db: AsyncSession = Depends(get_db)) -> dict:
    """Who can actually reach each relay, by region, as reported by clients.

    The one question the canary cannot answer: it probes from Frankfurt, where
    nothing is blocked, so "all relays alive" and "our users in RU cannot reach
    any of them" are both true at once. This reads the votes the clients have
    been casting — one entry per (relay, country), with the number of distinct
    reporter networks on each side — for the broker pool AND for the
    signed-config fleet.

    ⚠ Absence of a row is not failure. It means nobody in that region has
    reported lately: a relay nobody tries is indistinguishable here from one
    nobody can reach, and only the traffic mix can tell those apart.
    """
    now = int(time.time())
    min_score = now - _REACH_WINDOW

    endpoints: dict[str, str] = {}          # server:port -> source label
    for sp in sorted(fleet_endpoints()):
        endpoints[sp] = "fleet"
    for r in (await db.execute(select(BrokerRelay))).scalars().all():
        try:
            d = json.loads(r.descriptor)
        except ValueError:
            continue
        if d.get("server") and d.get("port") is not None:
            endpoints[f"{d['server']}:{d['port']}"] = f"broker:{r.tier}"

    out: list[dict] = []
    try:
        redis = await get_redis()
        # SCAN rather than a key per (relay × every country on earth): the
        # regions that reported are exactly the keys that exist.
        found: dict[str, dict[str, dict[str, int]]] = {}
        for state in ("ok", "fail"):
            cursor = 0
            while True:
                cursor, keys = await redis.scan(cursor, match=f"broker:reach:{state}:*", count=500)
                for raw in keys:
                    key = raw.decode() if isinstance(raw, bytes) else raw
                    # broker:reach:<state>:<server>:<port>:<region>
                    rest = key.split(":", 3)[3]
                    server, port, region = rest.rsplit(":", 2)[0], *rest.rsplit(":", 2)[1:]
                    sp = f"{server}:{port}"
                    if sp not in endpoints:
                        continue
                    n = int(await redis.zcount(key, min_score, "+inf") or 0)
                    if n:
                        found.setdefault(sp, {}).setdefault(region, {"ok": 0, "fail": 0})[state] = n
                if cursor == 0:
                    break
        for sp, regions in found.items():
            for region, counts in regions.items():
                out.append({
                    "endpoint": sp,
                    "source": endpoints[sp],
                    "region": region,
                    "ok_networks": counts["ok"],
                    "fail_networks": counts["fail"],
                    "reachable": counts["ok"] >= _REACH_QUORUM and counts["ok"] > counts["fail"],
                })
    except Exception:
        pass  # best-effort, like every other reader of this data

    # How the route actually ended up, per region, over the last 24h. This is
    # the half a per-relay probe cannot answer: a port that answers is not a
    # tunnel that carries traffic.
    transport: dict[str, dict[str, int]] = {}
    try:
        redis = await get_redis()
        hours = [time.strftime("%Y%m%d%H", time.gmtime(now - h * 3600)) for h in range(24)]
        cursor = 0
        keys: list[str] = []
        while True:
            cursor, batch = await redis.scan(cursor, match="transport:outcome:*", count=500)
            keys.extend(k.decode() if isinstance(k, bytes) else k for k in batch)
            if cursor == 0:
                break
        for key in keys:
            _, _, hour, region_key = key.split(":", 3)
            if hour not in hours:
                continue
            row = await redis.hgetall(key)
            bucket = transport.setdefault(region_key, {})
            for f, v in (row or {}).items():
                f = f.decode() if isinstance(f, bytes) else f
                bucket[f] = bucket.get(f, 0) + int(v)
    except Exception:
        pass

    out.sort(key=lambda e: (e["region"], e["endpoint"]))
    silent = sorted(sp for sp in endpoints if not any(e["endpoint"] == sp for e in out))
    return {
        "window_s": _REACH_WINDOW,
        "quorum": _REACH_QUORUM,
        "reports": out,
        # {region: {outcome: count}} over 24h. `tunnel_ok` against
        # `fell_to_front` is the ratio that says whether the fleet is carrying
        # the people it is reachable by.
        "transport": transport,
        # Endpoints nobody has voted on in the window. On the fleet this is the
        # number to watch: it was 100% of them before clients' reports for the
        # signed config were accepted at all.
        "silent": silent,
    }


class AdminSet(BaseModel):
    tag: str
    tier: str | None = None
    enabled: bool | None = None
    # Enable a PARKED row anyway. A row that registered `private`, has never
    # answered a probe and belongs to no pool is a node somebody meant to
    # sell; the web-admin toggle and the self-host console would otherwise
    # publish it with one click. `force` is for the other case that looks
    # identical from here: a community relay the founder disabled before it
    # ever went live and now wants back.
    force: bool = False


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
        if (
            body.enabled is True
            and not row.enabled
            and row.last_ok is None
            and row.tenant_id is None
            and row.pool_id is None
            and not body.force
        ):
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                "parked relay: assign it to a pool (tenants/assign) or pass force",
            )
        row.enabled = body.enabled
    await db.commit()
    return {"ok": True, "tag": row.tag, "tier": row.tier, "enabled": row.enabled}


# ── tenants (founder) ────────────────────────────────────────────────────

def _pool_or_400(pool: str | None) -> str | None:
    """A pool label as the console or the founder typed it, or None. An empty
    string is None too, which is how `tenants/set` clears a pool."""
    if pool is None or pool == "":
        return None
    if not _POOL_RE.match(pool):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "pool must match [a-z0-9-]{1,64}")
    return pool


def _inquiry_contact(tenant: RelayTenant) -> str:
    """The `contact` under which the island files its own team-paid inquiry
    for this tenant. The console's id when there is one, else ours; the same
    value on write, on dedupe and on close, so the three agree."""
    return f"cabinet:{tenant.ext_id or tenant.id}"


async def _apply_pool(db: AsyncSession, tenant: RelayTenant, pool: str | None) -> bool:
    """Put `tenant` on `pool` if the pool can serve, and say whether it did.

    `shared` and None are applied as given: the shared pool exists by
    definition (empty or not), and None is "no relays", which is a
    Supporter. A `team-*` pool is applied only once it has an ENABLED node;
    until then a Team buyer is left where they are (a fresh mint starts them
    on `shared` before calling this, so "where they are" is the shared pool;
    a later `set` never moves them sideways) and the island files a
    `team-paid` inquiry against their contact, once, so the founder sees a
    paid pool that needs nodes. The console's minute sync offers the pool
    again every tick, which is why the inquiry is deduped here and not left
    to the caller.

    When a team pool DOES apply, every open inquiry filed for this tenant is
    closed by the island itself, so `pools_needing_nodes` drops without a
    click. Nothing here commits; the caller's one commit covers it.
    """
    if pool is None or pool == _SHARED_POOL:
        tenant.pool_id = pool
        return True
    has_node = (
        await db.execute(
            select(BrokerRelay.tag)
            .where(BrokerRelay.pool_id == pool, BrokerRelay.enabled.is_(True))
            .limit(1)
        )
    ).first()
    contact = _inquiry_contact(tenant)
    if has_node is None:
        already = (
            await db.execute(
                select(RelayInquiry.id)
                .where(RelayInquiry.status == "open", RelayInquiry.contact == contact)
                .limit(1)
            )
        ).first()
        if already is None:
            db.add(RelayInquiry(
                tier=_TEAM_PAID_TIER,
                contact=contact,
                about=(
                    f"PAID team tenant {tenant.id} ({tenant.ext_id}) rides {tenant.pool_id} "
                    f"until pool {pool} has enabled nodes; paid_until {tenant.paid_until}"
                ),
                lang="",
                country="",
            ))
            log.warning("[broker] paid team tenant %s waits for pool %s", tenant.id, pool)
        return False
    tenant.pool_id = pool
    stamp = int(time.time())
    for row in (
        await db.execute(
            select(RelayInquiry)
            .where(RelayInquiry.status == "open", RelayInquiry.contact == contact)
        )
    ).scalars().all():
        row.status = "closed"
        row.note = f"pool applied {pool} {stamp}"
    return True


class TenantCreate(BaseModel):
    name: str | None = None
    # Days of access. Renewal is calling this again on an existing tenant,
    # which extends rather than restarts — same rule as the console's crypto
    # gateway, and for the same reason: paying early must not cost time.
    days: int = Field(default=31, ge=1, le=3660)
    # An absolute end (unix seconds) wins over `days`. The console knows the
    # exact end it sold; `days` is kept for the hand-minted trial.
    paid_until: int | None = Field(default=None, ge=0)
    # `shared`, `team-<id>`, or None for a Supporter. See _apply_pool.
    pool: str | None = None
    # The console's `tnt_` id: the double-mint guard below keys on it.
    ext_id: str | None = None


@router.post("/admin/tenants", dependencies=[Depends(require_admin)])
async def admin_create_tenant(body: TenantCreate, db: AsyncSession = Depends(get_db)):
    """Mint a tenant and hand back their key ONCE.

    Only the hash is stored, so this response is the only time the key exists
    anywhere we control. Losing it means issuing a new one, not recovering the
    old one — the same contract as the island owner token.

    With `ext_id`, minting is idempotent per console tenant: the cron and the
    cabinet can both arrive in the same second, and the second gets 409 with
    the existing id and NO key, so it goes and reads the key the first one
    stored rather than issuing a second one that would silently replace it.
    """
    pool = _pool_or_400(body.pool)
    if body.ext_id:
        # Two mints for one console id can be in flight on two uvicorn
        # workers at once (the minute cron and a cabinet opened in the same
        # second), and the existence check alone lets both see nothing and
        # both insert. On Postgres, hold a per-id advisory lock for this
        # transaction, the same primitive init_db uses to serialise workers:
        # the second racer waits here, and its check then sees the row the
        # first one committed. Released with the commit below. SQLite has no
        # analogue and serialises writers itself; _settle_double_mint after
        # the commit covers what is left there.
        if engine.dialect.name == "postgresql":
            await db.execute(
                text("SELECT pg_advisory_xact_lock(hashtext(:ext_id))"), {"ext_id": body.ext_id},
            )
        existing = (
            await db.execute(
                select(RelayTenant)
                .where(RelayTenant.ext_id == body.ext_id, RelayTenant.status == "active")
                .limit(1)
            )
        ).scalar_one_or_none()
        if existing is not None:
            return JSONResponse(status_code=status.HTTP_409_CONFLICT, content={"id": existing.id})
    key = secrets.token_urlsafe(24)
    now = int(time.time())
    tenant = RelayTenant(
        id="rt_" + secrets.token_hex(6),
        key_hash=hashlib.sha256(key.encode("utf-8")).hexdigest(),
        name=(body.name or None),
        status="active",
        paid_until=body.paid_until if body.paid_until is not None else now + body.days * 86400,
        ext_id=(body.ext_id or None),
        # A buyer of any pool starts on `shared`, so a Team whose own pool has
        # no nodes yet rides the shared nodes rather than nothing; _apply_pool
        # moves them the moment their pool can serve. No pool asked = no
        # relays (a Supporter).
        pool_id=_SHARED_POOL if pool is not None else None,
    )
    db.add(tenant)
    pool_applied = await _apply_pool(db, tenant, pool)
    await db.commit()
    if tenant.ext_id:
        winner = await _settle_double_mint(db, tenant)
        if winner is not None:
            return JSONResponse(status_code=status.HTTP_409_CONFLICT, content={"id": winner.id})
    return {
        "id": tenant.id, "key": key, "paid_until": tenant.paid_until, "name": tenant.name,
        "pool_id": tenant.pool_id, "pool_applied": pool_applied, "ext_id": tenant.ext_id,
    }


async def _settle_double_mint(db: AsyncSession, tenant: RelayTenant) -> RelayTenant | None:
    """The belt under the advisory lock, for dialects without one.

    After `tenant` is committed, read every ACTIVE tenant with its `ext_id`.
    If another one sorts first by (created_at, id), OURS is the duplicate:
    disable it and return the winner, so the caller answers 409 `{id}` with
    no key, exactly as if the existence check had caught it, and the worker
    goes and reads the key the winner's request stored. Both racers order
    the same rows the same way, so whenever the later committer sees both
    rows at most one 200 survives. The one window this cannot close is the
    later committer having built its row first (then it sorts first and
    keeps its 200 while the other already answered); that is what the
    Postgres lock is for, and on Postgres this never finds a second row.
    Only ever disables the row this request created, never anybody else's.
    """
    rows = (
        await db.execute(
            select(RelayTenant)
            .where(RelayTenant.ext_id == tenant.ext_id, RelayTenant.status == "active")
            .order_by(RelayTenant.created_at, RelayTenant.id)
        )
    ).scalars().all()
    if not rows or rows[0].id == tenant.id:
        return None
    tenant.status = "disabled"
    await db.commit()
    log.warning("[broker] double mint for %s: %s yields to %s", tenant.ext_id, tenant.id, rows[0].id)
    return rows[0]


class TenantSet(BaseModel):
    id: str
    status: str | None = None
    # Extends from whichever is later, the current end or today: paying early
    # adds to what is left, and paying after a lapse does not backdate a term
    # into the past and expire on arrival.
    add_days: int | None = Field(default=None, ge=1, le=3660)
    # The absolute end, for the console's sync: idempotent, so a retried or a
    # repeated push lands on the same value, where `add_days` would have
    # stacked. An upgrade with credit restarts the term from today, and only
    # an absolute value can say that.
    paid_until: int | None = Field(default=None, ge=0)
    # Move the tenant to a pool; empty string clears it. See _apply_pool.
    pool: str | None = None


@router.post("/admin/tenants/set", dependencies=[Depends(require_admin)])
async def admin_set_tenant(body: TenantSet, db: AsyncSession = Depends(get_db)) -> dict:
    tenant = (
        await db.execute(select(RelayTenant).where(RelayTenant.id == body.id))
    ).scalar_one_or_none()
    if tenant is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such tenant")
    if body.status is not None:
        if body.status not in ("active", "disabled"):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "status must be active or disabled")
        tenant.status = body.status
    if body.paid_until is not None:
        tenant.paid_until = body.paid_until
    if body.add_days is not None:
        base = max(int(time.time()), tenant.paid_until or 0)
        tenant.paid_until = base + body.add_days * 86400
    # Echoed as True when no pool was asked for: the console's guard reads
    # `pool_applied !== false`, and a term-only push must count as synced.
    pool_applied = True
    if body.pool is not None:
        pool_applied = await _apply_pool(db, tenant, _pool_or_400(body.pool))
    await db.commit()
    return {
        "id": tenant.id, "status": tenant.status, "paid_until": tenant.paid_until,
        "pool_id": tenant.pool_id, "pool_applied": pool_applied,
    }


class TenantRotate(BaseModel):
    id: str


@router.post("/admin/tenants/rotate", dependencies=[Depends(require_admin)])
async def admin_rotate_tenant(body: TenantRotate, db: AsyncSession = Depends(get_db)) -> dict:
    """Replace a tenant's key in place: same id, same pool, same direct rows,
    same term. The old key answers `unknown` from the tenant's next poll.

    In place rather than mint-and-disable, because the id is what the pool,
    the direct rows and the console's ledger all point at; a new id would
    mean re-attaching every one of them. Show-once, like create.
    """
    tenant = (
        await db.execute(select(RelayTenant).where(RelayTenant.id == body.id))
    ).scalar_one_or_none()
    if tenant is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such tenant")
    key = secrets.token_urlsafe(24)
    tenant.key_hash = hashlib.sha256(key.encode("utf-8")).hexdigest()
    await db.commit()
    return {"id": tenant.id, "key": key, "paid_until": tenant.paid_until, "pool_id": tenant.pool_id}


@router.get("/admin/tenants", dependencies=[Depends(require_admin)])
async def admin_list_tenants(db: AsyncSession = Depends(get_db)) -> dict:
    now = int(time.time())
    rows = (await db.execute(select(RelayTenant))).scalars().all()
    counts: dict[str, int] = {}
    for r in (await db.execute(select(BrokerRelay).where(BrokerRelay.tenant_id.isnot(None)))).scalars().all():
        counts[r.tenant_id] = counts.get(r.tenant_id, 0) + 1
    # Pool rows count for every tenant on that pool. Only ENABLED ones, since
    # a parked node is not serving anybody yet; `pool_live` is the number the
    # customer actually has right now, by the same window /bridges uses.
    pool_counts: dict[str, int] = {}
    pool_live: dict[str, int] = {}
    for r in (
        await db.execute(
            select(BrokerRelay).where(BrokerRelay.pool_id.isnot(None), BrokerRelay.enabled.is_(True))
        )
    ).scalars().all():
        pool_counts[r.pool_id] = pool_counts.get(r.pool_id, 0) + 1
        if r.last_ok is not None and now - r.last_ok <= _LIVENESS_WINDOW:
            pool_live[r.pool_id] = pool_live.get(r.pool_id, 0) + 1
    return {"tenants": [
        {
            "id": t.id, "name": t.name, "status": t.status,
            "paid_until": t.paid_until,
            "pool_id": t.pool_id, "ext_id": t.ext_id,
            "relays": counts.get(t.id, 0) + (pool_counts.get(t.pool_id, 0) if t.pool_id else 0),
            "pool_live": pool_live.get(t.pool_id, 0) if t.pool_id else 0,
            "created_at": int(t.created_at.timestamp()) if t.created_at else None,
        }
        for t in rows
    ]}


class TenantAssign(BaseModel):
    tag: str
    # One of the two, or neither. Ownership moves only when the body NAMES
    # one of them: pydantic cannot tell an absent field from a null one, and
    # a body that only toggles `enabled` (the founder darking a pool node for
    # a reboot) must not also hand the node to the public pool as a side
    # effect, where it would be served to strangers the moment it came back.
    # A release is therefore explicit, both named and both null (delete the
    # row instead when the node is retired: a released address becomes
    # public, and a burned one must not be pooled again).
    tenant_id: str | None = None
    pool_id: str | None = None
    # Applied in the same commit as the assignment, so a parked node is
    # pooled and lit atomically and never spends a moment enabled and public.
    enabled: bool | None = None


@router.post("/admin/tenants/assign", dependencies=[Depends(require_admin)])
async def admin_assign_relay(body: TenantAssign, db: AsyncSession = Depends(get_db)) -> dict:
    """Give an endpoint to a tenant or a pool, or hand it back to the public pool.

    ⚠ Assigning REMOVES the endpoint from public distribution immediately. That
    is the point, and it is also why an endpoint already published in the
    signed config is REFUSED (409): its address is out there, and charging
    for the privacy of an address that is already public would be selling
    something we cannot deliver. Stand up a new node instead.
    """
    pool_id = _pool_or_400(body.pool_id)
    if body.tenant_id is not None and pool_id is not None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "one of tenant_id or pool_id, not both")
    # Which ownership fields the body actually carried (see TenantAssign).
    touch = body.model_fields_set & {"tenant_id", "pool_id"}
    if touch and body.tenant_id is None and pool_id is None and touch != {"tenant_id", "pool_id"}:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "to release a relay to the public pool name both tenant_id and pool_id as null",
        )
    relay = (
        await db.execute(select(BrokerRelay).where(BrokerRelay.tag == body.tag))
    ).scalar_one_or_none()
    if relay is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such relay")
    if body.tenant_id is not None:
        tenant = (
            await db.execute(select(RelayTenant).where(RelayTenant.id == body.tenant_id))
        ).scalar_one_or_none()
        if tenant is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "no such tenant")
    if body.tenant_id is not None or pool_id is not None:
        try:
            server = json.loads(relay.descriptor).get("server")
        except (ValueError, AttributeError):
            server = None
        if server and server in relay_addresses():
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                "already published in the signed config: its address is public, stand up a new node",
            )
    # The same guard admin_set has, on the state this call would leave
    # behind: a parked row (never probed, owned by nobody) lit without a pool
    # or a tenant becomes an enabled community row, and the canary's first OK
    # puts the address every buyer was promised is unlisted into a public
    # answer. This route exists to pool and light in one commit; lighting
    # alone is admin/set, where `force` says the founder means it.
    next_tenant = body.tenant_id if touch else relay.tenant_id
    next_pool = pool_id if touch else relay.pool_id
    if (
        body.enabled is True
        and not relay.enabled
        and relay.last_ok is None
        and next_tenant is None
        and next_pool is None
    ):
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "parked relay: give it a pool or a tenant to enable it (admin/set force for a community relay)",
        )
    if touch:
        relay.tenant_id = body.tenant_id
        relay.pool_id = pool_id
    if body.enabled is not None:
        relay.enabled = body.enabled
    await db.commit()
    return {
        "tag": relay.tag, "tenant_id": relay.tenant_id,
        "pool_id": relay.pool_id, "enabled": relay.enabled,
    }


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
            # A self-serve row that has NEVER passed a probe is swept once it
            # has failed for about a day (the canary runs every ~10 min).
            #
            # ⚠ Deleted, not disabled, and that is the kinder of the two: a
            # re-registration recreates the row with the same tag (it is
            # derived from the operator key and the endpoint) and comes back
            # ENABLED, while the refresh path above leaves `enabled` alone —
            # so a row we disabled would stay dark after its owner fixed it
            # and re-registered, with nobody the wiser.
            #
            # Two things this stops. Dead weight: nothing prunes these today,
            # so the canary would knock on an address that never worked for as
            # long as the row exists. And a small piece of reach: registration
            # does not prove the registrant owns the address, so an entry for
            # SOMEBODY ELSE's IP turns our prober into a knock every ten
            # minutes. It never reaches users (the liveness gate in /bridges
            # sees to that), but it should not outlive a day either.
            #
            # Never a tenant's or a pool's row: those were placed by the
            # founder, not self-registered, and a paid node that is down is
            # an alert (the canary pushes one), not dead weight to sweep.
            if (
                row.tier == "community"
                and row.last_ok is None
                and row.tenant_id is None
                and row.pool_id is None
                and (row.fail_count or 0) >= _DEAD_AFTER_FAILS
            ):
                await db.delete(row)
                log.warning(
                    "[broker] swept never-live community relay after %d failures", row.fail_count
                )
        updated += 1
    await db.commit()
    # Parked rows nobody assigned in a week go here too: the canary is the
    # one caller that arrives on a schedule, and these rows are exactly the
    # ones it never probes, so nothing else would ever look at them. After
    # the commit above, so a row a report touched and the sweep deletes is
    # never flushed twice.
    if await _sweep_stale_parked(db):
        await db.commit()
    # The canary is the one caller that touches these rows on a schedule, so
    # it is also the cheapest place to keep the classifier's set current.
    await refresh_broker_transport_set(db)
    return {"ok": True, "updated": updated, "ts": now}


async def refresh_broker_transport_set(db: AsyncSession) -> int:
    """Hand the broker pool's addresses to the transport classifier.

    Called where the rows are already in hand: at boot and after every
    liveness report. Without it a request arriving from one of these
    machines counts as `direct`, and the relay share in the panel reads
    lower than the hourly log parser's - by exactly this traffic.
    """
    rows = (await db.execute(select(BrokerRelay.descriptor))).scalars().all()
    hosts: set[str] = set()
    for raw in rows:
        # The column is the signed descriptor VERBATIM, as text: it has to stay
        # byte-identical for the signature to verify, so it is never a dict
        # here however much it looks like one.
        try:
            desc = json.loads(raw) if isinstance(raw, str) else raw
        except (TypeError, ValueError):
            continue
        server = desc.get("server") if isinstance(desc, dict) else None
        if isinstance(server, str) and server:
            hosts.add(server)
    set_broker_addresses(hosts)
    return len(hosts)


@router.delete("/admin/{tag}", dependencies=[Depends(require_admin)])
async def admin_delete(tag: str, db: AsyncSession = Depends(get_db)) -> dict:
    await db.execute(delete(BrokerRelay).where(BrokerRelay.tag == tag))
    await db.commit()
    return {"ok": True}
