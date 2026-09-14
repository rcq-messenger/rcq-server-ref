"""Local-only verification of relay pools on the island (14.09.2026).

What is being sold is one sentence: a paid node's address is not in the public
list. Everything below is that sentence checked from every side we could think
of, plus the admin rules that keep the founder from breaking it by hand.

Invariants this file pins (the plan, relay-delivery-plan-2026-09-14.md):

  * a relay with tenant_id OR pool_id is never in a public answer, whatever
    its tier or liveness, from whatever network, with no key, a wrong key,
    an expired key or somebody else's key;
  * the key check never leaves the island (no socket may connect while the
    tests run; every outbound path is either faked or forbidden);
  * every failure resolves to "no tenant": `/reachability`'s `accepted` counts
    well-formed reports, so it cannot confirm a private address;
  * a parked row (enabled=false) is absent from /bridges and reads
    enabled=false in /admin/list, which is the set the canary probes;
  * the liveness sweep never deletes a pool or tenant row;

and every new admin rule: `private` on register (with the parked caps and
the week-old parked sweep), `force` on set, the assign guards (both ids ->
400, a signed-config address -> 409, pool+enabled in one commit, ownership
moves only when named, an explicit release, the parked guard), the
double-mint 409 on both paths (the existence check and the post-commit
settle), `pool_applied` with the island-side inquiry and its dedupe and
auto-close, absolute `paid_until`, `rotate`, the tenant list counters and the
two `/admin/stats` counters.

Runs the real FastAPI stack in-process on a throwaway SQLite DB. Redis is a
recording fake (the limiter and /bridges swallow Redis errors anyway, and the
fake lets case 10 assert what would have been written). No network.
Run: cd rcq-server-ref && PYTHONPATH=. /Users/tager/Documents/RCQ/backend/.venv/bin/python test_relay_pool_local.py
"""
import asyncio
import base64
import hashlib
import json
import os
import secrets
import socket
import sqlite3
import time
from datetime import datetime, timedelta, timezone

DB_FILE = "test_relay_pool.db"
os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///./{DB_FILE}"
os.environ["ENV"] = "dev"
os.environ.setdefault("JWT_SECRET", "test-secret-for-the-relay-pool")
os.environ.setdefault("ADMIN_USERNAME", "admin")
os.environ.setdefault("ADMIN_PASSWORD", "adminpw")
# No signed-config fleet on this box: relay_addresses() reads an empty set
# until case 7 monkeypatches it.
os.environ["RCQ_RELAYS_YAML"] = "/nonexistent/relays.yaml"
try:
    os.remove(DB_FILE)
except FileNotFoundError:
    pass

import httpx  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from sqlalchemy import select, text  # noqa: E402

from app.core import rate_limit as RL  # noqa: E402
from app.core.db import Base, SessionLocal, engine, init_db  # noqa: E402
from app.main import app  # noqa: E402
from app.models.broker import BrokerRelay, RelayTenant  # noqa: E402
from app.models.relay_inquiry import RelayInquiry  # noqa: E402
from app.routers import broker as B  # noqa: E402

# ⚠ The metadata is only complete once every model module has been imported
# (see test_stale_reader_local.py). app.main imports every router, which
# imports every model, so create_all below has the whole picture.

ADMIN = ("admin", "adminpw")
NOW = int(time.time())
FRESH = NOW - 60                       # inside _LIVENESS_WINDOW
STALE = NOW - B._LIVENESS_WINDOW - 600  # outside it
fails = 0


def check(name, cond):
    global fails
    print(f"  {'PASS' if cond else 'FAIL'}  {name}")
    if not cond:
        fails += 1


# ── the island must not leave the island ──────────────────────────────────
#
# Every outbound path is faked (Redis) or in-process (ASGI transport). If
# anything under test tried to reach a worker, a DNS name or a real Redis,
# it would have to open a socket, and this makes that an error rather than
# a silent round trip.
def _no_network(*_a, **_k):
    raise AssertionError("a socket tried to leave the island")


socket.getaddrinfo = _no_network
socket.create_connection = _no_network
socket.socket.connect = _no_network  # type: ignore[assignment]
socket.socket.connect_ex = _no_network  # type: ignore[assignment]


class FakePipe:
    def __init__(self, log):
        self.log = log
        self.n = 0

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    def _op(self, name, key):
        self.log.append((name, key))
        self.n += 1
        return self

    def zadd(self, key, mapping):
        return self._op("zadd", key)

    def zcount(self, key, *a):
        return self._op("zcount", key)

    def zremrangebyscore(self, key, *a):
        return self._op("zremrangebyscore", key)

    def expire(self, key, *a):
        return self._op("expire", key)

    def incr(self, key):
        return self._op("incr", key)

    def hincrby(self, key, *a):
        return self._op("hincrby", key)

    async def execute(self):
        return [0] * self.n


class FakeRedis:
    def __init__(self):
        self.log = []

    def pipeline(self, transaction=False):
        return FakePipe(self.log)

    async def eval(self, *a):
        return [1, 0]

    async def get(self, k):
        return None


FAKE = FakeRedis()


async def fake_get_redis():
    return FAKE


B.get_redis = fake_get_redis
RL.get_redis = fake_get_redis


# ── seeding ────────────────────────────────────────────────────────────────

def descriptor(server, port=443):
    return {
        "proto": "vless", "server": server, "port": port, "sni": "cdn.example",
        "uuid": "00000000-0000-4000-8000-000000000001", "pbk": "pbk", "sid": "ab",
    }


def raw_descriptor(server, port=443):
    return json.dumps(descriptor(server, port), sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def ago(**kw) -> datetime:
    return datetime.now(timezone.utc) - timedelta(**kw)


async def seed_relay(tag, server, *, tier="community", last_ok=None, tenant_id=None,
                     pool_id=None, enabled=True, port=443, created_at=None):
    async with SessionLocal() as db:
        row = BrokerRelay(
            tag=tag, descriptor=raw_descriptor(server, port), operator_key="opk-" + tag,
            tier=tier, enabled=enabled, ts=NOW, last_ok=last_ok,
            tenant_id=tenant_id, pool_id=pool_id,
        )
        if created_at is not None:
            row.created_at = created_at
        db.add(row)
        await db.commit()


async def seed_tenant(tid, *, pool_id=None, paid_until=NOW + 30 * 86400, status="active", ext_id=None,
                      created_at=None):
    key = "key-" + tid
    async with SessionLocal() as db:
        row = RelayTenant(
            id=tid, key_hash=hashlib.sha256(key.encode()).hexdigest(), name=tid,
            status=status, paid_until=paid_until, pool_id=pool_id, ext_id=ext_id,
        )
        if created_at is not None:
            row.created_at = created_at
        db.add(row)
        await db.commit()
    return key


async def reset():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)


async def relay_row(tag):
    async with SessionLocal() as db:
        return (await db.execute(select(BrokerRelay).where(BrokerRelay.tag == tag))).scalar_one_or_none()


async def inquiries(contact=None):
    async with SessionLocal() as db:
        q = select(RelayInquiry)
        if contact is not None:
            q = q.where(RelayInquiry.contact == contact)
        return (await db.execute(q)).scalars().all()


# ── HTTP helpers ───────────────────────────────────────────────────────────

XFFS = ["198.51.100.7", "203.0.113.9", "192.0.2.44", "100.64.3.3", "185.10.20.30"]


async def bridges(c, key=None, xff=XFFS[0], n=5):
    headers = {"x-forwarded-for": xff}
    if key:
        headers["authorization"] = "Bearer " + key
    r = await c.get(f"/broker/bridges?n={n}", headers=headers)
    assert r.status_code == 200, r.text
    return r.json()


def endpoints(d):
    return {f"{x['server']}:{x['port']}" for x in d["relays"]}


def private_endpoints(d):
    return {f"{x['server']}:{x['port']}" for x in d["relays"] if x.get("private")}


def sign_registration(priv, desc, ts):
    pub = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    sig = priv.sign(B._reg_signed_bytes(desc, ts))
    return {
        "descriptor": desc, "ts": ts,
        "key": base64.b64encode(pub).decode(), "sig": base64.b64encode(sig).decode(),
    }


# ── cases ──────────────────────────────────────────────────────────────────

async def case_invariant(c):
    print("\n1. INVARIANT: a tenant's or a pool's row is never in a public answer")
    await reset()
    # Two public rows that ARE served: a trusted one, and a live community one.
    await seed_relay("pub-t", "10.0.0.1", tier="trusted")
    await seed_relay("pub-c", "10.0.0.2", tier="community", last_ok=FRESH)
    public = {"10.0.0.1:443", "10.0.0.2:443"}
    # Eight private rows: owner x tier x liveness. Every combination that
    # could tempt _serve into saying yes.
    direct, pooled = set(), set()
    i = 0
    for owner in ("tenant", "pool"):
        for tier in ("community", "trusted"):
            for last_ok in (None, FRESH):
                i += 1
                server = f"10.9.9.{i}"
                await seed_relay(
                    f"prv-{i}", server, tier=tier, last_ok=last_ok,
                    tenant_id="rt_direct" if owner == "tenant" else None,
                    pool_id="shared" if owner == "pool" else None,
                )
                (direct if owner == "tenant" else pooled).add(f"{server}:443")
    own = await seed_tenant("rt_direct")                        # owns the 4 direct rows
    pool = await seed_tenant("rt_shared", pool_id="shared")     # on the pool of 4
    other = await seed_tenant("rt_other", pool_id="team-x")     # a pool with no rows
    expired = await seed_tenant("rt_expired", pool_id="shared", paid_until=NOW - 10)
    disabled = await seed_tenant("rt_disabled", pool_id="shared", status="disabled")

    matrix = [
        ("no key", None, None, set()),
        ("wrong key", "not-a-key-at-all-" * 2, "unknown", set()),
        ("own key (direct rows)", own, "ok", direct),
        ("pool key (shared)", pool, "ok", pooled),
        ("other tenant's key (team-x, empty)", other, "ok", set()),
        ("expired key on shared", expired, "expired", set()),
        ("disabled tenant's key", disabled, "unknown", set()),
    ]
    for label, key, want_state, want_private in matrix:
        leaked = set()
        wrong_state = False
        wrong_private = False
        for xff in XFFS:
            d = await bridges(c, key, xff)
            got = endpoints(d)
            # Anything private that this key does not own is a leak.
            leaked |= (got & (direct | pooled)) - want_private
            if d["key"] != want_state:
                wrong_state = True
            if private_endpoints(d) != want_private or d["private_count"] != len(want_private):
                wrong_private = True
            # The public set is still there, bucketed, and never empty.
            if not (got - direct - pooled) or not (got - direct - pooled) <= public:
                wrong_private = True
        check(f"{label}: no private row leaks from five networks (leaked={sorted(leaked)})", not leaked)
        check(f"{label}: key state is {want_state!r}", not wrong_state)
        check(f"{label}: exactly its own rows, flagged private, counted ({len(want_private)})", not wrong_private)


async def case_pool_serving(c):
    print("\n2-4. Pool serving: two shared rows, a second shared tenant, a team-x tenant, a supporter")
    await reset()
    await seed_relay("pub-t", "10.0.0.1", tier="trusted")
    await seed_relay("pool-a", "10.1.0.1", pool_id="shared", last_ok=FRESH)
    await seed_relay("pool-b", "10.1.0.2", pool_id="shared")            # never probed: still theirs
    await seed_relay("pool-parked", "10.1.0.3", pool_id="shared", enabled=False)
    await seed_relay("legacy", "10.2.0.1", tenant_id="rt_legacy", tier="trusted")
    k1 = await seed_tenant("rt_p1", pool_id="shared")
    k2 = await seed_tenant("rt_p2", pool_id="shared")
    kx = await seed_tenant("rt_team", pool_id="team-x")
    ks = await seed_tenant("rt_supporter", pool_id=None)
    kl = await seed_tenant("rt_legacy", pool_id=None)
    both = {"10.1.0.1:443", "10.1.0.2:443"}

    d = await bridges(c, k1)
    check("personal key on shared gets both enabled pool rows, private:true", private_endpoints(d) == both)
    check(f"private_count == 2 ({d['private_count']})", d["private_count"] == 2)
    check("the parked pool row is not among them", "10.1.0.3:443" not in endpoints(d))
    check("key: ok", d["key"] == "ok")
    d2 = await bridges(c, k2, XFFS[1])
    check("a second shared tenant sees the same two", private_endpoints(d2) == both)
    dx = await bridges(c, kx, XFFS[2])
    check("a team-x tenant (empty pool) sees none, key still ok",
          dx["private_count"] == 0 and dx["key"] == "ok" and not private_endpoints(dx))
    ds = await bridges(c, ks, XFFS[3])
    check("a supporter (pool NULL) gets key: ok and the public set only",
          ds["key"] == "ok" and ds["private_count"] == 0 and endpoints(ds) == {"10.0.0.1:443"})
    dl = await bridges(c, kl, XFFS[4])
    check("a legacy tenant_id row is still in `mine`, flagged private",
          private_endpoints(dl) == {"10.2.0.1:443"} and dl["private_count"] == 1)
    check("and that legacy row never reaches the shared tenant", "10.2.0.1:443" not in endpoints(d))


async def case_register_private(c):
    print("\n5. register private:true -> parked, and parked stays parked")
    await reset()
    await seed_relay("pub-t", "10.0.0.1", tier="trusted")
    ks = await seed_tenant("rt_s", pool_id="shared")
    priv = Ed25519PrivateKey.generate()
    desc = descriptor("park1.example.net", 8443)
    body = sign_registration(priv, desc, NOW)
    body["private"] = True
    r = await c.post("/broker/register", json=body)
    check(f"registers ({r.status_code})", r.status_code == 200)
    tag = r.json().get("tag")
    check("reply says enabled: false", r.json().get("enabled") is False)
    body2 = sign_registration(priv, desc, NOW + 1)      # a refresh, no `private`
    r2 = await c.post("/broker/register", json=body2)
    check("re-register with a higher ts keeps it parked", r2.status_code == 200 and r2.json()["enabled"] is False)
    body3 = sign_registration(priv, desc, NOW + 2)
    body3["private"] = True
    r3 = await c.post("/broker/register", json=body3)
    check("re-register WITH private again is a refresh too", r3.status_code == 200 and r3.json()["enabled"] is False)
    row = await relay_row(tag)
    check("row: enabled False, community, no pool, never probed",
          row is not None and row.enabled is False and row.tier == "community"
          and row.pool_id is None and row.last_ok is None)
    seen = set()
    for xff in XFFS:
        seen |= endpoints(await bridges(c, None, xff))
    seen |= endpoints(await bridges(c, ks, XFFS[0]))
    check("absent from /bridges on five networks and with a shared key", "park1.example.net:8443" not in seen)
    r = await c.get("/broker/admin/list", auth=ADMIN)
    mine = [x for x in r.json()["relays"] if x["tag"] == tag]
    check("admin/list shows enabled:false, last_ok:null, pool_id:null (what the canary filters on)",
          len(mine) == 1 and mine[0]["enabled"] is False and mine[0]["last_ok"] is None
          and mine[0]["pool_id"] is None)
    # A stranger's `private` parks only the stranger's own row.
    other = Ed25519PrivateKey.generate()
    b = sign_registration(other, descriptor("plain.example.net"), NOW)
    b["private"] = "yes"
    r = await c.post("/broker/register", json=b)
    check(f"private must be a boolean ({r.status_code})", r.status_code == 400)
    b = sign_registration(other, descriptor("plain.example.net"), NOW)
    r = await c.post("/broker/register", json=b)
    check("a plain registration still lands enabled", r.status_code == 200 and r.json()["enabled"] is True)
    return tag


async def case_admin_set_force(c, parked_tag):
    print("\n6. admin/set enabled:true on a parked row -> 409; force -> 200")
    r = await c.post("/broker/admin/set", json={"tag": parked_tag, "enabled": True}, auth=ADMIN)
    check(f"toggle refused ({r.status_code}: {r.json().get('detail')})", r.status_code == 409)
    check("and the row is still parked", (await relay_row(parked_tag)).enabled is False)
    r = await c.post("/broker/admin/set", json={"tag": parked_tag, "enabled": True, "force": True}, auth=ADMIN)
    check(f"force enables it ({r.status_code})", r.status_code == 200 and r.json()["enabled"] is True)
    r = await c.post("/broker/admin/set", json={"tag": parked_tag, "enabled": False}, auth=ADMIN)
    check("disabling never needs force", r.status_code == 200 and r.json()["enabled"] is False)
    # A row that was live once and got disabled is not "parked": plain enable.
    await seed_relay("was-live", "10.3.0.1", last_ok=STALE, enabled=False)
    r = await c.post("/broker/admin/set", json={"tag": "was-live", "enabled": True}, auth=ADMIN)
    check("a once-live disabled community row enables without force", r.status_code == 200)
    # A parked row that already sits in a pool: enabling it is the founder lighting it.
    await seed_relay("parked-pooled", "10.3.0.2", enabled=False, pool_id="shared")
    r = await c.post("/broker/admin/set", json={"tag": "parked-pooled", "enabled": True}, auth=ADMIN)
    check("a pooled parked row enables without force", r.status_code == 200 and r.json()["enabled"] is True)


async def case_assign(c):
    print("\n7. assign: both ids -> 400, fleet address -> 409, pool+enabled in one commit")
    await reset()
    await seed_relay("parked", "10.4.0.1", enabled=False)
    await seed_relay("fleet", "10.4.0.2", enabled=False)
    await seed_tenant("rt_a")
    r = await c.post("/broker/admin/tenants/assign",
                     json={"tag": "parked", "tenant_id": "rt_a", "pool_id": "shared"}, auth=ADMIN)
    check(f"both tenant_id and pool_id -> 400 ({r.status_code})", r.status_code == 400)
    r = await c.post("/broker/admin/tenants/assign", json={"tag": "parked", "pool_id": "Shared Pool!"}, auth=ADMIN)
    check(f"a malformed pool id -> 400 ({r.status_code})", r.status_code == 400)
    r = await c.post("/broker/admin/tenants/assign", json={"tag": "nope", "pool_id": "shared"}, auth=ADMIN)
    check(f"unknown tag -> 404 ({r.status_code})", r.status_code == 404)
    r = await c.post("/broker/admin/tenants/assign", json={"tag": "parked", "tenant_id": "rt_none"}, auth=ADMIN)
    check(f"unknown tenant -> 404 ({r.status_code})", r.status_code == 404)
    row = await relay_row("parked")
    check("nothing above touched the row", row.enabled is False and row.pool_id is None and row.tenant_id is None)

    saved = B.relay_addresses
    B.relay_addresses = lambda: frozenset({"10.4.0.2"})
    try:
        r = await c.post("/broker/admin/tenants/assign", json={"tag": "fleet", "pool_id": "shared", "enabled": True}, auth=ADMIN)
        check(f"a signed-config address -> 409 ({r.status_code})", r.status_code == 409)
        row = await relay_row("fleet")
        check("and it is neither pooled nor lit", row.pool_id is None and row.enabled is False)
        r = await c.post("/broker/admin/tenants/assign", json={"tag": "fleet", "tenant_id": "rt_a"}, auth=ADMIN)
        check("same for a direct tenant assignment", r.status_code == 409)
        r = await c.post("/broker/admin/tenants/assign",
                         json={"tag": "fleet", "tenant_id": None, "pool_id": None}, auth=ADMIN)
        check("releasing (both named null) a fleet-address row is not refused", r.status_code == 200)
    finally:
        B.relay_addresses = saved

    r = await c.post("/broker/admin/tenants/assign", json={"tag": "parked", "pool_id": "shared", "enabled": True}, auth=ADMIN)
    check(f"pool + enabled in one call ({r.status_code})", r.status_code == 200)
    check("reply {tag, tenant_id, pool_id, enabled}",
          r.json() == {"tag": "parked", "tenant_id": None, "pool_id": "shared", "enabled": True})
    row = await relay_row("parked")
    check("row pooled and lit", row.pool_id == "shared" and row.enabled is True and row.tenant_id is None)

    # Ownership moves only when the body names it: an `enabled`-only body is a
    # toggle, not a release (the founder darking a pool node for a reboot).
    r = await c.post("/broker/admin/tenants/assign", json={"tag": "parked", "enabled": False}, auth=ADMIN)
    check("assign {tag, enabled:false} on a pool row keeps pool_id",
          r.status_code == 200 and r.json() == {"tag": "parked", "tenant_id": None, "pool_id": "shared", "enabled": False})
    r = await c.post("/broker/admin/tenants/assign", json={"tag": "parked", "enabled": True}, auth=ADMIN)
    check("and re-lighting it keeps the pool too", r.json()["pool_id"] == "shared" and r.json()["enabled"] is True)
    seen = set()
    for xff in XFFS:
        seen |= endpoints(await bridges(c, None, xff))
    check("the node is still not in a public answer after the dark/light cycle", "10.4.0.1:443" not in seen)
    r = await c.post("/broker/admin/tenants/assign", json={"tag": "parked"}, auth=ADMIN)
    check("a bare {tag} changes nothing (echo)",
          r.status_code == 200 and r.json() == {"tag": "parked", "tenant_id": None, "pool_id": "shared", "enabled": True})
    r = await c.post("/broker/admin/tenants/assign", json={"tag": "parked", "pool_id": None}, auth=ADMIN)
    check(f"pool_id null alone is not a release -> 400 ({r.status_code})", r.status_code == 400)
    r = await c.post("/broker/admin/tenants/assign", json={"tag": "parked", "pool_id": ""}, auth=ADMIN)
    check(f"nor is an empty pool_id ({r.status_code})", r.status_code == 400)
    check("row still pooled after the refused releases", (await relay_row("parked")).pool_id == "shared")

    r = await c.post("/broker/admin/tenants/assign", json={"tag": "parked", "tenant_id": "rt_a"}, auth=ADMIN)
    check("moving to a tenant clears the pool (never both)",
          r.status_code == 200 and r.json()["pool_id"] is None and r.json()["tenant_id"] == "rt_a")
    r = await c.post("/broker/admin/tenants/assign",
                     json={"tag": "parked", "tenant_id": None, "pool_id": None}, auth=ADMIN)
    check("explicit release: both named null -> public, enabled untouched",
          r.json() == {"tag": "parked", "tenant_id": None, "pool_id": None, "enabled": True})

    print("\n7b. assign on a parked row: enabling without a pool or a tenant -> 409")
    await seed_relay("held", "10.4.0.3", enabled=False)
    r = await c.post("/broker/admin/tenants/assign", json={"tag": "held", "enabled": True}, auth=ADMIN)
    check(f"assign {{tag, enabled:true}} -> 409 ({r.status_code}: {r.json().get('detail')})", r.status_code == 409)
    r = await c.post("/broker/admin/tenants/assign",
                     json={"tag": "held", "enabled": True, "tenant_id": None, "pool_id": None}, auth=ADMIN)
    check("release + enable on a parked row -> 409 too", r.status_code == 409)
    row = await relay_row("held")
    check("row untouched: parked, no pool, no tenant",
          row.enabled is False and row.pool_id is None and row.tenant_id is None and row.last_ok is None)
    r = await c.post("/broker/admin/tenants/assign", json={"tag": "held", "enabled": False}, auth=ADMIN)
    check("disabling a parked row is fine", r.status_code == 200 and r.json()["enabled"] is False)
    r = await c.post("/broker/admin/tenants/assign", json={"tag": "held", "tenant_id": "rt_a", "enabled": True}, auth=ADMIN)
    check("tenant + enabled in one call lights it", r.status_code == 200 and r.json()["enabled"] is True)
    # A parked row already pooled (assigned dark, lit later) lights with enabled alone.
    await seed_relay("held-pooled", "10.4.0.4", enabled=False, pool_id="shared")
    r = await c.post("/broker/admin/tenants/assign", json={"tag": "held-pooled", "enabled": True}, auth=ADMIN)
    check("a pooled parked row lights with enabled alone", r.status_code == 200 and r.json()["enabled"] is True)


async def case_create_tenant(c):
    print("\n8. create: team pool without nodes -> shared + inquiry; double mint -> 409 {id}")
    await reset()
    r = await c.post("/broker/admin/tenants", json={"name": "acme", "pool": "team-a", "ext_id": "tnt_1"}, auth=ADMIN)
    check(f"minted ({r.status_code})", r.status_code == 200)
    d = r.json()
    check("rides shared, pool_applied False, ext_id echoed",
          d.get("pool_id") == "shared" and d.get("pool_applied") is False and d.get("ext_id") == "tnt_1")
    check("a key was issued", isinstance(d.get("key"), str) and len(d["key"]) >= 30)
    first_id, first_key = d["id"], d["key"]
    rows = await inquiries("cabinet:tnt_1")
    check("exactly one open team-paid inquiry, contact cabinet:tnt_1",
          len(rows) == 1 and rows[0].status == "open" and rows[0].tier == "team-paid")
    check("the inquiry names the tenant, the pool and the term",
          first_id in rows[0].about and "team-a" in rows[0].about and str(d["paid_until"]) in rows[0].about)
    r = await c.post("/broker/admin/tenants", json={"name": "acme", "pool": "team-a", "ext_id": "tnt_1"}, auth=ADMIN)
    check(f"second mint -> 409 ({r.status_code})", r.status_code == 409)
    check("body is exactly {id} of the first, no key", r.json() == {"id": first_id})
    check("still one inquiry", len(await inquiries("cabinet:tnt_1")) == 1)
    check("still one tenant with that ext_id", len([t for t in await all_tenants() if t.ext_id == "tnt_1"]) == 1)
    # A disabled tenant does not block a re-mint (the guard looks at active rows).
    await c.post("/broker/admin/tenants/set", json={"id": first_id, "status": "disabled"}, auth=ADMIN)
    r = await c.post("/broker/admin/tenants", json={"pool": "team-a", "ext_id": "tnt_1"}, auth=ADMIN)
    check("after disabling the first, the same ext_id mints again", r.status_code == 200 and r.json()["id"] != first_id)
    # Absolute paid_until wins over days; days alone still works; pool None is a Supporter.
    r = await c.post("/broker/admin/tenants", json={"paid_until": 1_900_000_000, "days": 5, "pool": "shared", "ext_id": "tnt_2"}, auth=ADMIN)
    check("paid_until absolute wins over days", r.json()["paid_until"] == 1_900_000_000 and r.json()["pool_applied"] is True)
    r = await c.post("/broker/admin/tenants", json={"days": 2}, auth=ADMIN)
    check("days alone: now + 2d, pool None, ext_id None",
          abs(r.json()["paid_until"] - (NOW + 2 * 86400)) < 120 and r.json()["pool_id"] is None
          and r.json()["ext_id"] is None and r.json()["pool_applied"] is True)
    r = await c.post("/broker/admin/tenants", json={"pool": "TEAM A"}, auth=ADMIN)
    check(f"a malformed pool -> 400 ({r.status_code})", r.status_code == 400)
    # A team pool that already has an enabled node applies at mint, no inquiry.
    await seed_relay("tb-1", "10.5.0.1", pool_id="team-b")
    r = await c.post("/broker/admin/tenants", json={"pool": "team-b", "ext_id": "tnt_3"}, auth=ADMIN)
    check("a team pool with an enabled node applies at mint",
          r.json()["pool_id"] == "team-b" and r.json()["pool_applied"] is True)
    check("and files no inquiry", not await inquiries("cabinet:tnt_3"))
    d = await bridges(c, r.json()["key"])
    check("its key sees the node", private_endpoints(d) == {"10.5.0.1:443"})

    print("\n8b. the label the worker really sends: team-tnt-<hex> for cabinet tnt_<hex>")
    # console-worker/tenants.js `poolFor` spells the D1 id's underscore as a
    # dash, and pins that against this exact grammar in its own test. The
    # underscore spelling is refused so a Team pool can only ever have one name.
    r = await c.post("/broker/admin/tenants", json={"pool": "team-tnt-0123abcd", "ext_id": "tnt_0123abcd"}, auth=ADMIN)
    check(f"mints with the worker's label ({r.status_code})", r.status_code == 200)
    check("rides shared, pool_applied False, ext_id is the raw cabinet id",
          r.json()["pool_id"] == "shared" and r.json()["pool_applied"] is False and r.json()["ext_id"] == "tnt_0123abcd")
    real_id, real_key = r.json()["id"], r.json()["key"]
    rows = await inquiries("cabinet:tnt_0123abcd")
    check("the inquiry is filed under the raw cabinet id and names the dashed pool",
          len(rows) == 1 and "team-tnt-0123abcd" in rows[0].about)
    await seed_relay("tt-1", "10.5.0.2", enabled=False)
    r = await c.post("/broker/admin/tenants/assign", json={"tag": "tt-1", "pool_id": "team-tnt-0123abcd", "enabled": True}, auth=ADMIN)
    check(f"assign with that pool_id ({r.status_code})", r.status_code == 200 and r.json()["pool_id"] == "team-tnt-0123abcd")
    r = await c.post("/broker/admin/tenants/set", json={"id": real_id, "pool": "team-tnt-0123abcd"}, auth=ADMIN)
    check("the sync's set then applies it", r.json()["pool_applied"] is True and r.json()["pool_id"] == "team-tnt-0123abcd")
    d = await bridges(c, real_key)
    check("and the key sees the node", private_endpoints(d) == {"10.5.0.2:443"} and d["key"] == "ok")
    r = await c.post("/broker/admin/tenants", json={"pool": "team-tnt_0123abcd", "ext_id": "tnt_x"}, auth=ADMIN)
    check(f"the underscore spelling is a 400, not a second pool ({r.status_code})", r.status_code == 400)
    r = await c.post("/broker/admin/tenants/assign", json={"tag": "tt-1", "pool_id": "team-tnt_0123abcd"}, auth=ADMIN)
    check("same on assign", r.status_code == 400)
    return first_key


async def case_double_mint_race(c):
    print("\n8c. double mint that slips past the existence check: the post-commit settle")
    await reset()
    # The helper on its own: two ACTIVE tenants share an ext_id; the younger
    # yields, the older keeps its 200, a disabled competitor does not count.
    await seed_tenant("rt_older", ext_id="tnt_r", created_at=ago(seconds=100))
    await seed_tenant("rt_younger", ext_id="tnt_r", created_at=ago(seconds=1))
    await seed_tenant("rt_dead", ext_id="tnt_r", status="disabled", created_at=ago(seconds=500))
    async with SessionLocal() as db:
        younger = (await db.execute(select(RelayTenant).where(RelayTenant.id == "rt_younger"))).scalar_one()
        winner = await B._settle_double_mint(db, younger)
        check("the younger row yields to the older", winner is not None and winner.id == "rt_older")
        older = (await db.execute(select(RelayTenant).where(RelayTenant.id == "rt_older"))).scalar_one()
        check("the older row does not yield", await B._settle_double_mint(db, older) is None)
    ts = {t.id: t.status for t in await all_tenants()}
    check(f"persisted: younger disabled, older active, dead untouched ({ts})",
          ts == {"rt_older": "active", "rt_younger": "disabled", "rt_dead": "disabled"})

    # The whole route: a competitor lands AFTER the existence check and
    # BEFORE the commit (the window two uvicorn workers can share), written
    # from a second connection while the request is between the two. The
    # request must answer 409 {id: competitor} and leave its own row disabled.
    older_ts = ago(seconds=60).strftime("%Y-%m-%d %H:%M:%S.%f")

    def land_competitor():
        con = sqlite3.connect(DB_FILE)
        try:
            con.execute(
                "INSERT INTO relay_tenants (id, key_hash, name, status, paid_until, pool_id, ext_id, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                ("rt_racer", hashlib.sha256(b"key-rt_racer").hexdigest(), "racer", "active",
                 NOW + 86400, "shared", "tnt_race", older_ts),
            )
            con.commit()
        finally:
            con.close()

    class RacingSecrets:
        # `token_urlsafe` is the first thing the route calls after the
        # existence check, which makes it the hook that puts the competitor
        # exactly inside the window.
        @staticmethod
        def token_urlsafe(n):
            land_competitor()
            return secrets.token_urlsafe(n)

        @staticmethod
        def token_hex(n):
            return secrets.token_hex(n)

    saved = B.secrets
    B.secrets = RacingSecrets
    try:
        r = await c.post("/broker/admin/tenants", json={"pool": "shared", "ext_id": "tnt_race"}, auth=ADMIN)
    finally:
        B.secrets = saved
    check(f"the later committer answers 409 ({r.status_code})", r.status_code == 409)
    check("with exactly {id} of the competitor and no key", r.json() == {"id": "rt_racer"})
    mine = [t for t in await all_tenants() if t.ext_id == "tnt_race"]
    check(f"one ACTIVE tenant for the ext_id, the loser disabled ({[(t.id, t.status) for t in mine]})",
          len(mine) == 2 and [t.status for t in mine if t.id == "rt_racer"] == ["active"]
          and [t.status for t in mine if t.id != "rt_racer"] == ["disabled"])
    r = await c.post("/broker/admin/tenants", json={"pool": "shared", "ext_id": "tnt_race"}, auth=ADMIN)
    check("a plain repeat is still caught by the existence check", r.status_code == 409 and r.json() == {"id": "rt_racer"})


async def case_parked_caps_and_sweep(c):
    print("\n5b. parked caps: 2 per key, 16 island-wide; a plain registration still lands")
    await reset()
    keys = [Ed25519PrivateKey.generate() for _ in range(9)]
    tags = []
    for k, priv in enumerate(keys[:8]):
        for i in range(2):
            b = sign_registration(priv, descriptor(f"park-{k}-{i}.example.net", 8443), NOW)
            b["private"] = True
            r = await c.post("/broker/register", json=b)
            assert r.status_code == 200, (k, i, r.text)
            tags.append(r.json()["tag"])
    check("16 parked rows from 8 keys land", len(tags) == 16)
    b = sign_registration(keys[0], descriptor("park-0-2.example.net", 8443), NOW)
    b["private"] = True
    r = await c.post("/broker/register", json=b)
    check(f"a third parked row on one key -> 429 ({r.status_code}: {r.json().get('detail')})", r.status_code == 429)
    b = sign_registration(keys[8], descriptor("park-8-0.example.net", 8443), NOW)
    b["private"] = True
    r = await c.post("/broker/register", json=b)
    check(f"the 17th parked row island-wide -> 429 ({r.status_code}: {r.json().get('detail')})", r.status_code == 429)
    b = sign_registration(keys[8], descriptor("plain-8.example.net", 8443), NOW)
    r = await c.post("/broker/register", json=b)
    check("a plain registration still lands, enabled", r.status_code == 200 and r.json()["enabled"] is True)
    b = sign_registration(keys[0], descriptor("park-0-0.example.net", 8443), NOW + 1)
    b["private"] = True
    r = await c.post("/broker/register", json=b)
    check("re-running bootstrap on a parked node is a refresh, not a 17th row", r.status_code == 200 and r.json()["enabled"] is False)
    r = await c.post("/broker/admin/tenants/assign", json={"tag": tags[0], "pool_id": "shared"}, auth=ADMIN)
    assert r.status_code == 200, r.text
    b = sign_registration(keys[8], descriptor("park-8-0.example.net", 8443), NOW)
    b["private"] = True
    r = await c.post("/broker/register", json=b)
    check("a parked row given a pool leaves the count: the 17th now lands", r.status_code == 200 and r.json()["enabled"] is False)

    print("\n5c. the liveness call sweeps parked rows nobody assigned in 7 days, and nothing else")
    await reset()
    await seed_relay("old-parked", "10.12.0.1", enabled=False, created_at=ago(days=8))
    await seed_relay("young-parked", "10.12.0.2", enabled=False, created_at=ago(days=6))
    await seed_relay("old-pooled", "10.12.0.3", enabled=False, pool_id="shared", created_at=ago(days=8))
    await seed_relay("old-tenant", "10.12.0.4", enabled=False, tenant_id="rt_t", created_at=ago(days=8))
    await seed_relay("old-was-live", "10.12.0.5", enabled=False, last_ok=STALE, created_at=ago(days=8))
    await seed_relay("old-public", "10.12.0.6", created_at=ago(days=8))
    r = await c.post("/broker/admin/liveness", json={"results": []}, auth=ADMIN)
    check(f"liveness answers ({r.status_code})", r.status_code == 200)
    left = {t for t in ("old-parked", "young-parked", "old-pooled", "old-tenant", "old-was-live", "old-public")
            if await relay_row(t) is not None}
    check(f"only the week-old never-assigned parked row is gone ({sorted(left)})",
          left == {"young-parked", "old-pooled", "old-tenant", "old-was-live", "old-public"})
    # And a report naming the row the sweep deletes does not trip the flush.
    await seed_relay("old-parked-2", "10.12.0.7", enabled=False, created_at=ago(days=8))
    r = await c.post("/broker/admin/liveness", json={"results": [{"tag": "old-parked-2", "ok": False}]}, auth=ADMIN)
    check("a failure report on a row the sweep removes is fine", r.status_code == 200 and await relay_row("old-parked-2") is None)


async def all_tenants():
    async with SessionLocal() as db:
        return (await db.execute(select(RelayTenant))).scalars().all()


async def case_liveness_sweep(c):
    print("\n9. liveness sweep: 144 failures delete a public community row, never a pool or tenant row")
    await reset()
    await seed_relay("pub-c", "10.6.0.1")
    await seed_relay("pool-c", "10.6.0.2", pool_id="shared")
    await seed_relay("tnt-c", "10.6.0.3", tenant_id="rt_z")
    await seed_relay("pub-trusted", "10.6.0.4", tier="trusted")
    results = [{"tag": t, "ok": False} for t in ("pub-c", "pool-c", "tnt-c", "pub-trusted")]
    for _ in range(B._DEAD_AFTER_FAILS):
        r = await c.post("/broker/admin/liveness", json={"results": results}, auth=ADMIN)
        assert r.status_code == 200, r.text
    check("public community row swept", await relay_row("pub-c") is None)
    row = await relay_row("pool-c")
    check(f"pool row survives with its failures counted ({row.fail_count if row else None})",
          row is not None and row.fail_count >= B._DEAD_AFTER_FAILS)
    check("tenant row survives", await relay_row("tnt-c") is not None)
    check("trusted public row survives (existing rule)", await relay_row("pub-trusted") is not None)


async def case_reachability(c):
    print("\n10. reachability: `accepted` counts well-formed reports, not matches")
    await reset()
    await seed_relay("pool-r", "10.7.0.1", pool_id="shared")
    await seed_relay("parked-r", "10.7.0.2", pool_id="shared", enabled=False)
    real = {"server": "10.7.0.1", "port": 443, "ok": True}
    parked = {"server": "10.7.0.2", "port": 443, "ok": True}
    fake = {"server": "10.7.0.99", "port": 443, "ok": True}
    garbage = {"server": "10.7.0.1", "port": "443"}
    FAKE.log.clear()
    r = await c.post("/broker/reachability", json={"reports": [real, garbage, fake]}, headers={"x-forwarded-for": XFFS[0]})
    check(f"answers ({r.status_code})", r.status_code == 200)
    check(f"accepted == 2: the two well-formed ones, garbage not ({r.json()['accepted']})", r.json()["accepted"] == 2)
    zadds = [k for op, k in FAKE.log if op == "zadd"]
    check("the vote for the pool row WAS recorded", any("10.7.0.1:443" in k for k in zadds))
    check("no key was minted for the made-up endpoint", not any("10.7.0.99" in k for k in zadds))
    FAKE.log.clear()
    r_real = await c.post("/broker/reachability", json={"reports": [real]}, headers={"x-forwarded-for": XFFS[1]})
    r_fake = await c.post("/broker/reachability", json={"reports": [fake]}, headers={"x-forwarded-for": XFFS[2]})
    r_parked = await c.post("/broker/reachability", json={"reports": [parked]}, headers={"x-forwarded-for": XFFS[3]})
    check("a real private endpoint and a made-up one get the same accepted (no oracle)",
          r_real.json()["accepted"] == r_fake.json()["accepted"] == r_parked.json()["accepted"] == 1)
    zadds = [k for op, k in FAKE.log if op == "zadd"]
    check("a parked row collects no votes (not enabled, not in the pool)", not any("10.7.0.2" in k for k in zadds))
    r = await c.post("/broker/reachability", json={"reports": [garbage]})
    check("a body of only garbage -> accepted 0 (well-formedness is still checked)", r.json()["accepted"] == 0)


async def case_stats(c):
    print("\n11. /admin/stats: public counts exclude pool rows; pools_needing_nodes; pools_dark")
    await reset()
    await seed_relay("pub-t", "10.8.0.1", tier="trusted")
    await seed_relay("pub-c", "10.8.0.2", last_ok=FRESH)
    await seed_relay("pool-stale", "10.8.0.3", pool_id="shared", last_ok=STALE)
    await seed_relay("tnt-x", "10.8.0.4", tenant_id="rt_q", tier="trusted")
    await seed_relay("parked-only", "10.8.0.5", pool_id="team-parked", enabled=False)
    r = await c.get("/admin/stats", auth=ADMIN)
    check(f"stats answer ({r.status_code})", r.status_code == 200)
    d = r.json()
    check(f"broker_public_relays counts the two public rows only ({d['broker_public_relays']})", d["broker_public_relays"] == 2)
    check(f"broker_public_live likewise ({d['broker_public_live']})", d["broker_public_live"] == 2)
    check(f"pools_needing_nodes 0 before any team mint ({d['pools_needing_nodes']})", d["pools_needing_nodes"] == 0)
    check(f"pools_dark 1: shared's only enabled row is stale; a parked-only pool is not dark ({d['pools_dark']})",
          d["pools_dark"] == 1)
    await c.post("/broker/admin/tenants", json={"pool": "team-a", "ext_id": "tnt_stats"}, auth=ADMIN)
    d = (await c.get("/admin/stats", auth=ADMIN)).json()
    check(f"pools_needing_nodes 1 after a team mint without nodes ({d['pools_needing_nodes']})", d["pools_needing_nodes"] == 1)
    await c.post("/broker/admin/liveness", json={"results": [{"tag": "pool-stale", "ok": True}]}, auth=ADMIN)
    d = (await c.get("/admin/stats", auth=ADMIN)).json()
    check(f"pools_dark 0 once the pool row answers ({d['pools_dark']})", d["pools_dark"] == 0)
    check("public counts unchanged by a pool row going live", d["broker_public_relays"] == 2 and d["broker_public_live"] == 2)


async def case_set_tenant(c):
    print("\nPart 2. set: absolute paid_until, add_days from a lapse, pool moves with inquiry auto-close")
    await reset()
    r = await c.post("/broker/admin/tenants", json={"pool": "shared", "ext_id": "tnt_9"}, auth=ADMIN)
    tid, key = r.json()["id"], r.json()["key"]
    X = 1_950_000_000
    r = await c.post("/broker/admin/tenants/set", json={"id": tid, "paid_until": X}, auth=ADMIN)
    check("set paid_until: X lands exactly", r.json()["paid_until"] == X)
    check("reply {id, status, paid_until, pool_id, pool_applied} with pool_applied True when no pool asked",
          r.json() == {"id": tid, "status": "active", "paid_until": X, "pool_id": "shared", "pool_applied": True})
    r = await c.post("/broker/admin/tenants/set", json={"id": tid, "paid_until": X}, auth=ADMIN)
    check("again is a no-op", r.json()["paid_until"] == X)
    r = await c.post("/broker/admin/tenants/set", json={"id": tid, "paid_until": NOW - 86400}, auth=ADMIN)
    d = await bridges(c, key)
    check("a past paid_until answers `expired` from the next poll", d["key"] == "expired")
    r = await c.post("/broker/admin/tenants/set", json={"id": tid, "add_days": 10}, auth=ADMIN)
    check("add_days from a lapsed end extends from now", abs(r.json()["paid_until"] - (NOW + 10 * 86400)) < 120)
    r = await c.post("/broker/admin/tenants/set", json={"id": tid, "paid_until": X, "add_days": 1}, auth=ADMIN)
    check("paid_until then add_days: absolute first, then extended", r.json()["paid_until"] == X + 86400)
    r = await c.post("/broker/admin/tenants/set", json={"id": tid, "paid_until": -1}, auth=ADMIN)
    check(f"a negative paid_until is refused ({r.status_code})", r.status_code == 422)

    # Pool move to a team pool that has no node yet.
    r = await c.post("/broker/admin/tenants/set", json={"id": tid, "pool": "team-y"}, auth=ADMIN)
    check("team-y without nodes: pool_applied False, keeps shared",
          r.json()["pool_applied"] is False and r.json()["pool_id"] == "shared")
    check("one open inquiry filed for cabinet:tnt_9",
          [(i.status, i.tier) for i in await inquiries("cabinet:tnt_9")] == [("open", "team-paid")])
    r = await c.post("/broker/admin/tenants/set", json={"id": tid, "pool": "team-y"}, auth=ADMIN)
    check("the minute sync repeating it does not file a second one", len(await inquiries("cabinet:tnt_9")) == 1)
    check("pools_needing_nodes reads 1", (await c.get("/admin/stats", auth=ADMIN)).json()["pools_needing_nodes"] == 1)
    # The founder raises a parked node and lights it into team-y in one call.
    await seed_relay("ty-1", "10.10.0.1", enabled=False)
    r = await c.post("/broker/admin/tenants/assign", json={"tag": "ty-1", "pool_id": "team-y", "enabled": True}, auth=ADMIN)
    assert r.status_code == 200, r.text
    r = await c.post("/broker/admin/tenants/set", json={"id": tid, "pool": "team-y"}, auth=ADMIN)
    check("the same set now applies: pool_applied True, pool_id team-y",
          r.json()["pool_applied"] is True and r.json()["pool_id"] == "team-y")
    rows = await inquiries("cabinet:tnt_9")
    check("the inquiry is closed by the island with a note",
          len(rows) == 1 and rows[0].status == "closed" and rows[0].note.startswith("pool applied team-y "))
    check("pools_needing_nodes drops to 0 without a click",
          (await c.get("/admin/stats", auth=ADMIN)).json()["pools_needing_nodes"] == 0)
    d = await bridges(c, key)
    check("the key now sees the team node and nothing from shared", private_endpoints(d) == {"10.10.0.1:443"})
    r = await c.post("/broker/admin/tenants/set", json={"id": tid, "pool": ""}, auth=ADMIN)
    check("pool: '' clears it", r.json()["pool_id"] is None and r.json()["pool_applied"] is True)
    r = await c.post("/broker/admin/tenants/set", json={"id": tid, "pool": "team-z"}, auth=ADMIN)
    check("from no pool, a team pool without nodes leaves the tenant where it is (None)",
          r.json()["pool_applied"] is False and r.json()["pool_id"] is None)
    r = await c.post("/broker/admin/tenants/set", json={"id": tid, "pool": "team z"}, auth=ADMIN)
    check(f"a malformed pool -> 400 ({r.status_code})", r.status_code == 400)
    r = await c.post("/broker/admin/tenants/set", json={"id": "rt_nope", "paid_until": X}, auth=ADMIN)
    check(f"unknown tenant -> 404 ({r.status_code})", r.status_code == 404)

    print("\nPart 2. tenant list: pool_id, ext_id, relays = direct + enabled pool rows, pool_live")
    await c.post("/broker/admin/tenants/set", json={"id": tid, "pool": "team-y"}, auth=ADMIN)
    await seed_relay("ty-2", "10.10.0.2", pool_id="team-y", last_ok=FRESH)
    await seed_relay("ty-parked", "10.10.0.3", pool_id="team-y", enabled=False)
    await seed_relay("direct-1", "10.10.0.4", tenant_id=tid)
    r = await c.get("/broker/admin/tenants", auth=ADMIN)
    t = [x for x in r.json()["tenants"] if x["id"] == tid][0]
    check("pool_id and ext_id listed", t["pool_id"] == "team-y" and t["ext_id"] == "tnt_9")
    check(f"relays = 1 direct + 2 enabled pool rows ({t['relays']})", t["relays"] == 3)
    check(f"pool_live = 1 (ty-2 fresh, ty-1 never probed, parked not counted) ({t['pool_live']})", t["pool_live"] == 1)


async def case_rotate(c):
    print("\nPart 2. rotate: same id, same pool, old key unknown, new key ok")
    await reset()
    await seed_relay("sh-1", "10.11.0.1", pool_id="shared")
    await seed_relay("sh-2", "10.11.0.2", pool_id="shared")
    r = await c.post("/broker/admin/tenants", json={"pool": "shared", "ext_id": "tnt_rot", "paid_until": 1_960_000_000}, auth=ADMIN)
    tid, old = r.json()["id"], r.json()["key"]
    await seed_relay("direct-rot", "10.11.0.3", tenant_id=tid)
    before = await bridges(c, old)
    r = await c.post("/broker/admin/tenants/rotate", json={"id": tid}, auth=ADMIN)
    check(f"rotate answers ({r.status_code})", r.status_code == 200)
    d = r.json()
    check("reply {id, key, paid_until, pool_id}", set(d) == {"id", "key", "paid_until", "pool_id"})
    check("id, pool_id, paid_until unchanged", d["id"] == tid and d["pool_id"] == "shared" and d["paid_until"] == 1_960_000_000)
    check("a new key", isinstance(d["key"], str) and d["key"] != old)
    check("old key -> unknown", (await bridges(c, old))["key"] == "unknown")
    after = await bridges(c, d["key"])
    check("new key -> ok with the same private rows (pool + direct)",
          after["key"] == "ok" and private_endpoints(after) == private_endpoints(before) == {"10.11.0.1:443", "10.11.0.2:443", "10.11.0.3:443"})
    check("one tenant row, not a mint-and-disable", len(await all_tenants()) == 1)
    r = await c.post("/broker/admin/tenants/rotate", json={"id": "rt_nope"}, auth=ADMIN)
    check(f"unknown id -> 404 ({r.status_code})", r.status_code == 404)
    r = await c.post("/broker/admin/tenants/rotate", json={"id": tid})
    check(f"no admin auth -> 401 ({r.status_code})", r.status_code == 401)


async def case_second_boot():
    print("\ninit_db twice: the add-lists survive a second boot on SQLite")
    await init_db()
    await init_db()
    async with SessionLocal() as db:
        cols = {row[1] for row in (await db.execute(text("PRAGMA table_info(relay_tenants)"))).all()}
        cols2 = {row[1] for row in (await db.execute(text("PRAGMA table_info(broker_relays)"))).all()}
    check("relay_tenants has pool_id and ext_id", {"pool_id", "ext_id"} <= cols)
    check("broker_relays has pool_id", "pool_id" in cols2)


async def main() -> int:
    await init_db()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        await case_invariant(c)
        await case_pool_serving(c)
        parked = await case_register_private(c)
        await case_admin_set_force(c, parked)
        await case_parked_caps_and_sweep(c)
        await case_assign(c)
        await case_create_tenant(c)
        await case_double_mint_race(c)
        await case_liveness_sweep(c)
        await case_reachability(c)
        await case_stats(c)
        await case_set_tenant(c)
        await case_rotate(c)
    await case_second_boot()
    await engine.dispose()
    try:
        os.remove(DB_FILE)
    except FileNotFoundError:
        pass
    print(f"\nrelay pool: {'ALL PASS' if fails == 0 else f'{fails} FAILURES ABOVE'}")
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
