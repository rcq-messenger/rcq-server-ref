"""Local-only verification of the guest self-join (spec 2026-09-15, 4 and 4.5).

A paid island. People from elsewhere get a guest copy through
`POST /auth/guest/challenge` + `POST /auth/guest`, created only together with
its first membership. Pins:

  * the door itself is unchanged: `/auth/register` without a code is still
    403 entry_required, and the capability is advertised;
  * the happy path: 201, guest:true, `entered_via='guest'`, `guest_status`
    proven, the membership, `last_seen` backdated, in the guest cache, no
    founder edge, no beta room, the room told, the counter bumped, and the
    client's follow-up `/join` short-circuits;
  * every refusal of section 11 for this route, each leaving no row: version,
    bad key (422), malformed signature, a register-typ challenge, another
    island's host, ik swapped after signing, group_id swapped after signing,
    a replayed challenge, a missing room, a closed room, allow_guests=false,
    the member ceiling, the room's daily budget (429 with Retry-After);
  * two concurrent requests for one key make exactly one row;
  * an existing native row gets a token and nothing else; an unclaimed seat
    is claimed with its identity key replaced and its rooms told; a proven
    guest with a new identity key is repaired; a retired key is
    identity_rotated; a revoked device is device_revoked;
  * the admission matrix on this route: off, open, invite+auto, invite+on,
    closed+refuse strangers; existing rows keep their tokens under "off";
  * Redis down at the single-use guard is 503 with no row; `mark_guest`
    failing is 503 with no row, and the challenge is given back;
  * recover and refresh claim a seat without touching its identity key, and
    say `guest` in the reply;
  * a guest's `/join` into another room: allow_guests, the per-guest room cap.

Runs the real FastAPI stack in-process on a throwaway SQLite DB with Redis
db 15. NOT deployed.
Run: PYTHONPATH=. /Users/tager/Documents/RCQ/backend/.venv/bin/python test_guest_join_local.py
"""
import asyncio
import base64
import hashlib
import os
from datetime import datetime, timedelta, timezone

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test_guest_join.db"
os.environ["ENV"] = "dev"
os.environ["REDIS_URL"] = "redis://localhost:6379/15"
for var in ("RCQ_GUEST_ADMISSION", "RCQ_ISLAND_HOST", "RCQ_FOUNDER_UIN", "RCQ_FOUNDER_BETA_GROUP_ID"):
    os.environ.pop(var, None)
for f in ("test_guest_join.db",):
    try:
        os.remove(f)
    except FileNotFoundError:
        pass

import httpx  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat  # noqa: E402
from sqlalchemy import func, select  # noqa: E402

import app.core.redis as redis_mod  # noqa: E402
import app.routers.auth as auth_router  # noqa: E402
import app.routers.groups as groups_mod  # noqa: E402
from app.core import guest_policy as gp  # noqa: E402
from app.core.db import SessionLocal, init_db  # noqa: E402
from app.core.redis import close_redis, get_redis  # noqa: E402
from app.core.redis_keys import DEV_REVOKED_PREFIX, account_key  # noqa: E402
from app.main import app  # noqa: E402
from app.models.contact import Contact  # noqa: E402
from app.models.group import GroupMember  # noqa: E402
from app.models.retired_signing_key import RetiredSigningKey  # noqa: E402
from app.models.user import User  # noqa: E402
from app.services import guest_proof, server_settings  # noqa: E402
from app.services.connection_manager import manager  # noqa: E402

HOST = "island-a.example"
fails = 0


def check(name, cond):
    global fails
    print(f"  {'PASS' if cond else 'FAIL'}  {name}")
    if not cond:
        fails += 1


def H(tok):
    return {"Authorization": f"Bearer {tok}"}


def code_of(r):
    try:
        detail = r.json().get("detail")
    except ValueError:
        return None
    return detail.get("code") if isinstance(detail, dict) else None


def aware(dt):
    return dt if dt is None or dt.tzinfo else dt.replace(tzinfo=timezone.utc)


class Keys:
    def __init__(self) -> None:
        self.priv = Ed25519PrivateKey.generate()
        self.sk_raw = self.priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.ik_raw = os.urandom(32)

    @property
    def sk(self) -> str:
        return base64.b64encode(self.sk_raw).decode()

    @property
    def ik(self) -> str:
        return base64.b64encode(self.ik_raw).decode()

    def sign(self, data: bytes) -> str:
        return base64.b64encode(self.priv.sign(data)).decode()


async def clear(*patterns):
    redis = await get_redis()
    for pattern in patterns:
        keys = [k async for k in redis.scan_iter(match=pattern)]
        if keys:
            await redis.delete(*keys)


async def reset_limits():
    # The per-caller limiters this file would otherwise trip by making many
    # requests from one address. ⚠ Deliberately NOT `rl:*`: the room budgets
    # (`rl:guest_room_join:*`, `rl:guest_add_group:*`) are what some checks
    # below fill up on purpose.
    await clear("rl:auth_*", "rl:groups_*", "rl:ceiling:*")


async def stat(name: str) -> int:
    raw = await (await get_redis()).get(f"stat:{name}:{datetime.now(timezone.utc):%Y%m%d}")
    return int(raw or 0)


async def set_settings(**values):
    async with SessionLocal() as db:
        await server_settings.apply(db, server_settings.validate(values))
        await db.commit()
    server_settings._cache.at = -1e9


async def rows_for(keys: Keys) -> int:
    async with SessionLocal() as db:
        return await db.scalar(
            select(func.count()).select_from(User).where(
                User.signing_key.in_((keys.sk, keys.sk.rstrip("=")))
            )
        )


async def user(uin):
    async with SessionLocal() as db:
        return await db.get(User, uin)


async def is_member(gid, uin) -> bool:
    async with SessionLocal() as db:
        return await db.scalar(
            select(GroupMember.id).where(GroupMember.group_id == gid, GroupMember.uin == uin)
        ) is not None


async def seat(keys: Keys, gid: int, *, status="added", ik: str | None = None) -> int:
    """A seat or guest row made directly, the way owner-add makes one."""
    async with SessionLocal() as db:
        from app.services.uin import allocate_uin

        uin = await allocate_uin(db)
        now = datetime.now(timezone.utc)
        db.add(User(
            uin=uin, nickname="seat", identity_key=ik or base64.b64encode(os.urandom(32)).decode(),
            signing_key=keys.sk, entered_via="guest", guest_status=status, guest_since=now,
            last_seen=now - timedelta(days=30),
        ))
        await db.flush()
        db.add(GroupMember(group_id=gid, uin=uin, role="member"))
        await db.commit()
    await gp.mark_guest(uin)
    return uin


async def main() -> int:
    await init_db()
    await (await get_redis()).flushdb()
    announced: list[int] = []
    real_rekey = groups_mod.broadcast_roster_rekey

    async def rekey_recorder(db, uin):
        announced.append(uin)
        return await real_rekey(db, uin)

    groups_mod.broadcast_roster_rekey = rekey_recorder
    minted_broadcasts: list[int] = []
    real_broadcast = auth_router._broadcast_membership

    async def broadcast_recorder(group_id, members, payload, extra_uins=None):
        minted_broadcasts.append(group_id)
        return await real_broadcast(group_id, members, payload, extra_uins)

    auth_router._broadcast_membership = broadcast_recorder

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:

        async def register(keys: Keys, nick: str):
            await reset_limits()
            r = await c.post("/auth/register", json={"nickname": nick, "identity_key": keys.ik, "signing_key": keys.sk})
            assert r.status_code == 201, r.text
            return r.json()["uin"], r.json()["token"]

        async def room(tok, name, **patch):
            await reset_limits()
            r = await c.post("/groups", headers=H(tok), json={"name": name, "member_uins": []})
            assert r.status_code == 201, r.text
            gid = r.json()["id"]
            if patch:
                r = await c.patch(f"/groups/{gid}", headers=H(tok), json=patch)
                assert r.status_code == 200, r.text
            return gid

        async def challenge(keys: Keys, typ="guest"):
            await reset_limits()
            path = "/auth/guest/challenge" if typ == "guest" else "/auth/register/challenge"
            r = await c.post(path, json={"signing_key": keys.sk})
            assert r.status_code == 200, r.text
            return r.json()["challenge"]

        def body(keys: Keys, gid: int, ch: str, *, host=HOST, sign_host=None, sign_gid=None,
                 sign_ik=None, v=1, device_id=None, nick="guest"):
            data = guest_proof.proof_bytes(sign_host or host, sign_gid or gid, sign_ik or keys.ik_raw, keys.sk_raw, ch)
            out = {"v": v, "host": host, "group_id": gid, "nickname": nick,
                   "identity_key": keys.ik, "signing_key": keys.sk, "challenge": ch,
                   "signature": keys.sign(data)}
            if device_id:
                out["device_id"] = device_id
            return out

        async def join(keys: Keys, gid: int, **kw):
            ch = await challenge(keys)
            await clear("rl:auth_guest*", "rl:ceiling:*")
            return await c.post("/auth/guest", json=body(keys, gid, ch, **kw))

        async def cap():
            return (await c.get("/server/info")).json()["capabilities"].get("guest_accounts_v1")

        # ── residents, made while the door is open ────────────────────────
        ko, km, kx = Keys(), Keys(), Keys()
        O, tok_o = await register(ko, "owner")
        M, tok_m = await register(km, "member")
        X, tok_x = await register(kx, "other")
        R = await room(tok_o, "open room")
        async with SessionLocal() as db:
            db.add(GroupMember(group_id=R, uin=M, role="member"))
            await db.commit()
        RC = await room(tok_o, "closed room", is_closed=True)
        RNG = await room(tok_o, "no guests", allow_guests=False)
        BETA = await room(tok_o, "beta")
        RX = await room(tok_x, "x's room")
        os.environ["RCQ_FOUNDER_UIN"] = str(O)
        os.environ["RCQ_FOUNDER_BETA_GROUP_ID"] = str(BETA)
        await set_settings(island_host=HOST, registration_policy="paid")

        print("The door:")
        await reset_limits()
        r = await c.post("/auth/register", json={"nickname": "n", "identity_key": Keys().ik, "signing_key": Keys().sk})
        check(f"/auth/register without a code is still 403 entry_required ({r.status_code})",
              r.status_code == 403 and code_of(r) == "entry_required")
        check("guest_accounts_v1 is advertised on a paid island", await cap() is True)

        # ── happy path ───────────────────────────────────────────────────
        print("\nSelf-join:")
        k1 = Keys()
        before_mint = await stat("guest_mint")
        r = await join(k1, R)
        check(f"★ 201 ({r.status_code})", r.status_code == 201)
        j = r.json() if r.status_code == 201 else {}
        check("  ... guest:true created:true and a token", j.get("guest") is True and j.get("created") is True and j.get("token"))
        G1, tok_g1 = j.get("uin"), j.get("token")
        u = await user(G1)
        check("  ... entered_via guest, guest_status proven, guest_since set",
              u is not None and u.entered_via == "guest" and u.guest_status == "proven" and u.guest_since is not None)
        check("  ... last_seen backdated by about DORMANT_DAYS-1",
              u is not None and aware(u.last_seen) < datetime.now(timezone.utc) - timedelta(days=12))
        check("★ ... the membership was created in the same request", await is_member(R, G1))
        check("  ... one row for the key", await rows_for(k1) == 1)
        check("  ... in the guest cache", await gp.is_guest(G1) is True)
        check("  ... no beta room", not await is_member(BETA, G1))
        async with SessionLocal() as db:
            edges = await db.scalar(select(func.count()).select_from(Contact).where(
                (Contact.owner_uin == G1) | (Contact.contact_uin == G1)))
        check("  ... no founder edge (no contact rows at all)", edges == 0)
        check("  ... the room was told", R in minted_broadcasts)
        check("  ... counted", await stat("guest_mint") == before_mint + 1)
        r = await c.get(f"/groups/{R}", headers=H(tok_g1))
        rows = {m["uin"]: m for m in r.json().get("members", [])} if r.status_code == 200 else {}
        check("  ... the token opens the room, roster says guest", rows.get(G1, {}).get("guest") is True)
        n_before = len(rows)
        await reset_limits()
        r = await c.post(f"/groups/{R}/join", headers=H(tok_g1))
        check(f"  ... the client's /join afterwards short-circuits ({r.status_code})",
              r.status_code == 200 and len(r.json()["members"]) == n_before)

        # ── refusals ─────────────────────────────────────────────────────
        print("\nRefusals (each leaves no row):")
        kr = Keys()

        async def refused(label, r, http, code):
            check(f"{label} -> {http} {code} ({r.status_code} {code_of(r)})",
                  r.status_code == http and (code is None or code_of(r) == code))

        ch = await challenge(kr)
        await refused("v=2", await c.post("/auth/guest", json=body(kr, R, ch, v=2)), 400, "guest_proof_version")
        bad = body(kr, R, await challenge(kr))
        bad["identity_key"] = base64.b64encode(os.urandom(31)).decode()
        await refused("a 31-byte identity key", await c.post("/auth/guest", json=bad), 422, None)
        bad = body(kr, R, await challenge(kr))
        bad["signature"] = "not base64 at all!"
        await refused("an undecodable signature", await c.post("/auth/guest", json=bad), 400, "guest_proof_malformed")
        await refused("a register-typ challenge", await c.post("/auth/guest", json=body(kr, R, await challenge(kr, "register"))),
                      400, "invalid_challenge")
        await refused("a challenge for another key", await c.post("/auth/guest", json=body(kr, R, await challenge(Keys()))),
                      400, "invalid_challenge")
        await refused("★ another island's host",
                      await c.post("/auth/guest", json=body(kr, R, await challenge(kr), host="island-b.example")),
                      400, "guest_wrong_host")
        other_ik = os.urandom(32)
        await refused("★ ik swapped after signing",
                      await c.post("/auth/guest", json=body(kr, R, await challenge(kr), sign_ik=other_ik)),
                      401, "bad_signature")
        await refused("★ group_id swapped after signing",
                      await c.post("/auth/guest", json=body(kr, R, await challenge(kr), sign_gid=RX)),
                      401, "bad_signature")
        spent = await challenge(kr)
        await c.post("/auth/guest", json=body(kr, 999999, spent))
        await refused("★ a replayed challenge", await c.post("/auth/guest", json=body(kr, R, spent)), 409, "guest_replayed")
        await refused("a missing room", await join(kr, 999998), 404, "group_not_found")
        await refused("a closed room", await join(kr, RC), 403, "group_closed")
        await refused("allow_guests=false", await join(kr, RNG), 403, "guest_room_closed")
        await set_settings(guest_room_member_ceiling=2)
        await refused("the member ceiling (2 members, ceiling 2)", await join(kr, R), 403, "guest_room_full")
        await set_settings(guest_room_member_ceiling=3500)
        check("  ... none of these made a row", await rows_for(kr) == 0)

        await set_settings(guest_room_joins_per_day=1)
        RB = await room(tok_x, "budget room")
        r = await join(Keys(), RB)
        check(f"the room's first guest of the day -> 201 ({r.status_code})", r.status_code == 201)
        r = await join(kr, RB)
        await refused("★ the next new guest that day", r, 429, "guest_room_limit")
        check("  ... with Retry-After", int(r.headers.get("Retry-After", "0")) >= 1)
        check("  ... and no row", await rows_for(kr) == 0)
        await set_settings(guest_room_joins_per_day=200)

        # ── concurrency ──────────────────────────────────────────────────
        print("\nTwo requests for one key at once:")
        kc = Keys()
        ch_a, ch_b = await challenge(kc), await challenge(kc)
        await reset_limits()
        ra, rb = await asyncio.gather(
            c.post("/auth/guest", json=body(kc, R, ch_a)),
            c.post("/auth/guest", json=body(kc, R, ch_b)),
        )
        codes = sorted([ra.status_code, rb.status_code])
        check(f"★ exactly one row ({codes})", await rows_for(kc) == 1)
        check("  ... one 201, the other 200 or 409 guest_busy",
              codes.count(201) == 1 and all(s in (200, 201, 409) for s in codes))

        # The race above may or may not land on the lock, depending on how the
        # two requests interleave. This one holds the create lock (4.4 step 9)
        # for the key by hand, the way a request still inside its insert would,
        # so guest_busy is pinned rather than hoped for. The lock is refused
        # outright, never waited on, and a busy answer must not release a lock
        # it does not own.
        kb = Keys()
        redis = await get_redis()
        lock_key = "gmk:" + hashlib.sha256(kb.sk_raw).hexdigest()[:32]
        await redis.set(lock_key, "another-request", ex=30)
        r = await join(kb, R)
        check(f"★ the create lock held by another request -> 409 guest_busy ({r.status_code} {code_of(r)})",
              r.status_code == 409 and code_of(r) == "guest_busy")
        check("  ... and no row", await rows_for(kb) == 0)
        held = await redis.get(lock_key)
        check("  ... the other request's lock is left alone", held in (b"another-request", "another-request"))
        await redis.delete(lock_key)
        r = await join(kb, R)
        check(f"  ... once it is released, a fresh challenge gets the copy ({r.status_code})", r.status_code == 201)

        # 6.2: the island's head count is the people who live here. Several guest
        # rows exist by now, so a count that forgot the filter would differ.
        async with SessionLocal() as db:
            natives = await db.scalar(select(func.count()).select_from(User).where(User.guest_status.is_(None)))
            everyone = await db.scalar(select(func.count()).select_from(User))
        served = (await c.get("/server/info")).json()["capabilities"].get("user_count")
        check(f"★ /server/info user_count excludes guests ({served} served, {natives} natives of {everyone})",
              everyone > natives and served == natives)

        # ── existing rows ────────────────────────────────────────────────
        print("\nExisting rows:")
        o_rooms = await is_member(RX, O)
        r = await join(ko, RX)
        check(f"★ a native row -> 200 guest:false created:false, same uin ({r.status_code})",
              r.status_code == 200 and r.json()["uin"] == O and r.json()["guest"] is False and r.json()["created"] is False)
        check("  ... no new row, no membership change", await rows_for(ko) == 1 and await is_member(RX, O) == o_rooms)

        ks = Keys()
        S = await seat(ks, R)
        announced.clear()
        claims = await stat("guest_claim")
        r = await join(ks, R)
        check(f"★ an unclaimed seat -> 200 guest:true created:false, the seat's uin ({r.status_code})",
              r.status_code == 200 and r.json()["uin"] == S and r.json()["guest"] is True and r.json()["created"] is False)
        u = await user(S)
        check("  ... claimed: proven, identity key replaced by the proven one",
              u.guest_status == "proven" and u.identity_key == ks.ik)
        check("  ... its rooms were told", S in announced)
        check("  ... counted as a claim", await stat("guest_claim") == claims + 1)
        check("  ... still one row", await rows_for(ks) == 1)

        announced.clear()
        k1.ik_raw = os.urandom(32)
        r = await join(k1, R)
        check(f"a proven guest with a new identity key -> 200 ({r.status_code})", r.status_code == 200 and r.json()["uin"] == G1)
        check("  ... repaired, and the rooms told", (await user(G1)).identity_key == k1.ik and G1 in announced)

        kret = Keys()
        async with SessionLocal() as db:
            db.add(RetiredSigningKey(sk_hash=hashlib.sha256(kret.sk_raw).hexdigest(), uin=X,
                                     rotated_at=datetime.now(timezone.utc)))
            await db.commit()
        r = await join(kret, R)
        check(f"★ a retired key -> 404 identity_rotated with the uin ({r.status_code})",
              r.status_code == 404 and code_of(r) == "identity_rotated" and r.json()["detail"].get("uin") == X)
        check("  ... and no row", await rows_for(kret) == 0)

        await (await get_redis()).sadd(account_key(DEV_REVOKED_PREFIX, O), "dev-revoked-1")
        r = await join(ko, RX, device_id="dev-revoked-1")
        check(f"a revoked device -> 401 device_revoked ({r.status_code})",
              r.status_code == 401 and code_of(r) == "device_revoked")

        # ── admission matrix on this route ───────────────────────────────
        print("\nAdmission:")
        await set_settings(guest_admission="off")
        check("off: capability false", await cap() is False)
        r = await join(Keys(), R)
        check(f"★ off: a new key -> 403 guest_closed ({r.status_code})", r.status_code == 403 and code_of(r) == "guest_closed")
        r = await join(k1, R)
        check(f"★ off: an existing guest still gets a token ({r.status_code})", r.status_code == 200 and r.json()["uin"] == G1)
        await set_settings(guest_admission="auto", registration_policy="open")
        check("open island: capability false", await cap() is False)
        r = await join(Keys(), R)
        check(f"open island: a new key -> 403 guest_closed ({r.status_code})", code_of(r) == "guest_closed")
        await set_settings(registration_policy="invite")
        check("invite island, auto: capability false", await cap() is False)
        r = await join(Keys(), R)
        check("  ... and a new key is guest_closed", code_of(r) == "guest_closed")
        await set_settings(guest_admission="on")
        check("invite island, on: capability true", await cap() is True)
        r = await join(Keys(), R)
        check(f"  ... and a new key gets a copy ({r.status_code})", r.status_code == 201)
        await set_settings(closed_island=True, federation_refuse_strangers=True)
        check("closed + refuse strangers beats on: capability false", await cap() is False)
        r = await join(Keys(), R)
        check("  ... and a new key is guest_closed", code_of(r) == "guest_closed")
        await set_settings(closed_island=False, federation_refuse_strangers=False,
                           guest_admission="auto", registration_policy="paid")

        # ── Redis and the cache failing ──────────────────────────────────
        print("\nFailures:")
        kd = Keys()
        ch = await challenge(kd)
        await reset_limits()
        saved = redis_mod.get_redis

        async def redis_down():
            raise ConnectionError("redis unreachable")

        redis_mod.get_redis = redis_down
        try:
            r = await c.post("/auth/guest", json=body(kd, R, ch))
        finally:
            redis_mod.get_redis = saved
        check(f"★ Redis down at the single-use guard -> 503 guest_unavailable ({r.status_code})",
              r.status_code == 503 and code_of(r) == "guest_unavailable")
        check("  ... and no row", await rows_for(kd) == 0)

        km2 = Keys()
        ch = await challenge(km2)
        real_mark = gp.mark_guest

        async def mark_fails(uin):
            raise gp.GuestCacheUnavailable("down")

        gp.mark_guest = mark_fails
        try:
            await reset_limits()
            r = await c.post("/auth/guest", json=body(km2, R, ch))
        finally:
            gp.mark_guest = real_mark
        check(f"★ mark_guest failing -> 503 guest_unavailable ({r.status_code})",
              r.status_code == 503 and code_of(r) == "guest_unavailable")
        check("  ... no row, no membership", await rows_for(km2) == 0)
        await reset_limits()
        r = await c.post("/auth/guest", json=body(km2, R, ch))
        check(f"  ... and the challenge was given back: the same request now works ({r.status_code})", r.status_code == 201)

        # ── recover and refresh ──────────────────────────────────────────
        print("\nRecover and refresh (4.5):")

        async def prove(path, keys: Keys, **extra):
            await reset_limits()
            ch = (await c.post("/auth/recover/challenge", json={"signing_key": keys.sk})).json()["challenge"]
            return await c.post(path, json={"signing_key": keys.sk, "challenge": ch,
                                            "signature": keys.sign(ch.encode()), **extra})

        kseat = Keys()
        adder_ik = base64.b64encode(os.urandom(32)).decode()
        S2 = await seat(kseat, R, ik=adder_ik)
        announced.clear()
        claims = await stat("guest_claim")
        r = await prove("/auth/recover", kseat)
        check(f"★ recover on a seat -> 200 guest:true ({r.status_code})",
              r.status_code == 200 and r.json()["uin"] == S2 and r.json().get("guest") is True)
        u = await user(S2)
        check("  ... the seat is claimed", u.guest_status == "proven")
        check("★ ... and its identity key is NOT touched (recover proves only the signing key)",
              u.identity_key == adder_ik)
        check("  ... rooms told, counted", S2 in announced and await stat("guest_claim") == claims + 1)
        check("  ... last_seen stamped one hour back, not now",
              timedelta(minutes=50) < datetime.now(timezone.utc) - aware(u.last_seen) < timedelta(minutes=70))
        r = await prove("/auth/recover", kseat)
        check("a second recover claims nothing new", r.status_code == 200 and await stat("guest_claim") == claims + 1)

        kseat2 = Keys()
        S3 = await seat(kseat2, R)
        r = await prove("/auth/refresh", kseat2, uin=S3)
        check(f"★ refresh on a seat -> 200 guest:true and claimed ({r.status_code})",
              r.status_code == 200 and r.json().get("guest") is True and (await user(S3)).guest_status == "proven")
        r = await prove("/auth/refresh", km, uin=M)
        check("refresh of a native account says guest:false", r.status_code == 200 and r.json().get("guest") is False)
        r = await prove("/auth/recover", km)
        check("recover of a native account says guest:false", r.status_code == 200 and r.json().get("guest") is False)

        # ── a guest joining a second room ────────────────────────────────
        print("\nA guest's /join into another room:")
        await reset_limits()
        r = await c.post(f"/groups/{RNG}/join", headers=H(tok_g1))
        check(f"allow_guests=false -> 403 guest_room_closed ({r.status_code})",
              r.status_code == 403 and code_of(r) == "guest_room_closed")
        R2 = await room(tok_x, "second room")
        await set_settings(guest_max_groups=1)
        await reset_limits()
        r = await c.post(f"/groups/{R2}/join", headers=H(tok_g1))
        check(f"★ past guest_max_groups -> 403 guest_group_limit ({r.status_code})",
              r.status_code == 403 and code_of(r) == "guest_group_limit")
        await set_settings(guest_max_groups=50)
        await reset_limits()
        r = await c.post(f"/groups/{R2}/join", headers=H(tok_g1))
        check(f"under the cap it joins ({r.status_code})", r.status_code == 200 and await is_member(R2, G1))
        await reset_limits()
        r = await c.post(f"/groups/{R2}/join", headers=H(tok_m))
        check("a native member's /join is untouched by any of this", r.status_code == 200)

    groups_mod.broadcast_roster_rekey = real_rekey
    auth_router._broadcast_membership = real_broadcast
    for var in ("RCQ_FOUNDER_UIN", "RCQ_FOUNDER_BETA_GROUP_ID"):
        os.environ.pop(var, None)
    await manager.shutdown()
    await close_redis()
    try:
        os.remove("test_guest_join.db")
    except FileNotFoundError:
        pass
    print("\n" + ("ALL PASS" if fails == 0 else f"{fails} FAILED"))
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
