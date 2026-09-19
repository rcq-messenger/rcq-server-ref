"""Local-only verification of guest enforcement (spec 2026-09-15, section 6).

A guest copy takes part in rooms and nothing else. This pins the mechanism and
every rule of the 6.2 matrix that lives on the server:

  * THE ROUTE WALK. Every route whose dependencies include `current_uin` or
    `current_uin_optional` must appear in EXPECTED below with the decision its
    endpoint carries (`@guest(ALLOW)`, `@guest(RULE)`, or no marker = deny).
    A new session route without an entry FAILS this file, and so does an entry
    for a route that no longer exists. The matrix is printed.
  * a guest token on every DENY route is 403 `guest_restricted`; on every
    ALLOW and RULE route it is never that; a native token is never that
    anywhere; `current_uin_optional` refuses a guest on an unmarked route
    rather than reading it as anonymous;
  * the rules: contacts respond (decline 200, accept 403, no edge), `info` of a
    non-co-member is byte-identical to a missing number, `PUT /users/me` keeps
    the nickname and drops the Hall of Fame fields, push-token is 204 with no
    row, transfer-owner to a guest is 409, search never lists a guest for
    anybody and is empty for a guest, lookup / discover / group search /
    audio rooms / uin listings / suggestions are empty for a guest, reports are
    5 a day for a guest, `add_edges` writes nothing with a guest;
  * keys on a closed island: 404 for a non-co-member (byte-identical to a
    missing number), a co-member's bundle WITHOUT a one-time prekey and none
    consumed, while a resident session still takes one; on an open island a
    non-co-member's bundle comes as to a stranger, without a prekey;
  * `door._is_resident` is false for a guest;
  * WS: typing and `call_answer` with an sdp, from a guest and to a guest, are
    not relayed; `call_offer` to a guest ends `unavailable` for the caller and
    reaches nobody; a resident pair is untouched;
  * Redis down: a guest is still refused (the row is read);
  * `POST /messages/sealed` to a guest queues the row and wakes nothing, for a
    message and for a ring; to a resident it still wakes;
  * the poll stamp: a guest's queue fetch stamps `last_seen` one hour back, at
    most once per window, and a resident's is untouched;
  * `/server/info user_count` and `/public/stats` count residents only;
    `dead_account_sweep` never selects a guest row;
  * `DELETE /auth/account` on a guest works and takes it out of the guest set.

Not repeated here (covered in test_guest_join_local.py): `mark_guest` failing
is 503 with no row.

Runs the real FastAPI stack in-process on a throwaway SQLite DB with Redis
db 15. NOT deployed.
Run: PYTHONPATH=. PYTHONPATH=. .venv/bin/python test_guest_policy_local.py
"""
import asyncio
import base64
import os
import re
from datetime import datetime, timedelta, timezone

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test_guest_policy.db"
os.environ["ENV"] = "dev"
os.environ["REDIS_URL"] = "redis://localhost:6379/15"
for var in ("RCQ_GUEST_ADMISSION", "RCQ_ISLAND_HOST", "RCQ_FOUNDER_UIN", "RCQ_FOUNDER_BETA_GROUP_ID"):
    os.environ.pop(var, None)
try:
    os.remove("test_guest_policy.db")
except FileNotFoundError:
    pass

import httpx  # noqa: E402
from fastapi import HTTPException  # noqa: E402
from fastapi.routing import APIRoute  # noqa: E402
from fastapi.security import HTTPAuthorizationCredentials  # noqa: E402
from sqlalchemy import func, select, text, update  # noqa: E402
from starlette.requests import Request  # noqa: E402

import app.core.redis as redis_mod  # noqa: E402
import app.routers.messages as messages_mod  # noqa: E402
import app.routers.server as server_mod  # noqa: E402
import app.routers.ws as ws_mod  # noqa: E402
from app.core import guest_policy as gp  # noqa: E402
from app.core import security  # noqa: E402
from app.core.db import SessionLocal, init_db  # noqa: E402
from app.core.redis import close_redis, get_redis  # noqa: E402
from app.main import app  # noqa: E402
from app.models.contact import Contact, ContactRequest  # noqa: E402
from app.models.device_token import DeviceToken  # noqa: E402
from app.models.group import GroupMember  # noqa: E402
from app.models.prekey import OneTimePreKey  # noqa: E402
from app.models.user import User  # noqa: E402
from app.services import contact_source, door, server_settings  # noqa: E402
from app.services.connection_manager import manager  # noqa: E402
from app.services.dead_account_sweep import _CANDIDATES  # noqa: E402
from app.services.uin import allocate_uin  # noqa: E402

D, A, R = "deny", "allow", "rule"

#: The 6.2 matrix, one row per (method, path). "rule" covers both RULE and
#: EMPTY routes: both are let through and the handler decides. Edit this table
#: in the same change as the route, and say in the review why.
EXPECTED: dict[tuple[str, str], str] = {
    # auth.py
    ("POST", "/auth/session"): A,
    ("POST", "/auth/device"): A,
    ("POST", "/auth/reissue"): A,
    ("DELETE", "/auth/account"): A,
    ("POST", "/auth/guest/settle"): A,
    # users.py
    ("GET", "/users/search"): R,            # EMPTY, and never lists guests
    ("POST", "/users/lookup"): R,           # EMPTY
    ("GET", "/users/{uin}/info"): R,
    ("PUT", "/users/me"): R,
    ("POST", "/users/me/push-token"): R,
    ("GET", "/users/me/push-health"): A,
    ("DELETE", "/users/me/push-token"): A,
    ("POST", "/users/me/capabilities"): A,
    ("GET", "/users/me/push-preferences"): A,
    ("PUT", "/users/me/push-preferences"): A,
    ("GET", "/users/me/turn-credentials"): D,
    # contacts.py
    ("GET", "/contacts"): A,
    ("POST", "/contacts/request"): D,
    ("GET", "/contacts/pending"): A,
    ("GET", "/contacts/outgoing"): A,
    ("DELETE", "/contacts/outgoing/{to_uin}"): A,
    ("POST", "/contacts/respond"): R,
    ("DELETE", "/contacts/pending/{request_id}"): A,
    ("DELETE", "/contacts/{contact_uin}"): A,
    ("POST", "/contacts/{contact_uin}/block"): A,
    # federation.py
    ("PUT", "/federation/island-record"): D,
    # groups.py
    ("POST", "/groups"): D,
    ("GET", "/groups"): A,
    ("GET", "/groups/{group_id}/preview"): A,
    ("GET", "/groups/discover"): R,         # EMPTY
    ("GET", "/groups/search"): R,           # EMPTY
    ("GET", "/groups/{group_id}"): A,
    ("POST", "/groups/{group_id}/join"): R,
    ("POST", "/groups/{group_id}/members"): D,
    ("POST", "/groups/{group_id}/guests"): D,
    ("DELETE", "/groups/{group_id}/members/{member_uin}"): A,
    ("PATCH", "/groups/{group_id}"): A,
    ("PATCH", "/groups/{group_id}/state"): A,
    ("POST", "/groups/{group_id}/members/{member_uin}/permissions"): A,
    ("POST", "/groups/{group_id}/transfer-owner"): R,
    ("DELETE", "/groups/{group_id}"): A,
    # messages.py (POST /messages/sealed has no session: n/a)
    ("POST", "/messages/group-sealed"): A,
    ("POST", "/messages/group-broadcast"): A,
    ("GET", "/messages/queue"): A,
    ("POST", "/messages/queue/ack"): A,
    ("POST", "/messages/group-log/fetch"): A,
    ("POST", "/messages/group-log/ack"): A,
    # keys.py
    ("POST", "/keys/bundle"): A,
    ("POST", "/keys/prekeys"): A,
    ("GET", "/keys/{uin}/bundle"): R,
    ("GET", "/keys/me/status"): A,
    ("POST", "/keys/devices"): A,
    ("GET", "/keys/{uin}/devices"): R,
    ("GET", "/keys/{uin}/devices/{device_id}/bundle"): R,
    ("POST", "/keys/devices/{device_id}/revoke"): A,
    ("POST", "/keys/devices/{device_id}/prekeys"): A,
    # guest_cards.py
    ("POST", "/guest-cards"): D,
    ("GET", "/guest-cards"): A,
    ("DELETE", "/guest-cards/{card_hash}"): A,
    # invites.py
    ("GET", "/invites"): A,
    ("POST", "/invites"): D,
    ("DELETE", "/invites/{invite_id}"): A,
    # residency.py
    ("POST", "/residency/redeem"): A,
    # presence.py
    ("POST", "/presence/status"): A,
    # random.py
    ("POST", "/random/queue"): D,
    ("POST", "/random/leave"): A,
    ("POST", "/random/skip"): D,
    # audio_rooms.py
    ("POST", "/audio_rooms"): D,
    ("GET", "/audio_rooms"): R,             # EMPTY
    ("POST", "/audio_rooms/join"): D,
    ("DELETE", "/audio_rooms/{room_id}/membership"): A,
    ("POST", "/audio_rooms/{room_id}/kick"): D,
    ("POST", "/audio_rooms/{room_id}/rotate_key"): D,
    ("POST", "/audio_rooms/{room_id}/members/{uin}/mute"): D,
    ("POST", "/audio_rooms/{room_id}/owner_only"): D,
    ("PATCH", "/audio_rooms/{room_id}"): D,
    ("DELETE", "/audio_rooms/{room_id}"): D,
    # reports.py
    ("POST", "/reports"): R,
    ("POST", "/reports/with_evidence"): R,
    ("GET", "/reports/mine"): A,
    ("POST", "/reports/mine/{report_id}/messages"): A,
    ("DELETE", "/reports/mine/{report_id}"): A,
    ("PATCH", "/reports/mine/{report_id}"): A,
    # sites.py
    ("GET", "/sites/mine"): A,
    ("PUT", "/sites/{name}"): D,
    ("DELETE", "/sites/{name}"): A,
    # migrate.py
    ("POST", "/account/migrate"): D,
    # uin_shop.py
    ("POST", "/uin/quote"): D,
    ("POST", "/uin/listings"): D,
    ("DELETE", "/uin/listings/{uin}"): D,
    ("GET", "/uin/listings"): R,            # EMPTY
    ("GET", "/uin/suggestions"): R,         # EMPTY
    ("GET", "/uin/mine"): A,
    ("DELETE", "/uin/mine/{uin}"): D,
    ("POST", "/uin/activate"): D,
    ("POST", "/uin/redeem"): D,
    ("POST", "/uin/purchase"): D,
    # link.py
    ("POST", "/link/{token}"): D,
    # devices.py
    ("POST", "/devices/link"): D,
    ("GET", "/devices"): A,
    ("DELETE", "/devices/me"): A,
    ("DELETE", "/devices/{device_id}"): A,
    # vault.py
    ("GET", "/vault"): A,
    ("GET", "/vault/{slot}"): A,
    ("PUT", "/vault/{slot}"): D,
    ("DELETE", "/vault/{slot}"): A,
}

#: ALLOW routes the generic probe must not call with the shared guest token,
#: because they would end it. Each is exercised on its own below.
DESTRUCTIVE = {("DELETE", "/auth/account")}

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
    except (ValueError, AttributeError):
        return None
    return detail.get("code") if isinstance(detail, dict) else None


def aware(dt):
    return dt if dt is None or dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def b64(n=32):
    return base64.b64encode(os.urandom(n)).decode()


async def clear(*patterns):
    redis = await get_redis()
    for pattern in patterns:
        keys = [k async for k in redis.scan_iter(match=pattern)]
        if keys:
            await redis.delete(*keys)


async def set_settings(**values):
    async with SessionLocal() as db:
        await server_settings.apply(db, server_settings.validate(values))
        await db.commit()
    server_settings._cache.at = -1e9


def session_dependency(dependant) -> bool:
    return dependant.call in (security.current_uin, security.current_uin_optional) or any(
        session_dependency(d) for d in dependant.dependencies
    )


def fill(path: str, gid: int) -> str:
    subs = {"group_id": str(gid), "slot": "contacts", "name": "somesite", "token": "tok",
            "card_hash": "a" * 64}
    return re.sub(r"\{(\w+)\}", lambda m: subs.get(m.group(1), "999999"), path)


async def resident(nick: str, **cols) -> tuple[int, str]:
    async with SessionLocal() as db:
        uin = await allocate_uin(db)
        db.add(User(uin=uin, nickname=nick, identity_key=b64(), signing_key=b64(),
                    call_policy="everyone", **cols))
        await db.commit()
    return uin, security.issue_token(uin, await security.uin_epoch(uin))


async def guest_row(nick: str, gid: int | None, status="proven") -> tuple[int, str]:
    async with SessionLocal() as db:
        uin = await allocate_uin(db)
        now = datetime.now(timezone.utc)
        db.add(User(uin=uin, nickname=nick, identity_key=b64(), signing_key=b64(),
                    entered_via="guest", guest_status=status, guest_since=now,
                    last_seen=now - timedelta(days=13), call_policy="everyone"))
        await db.flush()
        if gid is not None:
            db.add(GroupMember(group_id=gid, uin=uin, role="member"))
        await db.commit()
    await gp.mark_guest(uin)
    return uin, security.issue_token(uin, await security.uin_epoch(uin))


async def give_bundle(uin: int, opks: int) -> None:
    async with SessionLocal() as db:
        await db.execute(update(User).where(User.uin == uin).values(
            signal_identity_key=b64(33), signal_registration_id=7,
            signed_prekey_id=1, signed_prekey_public=b64(33), signed_prekey_signature=b64(64),
            kyber_prekey_id=1, kyber_prekey_public=b64(64), kyber_prekey_signature=b64(64),
        ))
        for i in range(opks):
            db.add(OneTimePreKey(uin=uin, prekey_id=100 + i, public_key=b64(33), device_id=None))
        await db.commit()


async def free_opks(uin: int) -> int:
    async with SessionLocal() as db:
        return await db.scalar(select(func.count()).select_from(OneTimePreKey).where(
            OneTimePreKey.uin == uin, OneTimePreKey.consumed.is_(False)))


async def user(uin):
    async with SessionLocal() as db:
        return await db.get(User, uin)


class FakeManager:
    """What `_handle_client_message` asks of the connection manager, recording
    every frame instead of sending it. Anything else is a no-op."""

    def __init__(self) -> None:
        self.sent: list[tuple[int, dict]] = []

    async def touch_device(self, uin, device_id):
        return False

    async def send(self, uin, payload, **kw):
        self.sent.append((int(uin), payload))
        return True

    async def online_devices(self, uin):
        return {"dev"}

    def __getattr__(self, name):
        async def noop(*a, **kw):
            return None

        return noop


async def main() -> int:
    await init_db()
    await (await get_redis()).flushdb()

    # ── 1. the route walk ────────────────────────────────────────────────
    print("Route walk (6.1):")
    seen: set[tuple[str, str]] = set()
    missing, wrong = [], []
    for route in app.routes:
        if not isinstance(route, APIRoute) or not session_dependency(route.dependant):
            continue
        actual = gp.route_policy(route.endpoint)
        for method in sorted(route.methods):
            key = (method, route.path)
            seen.add(key)
            want = EXPECTED.get(key)
            print(f"    {actual:5s} {method:6s} {route.path}")
            if want is None:
                missing.append(key)
            elif want != actual:
                wrong.append((key, want, actual))
    check(f"★ every session route has a guest decision in EXPECTED (missing: {missing})", not missing)
    check(f"★ every marker matches EXPECTED (wrong: {wrong})", not wrong)
    stale = sorted(set(EXPECTED) - seen)
    check(f"EXPECTED names no route that is gone or lost its session (stale: {stale})", not stale)

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:

        async def reset_limits():
            await clear("rl:*", "ceiling:*")

        # ── cast ─────────────────────────────────────────────────────────
        await set_settings(registration_policy="paid", uin_shop_enabled=True, uin_resale_enabled=True)
        O, tok_o = await resident("Zowner")
        M, tok_m = await resident("Zmember")
        X, tok_x = await resident("Zstranger")
        await reset_limits()
        r = await c.post("/groups", headers=H(tok_o), json={"name": "room", "member_uins": []})
        assert r.status_code == 201, r.text
        ROOM = r.json()["id"]
        r = await c.post("/groups", headers=H(tok_x), json={"name": "x's open room", "member_uins": []})
        assert r.status_code == 201, r.text
        async with SessionLocal() as db:
            db.add(GroupMember(group_id=ROOM, uin=M, role="member"))
            await db.commit()
        G, tok_g = await guest_row("Zguest", ROOM)

        # ── 2. probes ────────────────────────────────────────────────────
        print("\nProbes:")
        deny_bad, allow_bad, native_bad = [], [], []
        # The native probes run on a throwaway resident: with an empty body some
        # DENY routes still act on the CALLER (a burned or moved number ends its
        # session), and the residents above are needed intact afterwards.
        P, tok_p = await resident("Zprobe")
        for (method, path), policy in sorted(EXPECTED.items()):
            if (method, path) in DESTRUCTIVE:
                continue
            url = fill(path, ROOM)
            kw = {"json": {}} if method in ("POST", "PUT", "PATCH") else {}
            await reset_limits()
            r = await c.request(method, url, headers=H(tok_g), **kw)
            restricted = r.status_code == 403 and code_of(r) == "guest_restricted"
            if policy == D and not restricted:
                deny_bad.append((method, path, r.status_code, r.text[:80]))
            if policy != D and restricted:
                allow_bad.append((method, path))
            if policy == D:
                await reset_limits()
                r = await c.request(method, url, headers=H(tok_p), **kw)
                if code_of(r) == "guest_restricted":
                    native_bad.append((method, path))
                if (await c.get("/contacts", headers=H(tok_p))).status_code == 401:
                    print(f"    (note: {method} {path} with an empty body ended the caller's session)")
                    P, tok_p = await resident("Zprobe")
        check(f"★ a guest token on every DENY route -> 403 guest_restricted (not: {deny_bad})", not deny_bad)
        check(f"★ a guest token on ALLOW and RULE routes is never guest_restricted (was: {allow_bad})", not allow_bad)
        check(f"★ a native token is never guest_restricted (was: {native_bad})", not native_bad)
        check("  ... and the probes left the guest a guest", (await user(G)).guest_status == "proven")

        async def undecorated():  # stands in for any route without a marker
            return None

        req = Request({"type": "http", "endpoint": undecorated, "headers": []})

        async def optional(tok):
            try:
                return await security.current_uin_optional(
                    req, HTTPAuthorizationCredentials(scheme="Bearer", credentials=tok))
            except HTTPException as exc:
                return exc

        out = await optional(tok_g)
        check("★ current_uin_optional refuses a guest on an unmarked route (not anonymous)",
              isinstance(out, HTTPException) and out.status_code == 403)
        out_x = await optional(tok_x)
        check(f"  ... a native token passes as itself ({out_x!r})", out_x == X)
        check("  ... a broken token still reads as anonymous", await optional("junk") is None)

        # ── 3. rules ─────────────────────────────────────────────────────
        print("\nRules:")
        async with SessionLocal() as db:
            req_a = ContactRequest(from_uin=M, to_uin=G)
            req_b = ContactRequest(from_uin=O, to_uin=G)
            db.add_all([req_a, req_b])
            await db.commit()
            ra, rb = req_a.id, req_b.id
        await reset_limits()
        r = await c.post("/contacts/respond", headers=H(tok_g), json={"request_id": ra, "accept": True})
        check(f"★ respond accept=true -> 403 guest_restricted ({r.status_code})",
              r.status_code == 403 and code_of(r) == "guest_restricted")
        r = await c.post("/contacts/respond", headers=H(tok_g), json={"request_id": rb, "accept": False})
        check(f"respond accept=false -> 200 declined ({r.status_code})",
              r.status_code == 200 and r.json().get("state") == "declined")
        async with SessionLocal() as db:
            edges = await db.scalar(select(func.count()).select_from(Contact).where(
                (Contact.owner_uin == G) | (Contact.contact_uin == G)))
            pending = (await db.get(ContactRequest, ra)).state
        check("  ... no contact edge, and the refused request is still pending", edges == 0 and pending == "pending")
        async with SessionLocal() as db:
            wrote = await contact_source.add_edges(db, M, G)
            await db.commit()
            edges = await db.scalar(select(func.count()).select_from(Contact).where(
                (Contact.owner_uin == G) | (Contact.contact_uin == G)))
        check("★ add_edges with a guest on one side writes nothing", wrote is False and edges == 0)

        await reset_limits()
        r_x = await c.get(f"/users/{X}/info", headers=H(tok_g))
        r_none = await c.get("/users/88888888/info", headers=H(tok_g))
        check(f"★ info of a non-co-member -> byte-identical to a missing number ({r_x.status_code})",
              r_x.status_code == 404 and r_x.content == r_none.content)
        r = await c.get(f"/users/{M}/info", headers=H(tok_g))
        check(f"info of a co-member -> 200 ({r.status_code})", r.status_code == 200 and r.json()["uin"] == M)
        r = await c.get(f"/users/{G}/info", headers=H(tok_g))
        check(f"info of itself -> 200 with guest:true ({r.status_code})",
              r.status_code == 200 and r.json().get("guest") is True)

        r = await c.put("/users/me", headers=H(tok_g), json={"nickname": "Zrenamed", "hof_opt_in": True})
        u = await user(G)
        check(f"★ PUT /users/me applies the nickname and drops hof_opt_in ({r.status_code})",
              r.status_code == 200 and u.nickname == "Zrenamed" and not u.hof_opt_in)
        r = await c.put("/users/me", headers=H(tok_x), json={"hof_opt_in": True})
        check(f"  ... a resident's hof_opt_in still applies ({r.status_code} {r.text[:120]})",
              r.status_code == 200 and (await user(X)).hof_opt_in)

        r = await c.post("/users/me/push-token", headers=H(tok_g),
                         json={"token": "guest-token-1", "platform": "ios", "device_id": "d1"})
        async with SessionLocal() as db:
            n = await db.scalar(select(func.count()).select_from(DeviceToken).where(DeviceToken.uin == G))
        check(f"★ push-token for a guest -> 204 and no row ({r.status_code}, rows={n})", r.status_code == 204 and n == 0)

        await reset_limits()
        r = await c.post(f"/groups/{ROOM}/transfer-owner", headers=H(tok_o), json={"to_uin": G})
        check(f"★ transfer-owner to a guest -> 409 target_guest ({r.status_code})",
              r.status_code == 409 and code_of(r) == "target_guest")

        await reset_limits()
        r = await c.get("/users/search", headers=H(tok_x), params={"q": "Zrenamed"})
        check(f"★ search never lists a guest for a resident ({r.status_code} {r.text[:120]})",
              r.status_code == 200 and G not in [p["uin"] for p in r.json()])
        r = await c.get("/users/search", headers=H(tok_x), params={"q": "Zmember"})
        check("  ... while residents are still found", M in [p["uin"] for p in r.json()])
        r = await c.get("/users/search", headers=H(tok_g), params={"q": "Zmember"})
        check("search for a guest caller -> 200 []", r.status_code == 200 and r.json() == [])
        r = await c.post("/users/lookup", headers=H(tok_g), json={"uins": sorted([M, X, O])})
        check(f"lookup for a guest -> 200 empty ({r.status_code})", r.status_code == 200 and r.json() == {"users": []})

        empties = {
            "GET /groups/discover": await c.get("/groups/discover", headers=H(tok_g)),
            "GET /groups/search": await c.get("/groups/search", headers=H(tok_g), params={"q": "open room"}),
            "GET /audio_rooms": await c.get("/audio_rooms", headers=H(tok_g)),
            "GET /uin/listings": await c.get("/uin/listings", headers=H(tok_g)),
            "GET /uin/suggestions": await c.get("/uin/suggestions", headers=H(tok_g)),
        }
        bad = {k: (v.status_code, v.text[:60]) for k, v in empties.items() if v.status_code != 200 or v.json() != []}
        check(f"★ EMPTY routes answer a guest 200 [] (not: {bad})", not bad)
        r = await c.get("/groups/discover", headers=H(tok_m))
        check("  ... a resident's discover still lists rooms", r.status_code == 200 and len(r.json()) >= 1)
        await reset_limits()
        r = await c.get("/uin/suggestions", headers=H(tok_m))
        check("  ... and a resident still gets suggestions", r.status_code == 200 and len(r.json()) >= 1)

        codes = []
        for _ in range(6):
            await clear("rl:reports_*")
            r = await c.post("/reports", headers=H(tok_g),
                             json={"target_uin": M, "reason": "spam", "context": "contact"})
            codes.append((r.status_code, code_of(r)))
        check(f"★ a guest files 5 reports a day, the 6th is 429 ({codes})",
              [s for s, _ in codes[:5]] == [201] * 5 and codes[5] == (429, "rate_limited"))
        codes = []
        for _ in range(6):
            await clear("rl:reports_*")
            r = await c.post("/reports", headers=H(tok_x),
                             json={"target_uin": M, "reason": "spam", "context": "contact"})
            codes.append(r.status_code)
        check(f"  ... a resident has no such day budget ({codes})", codes == [201] * 6)

        # ── 4. keys ──────────────────────────────────────────────────────
        print("\nKeys:")
        await give_bundle(M, 3)
        await give_bundle(X, 3)
        await set_settings(closed_island=True)
        await reset_limits()
        r_x = await c.get(f"/keys/{X}/bundle", headers=H(tok_g))
        r_none = await c.get("/keys/88888888/bundle", headers=H(tok_g))
        check(f"★ closed island, non-co-member bundle -> 404 like a missing number ({r_x.status_code})",
              r_x.status_code == 404 and r_x.content == r_none.content)
        r = await c.get(f"/keys/{X}/devices", headers=H(tok_g))
        check(f"  ... device list 404 ({r.status_code})", r.status_code == 404)
        r = await c.get(f"/keys/{X}/devices/1/bundle", headers=H(tok_g))
        check(f"  ... device-1 bundle 404 ({r.status_code})", r.status_code == 404)
        check("  ... and X's prekeys are untouched", await free_opks(X) == 3)
        r = await c.get(f"/keys/{M}/bundle", headers=H(tok_g))
        check(f"★ closed island, co-member bundle -> 200 without a one-time prekey ({r.status_code})",
              r.status_code == 200 and r.json().get("one_time_prekey") is None)
        r = await c.get(f"/keys/{M}/devices/1/bundle", headers=H(tok_g))
        check(f"  ... same through the device path ({r.status_code})",
              r.status_code == 200 and r.json().get("one_time_prekey") is None)
        r = await c.get(f"/keys/{M}/devices", headers=H(tok_g))
        check(f"  ... the co-member's device list is readable ({r.status_code})", r.status_code == 200)
        check("★ ... and no prekey was consumed", await free_opks(M) == 3)
        r = await c.get(f"/users/{M}/info", headers=H(tok_g))
        check(f"closed island: info of a co-member still 200 (the room, not the door) ({r.status_code})",
              r.status_code == 200)
        r = await c.get(f"/users/{X}/info", headers=H(tok_g))
        check("closed island: info of a non-co-member 404", r.status_code == 404)
        r = await c.get(f"/keys/{M}/bundle", headers=H(tok_o))
        check("a resident session still takes a prekey on a closed island",
              r.status_code == 200 and r.json().get("one_time_prekey") is not None and await free_opks(M) == 2)
        await set_settings(closed_island=False)
        r = await c.get(f"/keys/{X}/bundle", headers=H(tok_g))
        check(f"open island: a non-co-member's bundle comes as to a stranger, no prekey ({r.status_code})",
              r.status_code == 200 and r.json().get("one_time_prekey") is None and await free_opks(X) == 3)

        async with SessionLocal() as db:
            check("★ door._is_resident is false for a guest", await door._is_resident(db, G) is False)
            check("  ... and true for a resident", await door._is_resident(db, M) is True)

        # ── 5. WebSocket frames ──────────────────────────────────────────
        print("\nWebSocket:")
        fake = FakeManager()
        real_manager, real_register = ws_mod.manager, ws_mod._register_call

        async def always_register(call_id, a, b):
            return True

        ws_mod.manager, ws_mod._register_call = fake, always_register
        try:
            async def frame(sender, msg):
                fake.sent.clear()
                await ws_mod._handle_client_message(sender, msg, device_id="dev")
                return list(fake.sent)

            sent = await frame(G, {"type": "typing", "to_uin": M, "active": True})
            check("★ typing from a guest is not relayed", all(u != M for u, _ in sent))
            sent = await frame(M, {"type": "typing", "to_uin": G, "active": True})
            check("★ typing to a guest is not relayed", all(u != G for u, _ in sent))
            sent = await frame(M, {"type": "typing", "to_uin": X, "active": True})
            check("  ... typing between residents still is", any(u == X and p["type"] == "typing" for u, p in sent))
            answer = {"type": "call_answer", "call_id": "c1", "sdp": "any text at all"}
            sent = await frame(G, {**answer, "to_uin": M})
            check("★ call_answer with an sdp from a guest is not relayed", all(u != M for u, _ in sent))
            sent = await frame(M, {**answer, "to_uin": G})
            check("★ call_answer with an sdp to a guest is not relayed", all(u != G for u, _ in sent))
            sent = await frame(M, {"type": "call_end", "call_id": "c1", "reason": "free text", "to_uin": G})
            check("  ... nor call_end with a reason", all(u != G for u, _ in sent))
            sent = await frame(M, {"type": "call_offer", "call_id": "c2", "sdp": "v=0", "to_uin": G})
            check("★ call_offer to a guest ends unavailable for the caller",
                  any(u == M and p.get("type") == "call_end" and p.get("reason") == "unavailable" for u, p in sent))
            check("  ... and reaches nobody else", all(u == M for u, _ in sent))
            sent = await frame(M, {**answer, "to_uin": X})
            check("  ... call_answer between residents is still relayed",
                  any(u == X and p["type"] == "call_answer" and p.get("sdp") for u, p in sent))
            check("_caller_allowed is false with a guest on either side",
                  not await ws_mod._caller_allowed(M, G) and not await ws_mod._caller_allowed(G, M))
        finally:
            ws_mod.manager, ws_mod._register_call = real_manager, real_register

        # ── 6. Redis down ────────────────────────────────────────────────
        print("\nRedis down:")
        saved = redis_mod.get_redis

        async def redis_down():
            raise ConnectionError("redis unreachable")

        redis_mod.get_redis = redis_down
        try:
            r_g = await c.get("/users/me/turn-credentials", headers=H(tok_g))
            r_x = await c.get("/users/me/turn-credentials", headers=H(tok_x))
        finally:
            redis_mod.get_redis = saved
        check(f"★ a guest is still refused, from the row ({r_g.status_code})",
              r_g.status_code == 403 and code_of(r_g) == "guest_restricted")
        check(f"  ... a resident is not ({r_x.status_code})", code_of(r_x) != "guest_restricted")

        # ── 7. sealed deposits wake nobody for a guest ───────────────────
        print("\nSealed deposits:")
        woken: list[tuple[str, int]] = []
        real = (messages_mod.apns_send, messages_mod.up_send, messages_mod._wake_for_sealed_call)

        async def fake_apns(uin, **kw):
            woken.append(("apns", uin))
            return 1

        async def fake_up(uin, **kw):
            woken.append(("up", uin))
            return 1

        async def fake_ring(uin, payload):
            woken.append(("ring", uin))
            return 1

        messages_mod.apns_send, messages_mod.up_send, messages_mod._wake_for_sealed_call = fake_apns, fake_up, fake_ring
        try:
            async def deposit(to, **extra):
                woken.clear()
                await reset_limits()
                return await c.post("/messages/sealed", json={"to_uin": to, "payload": b64(48),
                                                              "envelope_type": "message", **extra})

            r = await deposit(G)
            async with SessionLocal() as db:
                queued = await db.scalar(text("SELECT COUNT(*) FROM offline_messages WHERE to_uin = :u"), {"u": G})
            check(f"★ a message to a guest is queued and wakes nothing ({r.status_code}, {woken})",
                  r.status_code == 200 and queued >= 1 and not woken)
            r = await deposit(G, ring=True)
            check(f"  ... nor does a ring ({woken})", r.status_code == 200 and not woken)
            r = await deposit(M)
            check(f"  ... a message to a resident still wakes ({woken})", ("apns", M) in woken and ("up", M) in woken)
            r = await deposit(M, ring=True)
            check(f"  ... and a ring to a resident still rings ({woken})", ("ring", M) in woken)
        finally:
            messages_mod.apns_send, messages_mod.up_send, messages_mod._wake_for_sealed_call = real

        # ── 8. poll stamp ────────────────────────────────────────────────
        print("\nPoll stamp (8.3):")
        old = datetime.now(timezone.utc) - timedelta(days=30)
        async with SessionLocal() as db:
            await db.execute(update(User).where(User.uin.in_((G, X))).values(last_seen=old))
            await db.commit()
        await clear("gpoll:*")
        await reset_limits()
        r = await c.get("/messages/queue", headers=H(tok_g))
        ago = datetime.now(timezone.utc) - aware((await user(G)).last_seen)
        check(f"★ a guest's queue fetch stamps last_seen one hour back ({r.status_code}, {ago})",
              r.status_code == 200 and timedelta(minutes=50) < ago < timedelta(minutes=70))
        async with SessionLocal() as db:
            await db.execute(update(User).where(User.uin == G).values(last_seen=old))
            await db.commit()
        await c.post("/messages/group-log/fetch", headers=H(tok_g), json={})
        await c.get("/messages/queue", headers=H(tok_g))
        check("  ... at most once per window", aware((await user(G)).last_seen) < datetime.now(timezone.utc) - timedelta(days=29))
        await clear("gpoll:*")
        await reset_limits()
        r = await c.post("/messages/group-log/fetch", headers=H(tok_g), json={})
        ago = datetime.now(timezone.utc) - aware((await user(G)).last_seen)
        check(f"  ... the group-log fetch stamps too ({r.status_code})", timedelta(minutes=50) < ago < timedelta(minutes=70))
        await c.get("/messages/queue", headers=H(tok_x))
        check("  ... a resident's last_seen is not touched by it",
              aware((await user(X)).last_seen) < datetime.now(timezone.utc) - timedelta(days=29))

        # ── 9. counts and sweeps ─────────────────────────────────────────
        print("\nCounts and sweeps:")
        async with SessionLocal() as db:
            natives = await db.scalar(select(func.count(User.uin)).where(User.guest_status.is_(None)))
            everyone = await db.scalar(select(func.count(User.uin)))
        server_mod._USER_COUNT = (0.0, 0)
        served = (await c.get("/server/info")).json()["capabilities"].get("user_count")
        check(f"★ /server/info user_count counts residents only ({served} of {everyone}, natives {natives})",
              served == natives and natives < everyone)
        r = await c.get("/public/stats")
        check(f"/public/stats counts residents only ({r.json()})", r.json().get("user_count") == natives)

        long_ago = datetime.now(timezone.utc) - timedelta(days=90)
        async with SessionLocal() as db:
            dead_native, dead_guest = await allocate_uin(db), None
            db.add(User(uin=dead_native, nickname="user-dead1", identity_key=b64(), signing_key=b64(),
                        created_at=long_ago, last_seen=long_ago))
            await db.flush()
            dead_guest = await allocate_uin(db)
            db.add(User(uin=dead_guest, nickname="user-dead2", identity_key=b64(), signing_key=b64(),
                        created_at=long_ago, last_seen=long_ago, entered_via="guest",
                        guest_status="added", guest_since=long_ago))
            await db.commit()
            rows = (await db.execute(_CANDIDATES, {"cutoff": datetime.now(timezone.utc), "scan": 10_000})).all()
        picked = {int(row[0]) for row in rows}
        check("★ dead_account_sweep never selects a guest row", dead_guest not in picked)
        check("  ... while the same native row is still a candidate", dead_native in picked)

        # ── 10. burn ─────────────────────────────────────────────────────
        print("\nBurn:")
        G2, tok_g2 = await guest_row("Zburn", ROOM)
        r = await c.delete("/auth/account", headers=H(tok_g2))
        check(f"★ DELETE /auth/account on a guest -> 204 ({r.status_code})", r.status_code == 204)
        check("  ... the row is gone and the number left the guest set",
              await user(G2) is None and not await (await get_redis()).sismember(gp.GUEST_KEY, str(G2)))

    await manager.shutdown()
    await close_redis()
    try:
        os.remove("test_guest_policy.db")
    except FileNotFoundError:
        pass
    print("\n" + ("ALL PASS" if fails == 0 else f"{fails} FAILED"))
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
