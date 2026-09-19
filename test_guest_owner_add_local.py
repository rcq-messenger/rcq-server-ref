"""Local-only verification of owner-add by public keys (spec 2026-09-15, 5).

`POST /groups/{id}/guests` puts a contact from another island in a room here
by their public card. It replaces the legacy uin-for-key -> /auth/register ->
/members chain, which stopped at a paid door and handed the adder a session
token for somebody else's copy. Pins:

  * a plain member mints an unclaimed seat: created:true, the roster says
    invited, the row is `added` with a backdated `last_seen`, and no token is
    in the reply; the same key again reuses the seat;
  * a guest adder is 403 guest_restricted; a non-member is refused;
  * allow_guests=false stops a plain member and not the owner;
    guest_admission=off is guest_closed;
  * a native account's key follows `add_member` exactly (its English strings);
  * a proven guest: invite policy nobody -> invite_nobody, contacts with no
    shared room -> invite_contacts_only, with a shared room -> 200, and the
    per-guest room cap -> guest_group_limit;
  * a seat's fourth room -> 429 guest_add_limit scope seat; the room's mint
    budget -> 429 scope group; the per-adder limiter -> 429 rate_limited;
  * a retired key -> 409 guest_key_retired;
  * the owner's block list -> 403 blocked, on this route and on `/members`;
  * `/members` with a guest target obeys allow_guests; a native target does
    not care;
  * `/auth/guest` on a seat claims it and replaces its identity key, and the
    roster stops saying invited;
  * transfer-owner to a guest -> 409 target_guest.

Runs the real FastAPI stack in-process on a throwaway SQLite DB with Redis
db 15. NOT deployed.
Run: PYTHONPATH=. PYTHONPATH=. .venv/bin/python test_guest_owner_add_local.py
"""
import asyncio
import base64
import hashlib
import os
from datetime import datetime, timedelta, timezone

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test_guest_owner_add.db"
os.environ["ENV"] = "dev"
os.environ["REDIS_URL"] = "redis://localhost:6379/15"
for var in ("RCQ_GUEST_ADMISSION", "RCQ_ISLAND_HOST", "RCQ_FOUNDER_UIN", "RCQ_FOUNDER_BETA_GROUP_ID"):
    os.environ.pop(var, None)
for f in ("test_guest_owner_add.db",):
    try:
        os.remove(f)
    except FileNotFoundError:
        pass

import httpx  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat  # noqa: E402
from sqlalchemy import func, select, update  # noqa: E402

from app.core import guest_policy as gp  # noqa: E402
from app.core.db import SessionLocal, init_db  # noqa: E402
from app.core.redis import close_redis, get_redis  # noqa: E402
from app.main import app  # noqa: E402
from app.models.contact import Contact  # noqa: E402
from app.models.group import GroupMember  # noqa: E402
from app.models.retired_signing_key import RetiredSigningKey  # noqa: E402
from app.models.user import User  # noqa: E402
from app.services import guest_accounts, guest_proof, server_settings  # noqa: E402
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
    # Per-caller limiters only. ⚠ Not `rl:*`: the room mint budget
    # (`rl:guest_add_group:*`) and the room join budget are filled on purpose.
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
            select(func.count()).select_from(User).where(User.signing_key.in_((keys.sk, keys.sk.rstrip("="))))
        )


async def user(uin):
    async with SessionLocal() as db:
        return await db.get(User, uin)


async def is_member(gid, uin) -> bool:
    async with SessionLocal() as db:
        return await db.scalar(
            select(GroupMember.id).where(GroupMember.group_id == gid, GroupMember.uin == uin)
        ) is not None


async def set_policy(uin, policy):
    async with SessionLocal() as db:
        await db.execute(update(User).where(User.uin == uin).values(group_invite_policy=policy))
        await db.commit()


async def main() -> int:
    await init_db()
    await (await get_redis()).flushdb()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:

        async def register(keys: Keys, nick: str):
            await reset_limits()
            r = await c.post("/auth/register", json={"nickname": nick, "identity_key": keys.ik, "signing_key": keys.sk})
            assert r.status_code == 201, r.text
            return r.json()["uin"], r.json()["token"]

        async def room(tok, name, members=(), **patch):
            await reset_limits()
            r = await c.post("/groups", headers=H(tok), json={"name": name, "member_uins": []})
            assert r.status_code == 201, r.text
            gid = r.json()["id"]
            if members:
                async with SessionLocal() as db:
                    for m in members:
                        db.add(GroupMember(group_id=gid, uin=m, role="member"))
                    await db.commit()
            if patch:
                r = await c.patch(f"/groups/{gid}", headers=H(tok), json=patch)
                assert r.status_code == 200, r.text
            return gid

        async def add(tok, gid, keys: Keys, nick="friend", *, keep_limits=False):
            if not keep_limits:
                await reset_limits()
            return await c.post(f"/groups/{gid}/guests", headers=H(tok),
                                json={"identity_key": keys.ik, "signing_key": keys.sk, "nickname": nick})

        async def self_join(keys: Keys, gid: int):
            await reset_limits()
            ch = (await c.post("/auth/guest/challenge", json={"signing_key": keys.sk})).json()["challenge"]
            data = guest_proof.proof_bytes(HOST, gid, keys.ik_raw, keys.sk_raw, ch)
            return await c.post("/auth/guest", json={
                "v": 1, "host": HOST, "group_id": gid, "nickname": "guest",
                "identity_key": keys.ik, "signing_key": keys.sk, "challenge": ch, "signature": keys.sign(data),
            })

        ko, km, kx, kp = Keys(), Keys(), Keys(), Keys()
        O, tok_o = await register(ko, "owner")
        M, tok_m = await register(km, "member")
        X, tok_x = await register(kx, "outsider")
        P, tok_p = await register(kp, "other owner")
        R = await room(tok_o, "room", members=(M,))
        R2 = await room(tok_o, "no guests", members=(M,), allow_guests=False)
        await set_settings(island_host=HOST, registration_policy="paid")

        # ── a plain member mints a seat ──────────────────────────────────
        print("A plain member adds a contact from another island:")
        f1 = Keys()
        mints = await stat("guest_add_mint")
        r = await add(tok_m, R, f1)
        j = r.json() if r.status_code == 200 else {}
        check(f"★ 200 created:true ({r.status_code})", r.status_code == 200 and j.get("created") is True)
        F1 = j.get("added_uin")
        check("★ no token anywhere in the reply", "token" not in j and all("token" not in (m or {}) for m in j.get("members", [])))
        roster = {m["uin"]: m for m in j.get("members", [])}
        check("  ... the roster says guest and invited", roster.get(F1, {}).get("guest") is True and roster.get(F1, {}).get("invited") is True)
        u = await user(F1)
        check("  ... the row is an unclaimed seat, entered_via guest",
              u is not None and u.guest_status == "added" and u.entered_via == "guest" and u.guest_since is not None)
        check("  ... last_seen far past the dormant window",
              u is not None and aware(u.last_seen) < datetime.now(timezone.utc) - timedelta(days=20))
        check("  ... a member of the room, in the guest cache", await is_member(R, F1) and await gp.is_guest(F1))
        check("  ... counted as a mint", await stat("guest_add_mint") == mints + 1)
        existing = await stat("guest_add_existing")
        r = await add(tok_m, R, f1)
        check(f"the same key again -> same seat, created:false ({r.status_code})",
              r.status_code == 200 and r.json()["added_uin"] == F1 and r.json()["created"] is False)
        check("  ... one row, counted as existing", await rows_for(f1) == 1 and await stat("guest_add_existing") == existing + 1)
        unpadded = Keys()
        unpadded.priv, unpadded.sk_raw, unpadded.ik_raw = f1.priv, f1.sk_raw, f1.ik_raw
        await reset_limits()
        r = await c.post(f"/groups/{R}/guests", headers=H(tok_m),
                         json={"identity_key": f1.ik, "signing_key": f1.sk.rstrip("="), "nickname": "friend"})
        check("  ... the unpadded spelling lands on the same seat", r.status_code == 200 and r.json()["added_uin"] == F1)

        # ── who may add ──────────────────────────────────────────────────
        print("\nWho may add:")
        kg = Keys()
        r = await self_join(kg, R)
        assert r.status_code == 201, r.text
        G, tok_g = r.json()["uin"], r.json()["token"]
        stray = Keys()
        r = await add(tok_g, R, stray)
        check(f"★ a guest adder -> 403 guest_restricted ({r.status_code})",
              r.status_code == 403 and code_of(r) == "guest_restricted")
        check("  ... and no row", await rows_for(stray) == 0)
        r = await add(tok_x, R, stray)
        check(f"a non-member -> 403 ({r.status_code})", r.status_code == 403 and await rows_for(stray) == 0)

        # The island-wide ceiling is charged only by a caller that has
        # authenticated and passed the cheap checks. As a route dependency it
        # ran before `current_uin`, so anonymous calls, guest tokens and
        # non-members used up every owner-add on the island (review 2026-09-15).
        redis = await get_redis()

        async def ceiling_keys():
            return [k async for k in redis.scan_iter(match="rl:ceiling:guest_add:*")]

        await reset_limits()
        body = {"identity_key": stray.ik, "signing_key": stray.sk, "nickname": "x"}
        anon = await c.post(f"/groups/{R}/guests", json=body)
        as_guest = await c.post(f"/groups/{R}/guests", headers=H(tok_g), json=body)
        as_outsider = await c.post(f"/groups/{R}/guests", headers=H(tok_x), json=body)
        bad_key = await c.post(f"/groups/{R}/guests", headers=H(tok_m),
                               json={**body, "signing_key": "not-a-key"})
        check(f"anonymous, guest, non-member, bad key are all refused "
              f"({anon.status_code}, {as_guest.status_code}, {as_outsider.status_code}, {bad_key.status_code})",
              anon.status_code in (401, 403) and code_of(as_guest) == "guest_restricted"
              and as_outsider.status_code == 403 and bad_key.status_code == 422)
        check("★ ... and none of them spent the island's owner-add ceiling", await ceiling_keys() == [])
        r = await add(tok_m, R, f1, keep_limits=True)
        check(f"  ... while a member's real add does ({r.status_code})",
              r.status_code == 200 and len(await ceiling_keys()) == 2)
        r = await add(tok_m, R2, stray)
        check(f"★ allow_guests=false, plain member -> 403 guest_room_closed ({r.status_code})",
              r.status_code == 403 and code_of(r) == "guest_room_closed")
        r = await add(tok_o, R2, stray)
        check(f"  ... the owner may ({r.status_code})", r.status_code == 200 and r.json()["created"] is True)
        await set_settings(guest_admission="off")
        r = await add(tok_m, R, Keys())
        check(f"guest_admission=off -> 403 guest_closed ({r.status_code})",
              r.status_code == 403 and code_of(r) == "guest_closed")
        await set_settings(guest_admission="auto")

        # ── native targets ───────────────────────────────────────────────
        print("\nA native account's key:")
        r = await add(tok_m, R, kx)
        check(f"★ add_member rules: 'contacts' policy, not a contact -> 403 with the old string ({r.status_code})",
              r.status_code == 403 and r.json().get("detail") == "this user only accepts group invites from their contacts")
        await set_policy(X, "everyone")
        r = await add(tok_m, R, kx)
        check(f"  ... policy everyone -> 200, the native uin, created:false ({r.status_code})",
              r.status_code == 200 and r.json()["added_uin"] == X and r.json()["created"] is False)
        check("  ... no new row, and X is in the room", await rows_for(kx) == 1 and await is_member(R, X))

        # ── proven guest targets ─────────────────────────────────────────
        print("\nA proven guest's key:")
        R3 = await room(tok_p, "p's room")
        await set_policy(G, "nobody")
        r = await add(tok_p, R3, kg)
        check(f"policy nobody -> 403 invite_nobody ({r.status_code})",
              r.status_code == 403 and code_of(r) == "invite_nobody" and r.json()["detail"].get("message"))
        await set_policy(G, "contacts")
        r = await add(tok_p, R3, kg)
        check(f"★ contacts, no shared room -> 403 invite_contacts_only ({r.status_code})",
              r.status_code == 403 and code_of(r) == "invite_contacts_only")
        await reset_limits()
        r = await c.post(f"/groups/{R}/join", headers=H(tok_p))
        assert r.status_code == 200, r.text
        r = await add(tok_p, R3, kg)
        check(f"★ contacts, sharing a room -> 200 ({r.status_code})",
              r.status_code == 200 and r.json()["added_uin"] == G and await is_member(R3, G))
        await set_settings(guest_max_groups=2)
        R3b = await room(tok_p, "p's second room")
        r = await add(tok_p, R3b, kg)
        check(f"past guest_max_groups -> 403 guest_group_limit ({r.status_code})",
              r.status_code == 403 and code_of(r) == "guest_group_limit")
        await set_settings(guest_max_groups=50)

        # ── limits ───────────────────────────────────────────────────────
        print("\nLimits:")
        R4 = await room(tok_o, "r4")
        R5 = await room(tok_o, "r5")
        r = await add(tok_o, R2, f1)
        check(f"a seat's second room ({r.status_code})", r.status_code == 200)
        r = await add(tok_o, R4, f1)
        check(f"a seat's third room ({r.status_code})", r.status_code == 200)
        r = await add(tok_o, R5, f1)
        check(f"★ a seat's fourth room -> 429 guest_add_limit scope seat ({r.status_code})",
              r.status_code == 429 and code_of(r) == "guest_add_limit" and r.json()["detail"].get("scope") == "seat")

        saved_cap = guest_accounts.GROUP_ADD_MINTS_PER_DAY
        guest_accounts.GROUP_ADD_MINTS_PER_DAY = 1
        try:
            R6 = await room(tok_o, "r6")
            r = await add(tok_o, R6, Keys())
            check(f"the room's first mint of the day ({r.status_code})", r.status_code == 200)
            fresh = Keys()
            r = await add(tok_o, R6, fresh)
            check(f"★ over the room's mint budget -> 429 guest_add_limit scope group ({r.status_code})",
                  r.status_code == 429 and code_of(r) == "guest_add_limit" and r.json()["detail"].get("scope") == "group")
            check("  ... no row", await rows_for(fresh) == 0)
        finally:
            guest_accounts.GROUP_ADD_MINTS_PER_DAY = saved_cap

        await reset_limits()
        statuses = [(await add(tok_m, R, f1, keep_limits=True)).status_code for _ in range(11)]
        check(f"★ the per-adder limiter: ten an hour, the eleventh is 429 ({statuses[-2:]})",
              statuses[:10] == [200] * 10 and statuses[10] == 429)

        kret = Keys()
        async with SessionLocal() as db:
            db.add(RetiredSigningKey(sk_hash=hashlib.sha256(kret.sk_raw).hexdigest(), uin=X,
                                     rotated_at=datetime.now(timezone.utc)))
            await db.commit()
        r = await add(tok_m, R, kret)
        check(f"★ a retired key -> 409 guest_key_retired ({r.status_code})",
              r.status_code == 409 and code_of(r) == "guest_key_retired" and await rows_for(kret) == 0)

        # ── blocks and /members ──────────────────────────────────────────
        print("\nBlocks and /members:")
        R7 = await room(tok_o, "r7", members=(M,))
        async with SessionLocal() as db:
            db.add(Contact(owner_uin=O, contact_uin=G, blocked=True))
            await db.commit()
        await set_policy(G, "everyone")
        r = await add(tok_m, R7, kg)
        check(f"the owner blocked the guest -> 403 blocked ({r.status_code})",
              r.status_code == 403 and code_of(r) == "blocked" and r.json()["detail"].get("message"))
        await reset_limits()
        r = await c.post(f"/groups/{R7}/members", headers=H(tok_m), json={"uin": G})
        check(f"  ... through /members too ({r.status_code})", r.status_code == 403 and code_of(r) == "blocked")
        await reset_limits()
        r = await c.post(f"/groups/{R2}/members", headers=H(tok_m), json={"uin": F1})
        check(f"/members for a guest ALREADY in the room is a no-op 200 ({r.status_code})",
              r.status_code == 200 and await is_member(R2, F1))
        kseat2 = Keys()
        r = await add(tok_o, R4, kseat2)
        S2 = r.json()["added_uin"]
        await reset_limits()
        r = await c.post(f"/groups/{R2}/members", headers=H(tok_m), json={"uin": S2})
        check(f"  ... (a seat not yet in R2) -> 403 guest_room_closed ({r.status_code})",
              r.status_code == 403 and code_of(r) == "guest_room_closed" and not await is_member(R2, S2))
        await reset_limits()
        r = await c.post(f"/groups/{R2}/members", headers=H(tok_m), json={"uin": X})
        check(f"  ... a native target does not care about allow_guests ({r.status_code})", r.status_code == 200)

        # ── the room's ceiling and daily budget ──────────────────────────
        # Owner-add fills a room with new guest rows exactly as self-join does,
        # so the same two room controls (8.2) bind it: the member ceiling that
        # keeps a post under the payload cap, and the per-room daily budget.
        print("\nThe room's ceiling and daily budget:")
        R9 = await room(tok_o, "r9", members=(M,))
        await set_settings(guest_room_member_ceiling=2)
        full = Keys()
        r = await add(tok_o, R9, full)
        check(f"★ a room at the member ceiling -> 403 guest_room_full ({r.status_code} {code_of(r)})",
              r.status_code == 403 and code_of(r) == "guest_room_full")
        check("  ... and no row", await rows_for(full) == 0)
        await set_settings(guest_room_member_ceiling=3500, guest_room_joins_per_day=1)
        R10 = await room(tok_o, "r10")
        r = await add(tok_o, R10, Keys())
        check(f"the room's first new guest of the day ({r.status_code})", r.status_code == 200)
        over = Keys()
        r = await add(tok_o, R10, over)
        check(f"★ the next one -> 429 guest_room_limit ({r.status_code} {code_of(r)})",
              r.status_code == 429 and code_of(r) == "guest_room_limit")
        check("  ... with Retry-After, and no row",
              int(r.headers.get("Retry-After", "0")) >= 1 and await rows_for(over) == 0)
        await set_settings(guest_room_joins_per_day=200)

        # ── what the island keeps for a seat ─────────────────────────────
        # 8.3: a seat is minted with `last_seen` far behind the dormant window,
        # so group CONTENT is not stored for somebody who may never turn up,
        # while sender-key material (cls 2) is kept for every recipient, so a
        # seat that is claimed later is not left unable to read the room. The
        # claim stamps `last_seen` an hour back, and from then on content is
        # stored like for anyone else.
        print("\nWhat the island keeps for an unclaimed seat:")
        from app.models.group import OfflineGroupMessage

        R11 = await room(tok_o, "r11", members=(M,))
        kz = Keys()
        r = await add(tok_o, R11, kz)
        assert r.status_code == 200, r.text
        Z = r.json()["added_uin"]

        async def deposit(envelope_type: str):
            blob = lambda: base64.b64encode(os.urandom(64)).decode()  # noqa: E731
            return await c.post("/messages/group-sealed", json={
                "group_id": R11, "envelope_type": envelope_type,
                "payloads": [{"to_uin": Z, "payload": blob()}, {"to_uin": M, "payload": blob()}],
            })

        async def stored(uin: int, envelope_type: str) -> int:
            async with SessionLocal() as db:
                return await db.scalar(select(func.count()).select_from(OfflineGroupMessage).where(
                    OfflineGroupMessage.to_uin == uin, OfflineGroupMessage.envelope_type == envelope_type))

        r1, r2 = await deposit("skdm"), await deposit("message")
        check(f"both deposits accepted ({r1.status_code}, {r2.status_code})", r1.status_code == 200 and r2.status_code == 200)
        check("★ the seat is stored the skdm", await stored(Z, "skdm") == 1)
        check("★ ... and NOT the message", await stored(Z, "message") == 0)
        check("  ... while a resident member gets both", await stored(M, "skdm") == 1 and await stored(M, "message") == 1)
        await reset_limits()
        ch = (await c.post("/auth/recover/challenge", json={"signing_key": kz.sk})).json()["challenge"]
        r = await c.post("/auth/recover", json={"signing_key": kz.sk, "challenge": ch, "signature": kz.sign(ch.encode())})
        check(f"recover claims the seat ({r.status_code})",
              r.status_code == 200 and r.json()["uin"] == Z and (await user(Z)).guest_status == "proven")
        r = await deposit("message")
        check(f"★ after the claim a message IS stored for it ({r.status_code})",
              r.status_code == 200 and await stored(Z, "message") == 1)

        # ── the seat is claimed ──────────────────────────────────────────
        print("\nThe contact taps the link:")
        r = await self_join(f1, R)
        check(f"★ /auth/guest on the seat -> 200, the seat's uin ({r.status_code})",
              r.status_code == 200 and r.json()["uin"] == F1 and r.json()["created"] is False)
        u = await user(F1)
        check("  ... proven, identity key is the proven one", u.guest_status == "proven" and u.identity_key == f1.ik)
        r = await c.get(f"/groups/{R}", headers=H(tok_o))
        row = next((m for m in r.json()["members"] if m["uin"] == F1), {})
        check("  ... the roster no longer says invited", row.get("guest") is True and row.get("invited") is False)

        await reset_limits()
        r = await c.post(f"/groups/{R}/transfer-owner", headers=H(tok_o), json={"to_uin": G})
        check(f"★ transfer-owner to a guest -> 409 target_guest ({r.status_code})",
              r.status_code == 409 and code_of(r) == "target_guest")

    await manager.shutdown()
    await close_redis()
    try:
        os.remove("test_guest_owner_add.db")
    except FileNotFoundError:
        pass
    print("\n" + ("ALL PASS" if fails == 0 else f"{fails} FAILED"))
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
