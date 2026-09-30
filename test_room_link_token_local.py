"""Local-only verification of the room link key (report #990, step 2).

A room that is open but outside the catalogue was reachable by walking ids
through the join and the preview: "unlisted" meant "not searchable", never
"needs the link". Now the share token is the key to those rooms too.

Pins:
  * a catalogue room previews and joins without `k`;
  * an unlisted room with no `k`: SOFT mode serves the full card and lets the
    join through, and counts both; HARD mode answers 404 on preview and 403
    `room_link_invalid` on join;
  * a wrong `k` is refused in hard mode, the right one opens the room;
  * the owner and an existing member are never refused;
  * guest entry (`/auth/guest`) follows the join rule;
  * reset (`POST /groups/{id}/share-token`): a member without the `members`
    permission gets 403; the owner gets a new token, the old key stops
    opening the room in hard mode, and the membership broadcast carries the
    new token;
  * `/groups/discover` shows catalogue rooms only;
  * a CLOSED room keeps its own gate (redacted card in soft mode).

Runs the real FastAPI stack in-process on a throwaway SQLite DB with Redis
db 15. NOT deployed.
Run: PYTHONPATH=. .venv/bin/python test_room_link_token_local.py
"""
import asyncio
import base64
import os
from datetime import datetime, timezone

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test_room_link_token.db"
os.environ["ENV"] = "dev"
os.environ["REDIS_URL"] = "redis://localhost:6379/15"
os.environ.setdefault("REGISTER_CEILING_PER_MINUTE", "5000")
os.environ.setdefault("REGISTER_CEILING_PER_HOUR", "5000")
for var in ("RCQ_GUEST_ADMISSION", "RCQ_ISLAND_HOST", "RCQ_REQUIRE_ROOM_LINK_TOKEN",
            "RCQ_REQUIRE_CLOSED_GROUP_TOKEN"):
    os.environ.pop(var, None)
for f in ("test_room_link_token.db",):
    try:
        os.remove(f)
    except FileNotFoundError:
        pass


def _caller_addr():
    who = os.getpid()
    return (f"10.{(who >> 8) & 0xFF}.{who & 0xFF}.{(who >> 16) % 254 + 1}", 44445)


import httpx  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat  # noqa: E402
from sqlalchemy import update  # noqa: E402

import app.routers.groups as groups_mod  # noqa: E402
from app.core.db import SessionLocal, init_db  # noqa: E402
from app.core.redis import close_redis, get_redis  # noqa: E402
from app.main import app  # noqa: E402
from app.models.group import Group  # noqa: E402
from app.services import guest_proof, server_settings  # noqa: E402

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


async def stat(name: str) -> int:
    raw = await (await get_redis()).get(f"stat:{name}:{datetime.now(timezone.utc):%Y%m%d}")
    return int(raw or 0)


async def set_settings(**values):
    async with SessionLocal() as db:
        await server_settings.apply(db, server_settings.validate(values))
        await db.commit()
    server_settings._cache.at = -1e9


async def main() -> int:
    await init_db()
    await (await get_redis()).flushdb()
    await set_settings(island_host=HOST, guest_admission="on")

    broadcasts: list[tuple[int, dict]] = []
    real_broadcast = groups_mod._broadcast_membership

    async def broadcast_recorder(group_id, members, payload, extra_uins=None):
        broadcasts.append((group_id, payload.model_dump() if hasattr(payload, "model_dump") else dict(payload)))
        return await real_broadcast(group_id, members, payload, extra_uins=extra_uins)

    groups_mod._broadcast_membership = broadcast_recorder

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app, client=_caller_addr()), base_url="http://t") as c:

        async def register(nick: str):
            await clear("rl:*")
            k = Keys()
            r = await c.post("/auth/register", json={"nickname": nick, "identity_key": k.ik, "signing_key": k.sk})
            assert r.status_code == 201, r.text
            return r.json()["uin"], r.json()["token"]

        async def room(tok, name):
            await clear("rl:*")
            r = await c.post("/groups", headers=H(tok), json={"name": name, "member_uins": []})
            assert r.status_code == 201, r.text
            return r.json()["id"]

        async def preview(gid, tok=None, k=None):
            await clear("rl:*")
            params = {"k": k} if k is not None else {}
            return await c.get(f"/groups/{gid}/preview", headers=H(tok) if tok else {}, params=params)

        async def join(gid, tok, k=None):
            await clear("rl:*")
            params = {"k": k} if k is not None else {}
            return await c.post(f"/groups/{gid}/join", headers=H(tok), params=params)

        async def leave(gid, tok, uin):
            await clear("rl:*")
            return await c.delete(f"/groups/{gid}/members/{uin}", headers=H(tok))

        async def token_of(gid, tok):
            await clear("rl:*")
            r = await c.get(f"/groups/{gid}", headers=H(tok))
            assert r.status_code == 200, r.text
            return r.json().get("share_token")

        async def guest(gid: int, k=None):
            keys = Keys()
            await clear("rl:*")
            ch = (await c.post("/auth/guest/challenge", json={"signing_key": keys.sk})).json()["challenge"]
            data = guest_proof.proof_bytes(HOST, gid, keys.ik_raw, keys.sk_raw, ch)
            body = {
                "v": 1, "host": HOST, "group_id": gid, "nickname": "guest",
                "identity_key": keys.ik, "signing_key": keys.sk, "challenge": ch, "signature": keys.sign(data)}
            if k is not None:
                body["k"] = k
            return await c.post("/auth/guest", json=body)

        OWNER, tok_o = await register("owner")
        MEMBER, tok_m = await register("member")
        S1, tok_s1 = await register("stranger-one")
        S2, tok_s2 = await register("stranger-two")

        U = await room(tok_o, "unlisted room")   # what POST /groups makes: open, not in the catalogue
        L = await room(tok_o, "catalogue room")
        C = await room(tok_o, "closed room")
        async with SessionLocal() as db:
            await db.execute(update(Group).where(Group.id == L).values(in_catalog=True))
            await db.execute(update(Group).where(Group.id == C).values(is_closed=True))
            await db.commit()
        k_u = await token_of(U, tok_o)
        check("the unlisted room has a share token", bool(k_u))
        r = await join(U, tok_m, k=k_u)
        check("the member joins with the key", r.status_code == 200)

        print("\nSoft mode (the default):")
        groups_mod._REQUIRE_ROOM_LINK_TOKEN = False
        before = await stat("room_link_preview_tokenless")
        r = await preview(U, tok_s1)
        check("a tokenless preview of an unlisted room gets the full card",
              r.status_code == 200 and r.json().get("name") == "unlisted room")
        check("and is counted", await stat("room_link_preview_tokenless") == before + 1)
        before = await stat("room_join_tokenless")
        r = await join(U, tok_s1)
        check("a tokenless join goes through", r.status_code == 200)
        check("and is counted", await stat("room_join_tokenless") == before + 1)
        await leave(U, tok_s1, S1)
        r = await preview(L, tok_s1)
        check("a catalogue room previews without a key", r.status_code == 200 and r.json().get("name") == "catalogue room")
        before = await stat("room_link_preview_tokenless")
        await preview(L, tok_s1)
        check("and is not counted", await stat("room_link_preview_tokenless") == before)
        r = await preview(C, tok_s1)
        check("a closed room still gets its redacted card", r.status_code == 200 and r.json().get("name") == "")

        print("\nDiscover:")
        await clear("rl:*")
        r = await c.get("/groups/discover", headers=H(tok_s2))
        ids = [g["id"] for g in r.json()] if r.status_code == 200 else None
        check(f"catalogue rooms only ({ids})", ids is not None and L in ids and U not in ids and C not in ids)

        print("\nHard mode:")
        groups_mod._REQUIRE_ROOM_LINK_TOKEN = True
        r = await preview(U, tok_s2)
        check("a tokenless preview is 404", r.status_code == 404)
        r = await preview(U, None)
        check("an anonymous tokenless preview is 404", r.status_code == 404)
        r = await preview(U, tok_s2, k="x" * 22)
        check("a wrong key is 404", r.status_code == 404)
        r = await preview(U, tok_s2, k=k_u)
        check("the right key opens the card", r.status_code == 200 and r.json().get("name") == "unlisted room")
        r = await preview(U, tok_m)
        check("a member needs no key", r.status_code == 200)
        r = await preview(U, tok_o)
        check("the owner needs no key", r.status_code == 200)
        r = await join(U, tok_s2)
        check("a tokenless join is 403 room_link_invalid", r.status_code == 403 and code_of(r) == "room_link_invalid")
        r = await join(U, tok_s2, k="y" * 22)
        check("a wrong key too", r.status_code == 403 and code_of(r) == "room_link_invalid")
        r = await join(U, tok_m)
        check("an existing member is never refused", r.status_code == 200)
        r = await join(L, tok_s2)
        check("a catalogue room joins without a key", r.status_code == 200)
        r = await join(U, tok_s2, k=k_u)
        check("the right key lets the stranger in", r.status_code == 200)

        print("\nGuest entry:")
        # Guests are admitted on a paid island only (guest_policy.admission_open).
        await set_settings(registration_policy="paid")
        r = await guest(U)
        check("a tokenless guest entry is 403 room_link_invalid",
              r.status_code == 403 and code_of(r) == "room_link_invalid")
        r = await guest(U, k=k_u)
        check(f"with the key the guest comes in ({r.status_code})", r.status_code == 201)
        r = await guest(L)
        check(f"a catalogue room takes a guest without a key ({r.status_code})", r.status_code == 201)

        print("\nReset:")
        await clear("rl:*")
        r = await c.post(f"/groups/{U}/share-token", headers=H(tok_m))
        check("a member without the permission gets 403", r.status_code == 403)
        broadcasts.clear()
        await clear("rl:*")
        r = await c.post(f"/groups/{U}/share-token", headers=H(tok_o))
        new_k = r.json().get("share_token") if r.status_code == 200 else None
        check("the owner gets a new token", r.status_code == 200 and new_k and new_k != k_u)
        check("the broadcast carries it",
              any(gid == U and p.get("share_token") == new_k for gid, p in broadcasts))
        r = await preview(U, tok_s1, k=k_u)
        check("the old key no longer opens the room", r.status_code == 404)
        r = await preview(U, tok_s1, k=new_k)
        check("the new one does", r.status_code == 200)
        r = await join(U, tok_s1, k=k_u)
        check("nor joins with the old key", r.status_code == 403 and code_of(r) == "room_link_invalid")
        r = await join(U, tok_s1, k=new_k)
        check("but with the new one", r.status_code == 200)
        r = await preview(U, tok_m)
        check("members keep their seat after a reset", r.status_code == 200)

    groups_mod._REQUIRE_ROOM_LINK_TOKEN = False
    await close_redis()
    print(f"\n{'ALL PASS' if fails == 0 else f'{fails} FAILED'}")
    return fails


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
