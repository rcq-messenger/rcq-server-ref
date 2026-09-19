"""Local-only verification of the server half of the burn cascade (spec 2026-09-15, F2).

F2 is a client feature: the burning device walks every island it knows and, on
each, deletes with its stored token, then keeps proving the key at
`/auth/recover` and deleting whatever that resolves to until the island says
`identity_not_found`. None of that needs a new endpoint, but the loop is only
correct if the island behaves exactly this way, so this file pins it:

  * two rows with ONE key: DELETE with row A's token is 204, recover then
    resolves to row B, DELETE is 204, and recover is 404 identity_not_found,
    which is the only answer the client may count as "gone";
  * row A's token after its burn is 401 stale token (the epoch bump), so a
    retry with a stored token cannot reach a recycled number;
  * a suspended account cannot burn through this door (403);
  * a guest that owns a room takes the room and its own member row with it;
    the other members' rows go by ON DELETE CASCADE, a hard check on Postgres
    and a named KNOWN GAP line on SQLite, which never enforces it;
  * ⚠ after a signed rotation and a burn, recover with the OLD key is
    identity_not_found, not identity_rotated: the marker went with the account,
    so an offline sibling is not told to keep history its owner deleted.

Runs the real FastAPI stack in-process on a throwaway SQLite DB with Redis
db 15. NOT deployed.
Run: PYTHONPATH=. PYTHONPATH=. .venv/bin/python test_burn_recover_chain_local.py
"""
import asyncio
import base64
import os
import time
from datetime import datetime, timedelta, timezone

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test_burn_recover_chain.db"
os.environ["ENV"] = "dev"
os.environ["REDIS_URL"] = "redis://localhost:6379/15"
os.environ.pop("RCQ_ISLAND_HOST", None)
for f in ("test_burn_recover_chain.db",):
    try:
        os.remove(f)
    except FileNotFoundError:
        pass

import httpx  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat  # noqa: E402
from sqlalchemy import func, select  # noqa: E402

from app.core.db import SessionLocal, init_db  # noqa: E402
from app.core.redis import close_redis, get_redis  # noqa: E402
from app.core.security import mark_suspended  # noqa: E402
from app.main import app  # noqa: E402
from app.models.group import Group, GroupMember  # noqa: E402
from app.models.retired_signing_key import RetiredSigningKey  # noqa: E402
from app.models.user import User  # noqa: E402
from app.services import reissue_proof  # noqa: E402
from app.services.connection_manager import manager  # noqa: E402

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
        self.sk = base64.b64encode(self.sk_raw).decode()
        self.ik = base64.b64encode(self.ik_raw).decode()

    def sign(self, data: bytes) -> str:
        return base64.b64encode(self.priv.sign(data)).decode()


async def count(model, *where):
    async with SessionLocal() as db:
        return await db.scalar(select(func.count()).select_from(model).where(*where))


async def main() -> int:
    await init_db()
    await (await get_redis()).flushdb()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:

        async def register(keys: Keys, nick: str, proven: bool = False):
            body = {"nickname": nick, "identity_key": keys.ik, "signing_key": keys.sk}
            if proven:
                ch = (await c.post("/auth/register/challenge", json={"signing_key": keys.sk})).json()["challenge"]
                body.update(challenge=ch, signature=keys.sign(ch.encode()))
            r = await c.post("/auth/register", json=body)
            assert r.status_code == 201, r.text
            return r.json()["uin"], r.json()["token"]

        async def recover(keys: Keys):
            ch = (await c.post("/auth/recover/challenge", json={"signing_key": keys.sk})).json()["challenge"]
            return await c.post("/auth/recover", json={"signing_key": keys.sk, "challenge": ch, "signature": keys.sign(ch.encode())})

        print("Two rows carrying one key:")
        k = Keys()
        uin_a, tok_a = await register(k, "copy-a")
        uin_b, _ = await register(k, "copy-b", proven=True)
        # Make "first claim" unambiguous rather than a race between two inserts
        # a millisecond apart.
        async with SessionLocal() as db:
            a = await db.get(User, uin_a)
            a.created_at = a.identity_created_at = datetime.now(timezone.utc) - timedelta(days=1)
            await db.commit()
        r = await recover(k)
        check("recover resolves to the first claim, row A", r.status_code == 200 and r.json()["uin"] == uin_a)
        r = await c.delete("/auth/account", headers=H(tok_a))
        check(f"★ DELETE with row A's token -> 204 ({r.status_code})", r.status_code == 204)
        r = await c.get("/contacts/pending", headers=H(tok_a))
        check(f"★ row A's token afterwards -> 401 stale token ({r.status_code})",
              r.status_code == 401 and r.json().get("detail") == "stale token")
        r = await recover(k)
        check("★ recover now resolves to row B", r.status_code == 200 and r.json()["uin"] == uin_b)
        tok_b = r.json().get("token")
        r = await c.delete("/auth/account", headers=H(tok_b))
        check(f"★ DELETE with the recovered token -> 204 ({r.status_code})", r.status_code == 204)
        r = await recover(k)
        check(f"★ recover -> 404 identity_not_found, the only 'gone' ({r.status_code})",
              r.status_code == 404 and code_of(r) == "identity_not_found")

        print("\nSuspended:")
        ks = Keys()
        uin_s, tok_s = await register(ks, "suspended")
        async with SessionLocal() as db:
            (await db.get(User, uin_s)).is_suspended = True
            await db.commit()
        await mark_suspended(uin_s, True)
        r = await c.delete("/auth/account", headers=H(tok_s))
        check(f"★ a suspended account cannot burn -> 403 ({r.status_code})",
              r.status_code == 403 and code_of(r) == "suspended")
        check("  ... and its row is still there", await count(User, User.uin == uin_s) == 1)

        print("\nA guest that owns a room:")
        kg, km = Keys(), Keys()
        uin_g, tok_g = await register(kg, "guest-owner")
        uin_m, _ = await register(km, "member")
        async with SessionLocal() as db:
            g = Group(name="room", owner_uin=uin_g)
            db.add(g)
            await db.flush()
            gid = g.id
            db.add(GroupMember(group_id=gid, uin=uin_g, role="owner"))
            db.add(GroupMember(group_id=gid, uin=uin_m, role="member"))
            await db.commit()
        r = await c.delete("/auth/account", headers=H(tok_g))
        check(f"burn the owner -> 204 ({r.status_code})", r.status_code == 204)
        check("★ the room is gone", await count(Group, Group.id == gid) == 0)
        check("★ the owner's own member row is gone", await count(GroupMember, GroupMember.uin == uin_g) == 0)
        # ⚠ The OTHER members' rows go by `group_members.group_id ON DELETE
        # CASCADE`, which Postgres (the flagship, is2, every docker-compose
        # island) enforces and SQLite does not: this codebase never turns
        # `PRAGMA foreign_keys` on (see the note in services/report_sweep.py).
        # S1 changes nothing in the burn flow (spec F2), so on SQLite the gap is
        # printed by name rather than passed or failed; on Postgres it is a
        # hard check.
        from app.core.db import engine  # noqa: E402
        orphans = await count(GroupMember, GroupMember.group_id == gid)
        if engine.dialect.name == "postgresql":
            check("★ and every member row with it (ON DELETE CASCADE)", orphans == 0)
        else:
            print(f"  KNOWN GAP  SQLite leaves {orphans} other member row(s) of the burned "
                  "owner's room: the cascade is not enforced there")
        check("  ... the member's account is untouched", await count(User, User.uin == uin_m) == 1)

        print("\nA signed rotation, then a burn:")
        old, new = Keys(), Keys()
        uin_r, tok_r = await register(old, "rotator")
        ts, nonce = int(time.time()), os.urandom(16)
        data = reissue_proof.proof_bytes("t", uin_r, old.sk_raw, new.ik_raw, new.sk_raw, ts, nonce)
        r = await c.post("/auth/reissue", headers=H(tok_r), json={
            "identity_key": new.ik, "signing_key": new.sk, "proof_v": 1, "host": "t",
            "old_signing_key": old.sk, "ts": ts, "nonce": reissue_proof.canonical_nonce(nonce),
            "signature": old.sign(data),
        })
        check(f"signed rotation -> 200 ({r.status_code})", r.status_code == 200)
        tok_r = r.json().get("token", tok_r)
        r = await recover(old)
        check("  precondition: the old key hears identity_rotated before the burn",
              r.status_code == 404 and code_of(r) == "identity_rotated")
        r = await c.delete("/auth/account", headers=H(tok_r))
        check(f"burn with the rotated token -> 204 ({r.status_code})", r.status_code == 204)
        check("★ the marker went with the account", await count(RetiredSigningKey, RetiredSigningKey.uin == uin_r) == 0)
        r = await recover(old)
        check(f"★ recover with the OLD key -> identity_not_found, not identity_rotated ({code_of(r)})",
              r.status_code == 404 and code_of(r) == "identity_not_found")
        r = await recover(new)
        check("  ... and the new key too", r.status_code == 404 and code_of(r) == "identity_not_found")

    await manager.shutdown()
    await close_redis()
    try:
        os.remove("test_burn_recover_chain.db")
    except FileNotFoundError:
        pass
    print("\n" + ("ALL PASS" if fails == 0 else f"{fails} FAILED"))
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
