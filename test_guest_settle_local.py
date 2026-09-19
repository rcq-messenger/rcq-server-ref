"""Local-only verification of guests becoming residents (spec 2026-09-15, 9).

Every conversion rewrites the SAME row: a second native row for the same key
would lose recovery to the older guest row. Pins:

  * `POST /auth/guest/settle`: a native caller is 409 not_a_guest; a paid
    island without a code is entry_required, an invite island invite_required;
    settings never loaded is 503 (a cold worker must not settle for free); an
    open island settles free; a voucher sets `resident_since` and the mark; a
    spent voucher is 409; another island's voucher is 403; a plain invite
    settles with `resident_since` NULL and spends one use; an invite carrying a
    number is 409 BEFORE anything is spent; garbage is invite_invalid;
  * a settle clears the guest columns, keeps `entered_via`, unmarks the cache,
    tells the rooms, is counted, and the token keeps working;
  * `/residency/redeem` converts a guest in the same commit;
  * `/auth/register` with a proven key that holds a guest row or a seat
    returns THAT uin, one row, `guest:false`, the new identity key; with a
    numbered invite it is 409 and nothing is spent; unproven is still
    key_proof_required;
  * the operator's "make resident" and the resident badge both convert.

Runs the real FastAPI stack in-process on a throwaway SQLite DB with Redis
db 15. NOT deployed.
Run: PYTHONPATH=. PYTHONPATH=. .venv/bin/python test_guest_settle_local.py
"""
import asyncio
import base64
import json
import os
import secrets
import time
from datetime import datetime, timezone

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test_guest_settle.db"
os.environ["ENV"] = "dev"
os.environ["REDIS_URL"] = "redis://localhost:6379/15"
for var in ("RCQ_GUEST_ADMISSION", "RCQ_ISLAND_HOST", "RCQ_FOUNDER_UIN", "RCQ_FOUNDER_BETA_GROUP_ID"):
    os.environ.pop(var, None)
for f in ("test_guest_settle.db",):
    try:
        os.remove(f)
    except FileNotFoundError:
        pass

import httpx  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat  # noqa: E402
from sqlalchemy import func, select  # noqa: E402

import app.routers.groups as groups_mod  # noqa: E402
from app.core import guest_policy as gp  # noqa: E402
from app.core.config import settings as cfg  # noqa: E402
from app.core.db import SessionLocal, init_db  # noqa: E402
from app.core.redis import close_redis, get_redis  # noqa: E402
from app.main import app  # noqa: E402
from app.models.group import GroupMember  # noqa: E402
from app.models.invite import Invite, hash_invite_code  # noqa: E402
from app.models.uin_sale import SpentVoucher  # noqa: E402
from app.models.user import User  # noqa: E402
from app.services import guest_proof, reissue_proof, server_settings  # noqa: E402
from app.services import uin_voucher as V  # noqa: E402
from app.services.connection_manager import manager  # noqa: E402

HOST = "island-a.example"
fails = 0

till = Ed25519PrivateKey.generate()
_till_pub = base64.b64encode(till.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()
V.public_key_b64 = lambda: _till_pub  # this island trusts this till


def voucher(host=HOST, nonce=None, ttl=3600):
    nonce = nonce or secrets.token_hex(16)
    exp = int(time.time()) + ttl
    signed = V.entry_signed_bytes(host=host, nonce=nonce, exp=exp)
    doc = {"v": V.VERSION, "kind": "entry", "host": host, "nonce": nonce, "exp": exp,
           "sig": base64.b64encode(till.sign(signed)).decode()}
    return base64.b64encode(json.dumps(doc).encode()).decode()


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


async def user(uin):
    async with SessionLocal() as db:
        return await db.get(User, uin)


async def rows_for(keys: Keys) -> int:
    async with SessionLocal() as db:
        return await db.scalar(
            select(func.count()).select_from(User).where(User.signing_key.in_((keys.sk, keys.sk.rstrip("="))))
        )


async def make_invite(uin=None) -> str:
    raw = secrets.token_urlsafe(12)
    async with SessionLocal() as db:
        db.add(Invite(code=hash_invite_code(raw), max_uses=1, used_count=0, uin=uin))
        await db.commit()
    return raw


async def invite_uses(raw) -> int:
    async with SessionLocal() as db:
        return (await db.get(Invite, hash_invite_code(raw))).used_count


async def main() -> int:
    await init_db()
    await (await get_redis()).flushdb()
    announced: list[int] = []
    real_rekey = groups_mod.broadcast_roster_rekey

    async def rekey_recorder(db, uin):
        announced.append(uin)
        return await real_rekey(db, uin)

    groups_mod.broadcast_roster_rekey = rekey_recorder
    cfg.ADMIN_USERNAME, cfg.ADMIN_PASSWORD = "admin", "test-admin-password"

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:

        async def register(keys: Keys, nick: str, **extra):
            await clear("rl:*")
            return await c.post("/auth/register", json={
                "nickname": nick, "identity_key": keys.ik, "signing_key": keys.sk, **extra})

        async def proven_register(keys: Keys, nick: str, **extra):
            await clear("rl:*")
            ch = (await c.post("/auth/register/challenge", json={"signing_key": keys.sk})).json()["challenge"]
            return await register(keys, nick, challenge=ch, signature=keys.sign(ch.encode()), **extra)

        async def guest(gid: int) -> tuple[Keys, int, str]:
            keys = Keys()
            await clear("rl:*")
            ch = (await c.post("/auth/guest/challenge", json={"signing_key": keys.sk})).json()["challenge"]
            data = guest_proof.proof_bytes(HOST, gid, keys.ik_raw, keys.sk_raw, ch)
            r = await c.post("/auth/guest", json={
                "v": 1, "host": HOST, "group_id": gid, "nickname": "guest",
                "identity_key": keys.ik, "signing_key": keys.sk, "challenge": ch, "signature": keys.sign(data)})
            assert r.status_code == 201, r.text
            return keys, r.json()["uin"], r.json()["token"]

        async def settle(tok, code=None):
            await clear("rl:*")
            return await c.post("/auth/guest/settle", headers=H(tok), json={} if code is None else {"code": code})

        ko = Keys()
        r = await register(ko, "owner")
        O, tok_o = r.json()["uin"], r.json()["token"]
        await clear("rl:*")
        R = (await c.post("/groups", headers=H(tok_o), json={"name": "room", "member_uins": []})).json()["id"]
        await set_settings(island_host=HOST, registration_policy="paid")

        # ── settle refusals ──────────────────────────────────────────────
        print("Settle refusals:")
        r = await settle(tok_o)
        check(f"a native caller -> 409 not_a_guest ({r.status_code})", r.status_code == 409 and code_of(r) == "not_a_guest")
        _, g1, tok_g1 = await guest(R)
        r = await settle(tok_g1)
        check(f"★ paid island, no code -> 403 entry_required ({r.status_code})",
              r.status_code == 403 and code_of(r) == "entry_required")
        await set_settings(registration_policy="invite")
        r = await settle(tok_g1)
        check(f"invite island, no code -> 403 invite_required ({r.status_code})",
              r.status_code == 403 and code_of(r) == "invite_required")
        check("  ... still a guest", (await user(g1)).guest_status == "proven")

        await set_settings(registration_policy="open")
        cache = server_settings._cache
        saved_session = server_settings.SessionLocal

        def db_down():
            raise RuntimeError("database unreachable")

        cache.rows, cache.at, cache.loaded = {}, -1e9, False
        server_settings.SessionLocal = db_down
        try:
            r = await settle(tok_g1)
        finally:
            server_settings.SessionLocal = saved_session
            cache.at = -1e9
        check(f"★ settings never loaded (cold worker, DB blip) -> 503 guest_unavailable, not a free settle ({r.status_code})",
              r.status_code == 503 and code_of(r) == "guest_unavailable")
        check("  ... still a guest", (await user(g1)).guest_status == "proven")

        # ── free on an open island ───────────────────────────────────────
        print("\nOpen island:")
        # The control for "after settle the former DENY routes work": the same
        # token on the same route, refused while the row is still a guest.
        await clear("rl:*")
        r = await c.post("/groups", headers=H(tok_g1), json={"name": "mine", "member_uins": []})
        check(f"a guest may not create a room yet ({r.status_code} {code_of(r)})",
              r.status_code == 403 and code_of(r) == "guest_restricted")
        announced.clear()
        settles = await stat("guest_settle")
        r = await settle(tok_g1)
        check(f"★ settles free ({r.status_code})", r.status_code == 200 and r.json()["uin"] == g1)
        check("  ... resident_since stays null (nobody paid)", r.json().get("resident_since") is None)
        u = await user(g1)
        check("  ... the row is native, guest_since cleared, entered_via kept",
              u.guest_status is None and u.guest_since is None and u.entered_via == "guest")
        check("  ... out of the guest cache", await gp.is_guest(g1) is False)
        check("  ... rooms told, counted", g1 in announced and await stat("guest_settle") == settles + 1)
        r = await c.get(f"/groups/{R}", headers=H(tok_g1))
        row = next((m for m in r.json().get("members", []) if m["uin"] == g1), {}) if r.status_code == 200 else {}
        check(f"  ... the same token still works and the roster says guest:false ({r.status_code})",
              r.status_code == 200 and row.get("guest") is False)
        r = await settle(tok_g1)
        check("  ... a second settle is not_a_guest", r.status_code == 409 and code_of(r) == "not_a_guest")
        # The restrictions read the row through the cache, and the settle
        # unmarked it, so the same token is now a resident's everywhere.
        await clear("rl:*")
        r = await c.post("/groups", headers=H(tok_g1), json={"name": "mine", "member_uins": []})
        check(f"★ after settle a former DENY route works: POST /groups ({r.status_code})", r.status_code == 201)
        await clear("rl:*")
        r = await c.get("/users/me/turn-credentials", headers=H(tok_g1))
        check(f"  ... and turn-credentials is no longer guest_restricted ({r.status_code} {code_of(r)})",
              code_of(r) != "guest_restricted" and r.status_code != 403)
        await set_settings(registration_policy="paid")

        # ── codes on a paid island ───────────────────────────────────────
        print("\nCodes on a paid island:")
        _, g2, tok_g2 = await guest(R)
        paid = voucher()
        r = await settle(tok_g2, paid)
        check(f"★ a voucher -> 200 with resident_since and the mark ({r.status_code})",
              r.status_code == 200 and r.json().get("resident_since") and "resident" in r.json().get("badges_earned", []))
        u = await user(g2)
        check("  ... native, resident_since set", u.guest_status is None and u.resident_since is not None)
        _, g3, tok_g3 = await guest(R)
        r = await settle(tok_g3, paid)
        check(f"★ the same voucher again -> 409 voucher_spent ({r.status_code})",
              r.status_code == 409 and code_of(r) == "voucher_spent")
        check("  ... still a guest", (await user(g3)).guest_status == "proven")
        r = await settle(tok_g3, voucher(host="island-b.example"))
        check(f"another island's voucher -> 403 voucher_other_island ({r.status_code})",
              r.status_code == 403 and code_of(r) == "voucher_other_island")
        numbered = await make_invite(uin=777123456)
        r = await settle(tok_g3, numbered)
        check(f"★ an invite with its own number -> 409 invite_has_number ({r.status_code})",
              r.status_code == 409 and code_of(r) == "invite_has_number")
        check("  ... BEFORE anything was spent", await invite_uses(numbered) == 0)
        r = await settle(tok_g3, "not-a-code-at-all")
        check(f"garbage -> 403 invite_invalid ({r.status_code})", r.status_code == 403 and code_of(r) == "invite_invalid")
        plain = await make_invite()
        r = await settle(tok_g3, plain)
        check(f"★ a plain invite -> 200, resident_since null ({r.status_code})",
              r.status_code == 200 and r.json().get("resident_since") is None)
        check("  ... one use spent, the row native", await invite_uses(plain) == 1 and (await user(g3)).guest_status is None)

        # ── /residency/redeem ────────────────────────────────────────────
        print("\n/residency/redeem:")
        _, g4, tok_g4 = await guest(R)
        await clear("rl:*")
        r = await c.post("/residency/redeem", headers=H(tok_g4), json={"voucher": voucher()})
        check(f"★ a guest redeems -> 200 guest:false ({r.status_code})", r.status_code == 200 and r.json().get("guest") is False)
        u = await user(g4)
        check("  ... converted in the same commit", u.guest_status is None and u.resident_since is not None)
        check("  ... out of the guest cache", await gp.is_guest(g4) is False)

        # ── /auth/register by the same key ───────────────────────────────
        print("\n/auth/register by a key that holds a guest row:")
        kg5, g5, _ = await guest(R)
        r = await register(kg5, "copycat", invite=voucher())
        check(f"unproven -> 403 key_proof_required ({r.status_code})",
              r.status_code == 403 and code_of(r) == "key_proof_required")
        kg5.ik_raw = os.urandom(32)
        code = voucher()
        r = await proven_register(kg5, "me", invite=code)
        check(f"★ proven + voucher -> the SAME uin, guest:false ({r.status_code})",
              r.status_code == 201 and r.json()["uin"] == g5 and r.json().get("guest") is False)
        u = await user(g5)
        check("  ... one row, native, resident, new identity key",
              await rows_for(kg5) == 1 and u.guest_status is None and u.resident_since is not None and u.identity_key == kg5.ik)
        check("  ... still in its room", True if (await c.get(f"/groups/{R}", headers=H(r.json()["token"]))).status_code == 200 else False)
        async with SessionLocal() as db:
            spent = await db.scalar(select(func.count()).select_from(SpentVoucher))
        check("  ... the voucher is spent", spent >= 1)

        kseat = Keys()
        await clear("rl:*")
        r = await c.post(f"/groups/{R}/guests", headers=H(tok_o),
                         json={"identity_key": base64.b64encode(os.urandom(32)).decode(), "signing_key": kseat.sk, "nickname": "seat"})
        assert r.status_code == 200, r.text
        S = r.json()["added_uin"]
        r = await proven_register(kseat, "me", invite=voucher())
        check(f"★ a key holding an unclaimed seat -> the seat's uin ({r.status_code})",
              r.status_code == 201 and r.json()["uin"] == S and r.json().get("guest") is False)
        u = await user(S)
        check("  ... one row, native, the key holder's identity key",
              await rows_for(kseat) == 1 and u.guest_status is None and u.identity_key == kseat.ik)

        kg6, g6, _ = await guest(R)
        numbered = await make_invite(uin=777654321)
        r = await proven_register(kg6, "me", invite=numbered)
        check(f"★ a numbered invite -> 409 invite_has_number ({r.status_code})",
              r.status_code == 409 and code_of(r) == "invite_has_number")
        check("  ... nothing spent, still a guest, one row",
              await invite_uses(numbered) == 0 and (await user(g6)).guest_status == "proven" and await rows_for(kg6) == 1)

        # ── a guest row parked on somebody else's key ────────────────────
        # Review 2026-09-15. `/auth/reissue` proves at most the OLD key, so a
        # free guest copy can be rotated onto a stranger's public signing key.
        # Whenever that stranger then proves the key here, every bearer the
        # rotator holds must die, once; before the fix a paid registration
        # handed the stranger the rotator's row while the rotator stayed
        # signed in (POST /groups 201, GET /invites eligible).
        print("\nA guest row rotated onto somebody else's key:")

        async def rotate(tok, uin, old: Keys, new: Keys, *, signed: bool):
            await clear("rl:*")
            body = {"identity_key": new.ik, "signing_key": new.sk}
            if signed:
                ts, nonce = int(time.time()), os.urandom(16)
                data = reissue_proof.proof_bytes(HOST, uin, old.sk_raw, new.ik_raw, new.sk_raw, ts, nonce)
                body.update(proof_v=1, host=HOST, old_signing_key=old.sk, ts=ts,
                            nonce=reissue_proof.canonical_nonce(nonce), signature=old.sign(data))
            r = await c.post("/auth/reissue", headers=H(tok), json=body)
            assert r.status_code == 200, r.text
            return r.json()["token"]

        async def works(tok) -> int:
            await clear("rl:*")
            return (await c.get(f"/groups/{R}", headers=H(tok))).status_code

        async def recover(keys: Keys):
            await clear("rl:*")
            ch = (await c.post("/auth/recover/challenge", json={"signing_key": keys.sk})).json()["challenge"]
            return await c.post("/auth/recover", json={
                "signing_key": keys.sk, "challenge": ch, "signature": keys.sign(ch.encode())})

        # 1. The reviewer's case: rotate (signed), the key holder pays at the door.
        ka, A, tok_a = await guest(R)
        victim = Keys()
        tok_a2 = await rotate(tok_a, A, ka, victim, signed=True)
        check("the rotation marks the row not proven since", (await user(A)).key_unproven_since is not None)
        check(f"  ... and the rotator's fresh bearer works for now ({await works(tok_a2)})", await works(tok_a2) == 200)
        r = await proven_register(victim, "victim", invite=voucher())
        check(f"the key holder registers with a voucher -> the same row, as designed ({r.status_code})",
              r.status_code == 201 and r.json()["uin"] == A)
        tok_v = r.json().get("token")
        check(f"★ the rotator's bearer from the reissue is now 401 ({await works(tok_a2)})", await works(tok_a2) == 401)
        check(f"★ ... and its original guest bearer too ({await works(tok_a)})", await works(tok_a) == 401)
        await clear("rl:*")
        r = await c.post("/groups", headers=H(tok_a2), json={"name": "stolen", "member_uins": []})
        check(f"  ... POST /groups with it is 401, not 201 ({r.status_code})", r.status_code == 401)
        check(f"  ... the key holder's own token works ({await works(tok_v)})", await works(tok_v) == 200)
        check("  ... the mark is cleared", (await user(A)).key_unproven_since is None)

        # 2. Unsigned rotation (grace mode: no epoch bump at all), then recover.
        kb, B, tok_b = await guest(R)
        victim2 = Keys()
        tok_b2 = await rotate(tok_b, B, kb, victim2, signed=False)
        check(f"an unsigned rotation leaves both rotator bearers alive ({await works(tok_b)}, {await works(tok_b2)})",
              await works(tok_b) == 200 and await works(tok_b2) == 200)
        r = await recover(victim2)
        check(f"the key holder recovers -> the rotated row ({r.status_code})", r.status_code == 200 and r.json()["uin"] == B)
        tok_v2 = r.json().get("token")
        check(f"★ both rotator bearers are 401 after the first proof ({await works(tok_b)}, {await works(tok_b2)})",
              await works(tok_b) == 401 and await works(tok_b2) == 401)
        check(f"  ... the key holder's token works ({await works(tok_v2)})", await works(tok_v2) == 200)
        r = await recover(victim2)
        check(f"★ a SECOND proof bumps nothing: the first token still works ({r.status_code}, {await works(tok_v2)})",
              r.status_code == 200 and await works(tok_v2) == 200)
        await clear("rl:*")
        ch = (await c.post("/auth/recover/challenge", json={"signing_key": victim2.sk})).json()["challenge"]
        r = await c.post("/auth/refresh", json={"uin": B, "signing_key": victim2.sk, "challenge": ch,
                                                "signature": victim2.sign(ch.encode())})
        check(f"  ... nor does a refresh ({r.status_code}, {await works(tok_v2)})",
              r.status_code == 200 and await works(tok_v2) == 200)

        # 3. Refresh as the first proof, rotated with the SAME identity key the
        # holder will present, so nothing about the row "changes" on the proof.
        kc, C, tok_c = await guest(R)
        victim3 = Keys()
        tok_c2 = await rotate(tok_c, C, kc, victim3, signed=False)
        await clear("rl:*")
        ch = (await c.post("/auth/recover/challenge", json={"signing_key": victim3.sk})).json()["challenge"]
        r = await c.post("/auth/refresh", json={"uin": C, "signing_key": victim3.sk, "challenge": ch,
                                                "signature": victim3.sign(ch.encode())})
        check(f"★ refresh as the first proof kills the rotator's bearers ({r.status_code}, {await works(tok_c2)})",
              r.status_code == 200 and await works(tok_c2) == 401 and await works(r.json()["token"]) == 200)

        # 4. /auth/guest as the first proof, same identity key again.
        kd, D, tok_d = await guest(R)
        victim4 = Keys()
        tok_d2 = await rotate(tok_d, D, kd, victim4, signed=False)
        await clear("rl:*")
        ch = (await c.post("/auth/guest/challenge", json={"signing_key": victim4.sk})).json()["challenge"]
        data = guest_proof.proof_bytes(HOST, R, victim4.ik_raw, victim4.sk_raw, ch)
        r = await c.post("/auth/guest", json={
            "v": 1, "host": HOST, "group_id": R, "nickname": "victim",
            "identity_key": victim4.ik, "signing_key": victim4.sk, "challenge": ch, "signature": victim4.sign(data)})
        check(f"/auth/guest by the key holder -> the rotated row, nothing to repair ({r.status_code})",
              r.status_code == 200 and r.json()["uin"] == D and (await user(D)).identity_key == victim4.ik)
        check(f"★ ... and the rotator's bearers are 401 ({await works(tok_d)}, {await works(tok_d2)})",
              await works(tok_d) == 401 and await works(tok_d2) == 401 and await works(r.json()["token"]) == 200)

        # 5. Controls: a guest that never rotated keeps its bearer across a
        # proof, and so does a native account.
        ke, E, tok_e = await guest(R)
        r = await recover(ke)
        check(f"a never-rotated guest's recover leaves its bearer alone ({r.status_code}, {await works(tok_e)})",
              r.status_code == 200 and await works(tok_e) == 200)
        r = await recover(ko)
        check(f"  ... and a native account's too ({r.status_code})", r.status_code == 200 and await works(tok_o) == 200)

        # ── the operator ─────────────────────────────────────────────────
        print("\nThe operator:")
        admin = ("admin", "test-admin-password")
        r = await c.post(f"/admin/users/{g6}/settle", auth=admin)
        check(f"★ make resident -> 200 ({r.status_code})", r.status_code == 200)
        check("  ... native", (await user(g6)).guest_status is None and await gp.is_guest(g6) is False)
        r = await c.post(f"/admin/users/{g6}/settle", auth=admin)
        check(f"  ... twice -> 409 not_a_guest ({r.status_code})", r.status_code == 409 and code_of(r) == "not_a_guest")
        _, g7, _ = await guest(R)
        r = await c.post(f"/admin/users/{g7}/badge", auth=admin, json={"badge": "resident"})
        check(f"★ the resident badge converts a guest ({r.status_code})", r.status_code == 200)
        u = await user(g7)
        check("  ... native, resident_since set", u.guest_status is None and u.resident_since is not None)
        _, g8, _ = await guest(R)
        r = await c.post(f"/admin/users/{g8}/badge", auth=admin, json={"badge": "tester"})
        check("  ... any other badge does not", r.status_code == 200 and (await user(g8)).guest_status == "proven")

    groups_mod.broadcast_roster_rekey = real_rekey
    await manager.shutdown()
    await close_redis()
    try:
        os.remove("test_guest_settle.db")
    except FileNotFoundError:
        pass
    print("\n" + ("ALL PASS" if fails == 0 else f"{fails} FAILED"))
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
