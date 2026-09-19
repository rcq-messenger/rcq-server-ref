"""Local-only verification of the signed key rotation (spec 2026-09-15, F3).

`POST /auth/reissue` used to take a bearer token as the whole authorisation for
rewriting an account's keys, so a stolen token could swap in keys of its own
and lock the owner out. S1 adds an optional proof, signed by the OLD signing key
over the exact change, bound to this island and this number, with a timestamp
and a nonce. Grace mode: a missing proof still works (and is counted) until the
operator flips `reissue_require_proof`. Pins:

  * a signed rotation applies, BUMPS the epoch so every older token dies (the
    rotating caller gets a fresh one), and records the retired key;
  * the identical request again is the same-keys branch, and a replay of its
    nonce against a row put back on the old keys is 409 reissue_replayed;
  * a proof by the wrong key is 403 (never 401), an old_signing_key that is not
    the row's is 409, a ts outside 600 s is 400 with the island's `now`, a proof
    for another host is 400, a partial proof is 400 malformed, a future version
    is 400 version, a non-32-byte key is 400 bad_key, and Redis being down at
    the nonce is 503; every refusal leaves the keys and the epoch alone;
  * with island_host empty the Host header is the binding (and counted);
  * an unsigned rotation in grace applies, is counted and logged, and does NOT
    bump the epoch (older sibling clients would wipe sooner);
  * with the setting on, unsigned is 403 and the same-keys branch echoes the
    presented bearer instead of minting a session; a signed rotation still works;
  * /auth/refresh and /auth/recover answer `identity_rotated` with the uin for
    the retired key, and 200 for the new one;
  * a burn removes the marker, a number move carries it;
  * `fixtures/reissue-proof-v1.json`, the vector every client tests against,
    rebuilds byte for byte and verifies with `cryptography`;
  * `reissue_proof_v1` is advertised and the setting defaults to off.

Runs the real FastAPI stack in-process on a throwaway SQLite DB with Redis
db 15. NOT deployed.
Run: PYTHONPATH=. PYTHONPATH=. .venv/bin/python test_reissue_proof_local.py
"""
import asyncio
import base64
import hashlib
import json
import os
import time
from datetime import datetime, timezone

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test_reissue_proof.db"
os.environ["ENV"] = "dev"
os.environ["REDIS_URL"] = "redis://localhost:6379/15"
os.environ.pop("RCQ_ISLAND_HOST", None)
os.environ.pop("RCQ_REISSUE_REQUIRE_PROOF", None)
for f in ("test_reissue_proof.db",):
    try:
        os.remove(f)
    except FileNotFoundError:
        pass

import httpx  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: E402
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat  # noqa: E402
from sqlalchemy import func, select  # noqa: E402

from app.core.db import SessionLocal, init_db  # noqa: E402
from app.core.redis import close_redis, get_redis  # noqa: E402
from app.core.security import uin_epoch  # noqa: E402
from app.main import app  # noqa: E402
from app.models.retired_signing_key import RetiredSigningKey  # noqa: E402
from app.models.user import User  # noqa: E402
from app.routers import auth as auth_router  # noqa: E402
from app.routers.migrate import _perform_migration  # noqa: E402
from app.services import reissue_proof, server_settings  # noqa: E402
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
    """One identity as a client holds it: an Ed25519 signing pair and a raw
    32-byte identity key (the island never checks the X25519 half)."""

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


def proof_body(old: Keys, new: Keys, host: str, uin: int, *, ts=None, nonce=None,
               signer: Keys | None = None, old_sk_claim: str | None = None,
               wire_host: str | None = None) -> dict:
    """The request a C2 client sends. `signer`, `old_sk_claim` and `wire_host`
    exist only to build the broken variants."""
    ts = int(time.time()) if ts is None else ts
    nonce = os.urandom(16) if nonce is None else nonce
    data = reissue_proof.proof_bytes(host, uin, old.sk_raw, new.ik_raw, new.sk_raw, ts, nonce)
    return {
        "identity_key": new.ik,
        "signing_key": new.sk,
        "proof_v": 1,
        "host": wire_host if wire_host is not None else host,
        "old_signing_key": old_sk_claim if old_sk_claim is not None else old.sk,
        "ts": ts,
        "nonce": reissue_proof.canonical_nonce(nonce),
        "signature": (signer or old).sign(data),
    }


async def clear(*patterns):
    redis = await get_redis()
    for pattern in patterns:
        keys = [k async for k in redis.scan_iter(match=pattern)]
        if keys:
            await redis.delete(*keys)


async def stat(name: str) -> int:
    redis = await get_redis()
    raw = await redis.get(f"stat:{name}:{datetime.now(timezone.utc):%Y%m%d}")
    return int(raw or 0)


async def set_setting(key, value):
    async with SessionLocal() as db:
        await server_settings.apply(db, server_settings.validate({key: value}))
        await db.commit()
    server_settings._cache.at = -1e9


async def row_keys(uin):
    async with SessionLocal() as db:
        u = await db.get(User, uin)
        return (u.identity_key, u.signing_key) if u else None


async def markers_for(uin):
    async with SessionLocal() as db:
        return await db.scalar(
            select(func.count()).select_from(RetiredSigningKey).where(RetiredSigningKey.uin == uin)
        )


async def main() -> int:
    await init_db()
    # Db 15 is the throwaway Redis every local test shares; a cached epoch for
    # a number this file reuses would fail it for an unrelated reason.
    await (await get_redis()).flushdb()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:

        async def reissue(tok, body):
            # 10 an hour per account is the real limit; this file spends more.
            await clear("rl:auth_reissue:*")
            return await c.post("/auth/reissue", headers=H(tok), json=body)

        async def register(keys: Keys, nick: str):
            r = await c.post("/auth/register", json={"nickname": nick, "identity_key": keys.ik, "signing_key": keys.sk})
            assert r.status_code == 201, r.text
            return r.json()["uin"], r.json()["token"]

        async def prove(path: str, keys: Keys, **extra):
            ch = (await c.post("/auth/recover/challenge", json={"signing_key": keys.sk})).json()["challenge"]
            return await c.post(path, json={"signing_key": keys.sk, "challenge": ch, "signature": keys.sign(ch.encode()), **extra})

        async def authed(tok):
            return await c.get("/contacts/pending", headers=H(tok))

        print("Defaults:")
        check("reissue_require_proof defaults to off", await server_settings.get("reissue_require_proof") is False)
        r = await c.get("/server/info")
        check("★ /server/info advertises reissue_proof_v1", r.json()["capabilities"].get("reissue_proof_v1") is True)

        # ── 1. signed rotation, island_host empty: the Host header binds ─────
        print("\nA signed rotation (island_host empty, so the Host header binds):")
        old1, new1 = Keys(), Keys()
        u1, tok1 = await register(old1, "one")
        nonce1 = os.urandom(16)
        body1 = proof_body(old1, new1, "t", u1, nonce=nonce1)
        r = await reissue(tok1, body1)
        check(f"★ signed reissue -> 200 ({r.status_code})", r.status_code == 200)
        new_tok1 = r.json().get("token") if r.status_code == 200 else None
        check("  ... the row carries the new keys", await row_keys(u1) == (new1.ik, new1.sk))
        check("★ ... the epoch was bumped", await uin_epoch(u1) == 1)
        r = await authed(tok1)
        check(f"★ ... the old token is now 401 stale ({r.status_code})",
              r.status_code == 401 and r.json().get("detail") == "stale token")
        check("  ... the token handed back works", (await authed(new_tok1)).status_code == 200)
        check("  ... one retired-key marker for the account", await markers_for(u1) == 1)
        check("  ... counted as signed", await stat("reissue_signed") == 1)
        check("  ... and the Host-header binding was counted", await stat("reissue_host_from_header") >= 1)

        print("\nThe same request again:")
        epoch_before = await uin_epoch(u1)
        r = await reissue(new_tok1, body1)
        check(f"★ identical request with the new token -> same-keys 200 ({r.status_code})", r.status_code == 200)
        check("  ... counted as same-keys", await stat("reissue_samekeys") == 1)
        check("  ... and no second epoch bump", await uin_epoch(u1) == epoch_before)

        print("\nReplay:")
        async with SessionLocal() as db:
            u = await db.get(User, u1)
            u.identity_key, u.signing_key = old1.ik, old1.sk
            await db.commit()
        r = await reissue(new_tok1, body1)
        check(f"★ the spent nonce against a row put back on the old keys -> 409 ({r.status_code})",
              r.status_code == 409 and code_of(r) == "reissue_replayed")
        check("  ... and nothing was applied", await row_keys(u1) == (old1.ik, old1.sk))

        # ── 2. refusals, with the island's own host set ───────────────────────
        await set_setting("island_host", "island-a.example")
        print("\nRefusals (island_host = island-a.example):")
        old2, new2 = Keys(), Keys()
        u2, tok2 = await register(old2, "two")

        async def unchanged(label):
            check(f"  ... {label}: keys and epoch untouched",
                  await row_keys(u2) == (old2.ik, old2.sk) and await uin_epoch(u2) == 0)

        stranger = Keys()
        r = await reissue(tok2, proof_body(old2, new2, "island-a.example", u2, signer=stranger))
        check(f"★ signed by the wrong key -> 403 reissue_bad_signature ({r.status_code})",
              r.status_code == 403 and code_of(r) == "reissue_bad_signature")
        await unchanged("wrong key")
        check("  ★ a present-but-bad proof is refused even in grace", await server_settings.get("reissue_require_proof") is False)

        r = await reissue(tok2, proof_body(stranger, new2, "island-a.example", u2))
        check(f"old_signing_key is not the row's -> 409 reissue_old_key_mismatch ({r.status_code})",
              r.status_code == 409 and code_of(r) == "reissue_old_key_mismatch")
        await unchanged("mismatch")

        r = await reissue(tok2, proof_body(old2, new2, "island-a.example", u2, ts=int(time.time()) - 601))
        now_said = (r.json().get("detail") or {}).get("now") if r.status_code == 400 else None
        check(f"ts outside the window -> 400 reissue_clock_skew ({r.status_code})",
              r.status_code == 400 and code_of(r) == "reissue_clock_skew")
        check("  ... carrying the island's now", isinstance(now_said, int) and abs(now_said - time.time()) < 30)
        r = await reissue(tok2, proof_body(old2, new2, "island-a.example", u2, ts=int(time.time()) + 601))
        check("  ... in the future too", r.status_code == 400 and code_of(r) == "reissue_clock_skew")
        await unchanged("skew")

        r = await reissue(tok2, proof_body(old2, new2, "t", u2))
        check(f"★ Host header is NOT the binding once island_host is set -> 400 ({r.status_code})",
              r.status_code == 400 and code_of(r) == "reissue_wrong_host")

        partial = {"identity_key": new2.ik, "signing_key": new2.sk, "proof_v": 1, "host": "island-a.example"}
        r = await reissue(tok2, partial)
        check(f"a partial proof -> 400 reissue_proof_malformed ({r.status_code})",
              r.status_code == 400 and code_of(r) == "reissue_proof_malformed")
        bad_nonce = proof_body(old2, new2, "island-a.example", u2)
        bad_nonce["nonce"] = base64.b64encode(os.urandom(16)).decode()
        r = await reissue(tok2, bad_nonce)
        check("a nonce that is not 22 base64url characters -> 400 malformed",
              r.status_code == 400 and code_of(r) == "reissue_proof_malformed")
        v2 = proof_body(old2, new2, "island-a.example", u2)
        v2["proof_v"] = 2
        r = await reissue(tok2, v2)
        check("proof_v 2 -> 400 reissue_proof_version", r.status_code == 400 and code_of(r) == "reissue_proof_version")
        r = await reissue(tok2, {"identity_key": base64.b64encode(os.urandom(31)).decode(), "signing_key": new2.sk})
        check(f"a non-32-byte key -> 400 bad_key ({r.status_code})", r.status_code == 400 and code_of(r) == "bad_key")
        await unchanged("malformed")

        async def redis_down(key):
            raise ConnectionError("redis is down")

        real_claim = auth_router._claim_reissue_nonce
        auth_router._claim_reissue_nonce = redis_down
        try:
            r = await reissue(tok2, proof_body(old2, new2, "island-a.example", u2))
        finally:
            auth_router._claim_reissue_nonce = real_claim
        check(f"Redis down at the nonce -> 503 reissue_unavailable ({r.status_code})",
              r.status_code == 503 and code_of(r) == "reissue_unavailable")
        await unchanged("no replay guard")

        print("\nA proof for island A is refused on island B:")
        proof_for_a = proof_body(old2, new2, "island-a.example", u2)
        await set_setting("island_host", "island-b.example")
        r = await reissue(tok2, proof_for_a)
        check(f"★ on B -> 400 reissue_wrong_host ({r.status_code})",
              r.status_code == 400 and code_of(r) == "reissue_wrong_host")
        await unchanged("other island")
        await set_setting("island_host", "island-a.example")
        spelled = dict(proof_for_a, host="ISLAND-A.example:443")
        r = await reissue(tok2, spelled)
        check(f"★ the same proof on A, host spelled with case and :443 -> 200 ({r.status_code})",
              r.status_code == 200)
        tok2 = r.json().get("token", tok2)
        check("  ... applied", await row_keys(u2) == (new2.ik, new2.sk) and await uin_epoch(u2) == 1)

        print("\nA front alias is the same island:")
        old5, new5 = Keys(), Keys()
        u5, tok5 = await register(old5, "five")
        r = await reissue(tok5, proof_body(old5, new5, "cdn.rcq.app", u5))
        check(f"a proof bound to FRONT_ALIAS_HOSTS applies ({r.status_code})", r.status_code == 200)

        # ── 3. unsigned in grace ─────────────────────────────────────────────
        print("\nUnsigned, in grace:")
        old3, new3 = Keys(), Keys()
        u3, tok3 = await register(old3, "three")
        before = await stat("reissue_unsigned")
        r = await reissue(tok3, {"identity_key": new3.ik, "signing_key": new3.sk})
        check(f"★ unsigned reissue still works in grace ({r.status_code})", r.status_code == 200)
        check("  ... counted", await stat("reissue_unsigned") == before + 1)
        check("★ ... NO epoch bump", await uin_epoch(u3) == 0)
        check("  ... so the token it had still works", (await authed(tok3)).status_code == 200)
        check("  ... the marker is recorded all the same", await markers_for(u3) == 1)

        # ── 3b. adopting a key another account holds ─────────────────────────
        print("\nA key change onto another account's signing key:")
        s_old, victim = Keys(), Keys()
        us, toks = await register(s_old, "older")
        uv, _tokv = await register(victim, "victim")
        grab = Keys()
        grab.sk_raw = victim.sk_raw
        before = await stat("reissue_unsigned")
        r = await reissue(toks, {"identity_key": grab.ik, "signing_key": victim.sk})
        check(f"★ unsigned, onto the victim's key -> 403 key_proof_required ({r.status_code})",
              r.status_code == 403 and code_of(r) == "key_proof_required")
        check("  ... not counted as an unsigned change", await stat("reissue_unsigned") == before)
        r = await reissue(toks, {"identity_key": grab.ik, "signing_key": victim.sk.rstrip("=")})
        check("  ... the unpadded spelling too", r.status_code == 403 and code_of(r) == "key_proof_required")
        r = await reissue(toks, proof_body(s_old, grab, "island-a.example", us))
        check(f"★ signed with its OWN old key -> 403 key_proof_required ({r.status_code})",
              r.status_code == 403 and code_of(r) == "key_proof_required")
        check("  ... nothing applied, no epoch bump",
              await row_keys(us) == (s_old.ik, s_old.sk) and await uin_epoch(us) == 0)
        async with SessionLocal() as db:
            check("  ★ ... and the victim's key still leads to the victim",
                  await auth_router.uin_for_signing_key(db, victim.sk) == uv)

        print("\nThe same person's two rows here, rotating in a cascade:")
        dup_old, dup_new = Keys(), Keys()
        ua, toka = await register(dup_old, "row-a")
        ub, tokb = await register(Keys(), "row-b")
        async with SessionLocal() as db:
            u = await db.get(User, ub)
            u.identity_key, u.signing_key = dup_old.ik, dup_old.sk
            await db.commit()
        r = await reissue(toka, proof_body(dup_old, dup_new, "island-a.example", ua))
        check(f"row A rotates first (signed) -> 200 ({r.status_code})", r.status_code == 200)
        r = await reissue(tokb, {"identity_key": dup_new.ik, "signing_key": dup_new.sk})
        check(f"  row B unsigned onto A's new key -> 403 key_proof_required ({r.status_code})",
              r.status_code == 403 and code_of(r) == "key_proof_required")
        r = await reissue(tokb, proof_body(dup_old, dup_new, "island-a.example", ub))
        check(f"★ row B signed by the key A retired -> 200 ({r.status_code})", r.status_code == 200)
        check("  ... applied", await row_keys(ub) == (dup_new.ik, dup_new.sk))

        # ── 3c. open sockets after a key change ──────────────────────────────
        print("\nSockets that were open before the change:")
        order: list[tuple] = []

        class Sock:
            def __init__(self, name):
                self.name = name
                self.closed = None

            async def accept(self):
                pass

            async def send_text(self, text):
                order.append((self.name, "frame", json.loads(text).get("type")))

            async def close(self, code=1000, reason=""):
                self.closed = code
                order.append((self.name, "close", code))

        async def settle(cond, timeout=3.0):
            deadline = time.monotonic() + timeout
            while not cond() and time.monotonic() < deadline:
                await asyncio.sleep(0.02)
            await asyncio.sleep(0.1)

        k_old, k_new = Keys(), Keys()
        uk, tokk = await register(k_old, "kicked")
        thief, laptop = Sock("thief"), Sock("laptop")
        await manager.connect(uk, thief, "primary")
        await manager.connect(uk, laptop, "laptop")
        await settle(lambda: False, timeout=0.2)
        r = await reissue(tokk, proof_body(k_old, k_new, "island-a.example", uk))
        check(f"signed reissue -> 200 ({r.status_code})", r.status_code == 200)
        await settle(lambda: thief.closed is not None and laptop.closed is not None)
        check(f"★ the socket opened with the old token is closed ({thief.closed})", thief.closed == 1012)
        check(f"  ... every device of the account, not only the caller's ({laptop.closed})", laptop.closed == 1012)
        check("  ★ ... and the laptop heard vault_reset BEFORE its close",
              [e for e in order if e[0] == "laptop"][:2] == [("laptop", "frame", "vault_reset"), ("laptop", "close", 1012)])
        check("  ... the manager holds nothing for the account", uk not in manager._conns)

        u_old, u_new = Keys(), Keys()
        uu, toku = await register(u_old, "not-kicked")
        stay = Sock("stay")
        await manager.connect(uu, stay, "laptop")
        r = await reissue(toku, {"identity_key": u_new.ik, "signing_key": u_new.sk})
        check(f"an unsigned reissue -> 200 ({r.status_code})", r.status_code == 200)
        await settle(lambda: any(e[0] == "stay" for e in order))
        check("  ★ ... closes nothing: its tokens live on by design",
              stay.closed is None and uu in manager._conns)
        await manager.disconnect(uu, stay)

        # ── 4. identity_rotated ──────────────────────────────────────────────
        print("\nrefresh and recover after a rotation:")
        r = await prove("/auth/recover", old2)
        check(f"★ recover with the OLD key -> 404 identity_rotated ({r.status_code})",
              r.status_code == 404 and code_of(r) == "identity_rotated" and r.json()["detail"].get("uin") == u2)
        r = await prove("/auth/refresh", old2, uin=u2)
        check(f"★ refresh with the OLD key -> 404 identity_rotated ({r.status_code})",
              r.status_code == 404 and code_of(r) == "identity_rotated" and r.json()["detail"].get("uin") == u2)
        r = await prove("/auth/recover", new2)
        check("recover with the NEW key -> 200 on the same number", r.status_code == 200 and r.json()["uin"] == u2)
        r = await prove("/auth/refresh", new2, uin=u2)
        check("refresh with the NEW key -> 200", r.status_code == 200 and r.json()["uin"] == u2)
        r = await prove("/auth/recover", Keys())
        check("a key nobody ever held is still identity_not_found", r.status_code == 404 and code_of(r) == "identity_not_found")

        # ── 5. the switch ────────────────────────────────────────────────────
        print("\nreissue_require_proof on:")
        await set_setting("reissue_require_proof", True)
        check("the override reads back", await server_settings.get("reissue_require_proof") is True)
        newer3 = Keys()
        r = await reissue(tok3, {"identity_key": newer3.ik, "signing_key": newer3.sk})
        check(f"★ unsigned -> 403 reissue_proof_required ({r.status_code})",
              r.status_code == 403 and code_of(r) == "reissue_proof_required")
        check("  ... and nothing applied", await row_keys(u3) == (new3.ik, new3.sk))
        r = await reissue(tok3, {"identity_key": new3.ik, "signing_key": new3.sk})
        check(f"★ same keys -> 200 that ECHOES the bearer, no fresh session ({r.status_code})",
              r.status_code == 200 and r.json().get("token") == tok3)
        old4, new4 = Keys(), Keys()
        u4, tok4 = await register(old4, "four")
        r = await reissue(tok4, proof_body(old4, new4, "island-a.example", u4))
        check(f"a signed rotation still works with the switch on ({r.status_code})", r.status_code == 200)
        await set_setting("reissue_require_proof", False)
        check("  ... and switching it off is the rollback", await server_settings.get("reissue_require_proof") is False)

        # ── 6. burn and move ─────────────────────────────────────────────────
        print("\nBurn and move:")
        r = await c.delete("/auth/account", headers=H(tok3))
        check(f"burn the unsigned-rotated account ({r.status_code})", r.status_code == 204)
        check("★ the burn removed its marker", await markers_for(u3) == 0)
        r = await prove("/auth/recover", old3)
        check("  ... so the old key hears identity_not_found, which is now true",
              r.status_code == 404 and code_of(r) == "identity_not_found")

        target = 700900777
        async with SessionLocal() as db:
            user = await db.get(User, u2)
            await _perform_migration(db, user, target_uin=target)
            await db.commit()
        check("★ a move carries the marker to the new number", await markers_for(target) == 1 and await markers_for(u2) == 0)
        r = await prove("/auth/recover", old2)
        check("  ... and the old key is told the NEW number",
              r.status_code == 404 and code_of(r) == "identity_rotated" and r.json()["detail"].get("uin") == target)
        r = await prove("/auth/refresh", old2, uin=u2)
        check("  ... by refresh too, asking about the number it left",
              r.status_code == 404 and code_of(r) == "identity_rotated" and r.json()["detail"].get("uin") == target)

    # ── 7. the shared vector ────────────────────────────────────────────────
    print("\nfixtures/reissue-proof-v1.json:")
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "reissue-proof-v1.json")) as fh:
        vec = json.load(fh)
    old_sk = base64.b64decode(vec["old_signing_key"])
    data = reissue_proof.proof_bytes(
        vec["host"], vec["uin"], old_sk,
        base64.b64decode(vec["new_identity_key"]), base64.b64decode(vec["new_signing_key"]),
        vec["ts"], reissue_proof.decode_nonce(vec["nonce"]),
    )
    check("★ the bytes rebuild exactly", data.hex() == vec["bytes_hex"] and data.decode() == vec["bytes_text"])
    check("  ... no trailing newline, eight lines", not data.endswith(b"\n") and len(data.split(b"\n")) == 8)
    try:
        Ed25519PublicKey.from_public_bytes(old_sk).verify(base64.b64decode(vec["signature"]), data)
        verified = True
    except Exception:  # noqa: BLE001
        verified = False
    check("★ the signature verifies under old_signing_key with cryptography", verified)
    seed_priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(vec["old_signing_seed_hex"]))
    check("  ... the seed is that key", seed_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw) == old_sk)
    check("  ... and signing again reproduces the signature (Ed25519 is deterministic)",
          base64.b64encode(seed_priv.sign(data)).decode() == vec["signature"])
    check("  ... every listed host spelling is the same binding",
          all(reissue_proof.canonical_host(h) == vec["host"] for h in vec["host_spellings_same_binding"]))
    check("  ... and a non-443 port stays in it",
          reissue_proof.canonical_host(vec["host_with_port_example"]["input"]) == vec["host_with_port_example"]["canonical"])
    check("  ... an unpadded spelling of the key decodes to the same bytes, so it signs the same text",
          reissue_proof.decode_key32(vec["old_signing_key"].rstrip("=")) == old_sk
          and hashlib.sha256(reissue_proof.decode_key32(vec["old_signing_key"].rstrip("="))).hexdigest()
          == hashlib.sha256(old_sk).hexdigest())

    await manager.shutdown()
    await close_redis()
    try:
        os.remove("test_reissue_proof.db")
    except FileNotFoundError:
        pass
    print("\n" + ("ALL PASS" if fails == 0 else f"{fails} FAILED"))
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
