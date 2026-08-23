"""Local-only verification that registration proves the signing key.

A public signing key is public, so claiming one at registration must cost the
private half. The proof is not demanded of every caller yet (old clients are in
people's hands), but it IS demanded for the two cases the hijack needed: a key
that already belongs to somebody, and a request for a specific number.

Runs the real FastAPI stack in-process on a throwaway SQLite DB.
NOT part of the prod suite; NOT deployed.
Run: cd backend && PYTHONPATH=. .venv/bin/python test_register_proof_local.py
"""
import asyncio
import base64
import os

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test_register_proof.db"
os.environ["ENV"] = "dev"

for f in ("test_register_proof.db",):
    try:
        os.remove(f)
    except FileNotFoundError:
        pass

import httpx  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from app.main import app  # noqa: E402
from app.core.db import init_db  # noqa: E402

fails = 0


def check(name, cond):
    global fails
    print(f"  {'PASS' if cond else 'FAIL'}  {name}")
    if not cond:
        fails += 1


def b64(n=32):
    return base64.b64encode(os.urandom(n)).decode()


def keypair():
    """(private key object, base64 public key) — the shape the wire uses."""
    sk = Ed25519PrivateKey.generate()
    pub = sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    return sk, base64.b64encode(pub).decode()


def sign(sk, msg: str) -> str:
    return base64.b64encode(sk.sign(msg.encode())).decode()


def body(signing_key: str, **extra):
    return {"nickname": "someone", "identity_key": b64(), "signing_key": signing_key, **extra}


async def clear_limiter():
    """The limiter lives in the shared dev Redis, not in the throwaway DB, so a
    second run of this file would trip `auth_register` (20/hour per IP) and fail
    on its first check for a reason that has nothing to do with the test."""
    try:
        from app.core.redis import get_redis
        redis = await get_redis()
        for pattern in ("rl:auth_register:*", "rl:auth_register_challenge:*", "rl:auth_recover*"):
            keys = [k async for k in redis.scan_iter(match=pattern)]
            if keys:
                await redis.delete(*keys)
    except Exception as exc:  # noqa: BLE001 — no Redis is fine, the limiter opens up
        print(f"  (limiter not cleared: {exc})")


async def main():
    await init_db()
    await clear_limiter()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        alice_sk, alice_pub = keypair()

        # --- Ordinary registration, no proof: still works (old clients) ------
        r = await c.post("/auth/register", json=body(alice_pub))
        check("plain registration of a fresh key still works", r.status_code == 201)
        alice_uin = r.json()["uin"]

        # --- The impersonation case: same key, no proof ----------------------
        r = await c.post("/auth/register", json=body(alice_pub))
        check("★ re-claiming a known key without proof is refused", r.status_code == 403)
        check("and says why", r.json().get("detail", {}).get("code") == "key_proof_required")

        # --- The squatting case: a specific number, no proof -----------------
        # Not a refusal: every client in the field asks for a number when it
        # adds a backup island, so this degrades to a fresh number instead of
        # breaking multihoming for anyone who has not updated.
        r = await c.post("/auth/register", json=body(keypair()[1], desired_uin=7))
        check("★ an unproven request for a number still registers", r.status_code == 201)
        check("★ but does NOT get the number", r.json().get("uin") != 7)

        # --- With proof: both are allowed ------------------------------------
        r = await c.post("/auth/register/challenge", json={"signing_key": alice_pub})
        check("challenge endpoint -> 200", r.status_code == 200)
        ch = r.json()["challenge"]
        r = await c.post(
            "/auth/register",
            json=body(alice_pub, challenge=ch, signature=sign(alice_sk, ch), desired_uin=4242),
        )
        check("★ proven owner may re-use their key AND pick a number", r.status_code == 201)
        check("and gets the number asked for", r.json().get("uin") == 4242)

        # --- A stolen key with somebody else's signature ---------------------
        mallory_sk, _ = keypair()
        r = await c.post("/auth/register/challenge", json={"signing_key": alice_pub})
        ch = r.json()["challenge"]
        r = await c.post(
            "/auth/register",
            json=body(alice_pub, challenge=ch, signature=sign(mallory_sk, ch)),
        )
        check("★ a signature by the wrong key is refused", r.status_code == 401)
        check("and says why", r.json().get("detail", {}).get("code") == "bad_signature")

        # --- A challenge minted for a DIFFERENT key --------------------------
        bob_sk, bob_pub = keypair()
        r = await c.post("/auth/register/challenge", json={"signing_key": bob_pub})
        bob_ch = r.json()["challenge"]
        r = await c.post(
            "/auth/register",
            json=body(alice_pub, challenge=bob_ch, signature=sign(alice_sk, bob_ch)),
        )
        check("a challenge bound to another key is refused", r.status_code == 400)

        # --- A RECOVER challenge must not be spendable at registration -------
        r = await c.post("/auth/recover/challenge", json={"signing_key": alice_pub})
        rec_ch = r.json()["challenge"]
        r = await c.post(
            "/auth/register",
            json=body(alice_pub, challenge=rec_ch, signature=sign(alice_sk, rec_ch)),
        )
        check("★ a recovery challenge is not a registration challenge", r.status_code == 400)

        # --- Recovery still works end to end (nothing was broken) ------------
        r = await c.post("/auth/recover/challenge", json={"signing_key": alice_pub})
        rec_ch = r.json()["challenge"]
        r = await c.post(
            "/auth/recover",
            json={"signing_key": alice_pub, "challenge": rec_ch, "signature": sign(alice_sk, rec_ch)},
        )
        check("recovery still returns the FIRST account for the key", r.status_code == 200
              and r.json().get("uin") == alice_uin)

        # --- A fresh key with no number asked for needs nothing --------------
        r = await c.post("/auth/register", json=body(keypair()[1]))
        check("a brand-new key with no number request still needs no proof", r.status_code == 201)

    print("\nALL REGISTRATION-PROOF CHECKS PASSED ✅" if fails == 0 else f"\n{fails} CHECK(S) FAILED ❌")
    raise SystemExit(0 if fails == 0 else 1)


asyncio.run(main())
