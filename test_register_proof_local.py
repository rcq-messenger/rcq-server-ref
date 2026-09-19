"""Local-only verification that registration proves the signing key.

A public signing key is public, so claiming one at registration must cost the
private half. The proof is not demanded of every caller yet (old clients are in
people's hands), but it IS demanded for the two cases the hijack needed: a key
that already belongs to somebody, and a request for a specific number.

⚠ The numbers below are deliberately ORDINARY (eight digits, high entropy).
`desired_uin` still has no floor and must never grow one — an ordinary number
is a loan and asking for your own back is what multihoming IS — but since
2026-09-01 the SCARCE stock is not handed out through this door at all: a short
or patterned number (`services/uin.is_reserved_uin` — 4242 is four digits, so
it is one) leaves only through a door somebody stands at, or to a caller who
already answers to it on another island (a signed federation home record,
`_owns_uin_elsewhere`). Proving the SIGNING KEY is not that proof: a squatter
proves their own key, which says nothing about who holds the number. So the
proof dimension this file is about has to be tested on a number the scarce rule
does not speak to, and the scarce rule gets a check of its own at the end.

Runs the real FastAPI stack in-process on a throwaway SQLite DB.
NOT part of the prod suite; NOT deployed.
Run: cd backend && PYTHONPATH=. .venv/bin/python test_register_proof_local.py
"""
import asyncio
import base64
import os

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test_register_proof.db"
os.environ["ENV"] = "dev"
# ⚠ A SCRATCH Redis namespace, and this line is why the file could look broken
# for weeks. The throwaway SQLite above is deleted on every run, but the rate
# limiter and the island-wide registration ceiling do not live in SQLite: they
# live in Redis, which is shared with the local two-island stand and with the
# previous run of this very file. Fifteen registrations later the island answers
# 503 island_busy or 429 to a perfectly good request, the FIRST check fails, and
# the file reads as "registration is broken" when nothing is. db 15 is nobody's
# product data, and `setdefault` leaves an operator free to point it elsewhere.
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/15")
# ⚠ And the island's own protections, raised for this file only. `/auth/register`
# carries three independent limits, and a file that registers a dozen accounts in
# two seconds trips all of them on its SECOND run of the hour:
#   * the island ceiling, 40/minute and 400/hour (config.REGISTER_CEILING_*),
#     read through a lambda precisely so a test may raise it (see the docstring
#     of core.rate_limit.island_ceiling);
#   * rate_limit("auth_register", 20, 3600) per caller, and
#   * the same per /24, both hardcoded on the route, which is why the caller
#     ADDRESS below is unique per run instead.
# Without this the island answers 503 island_busy or 429 to a perfectly good
# request and the file reads as "registration is broken".
os.environ.setdefault("REGISTER_CEILING_PER_MINUTE", "5000")
os.environ.setdefault("REGISTER_CEILING_PER_HOUR", "5000")

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
    # A caller address nobody else shares, and a fresh one on every run: the two
    # per-caller limits on the route are keyed by it, they live in Redis rather
    # than in the throwaway database, and 20 per hour is fewer than this file
    # spends in one pass. The subnet moves too, because one of the two limits is
    # per /24.
    who = os.getpid()
    client_ip = f"10.{(who >> 8) & 0xFF}.{who & 0xFF}.{(who >> 16) % 254 + 1}"
    transport = httpx.ASGITransport(app=app, client=(client_ip, 44444))
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
        # ⚠ An ordinary number on purpose. With `desired_uin=7` this pair passed
        # for two reasons at once — no proof AND a one-digit number the scarce
        # rule withholds from everybody — so it would have gone on passing if the
        # proof gate were deleted outright.
        ORDINARY = 27_418_596
        r = await c.post("/auth/register", json=body(keypair()[1], desired_uin=ORDINARY))
        check("★ an unproven request for a number still registers", r.status_code == 201)
        check("★ but does NOT get the number", r.json().get("uin") != ORDINARY)

        # --- With proof: both are allowed ------------------------------------
        r = await c.post("/auth/register/challenge", json={"signing_key": alice_pub})
        check("challenge endpoint -> 200", r.status_code == 200)
        ch = r.json()["challenge"]
        WANTED = 13_975_428
        r = await c.post(
            "/auth/register",
            json=body(alice_pub, challenge=ch, signature=sign(alice_sk, ch), desired_uin=WANTED),
        )
        check("★ proven owner may re-use their key AND pick a number", r.status_code == 201)
        check("and gets the number asked for", r.json().get("uin") == WANTED)

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

        # --- Proof of the KEY is not proof of the NUMBER ----------------------
        # The scarce stock (short or patterned) does not leave through this door
        # for a caller who cannot show prior tenure elsewhere, and a signature
        # over a registration challenge is not that: it proves the caller holds
        # their own key, which says nothing about who holds #4242. This is NOT a
        # floor on desired_uin — 13_975_428 above IS granted on proof, and it is
        # numerically lower than plenty of numbers the scarce rule withholds —
        # it is the scarce-stock rule and nothing else.
        SCARCE = 4242
        carol_sk, carol_pub = keypair()
        r = await c.post("/auth/register/challenge", json={"signing_key": carol_pub})
        ch = r.json()["challenge"]
        r = await c.post(
            "/auth/register",
            json=body(carol_pub, challenge=ch, signature=sign(carol_sk, ch), desired_uin=SCARCE),
        )
        check("★ a short number is not refused, it is simply not granted", r.status_code == 201)
        check("★ and proving the signing key does not buy the scarce stock",
              r.json().get("uin") != SCARCE)

        # --- A fresh key with no number asked for needs nothing --------------
        r = await c.post("/auth/register", json=body(keypair()[1]))
        check("a brand-new key with no number request still needs no proof", r.status_code == 201)

    print("\nALL REGISTRATION-PROOF CHECKS PASSED ✅" if fails == 0 else f"\n{fails} CHECK(S) FAILED ❌")
    raise SystemExit(0 if fails == 0 else 1)


asyncio.run(main())
