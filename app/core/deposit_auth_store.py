"""F3 deposit-auth — redis-backed issuer key, issuance + spent-set logic.

Sits between the pure crypto (`app.core.deposit_auth`) and the HTTP router
(`app.routers.deposit_auth`). Kept fastapi-free (and the redis client is only a
type hint, never imported at runtime thanks to `from __future__ import
annotations`) so the whole issuance/redemption flow is unit-testable against a
duck-typed fake redis — see `tools/test-deposit-auth-flow.py`.
"""

from __future__ import annotations

import base64
from typing import TYPE_CHECKING

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    load_pem_private_key,
)

from app.core import deposit_auth as da

if TYPE_CHECKING:  # the real client is injected at call time; never imported here
    from redis.asyncio import Redis

# Redis key holding the island's issuer RSA private key (PEM), shared across app
# replicas so every worker signs/verifies under the same epoch. SETNX on first
# generate (first writer wins). Rotating = DEL this key (clients re-fetch /params,
# re-mint); outstanding old-epoch tokens then fail verify (soft, expected).
_ISSUER_KEY = "depauth:issuer:privkey:v1"
# Spent token validity / GC window. A token must be spent within this; the
# spent-set entry self-expires after, bounding storage.
SPENT_TTL = 14 * 24 * 3600

# In-process cache of the parsed issuer key, keyed by its PEM, so the hot deposit
# path doesn't re-parse RSA every call. Busted when the PEM in redis changes.
_cache: dict[str, RSAPrivateKey] = {}


async def issuer_key(redis: Redis) -> RSAPrivateKey:
    """The island's issuer private key, generated + persisted on first use
    (atomically via SETNX, so concurrent workers converge on one key)."""
    pem = await redis.get(_ISSUER_KEY)
    if pem is None:
        priv = da.new_issuer_key()
        new_pem = priv.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode()
        won = await redis.set(_ISSUER_KEY, new_pem, nx=True)
        pem = new_pem if won else await redis.get(_ISSUER_KEY)
    cached = _cache.get(pem)
    if cached is None:
        cached = load_pem_private_key(pem.encode(), password=None)
        _cache.clear()
        _cache[pem] = cached
    return cached


async def current_params(redis: Redis, pow_bits: int) -> dict:
    """The current epoch pubkey + PoW difficulty for `/deposit-auth/params`."""
    pub = (await issuer_key(redis)).public_key()
    return {
        "epoch_id": da.epoch_id(pub),
        "suite": "RSABSSA-SHA384-PSS-Randomized",
        "pubkey": da.public_jwk(pub),
        "pow": {"algo": "sha256-hashcash", "difficulty": pow_bits},
    }


async def sign_blinded(
    redis: Redis, epoch_id: str, blinded_b64: str, pow_nonce: str, pow_bits: int
) -> tuple[bytes | None, str | None]:
    """Issue one token: validate epoch + proof-of-work, then raw-RSA blind-sign.

    Returns (blind_sig_bytes, None) on success, or (None, reason) where reason is
    one of: stale_epoch, bad_base64, low_pow, malformed. The PoW is bound to the
    EXACT blinded value (`{epoch_id}:{blinded_b64}`), so one solve = one token and
    it can't be precomputed.
    """
    priv = await issuer_key(redis)
    if epoch_id != da.epoch_id(priv.public_key()):
        return None, "stale_epoch"
    try:
        blinded = base64.b64decode(blinded_b64)
    except Exception:
        return None, "bad_base64"
    if not da.verify_pow(f"{epoch_id}:{blinded_b64}", pow_nonce, pow_bits):
        return None, "low_pow"
    try:
        return da.blind_sign(blinded, priv), None
    except ValueError:
        return None, "malformed"


async def verify_and_consume_token(token: dict, redis: Redis, spent_ttl: int = SPENT_TTL) -> bool:
    """Verify a spent deposit token and atomically mark it spent.

    True only if the token is a valid, unspent RSA-PSS signature under the CURRENT
    epoch key. False covers a malformed token, wrong/rotated epoch, a bad signature
    (forgery), or a double-spend. Sealed sender is preserved — the server learns "a
    validly-issued token was spent", never who spent it.
    """
    try:
        epoch = str(token["epoch_id"])
        prepared = base64.b64decode(token["prepared"])
        sig = base64.b64decode(token["sig"])
    except Exception:
        return False
    pub = (await issuer_key(redis)).public_key()
    if epoch != da.epoch_id(pub):
        return False
    if not da.verify(pub, prepared, sig):
        return False
    # SETNX the spent entry: truthy = first spend, None = replay (double-spend).
    ok = await redis.set(f"depauth:spent:{epoch}:{da.token_id(prepared, sig)}", "1", nx=True, ex=spent_ttl)
    return bool(ok)
