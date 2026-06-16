#!/usr/bin/env python3
"""End-to-end proof of the F3 deposit-auth issuance + redemption FLOW.

Drives the REAL redis-backed logic (`app.core.deposit_auth_store`: issuer_key /
current_params / sign_blinded / verify_and_consume_token — the exact code the
HTTP router and the /messages/sealed gate call) against a duck-typed fake redis.
A client mints a token using ONLY the published params (n, e, difficulty), the
island issues it, the client unblinds, the island verifies + consumes it. Proves:
issue -> spend -> double-spend reject -> forgery/tamper reject -> stale-epoch
reject -> PoW gate -> issuer-key persistence.

Run:  python3 tools/test-deposit-auth-flow.py   (needs `cryptography`)
"""
import asyncio
import base64
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers  # noqa: E402

from app.core import deposit_auth as da  # noqa: E402
from app.core import deposit_auth_store as store  # noqa: E402

POW_BITS = 12  # low for a fast test; prod default is 20

OK = "\033[32mPASS\033[0m"
BAD = "\033[31mFAIL\033[0m"
failures = 0


def check(name: str, cond: bool) -> None:
    global failures
    print(f"  [{OK if cond else BAD}] {name}")
    if not cond:
        failures += 1


class FakeRedis:
    """Minimal async redis: get + set(nx, ex). Enough for issuer key + spent-set."""

    def __init__(self) -> None:
        self.kv: dict[str, str] = {}

    async def get(self, k: str):
        return self.kv.get(k)

    async def set(self, k: str, v: str, nx: bool = False, ex: int | None = None):
        if nx and k in self.kv:
            return None
        self.kv[k] = v
        return True


def _pub_from_params(p: dict):
    pad = "=" * (-len(p["pubkey"]["n"]) % 4)
    n = int.from_bytes(base64.urlsafe_b64decode(p["pubkey"]["n"] + pad), "big")
    return RSAPublicNumbers(p["pubkey"]["e"], n).public_key(), n


def _mint(p: dict, n: int, e: int, pow_bits: int):
    """Client side: build a token request from the published params."""
    msg = da.new_token_msg()
    prepared = da.prepare(msg)
    blinded, blind_inv = da.blind(n, e, prepared)
    blinded_b64 = base64.b64encode(blinded).decode()
    nonce = da.solve_pow(f"{p['epoch_id']}:{blinded_b64}", pow_bits)
    return prepared, blind_inv, blinded_b64, nonce


def _token(epoch_id, prepared, sig):
    return {
        "epoch_id": epoch_id,
        "prepared": base64.b64encode(prepared).decode(),
        "sig": base64.b64encode(sig).decode(),
    }


async def main() -> int:
    store._cache.clear()
    print("F3 deposit-auth flow proof (real store + fake redis)\n")
    redis = FakeRedis()

    # ── happy path: params -> mint -> issue -> finalize -> spend ──────────────
    print("Issue + redeem:")
    p = await store.current_params(redis, POW_BITS)
    pub, n = _pub_from_params(p)
    e = p["pubkey"]["e"]
    check("params advertise a 2048-bit modulus + epoch + difficulty",
          n.bit_length() == 2048 and len(p["epoch_id"]) == 16 and p["pow"]["difficulty"] == POW_BITS)

    prepared, blind_inv, blinded_b64, nonce = _mint(p, n, e, POW_BITS)
    blind_sig, reason = await store.sign_blinded(redis, p["epoch_id"], blinded_b64, nonce, POW_BITS)
    check("issuer accepts a PoW-valid request", reason is None and blind_sig is not None)
    sig = da.finalize(blind_sig, blind_inv, pub, prepared)
    token = _token(p["epoch_id"], prepared, sig)
    check("first deposit with the token is accepted", await store.verify_and_consume_token(token, redis))
    check("replay of the SAME token is rejected (double-spend)",
          not await store.verify_and_consume_token(token, redis))

    # ── PoW gate ──────────────────────────────────────────────────────────────
    print("\nProof-of-work gate:")
    prepared2, inv2, blinded2_b64, _ = _mint(p, n, e, POW_BITS)
    _, reason_lowpow = await store.sign_blinded(redis, p["epoch_id"], blinded2_b64, "0", POW_BITS)
    check("issuer rejects a request with no/low proof-of-work", reason_lowpow == "low_pow")
    # too-high difficulty: the same nonce no longer satisfies a harder target
    nonce2 = da.solve_pow(f"{p['epoch_id']}:{blinded2_b64}", POW_BITS)
    _, reason_harder = await store.sign_blinded(redis, p["epoch_id"], blinded2_b64, nonce2, POW_BITS + 12)
    check("raising the difficulty knob rejects an old-difficulty solution", reason_harder == "low_pow")

    # ── stale epoch ─────────────────────────────────────────────────────────────
    print("\nEpoch binding:")
    _, reason_epoch = await store.sign_blinded(redis, "deadbeefdeadbeef", blinded2_b64, nonce2, POW_BITS)
    check("issuer rejects a stale/unknown epoch", reason_epoch == "stale_epoch")

    # ── forgery + tamper at redemption ──────────────────────────────────────────
    print("\nForgery + tamper at redemption:")
    forged = _token(p["epoch_id"], prepared2, os.urandom(len(sig)))
    check("a forged signature is rejected", not await store.verify_and_consume_token(forged, redis))
    bad = bytearray(sig); bad[5] ^= 0x01
    check("a tampered signature is rejected", not await store.verify_and_consume_token(_token(p["epoch_id"], prepared, bytes(bad)), redis))
    check("a valid sig under a WRONG epoch id is rejected",
          not await store.verify_and_consume_token(_token("deadbeefdeadbeef", prepared, sig), redis))
    check("a malformed token (missing fields) is rejected",
          not await store.verify_and_consume_token({"epoch_id": p["epoch_id"]}, redis))

    # ── a fresh, independent token also works (issuer key is stable) ─────────────
    print("\nIssuer key persistence + a second token:")
    prepared3, inv3, blinded3_b64, nonce3 = _mint(p, n, e, POW_BITS)
    bs3, _ = await store.sign_blinded(redis, p["epoch_id"], blinded3_b64, nonce3, POW_BITS)
    sig3 = da.finalize(bs3, inv3, pub, prepared3)
    check("a distinct second token is accepted", await store.verify_and_consume_token(_token(p["epoch_id"], prepared3, sig3), redis))
    p_again = await store.current_params(redis, POW_BITS)
    check("issuer key persists across calls (same epoch id)", p_again["epoch_id"] == p["epoch_id"])
    store._cache.clear()
    p_fresh = await store.current_params(FakeRedis(), POW_BITS)
    check("a different island (fresh redis) has a different epoch key", p_fresh["epoch_id"] != p["epoch_id"])

    print()
    if failures:
        print(f"\033[31m{failures} check(s) FAILED\033[0m")
        return 1
    print("\033[32mall checks passed\033[0m")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
