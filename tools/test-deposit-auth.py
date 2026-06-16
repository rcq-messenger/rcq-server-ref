#!/usr/bin/env python3
"""Standalone proof of the F3 deposit-auth crypto core (no DB / redis / server).

Proves the hand-rolled RFC 9474 RSABSSA blind-signature chain is correct by using
`cryptography`'s STANDARD RSA-PSS verify as the oracle — if a token unblinded from
our manual EMSA-PSS encode + raw-RSA blind-sign verifies as a plain PSS signature,
the math is right and it will interop with swift-crypto / JCA on the clients.

Run:  python3 tools/test-deposit-auth.py   (needs `cryptography`)
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.core import deposit_auth as da  # noqa: E402

OK = "\033[32mPASS\033[0m"
BAD = "\033[31mFAIL\033[0m"
failures = 0


def check(name: str, cond: bool) -> None:
    global failures
    print(f"  [{OK if cond else BAD}] {name}")
    if not cond:
        failures += 1


def main() -> int:
    print("F3 deposit-auth crypto proof\n")

    # ── issuance roundtrip ────────────────────────────────────────────────────
    print("RSABSSA blind-signature roundtrip:")
    priv = da.new_issuer_key()
    pub = priv.public_key()
    n = pub.public_numbers().n

    msg = da.new_token_msg()              # the 32-byte token nonce
    prepared = da.prepare(msg)            # randomized: 32 random || msg
    blinded, blind_inv = da.blind(n, pub.public_numbers().e, prepared)  # CLIENT
    blind_sig = da.blind_sign(blinded, priv)                            # ISSUER
    sig = da.finalize(blind_sig, blind_inv, pub, prepared)             # CLIENT

    check("finalized token verifies as standard RSA-PSS", da.verify(pub, prepared, sig))
    check("blinded value differs from the prepared message (sender hidden at issuance)",
          blinded != prepared and len(blinded) == (n.bit_length() + 7) // 8)
    check("issuer's CRT blind-sign == textbook pow(x,d,n)",
          da._os2ip(blind_sig) == pow(da._os2ip(blinded), priv.private_numbers().d, n))

    # ── unlinkability sanity: two tokens from the same key are independent ─────
    msg2 = da.new_token_msg()
    prepared2 = da.prepare(msg2)
    blinded2, inv2 = da.blind(n, pub.public_numbers().e, prepared2)
    sig2 = da.finalize(da.blind_sign(blinded2, priv), inv2, pub, prepared2)
    check("a second token also verifies", da.verify(pub, prepared2, sig2))
    check("the two tokens are distinct", da.token_id(prepared, sig) != da.token_id(prepared2, sig2))

    # ── forgery / tamper resistance ───────────────────────────────────────────
    print("\nForgery + tamper resistance:")
    forged = os.urandom(len(sig))
    check("random signature is rejected (one-more-unforgeability)", not da.verify(pub, prepared, forged))
    bad = bytearray(sig); bad[10] ^= 0x01
    check("flipping one signature byte is rejected", not da.verify(pub, prepared, bytes(bad)))
    check("a token does not verify under a DIFFERENT prepared message",
          not da.verify(pub, da.prepare(da.new_token_msg()), sig))
    other_pub = da.new_issuer_key().public_key()
    check("a token does not verify under a different issuer key",
          not da.verify(other_pub, prepared, sig))

    # ── double-spend detection (spent-set semantics) ──────────────────────────
    print("\nDouble-spend detection (token id is stable per token):")
    spent: set[str] = set()
    tid = da.token_id(prepared, sig)
    first = tid not in spent
    spent.add(tid)
    second = tid not in spent   # replay of the SAME token
    check("first spend accepted", first)
    check("replay of the same token rejected", not second)
    check("token_id is deterministic", da.token_id(prepared, sig) == tid)

    # ── key serialization round-trips for the params endpoint ─────────────────
    print("\nParams (epoch pubkey) serialization:")
    jwk = da.public_jwk(pub)
    import base64
    n_back = int.from_bytes(base64.urlsafe_b64decode(jwk["n"] + "=" * (-len(jwk["n"]) % 4)), "big")
    check("published n round-trips", n_back == n and jwk["e"] == pub.public_numbers().e)
    check("epoch_id is stable + 16 hex chars",
          da.epoch_id(pub) == da.epoch_id(pub) and len(da.epoch_id(pub)) == 16)
    check("epoch_id differs across keys", da.epoch_id(pub) != da.epoch_id(other_pub))

    # ── proof-of-work faucet (stranger first-contact) ─────────────────────────
    print("\nProof-of-work (SHA-256 hashcash faucet):")
    check("_leading_zero_bits(0xff..) == 0", da._leading_zero_bits(b"\xff\xff") == 0)
    check("_leading_zero_bits(0x00 0x0f) == 12", da._leading_zero_bits(b"\x00\x0f\xff") == 12)
    check("_leading_zero_bits(0x00 0x00 0x80) == 16", da._leading_zero_bits(b"\x00\x00\x80") == 16)
    challenge = "epoch-abc:" + os.urandom(8).hex()
    for bits in (8, 12, 16):
        nonce = da.solve_pow(challenge, bits)
        check(f"solved PoW @ {bits} bits verifies", da.verify_pow(challenge, nonce, bits))
    nonce16 = da.solve_pow(challenge, 16)
    check("a PoW solution for a DIFFERENT challenge is rejected",
          not da.verify_pow(challenge + "x", nonce16, 16))
    import hashlib as _h
    nonce8 = da.solve_pow(challenge, 8)
    actual = da._leading_zero_bits(_h.sha256(f"{challenge}:{nonce8}".encode()).digest())
    check("verify_pow rejects a difficulty above the solution's actual zero-bits",
          not da.verify_pow(challenge, nonce8, actual + 1))

    print()
    if failures:
        print(f"\033[31m{failures} check(s) FAILED\033[0m")
        return 1
    print("\033[32mall checks passed\033[0m")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
