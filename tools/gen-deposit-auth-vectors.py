#!/usr/bin/env python3
"""Emit F3 deposit-auth interop vectors for the client crypto tests.

Generates an issuer RSA key + a Python-issued token, written as key=value lines
(no JSON lib needed on the JVM/Swift side). The client test verifies the Python
token (python->client interop) and emits its own token, which `verify-client-token.py`
then checks (client->python interop). `d_hex` is included so the client test can
play the issuer locally (blinded^d mod n) without a live server.

Usage:  python3 tools/gen-deposit-auth-vectors.py [out_path]   (default /tmp/depauth_vectors.txt)
"""
import base64
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.core import deposit_auth as da  # noqa: E402

out_path = sys.argv[1] if len(sys.argv) > 1 else "/tmp/depauth_vectors.txt"

priv = da.new_issuer_key()
nums = priv.private_numbers()
n = nums.public_numbers.n
e = nums.public_numbers.e
d = nums.d
p = nums.p
q = nums.q
pub = priv.public_key()


def hx(x: int) -> str:
    h = format(x, "x")
    return ("0" + h) if len(h) % 2 else h

# A genuine Python-issued token (the full blind -> blind_sign -> finalize chain).
prepared = da.prepare(da.new_token_msg())
blinded, blind_inv = da.blind(n, e, prepared)
sig = da.finalize(da.blind_sign(blinded, priv), blind_inv, pub, prepared)
assert da.verify(pub, prepared, sig), "python self-check failed"

lines = [
    f"n_hex={hx(n)}",
    f"e={e}",
    f"e_hex={hx(e)}",
    f"d_hex={hx(d)}",
    f"p_hex={hx(p)}",
    f"q_hex={hx(q)}",
    f"py_prepared_b64={base64.b64encode(prepared).decode()}",
    f"py_sig_b64={base64.b64encode(sig).decode()}",
]
with open(out_path, "w") as f:
    f.write("\n".join(lines) + "\n")
print(f"wrote {out_path} (n={n.bit_length()} bits, python token issued + self-verified)")
