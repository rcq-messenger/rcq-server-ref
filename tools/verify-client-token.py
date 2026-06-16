#!/usr/bin/env python3
"""Verify a client-issued F3 token under the Python issuer pubkey (client->python
interop). Reads the client token (key=value: prepared_b64, sig_b64) + the vectors
file (for n, e). Exits 0 iff the token is a valid RSA-PSS signature.

Usage:  python3 tools/verify-client-token.py <client_token.txt> [vectors.txt]
"""
import base64
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers  # noqa: E402

from app.core import deposit_auth as da  # noqa: E402


def load(path: str) -> dict:
    out = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if "=" in line:
                k, v = line.split("=", 1)
                out[k] = v
    return out


tok = load(sys.argv[1])
vec = load(sys.argv[2] if len(sys.argv) > 2 else "/tmp/depauth_vectors.txt")

pub = RSAPublicNumbers(int(vec["e"]), int(vec["n_hex"], 16)).public_key()
prepared = base64.b64decode(tok["prepared_b64"])
sig = base64.b64decode(tok["sig_b64"])

ok = da.verify(pub, prepared, sig)
print("client->python interop:", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
