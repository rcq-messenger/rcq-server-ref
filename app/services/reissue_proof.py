"""The signed bytes of an `rcq-reissue-v1` proof, written once.

`POST /auth/reissue` rewrites an account's keys. Until this existed the bearer
token alone authorised it, so anybody holding a stolen token could rotate the
row to keys of their own and lock the owner out for good. The proof is a
signature by the OLD signing key over the exact change being made, bound to the
island and the number it is made on, with a timestamp and a nonce against
replay (spec 2026-09-15, F3).

Pure on purpose: no database, no Redis, no FastAPI. The same bytes are built by
Android (crypto/ReissueProof.kt), iOS (Services/ReissueProof.swift) and web
(src/lib/reissue-proof.ts), and `fixtures/reissue-proof-v1.json` pins them. A
second copy of this layout anywhere on the server would be the drift the
fixture exists to catch, so the route imports it from here.

⚠ THE SERVER NEVER SIGNS OR VERIFIES THE STRINGS IT WAS SENT. Every field is
decoded and re-encoded canonically before it goes into the bytes. Otherwise the
same key in padded and unpadded base64, or the same nonce with different
trailing bits, would be two different messages, and a nonce spelled a second
way would walk straight past the replay guard.
"""
from __future__ import annotations

import base64

PREFIX = "rcq-reissue-v1"
VERSION = 1


def _b64_any(value: str) -> bytes:
    """Standard base64, padding optional. Raises ValueError on anything else."""
    raw = value.strip()
    return base64.b64decode(raw + "=" * (-len(raw) % 4), validate=True)


def decode_key32(value: str) -> bytes:
    """A 32-byte public key from its wire spelling, or ValueError."""
    decoded = _b64_any(value)
    if len(decoded) != 32:
        raise ValueError("key must be 32 bytes")
    return decoded


def decode_signature(value: str) -> bytes:
    """A 64-byte Ed25519 signature from standard base64, or ValueError."""
    decoded = _b64_any(value)
    if len(decoded) != 64:
        raise ValueError("signature must be 64 bytes")
    return decoded


def decode_nonce(value: str) -> bytes:
    """16 bytes from base64url without padding (22 characters), or ValueError.

    Standard-alphabet characters are refused rather than translated: the spec
    names base64url, and accepting both would give one nonce two spellings.
    """
    raw = value.strip()
    if len(raw) != 22 or not all(c.isalnum() or c in "-_" for c in raw):
        raise ValueError("nonce must be 22 base64url characters")
    decoded = base64.urlsafe_b64decode(raw + "==")
    if len(decoded) != 16:
        raise ValueError("nonce must be 16 bytes")
    return decoded


def canonical_key(raw: bytes) -> str:
    """Standard padded base64 of the decoded bytes: the spelling that is signed."""
    return base64.b64encode(raw).decode("ascii")


def canonical_nonce(raw: bytes) -> str:
    """base64url without padding: the spelling that is signed AND the replay key."""
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def canonical_host(value: str) -> str:
    """Lowercase host, with `:port` only when the port is not 443.

    ⚠ The port is part of the binding (critic 11): two islands on one hostname
    and different ports must not accept each other's proofs. 443 is dropped
    because that is how a client that never typed a port names the island,
    and a Host header from a proxy may or may not carry it.

    A trailing dot (a fully-qualified spelling) is dropped too, since it names
    the same island. Brackets around an IPv6 literal are kept.
    """
    host = (value or "").strip().lower()
    port = ""
    if host.startswith("["):
        end = host.find("]")
        if end != -1 and host[end + 1:end + 2] == ":":
            host, port = host[:end + 1], host[end + 2:]
    elif host.count(":") == 1:
        host, port = host.split(":", 1)
    host = host.rstrip(".")
    if port and port != "443":
        return f"{host}:{port}"
    return host


def proof_bytes(
    host: str,
    uin: int,
    old_sk: bytes,
    new_ik: bytes,
    new_sk: bytes,
    ts: int,
    nonce: bytes,
) -> bytes:
    """The exact bytes the OLD signing key signs.

    UTF-8, one field per line, joined by a single newline, no trailing newline:

        rcq-reissue-v1
        <host>     canonical_host
        <uin>      decimal, the row's number on THIS island
        <old_sk>   standard padded base64 of 32 bytes
        <new_ik>   standard padded base64 of 32 bytes
        <new_sk>   standard padded base64 of 32 bytes
        <ts>       unix seconds, decimal
        <nonce>    16 bytes, base64url, no padding
    """
    lines = [
        PREFIX,
        canonical_host(host),
        str(int(uin)),
        canonical_key(old_sk),
        canonical_key(new_ik),
        canonical_key(new_sk),
        str(int(ts)),
        canonical_nonce(nonce),
    ]
    return "\n".join(lines).encode("utf-8")
