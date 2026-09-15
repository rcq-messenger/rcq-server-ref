"""The signed bytes of an `rcq-guest-v1` proof, written once.

`POST /auth/guest` gives somebody whose account lives on another island a guest
copy here, and the first membership of that copy, without a voucher or an
invite (spec 2026-09-15, section 4). The only thing the island can check is
that the caller holds the private half of the signing key the copy will carry,
so what that key signs has to pin down everything a relay, a front or a
replaying stranger could otherwise change:

  * the ISLAND (canonical host), so a proof made for island A cannot mint a
    copy on island C, including islands that still share the default
    JWT_SECRET and therefore accept each other's challenges;
  * the ROOM (the group id on THIS island), so a relaying front cannot move a
    person into a different room than the one they tapped;
  * the IDENTITY KEY, which today's register proof does not cover (it signs the
    challenge string alone), so nobody in the middle can pin an `ik` of their
    choosing to somebody else's signing key;
  * the SIGNING KEY and a single-use CHALLENGE, for freshness.

Pure on purpose, like `reissue_proof`: no database, no Redis, no FastAPI. The
same bytes are built by Android (crypto/GuestProof.kt), iOS
(Services/GuestProof.swift) and web (src/lib/guest-proof.ts), and
`fixtures/guest-proof-v1.json` pins them. The field encoders are imported from
`reissue_proof` rather than copied, because two copies of "canonical host" are
two chances for the proofs to disagree about which island they name.

⚠ THE SERVER NEVER SIGNS OR VERIFIES THE STRINGS IT WAS SENT. Keys are decoded
and re-encoded as standard padded base64, the host is canonicalised, and only
the challenge goes in verbatim (it is the island's own JWT, and the client
must sign exactly what it was handed).
"""
from __future__ import annotations

from app.services.reissue_proof import (  # noqa: F401 - re-exported for callers
    canonical_host,
    canonical_key,
    decode_key32,
    decode_signature,
)

PREFIX = "rcq-guest-v1"
VERSION = 1


def proof_bytes(
    host: str,
    group_id: int,
    identity_key: bytes,
    signing_key: bytes,
    challenge: str,
) -> bytes:
    """The exact bytes the guest's signing key signs.

    UTF-8, six fields joined by a single newline (0x0A), no trailing newline:

        rcq-guest-v1
        <host>          canonical_host: lowercase, ":port" only when not 443
        <group_id>      decimal ASCII, no sign, no leading zeros
        <identity_key>  standard padded base64 of the 32 X25519 bytes
        <signing_key>   standard padded base64 of the 32 Ed25519 bytes
        <challenge>     verbatim, from POST /auth/guest/challenge

    Raises ValueError for input that cannot be one line of the layout: a
    non-positive room id, a key that is not 32 bytes, or a host or challenge
    carrying a newline. A field with a newline inside it would shift every
    field after it, and two different requests could then sign the same bytes.
    """
    gid = int(group_id)
    if gid <= 0:
        raise ValueError("group_id must be positive")
    if len(identity_key) != 32 or len(signing_key) != 32:
        raise ValueError("keys must be 32 bytes")
    host_line = canonical_host(host)
    if not host_line or "\n" in host_line or "\r" in host_line:
        raise ValueError("bad host")
    if not challenge or "\n" in challenge or "\r" in challenge:
        raise ValueError("bad challenge")
    lines = [
        PREFIX,
        host_line,
        str(gid),
        canonical_key(identity_key),
        canonical_key(signing_key),
        challenge,
    ]
    return "\n".join(lines).encode("utf-8")
