"""Local-only check of the `rcq-guest-v1` proof bytes (spec 2026-09-15, 4.3).

`fixtures/guest-proof-v1.json` is the vector Android, iOS and web copy into
their own test resources. If the server's bytes and the fixture disagree, every
client that passes its own test against the fixture is refused by the island
with `bad_signature`, so this pins:

  * `guest_proof.proof_bytes` rebuilds the fixture byte for byte (hex and text);
  * six lines, no trailing newline, the prefix first;
  * the signature verifies under the fixture's signing key, the seed is that
    key, and signing again reproduces it (Ed25519 is deterministic);
  * padded and unpadded spellings of a key give the same bytes, because the
    server re-encodes keys before building them;
  * every listed host spelling canonicalises to the fixture's host, and a
    non-443 port stays in it;
  * a room id of 0 and a host or challenge with a newline are refused, since a
    newline inside a field would let two requests sign the same bytes.

Pure: no database, no Redis. NOT deployed.
Run: PYTHONPATH=. PYTHONPATH=. .venv/bin/python test_guest_proof_fixture_local.py
"""
import base64
import json
import os

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from app.services import guest_proof, reissue_proof

fails = 0


def check(name, cond):
    global fails
    print(f"  {'PASS' if cond else 'FAIL'}  {name}")
    if not cond:
        fails += 1


def refuses(fn) -> bool:
    try:
        fn()
    except ValueError:
        return True
    return False


def main() -> int:
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "guest-proof-v1.json")
    with open(path) as fh:
        vec = json.load(fh)

    print("fixtures/guest-proof-v1.json:")
    ik = reissue_proof.decode_key32(vec["identity_key_b64_unpadded"])
    sk = base64.b64decode(vec["signing_key_b64"])
    data = guest_proof.proof_bytes(vec["host_input"], vec["group_id"], ik, sk, vec["challenge"])
    check("★ the bytes rebuild exactly (hex)", data.hex() == vec["proof_bytes_hex"])
    check("  ... and as text", data.decode() == vec["proof_bytes_text"])
    lines = data.split(b"\n")
    check("  ... six lines, no trailing newline, prefix first",
          len(lines) == 6 and not data.endswith(b"\n") and lines[0] == b"rcq-guest-v1")
    check("  ... the host line is the canonical host", lines[1].decode() == vec["canonical_host"] == "api.rcq.app")
    check("  ... the room line is plain decimal", lines[2] == str(vec["group_id"]).encode())
    check("  ... keys are signed PADDED even though the fixture gives ik unpadded",
          lines[3].decode() == vec["identity_key_b64"] and lines[3].endswith(b"="))
    check("  ... the challenge is verbatim", lines[5].decode() == vec["challenge"])

    try:
        Ed25519PublicKey.from_public_bytes(sk).verify(base64.b64decode(vec["signature_b64"]), data)
        verified = True
    except Exception:  # noqa: BLE001
        verified = False
    check("★ the signature verifies under signing_key_b64", verified)
    seed = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(vec["signing_seed_hex"]))
    check("  ... the seed is that key", seed.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw) == sk)
    check("  ... signing again reproduces the signature",
          base64.b64encode(seed.sign(data)).decode() == vec["signature_b64"])

    print("\nSpellings:")
    padded_ik = reissue_proof.decode_key32(vec["identity_key_b64"])
    unpadded_sk = reissue_proof.decode_key32(vec["signing_key_b64"].rstrip("="))
    check("★ padded and unpadded keys give the same bytes",
          guest_proof.proof_bytes(vec["host_input"], vec["group_id"], padded_ik, unpadded_sk, vec["challenge"]) == data)
    check("every listed host spelling is the same binding",
          all(guest_proof.canonical_host(h) == vec["canonical_host"] for h in vec["host_spellings_same_binding"]))
    check("  ... and signs the same bytes",
          all(guest_proof.proof_bytes(h, vec["group_id"], ik, sk, vec["challenge"]) == data
              for h in vec["host_spellings_same_binding"]))
    check("a non-443 port stays in the binding",
          guest_proof.canonical_host("Island.Example:8443") == "island.example:8443")
    check("another room is different bytes",
          guest_proof.proof_bytes(vec["host_input"], 42, ik, sk, vec["challenge"]) != data)

    print("\nRefusals:")
    check("group_id 0 is refused", refuses(lambda: guest_proof.proof_bytes("h", 0, ik, sk, "c")))
    check("a newline in the host is refused", refuses(lambda: guest_proof.proof_bytes("a\nb", 1, ik, sk, "c")))
    check("a newline in the challenge is refused", refuses(lambda: guest_proof.proof_bytes("h", 1, ik, sk, "c\nd")))
    check("an empty challenge is refused", refuses(lambda: guest_proof.proof_bytes("h", 1, ik, sk, "")))
    check("a 31-byte key is refused", refuses(lambda: guest_proof.proof_bytes("h", 1, ik[:31], sk, "c")))

    print("\n" + ("ALL PASS" if fails == 0 else f"{fails} FAILED"))
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(main())
