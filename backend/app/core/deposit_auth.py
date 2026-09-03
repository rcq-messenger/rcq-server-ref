"""F3 deposit-auth — anonymous blinded deposit tokens (RFC 9474 RSABSSA).

RCQ delivery is sealed-sender: `/messages/sealed` takes no auth because the
recipient is the only party who can identify a sender (by decrypting). That makes
per-sender rate limiting impossible — the spam floor is a blunt per-IP cap, which
a botnet (or many legit users sharing one onion-exit IP) defeats. F3 closes the
gap WITHOUT re-introducing sender identification:

  * The recipient's island issues anonymous tokens. A sender spends ONE token per
    sealed deposit. The server verifies the token and rate-limits by issuance
    allotment — but the spent token is cryptographically UNLINKABLE to its
    issuance, so sealed sender is preserved (the server learns "a validly-issued
    token was spent, not double-spent", never WHO spent it).
  * Token = an RFC 9474 RSA blind signature (RSABSSA-SHA384-PSS, randomized) — the
    same Privacy Pass "blind RSA" primitive Apple/Cloudflare deploy. The unblinded
    token is a plain RSA-PSS signature, so verification is standard RSA everywhere
    (Python `cryptography`, Swift `_CryptoExtras`, Android JCA/BouncyCastle).

Issuance is gated so it actually rate-limits:
  * CONTACTS (people who accepted you) draw from a generous per-relationship
    allotment — issued by the recipient's island, redeemed anonymously.
  * STRANGERS (first contact) must mint a SCARCE token via proof-of-work. Deposit
    auth can only RATE-LIMIT first contact, never block it (else nobody could ever
    reach you), so the PoW makes mass first-contact spam expensive while a single
    legit first message stays cheap. PoW = SHA-256 hashcash (leading-zero-bits) —
    dependency-free and byte-identical on the backend and both mobile clients,
    and it works behind onion where per-IP faucets are defeated by shared exits.

This module is PURE (crypto + PoW + serialization, no DB/redis) so it is unit
testable in isolation; the redis-backed issuer key, spent-set and allotment live
in `app/routers/deposit_auth.py`. Wire format + threat model:
`RCQ/docs/deposit-auth-design.md`. Proof: `tools/test-deposit-auth.py`.
"""

from __future__ import annotations

import base64
import hashlib
import secrets

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

# ── RSABSSA-SHA384-PSS-Randomized parameters (RFC 9474 §5) ────────────────────
MODULUS_BITS = 2048
SALT_LEN = 48           # = hLen for SHA-384
RANDOM_PREFIX_LEN = 32  # randomized variant: prepend 32 random bytes to the msg
_HASH = hashlib.sha384


def _i2osp(x: int, length: int) -> bytes:
    return x.to_bytes(length, "big")


def _os2ip(b: bytes) -> int:
    return int.from_bytes(b, "big")


def _mgf1(seed: bytes, length: int) -> bytes:
    """MGF1 with SHA-384 (RFC 8017 §B.2.1)."""
    out = bytearray()
    counter = 0
    while len(out) < length:
        out += _HASH(seed + _i2osp(counter, 4)).digest()
        counter += 1
    return bytes(out[:length])


def _emsa_pss_encode(msg: bytes, em_bits: int) -> bytes:
    """EMSA-PSS-ENCODE (RFC 8017 §9.1.1) with SHA-384, MGF1-SHA-384, sLen=48.

    Returns the encoded message EM (em_len bytes). The blind-signing client does
    this encode itself (the issuer only raw-RSA-signs the blinded integer), so it
    must match RFC 8017 exactly or `cryptography`'s standard PSS verify rejects.
    """
    h_len = _HASH().digest_size
    em_len = (em_bits + 7) // 8
    m_hash = _HASH(msg).digest()
    if em_len < h_len + SALT_LEN + 2:
        raise ValueError("encoding error: modulus too small")
    salt = secrets.token_bytes(SALT_LEN)
    m_prime = b"\x00" * 8 + m_hash + salt
    h = _HASH(m_prime).digest()
    ps = b"\x00" * (em_len - SALT_LEN - h_len - 2)
    db = ps + b"\x01" + salt
    db_mask = _mgf1(h, em_len - h_len - 1)
    masked_db = bytearray(a ^ b for a, b in zip(db, db_mask))
    # Clear the leftmost (8*em_len - em_bits) bits of maskedDB so EM < 2^em_bits < n.
    clear = 8 * em_len - em_bits
    if clear:
        masked_db[0] &= 0xFF >> clear
    return bytes(masked_db) + h + b"\xbc"


# ── token nonce + message preparation ─────────────────────────────────────────
def prepare(msg: bytes) -> bytes:
    """RSABSSA randomized prepare: prepend 32 random bytes (RFC 9474 §4.1)."""
    return secrets.token_bytes(RANDOM_PREFIX_LEN) + msg


def new_token_msg() -> bytes:
    """A fresh random 32-byte token nonce (the unblinded message to be signed)."""
    return secrets.token_bytes(32)


# ── blind / sign / finalize / verify ──────────────────────────────────────────
def blind(n: int, e: int, prepared: bytes) -> tuple[bytes, int]:
    """CLIENT: blind a prepared message. Returns (blinded_bytes, blind_inv).

    blinded = m * r^e mod n, where m = OS2IP(EMSA-PSS-ENCODE(prepared)). The
    issuer never sees `prepared` or the eventual signature — only `blinded`.
    """
    mod_len = (n.bit_length() + 7) // 8
    em = _emsa_pss_encode(prepared, n.bit_length() - 1)
    m = _os2ip(em)
    if m >= n:
        raise ValueError("encoded message not < modulus")
    while True:
        r = secrets.randbelow(n - 1) + 1          # r in [1, n)
        try:
            r_inv = pow(r, -1, n)                  # requires gcd(r, n) == 1
        except ValueError:
            continue
        break
    x = (m * pow(r, e, n)) % n
    return _i2osp(x, mod_len), r_inv


def blind_sign(blinded: bytes, priv: RSAPrivateKey) -> bytes:
    """ISSUER: raw-RSA sign the blinded representative. blind_sig = blinded^d mod n.

    This is the ONLY step that debits the sender's allotment / consumes the PoW.
    The issuer learns nothing linkable: `blinded` is statistically independent of
    the token the sender will later spend.
    """
    nums = priv.private_numbers()
    n = nums.public_numbers.n
    x = _os2ip(blinded)
    if not (0 <= x < n):
        raise ValueError("blinded value out of range")
    # CRT for speed (equivalent to pow(x, d, n)).
    p, q = nums.p, nums.q
    m1 = pow(x % p, nums.dmp1, p)
    m2 = pow(x % q, nums.dmq1, q)
    h = (nums.iqmp * (m1 - m2)) % p
    y = (m2 + h * q) % n
    return _i2osp(y, (n.bit_length() + 7) // 8)


def finalize(blind_sig: bytes, blind_inv: int, public_key: RSAPublicKey, prepared: bytes) -> bytes:
    """CLIENT: unblind -> a standard RSA-PSS signature. Verifies before returning."""
    n = public_key.public_numbers().n
    mod_len = (n.bit_length() + 7) // 8
    y = _os2ip(blind_sig)
    s = (y * blind_inv) % n
    sig = _i2osp(s, mod_len)
    if not verify(public_key, prepared, sig):
        raise ValueError("finalize produced an invalid signature")
    return sig


def verify(public_key: RSAPublicKey, prepared: bytes, sig: bytes) -> bool:
    """SERVER (at deposit): verify the unblinded token is a valid RSA-PSS sig over
    `prepared`. Standard RSA-PSS — `cryptography` is the interop oracle."""
    try:
        public_key.verify(
            sig,
            prepared,
            padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=SALT_LEN),
            hashes.SHA384(),
        )
        return True
    except Exception:
        return False


def token_id(prepared: bytes, sig: bytes) -> str:
    """Stable per-token id for the spent-set (1:1 with an issuance)."""
    return hashlib.sha256(prepared + sig).hexdigest()


# ── key (de)serialization for the params endpoint + epoch id ──────────────────
def new_issuer_key() -> RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=MODULUS_BITS)


def public_jwk(public_key: RSAPublicKey) -> dict:
    """Publish the epoch pubkey (clients pin this). `n`+`e` for the Python/Android
    hand-rolled path; `spki` (DER SubjectPublicKeyInfo, base64) for iOS swift-crypto
    `_RSA.BlindSigning.PublicKey(derRepresentation:)`."""
    nums = public_key.public_numbers()
    n_bytes = _i2osp(nums.n, (nums.n.bit_length() + 7) // 8)
    der = public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return {
        "n": base64.urlsafe_b64encode(n_bytes).decode().rstrip("="),
        "e": nums.e,
        "spki": base64.b64encode(der).decode(),
    }


def epoch_id(public_key: RSAPublicKey) -> str:
    """Short id binding tokens to an issuer key. Clients pin it from
    `/deposit-auth/params` and refuse a per-request key (anti-tagging)."""
    nums = public_key.public_numbers()
    n_bytes = _i2osp(nums.n, (nums.n.bit_length() + 7) // 8)
    return hashlib.sha256(n_bytes).hexdigest()[:16]


# ── proof-of-work (SHA-256 hashcash) for the stranger first-contact faucet ─────
def _leading_zero_bits(digest: bytes) -> int:
    bits = 0
    for byte in digest:
        if byte == 0:
            bits += 8
            continue
        bits += 8 - byte.bit_length()
        break
    return bits


def verify_pow(challenge: str, nonce: str, difficulty_bits: int) -> bool:
    """SHA-256(challenge || ':' || nonce) must have >= difficulty_bits leading
    zero bits. Dependency-free + identical on every client."""
    digest = hashlib.sha256(f"{challenge}:{nonce}".encode()).digest()
    return _leading_zero_bits(digest) >= difficulty_bits


def solve_pow(challenge: str, difficulty_bits: int) -> str:
    """Reference solver (used by the test + as the client algorithm spec)."""
    counter = 0
    while True:
        nonce = str(counter)
        if verify_pow(challenge, nonce, difficulty_bits):
            return nonce
        counter += 1
