"""A voucher is the only way a number is sold, and it is the only thing the
island ever learns about a payment.

⚠⚠ THE ISLAND IS NOT A TILL AND MUST NEVER BECOME ONE. Money is watched
outside, by the same worker that already sells relay slots
(`deploy/console-worker/payments.js`): it issues an invoice, watches the
founder's own wallets through public explorers, and when the transfer lands it
signs a voucher. Nothing here holds a wallet, an address, an amount, a chain or
a transaction, and nothing here can spend anything.

What each side knows, and no more than that:

  * the till knows a number was sold and for what. It never sees an account, a
    token or the buyer's number: the invoice call carries none of them;
  * the island knows a number was paid for. It never sees a chain, an amount,
    an invoice or an address: the voucher carries none of them.

The voucher is a bearer token on purpose. Whoever holds it may redeem it once,
which is exactly the property that lets the two halves stay strangers: the
buyer carries the proof from one to the other. It is signed with Ed25519 rather
than shared-secret HMAC because the island is the larger and more exposed
surface of the two, and a compromise of it must not mint numbers.

⚠ The signed bytes are built field by field, never "the document minus its
signature". A dict-minus-key canonicalisation lets an attacker add a field the
signer never saw, and every future field silently falls outside the signature.
Same rule, same reason, as `_verify_record_sig` in the federation router.
"""

from __future__ import annotations

import base64
import binascii
import json
import logging
import os
import time

log = logging.getLogger("rcq.uin_voucher")

#: How long a signed voucher may sit unredeemed. Long enough that a buyer can
#: close the tab and come back, short enough that a spent-nonce row is not kept
#: for ever: once a voucher's own expiry has passed, replaying it fails on the
#: clock and the row that remembers it can be swept.
MAX_AGE_SECONDS = 7 * 24 * 3600

#: Version of the signed shape. A voucher that does not carry this exact value
#: is refused rather than interpreted: an old island must not guess at a
#: document a newer till invented.
VERSION = 1


class VoucherError(Exception):
    """Refusal reason, in the client-visible `code` vocabulary."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def signed_bytes(*, uin: int, nonce: str, exp: int) -> bytes:
    """The exact bytes the till signs, built field by field.

    Compact separators and sorted keys are not cosmetic: both sides must
    produce the same bytes from the same three values, and a space would change
    the signature.
    """
    doc = {"v": VERSION, "uin": int(uin), "nonce": str(nonce), "exp": int(exp)}
    return json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()


def resale_signed_bytes(*, uin: int, seller: int, price_cents: int, nonce: str, exp: int) -> bytes:
    """The bytes the till signs for a number sold by a PERSON, not by the island.

    ⚠⚠ A separate document, and deliberately not an extra field on the other
    one. The field sets differ, so neither can ever be read as the other, and
    that is what stops the substitution this design would otherwise invite: a
    voucher bought for $0.99 against ordinary space being redeemed a moment
    later against a listing somebody priced at $250. Same key, two jobs, no
    overlap — the reasoning `hold_signed_bytes` already records.

    `seller` and `price_cents` are inside the signature because the island
    checks them against the listing before it moves anybody's property. A till
    that signed for one seller cannot have its voucher spent on another's
    number, and a price that changed between invoice and redemption stops the
    redemption rather than surprising either side.
    """
    doc = {"v": VERSION, "kind": "resale", "uin": int(uin), "seller": int(seller),
           "price_cents": int(price_cents), "nonce": str(nonce), "exp": int(exp)}
    return json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()


def verify_resale(voucher: str, *, expect_uin: int, now: int | None = None) -> tuple[str, int, int]:
    """Check a resale voucher; return `(nonce, seller, price_cents)`.

    Same vocabulary of errors as `verify`, so a client never has to learn two.
    """
    pub_b64 = public_key_b64()
    if not pub_b64:
        raise VoucherError("sales_disabled")
    try:
        doc = json.loads(base64.b64decode(voucher.strip(), validate=True))
    except (ValueError, binascii.Error, TypeError):
        raise VoucherError("bad_voucher") from None
    if not isinstance(doc, dict) or doc.get("v") != VERSION or doc.get("kind") != "resale":
        raise VoucherError("bad_voucher")
    try:
        uin = int(doc["uin"])
        seller = int(doc["seller"])
        price_cents = int(doc["price_cents"])
        exp = int(doc["exp"])
        nonce = str(doc["nonce"])
        sig = base64.b64decode(str(doc["sig"]), validate=True)
    except (KeyError, ValueError, TypeError, binascii.Error):
        raise VoucherError("bad_voucher") from None
    if not (16 <= len(nonce) <= 128) or not nonce.isascii():
        raise VoucherError("bad_voucher")
    if uin != int(expect_uin):
        raise VoucherError("voucher_other_uin")
    if price_cents < 0 or seller <= 0:
        raise VoucherError("bad_voucher")

    seconds = int(time.time() if now is None else now)
    if exp <= seconds:
        raise VoucherError("voucher_expired")
    if exp - seconds > MAX_AGE_SECONDS:
        raise VoucherError("bad_voucher")

    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(pub_b64, validate=True))
        pub.verify(sig, resale_signed_bytes(uin=uin, seller=seller,
                                            price_cents=price_cents, nonce=nonce, exp=exp))
    except (InvalidSignature, ValueError, TypeError, binascii.Error):
        raise VoucherError("bad_voucher") from None

    return nonce, seller, price_cents


def public_key_b64() -> str | None:
    """The till's public half, from the environment. Absent means numbers are
    not for sale on this island, which is the right default for a self-hosted
    one: an operator who has not set up a till cannot be paid, so nothing here
    should pretend otherwise."""
    # ⚠ The console's value wins, the .env is the default. An operator who
    # pastes their till's key into the admin page expects it to take effect,
    # and an island that needed a restart for it would be a shop that cannot be
    # opened by the person who owns it. Read synchronously from a cache the
    # settings service keeps warm, because verification happens on a hot path
    # and must not open a database session per voucher.
    from app.services import server_settings

    override = server_settings.cached_str("uin_voucher_pubkey")
    if override:
        return override
    return (os.environ.get("RCQ_UIN_VOUCHER_PUBKEY") or "").strip() or None


def verify(voucher: str, *, expect_uin: int, now: int | None = None) -> str:
    """Check a voucher and return its nonce, or raise `VoucherError`.

    The nonce is what the caller must then record as spent: verification alone
    proves the till signed this, not that nobody has redeemed it yet. Those are
    two different questions and they are answered in two different places -
    here, and in one row with the nonce as its primary key.
    """
    pub_b64 = public_key_b64()
    if not pub_b64:
        raise VoucherError("sales_disabled")

    try:
        raw = base64.b64decode(voucher.strip(), validate=True)
        doc = json.loads(raw)
    except (ValueError, binascii.Error, TypeError):
        raise VoucherError("bad_voucher") from None
    if not isinstance(doc, dict):
        raise VoucherError("bad_voucher")

    if doc.get("v") != VERSION:
        raise VoucherError("bad_voucher")
    try:
        uin = int(doc["uin"])
        exp = int(doc["exp"])
        nonce = str(doc["nonce"])
        sig = base64.b64decode(str(doc["sig"]), validate=True)
    except (KeyError, ValueError, TypeError, binascii.Error):
        raise VoucherError("bad_voucher") from None
    # A nonce is what stops a replay, so it has to be big enough to be
    # unguessable and bounded so a row cannot be inflated by whoever mints it.
    if not (16 <= len(nonce) <= 128) or not nonce.isascii():
        raise VoucherError("bad_voucher")

    # ⚠ The number is checked against what the CALLER asked for, not taken from
    # the voucher. A voucher for #777 redeemed against #778 is not a mistake to
    # be helpful about: it is either a bug or somebody trying their luck.
    if uin != int(expect_uin):
        raise VoucherError("voucher_other_uin")

    seconds = int(time.time() if now is None else now)
    if exp <= seconds:
        raise VoucherError("voucher_expired")
    # A till that hands out a year-long voucher would keep a spent row alive for
    # a year. The window is ours to bound, whatever the till claims.
    if exp - seconds > MAX_AGE_SECONDS:
        raise VoucherError("bad_voucher")

    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(pub_b64, validate=True))
        pub.verify(sig, signed_bytes(uin=uin, nonce=nonce, exp=exp))
    except (InvalidSignature, ValueError, TypeError, binascii.Error):
        raise VoucherError("bad_voucher") from None

    return nonce


#: A hold request is good for minutes, not days: it is a message from the till
#: to the island, made and used in the same breath. ⚠ Anyone who sees one may
#: replay it inside that window, which is why it can only place or lift a hold
#: on a number the till named - the worst a replay does is re-place a hold the
#: till can lift again, and it can never grant anything.
HOLD_MAX_AGE_SECONDS = 600

_HOLD_KINDS = ("hold", "release")


def hold_signed_bytes(*, kind: str, uin: int, hold_id: str, exp: int) -> bytes:
    """The bytes the till signs to reserve or release a number.

    ⚠ `kind` is inside the signature, and the field set differs from a
    voucher's, so neither document can ever be read as the other. That is
    domain separation, and it is the reason one key can safely do both jobs.
    """
    doc = {"v": VERSION, "kind": str(kind), "uin": int(uin),
           "hold_id": str(hold_id), "exp": int(exp)}
    return json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()


def verify_hold(request: str, *, now: int | None = None) -> tuple[str, int, str, int]:
    """Check a signed hold request; return `(kind, uin, hold_id, exp)`.

    Raises `VoucherError` with the same vocabulary the redemption uses, so a
    client never has to learn two.
    """
    pub_b64 = public_key_b64()
    if not pub_b64:
        raise VoucherError("sales_disabled")

    try:
        raw = base64.b64decode(request.strip(), validate=True)
        doc = json.loads(raw)
    except (ValueError, binascii.Error, TypeError):
        raise VoucherError("bad_voucher") from None
    if not isinstance(doc, dict) or doc.get("v") != VERSION:
        raise VoucherError("bad_voucher")
    try:
        kind = str(doc["kind"])
        uin = int(doc["uin"])
        hold_id = str(doc["hold_id"])
        exp = int(doc["exp"])
        sig = base64.b64decode(str(doc["sig"]), validate=True)
    except (KeyError, ValueError, TypeError, binascii.Error):
        raise VoucherError("bad_voucher") from None
    if kind not in _HOLD_KINDS or not (1 <= len(hold_id) <= 64) or not hold_id.isascii():
        raise VoucherError("bad_voucher")

    seconds = int(time.time() if now is None else now)
    if exp <= seconds:
        raise VoucherError("voucher_expired")
    if exp - seconds > HOLD_MAX_AGE_SECONDS:
        raise VoucherError("bad_voucher")

    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(pub_b64, validate=True))
        pub.verify(sig, hold_signed_bytes(kind=kind, uin=uin, hold_id=hold_id, exp=exp))
    except (InvalidSignature, ValueError, TypeError, binascii.Error):
        raise VoucherError("bad_voucher") from None

    return kind, uin, hold_id, exp
