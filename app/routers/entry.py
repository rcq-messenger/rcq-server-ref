"""Selling ENTRY to this island: the one question the till has to ask it.

The island never touches money (services/uin_voucher has the long version), so
the till outside it writes the invoice, watches the wallet and signs the entry
voucher that `routers/auth.py` and `routers/residency.py` redeem. What the till
cannot know on its own is what THIS island charges and where its operator is
paid: both are settings the operator changes live in their console
(`entry_price_cents`, `uin_payout_addresses`), and a till that carried its own
copy of either would drift from them with nobody watching. That was the
two-ladders trap the number shop fell into (uins.js), and entry does not
repeat it: the till asks, per invoice, and invoices exactly what it was told.

⚠⚠ SIGNED, NOT PUBLIC, for the same reason `uin_shop.payout_target` is. The
answer names the operator's wallets and price, and a price is public anyway,
so the signature is not about secrecy. It is about which till this island
answers to. The island trusts exactly one till, the one whose public key is in
`uin_voucher_pubkey`, because that is the only till whose vouchers it will
redeem. A till whose `UIN_ISLAND_API` points at the wrong island, or a stray
copy of the worker somebody deployed against us, would otherwise be told our
wallets, write invoices in our name, sell entry codes our island then refuses,
and have no refund path. With the host inside the signature and checked
against `island_host`, that till gets 403 and writes nothing.

NOT under `require_shop_open`, deliberately. Numbers and entry are two
products: an island can sell residency with its number shop closed, and the
flagship did exactly that from 07.09. Entry is for sale when the price is not
zero and the operator has named wallets, and those two facts are the only gate.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel

from app.routers.uin_shop import operator_addresses
from app.services import server_settings, uin_voucher

router = APIRouter(prefix="/entry", tags=["entry"])


class EntryPayoutQuestionIn(BaseModel):
    #: A signed `entry_payout` document
    #: (services/uin_voucher.entry_payout_signed_bytes).
    request: str


class EntryPayoutTargetOut(BaseModel):
    #: The island the till asked about, as this island knows itself. The till
    #: writes it onto the invoice and into the voucher it later signs.
    host: str
    price_cents: int
    #: chain id -> the operator's address, the same map the number shop hands
    #: out: one set of wallets serves numbers and entry.
    addresses: dict[str, str]


@router.post("/payout-target", response_model=EntryPayoutTargetOut)
async def entry_payout_target(body: EntryPayoutQuestionIn) -> EntryPayoutTargetOut:
    """The till asking: somebody wants to join this island, what does it cost
    and where do they pay?

    Refusals, in the order they are decided:
      * 403 `{code}` when the request is not from the till this island trusts,
        is stale, or names another island (`voucher_other_island`). The till
        must not write an invoice on any of these;
      * 409 `not_for_sale` when the price is zero: the operator is not selling
        entry, whatever the door policy says;
      * 409 `no_payout` when the operator has set no wallet: a price nobody can
        be paid at is not a sale.

    ⚠ No authentication beyond the signature, and none is needed: the reply is
    a price and an address, both of which the buyer is about to be shown. What
    it must not do is answer a stranger's till, and it does not.
    """
    try:
        host = uin_voucher.verify_entry_payout(
            body.request, expect_host=str(await server_settings.get("island_host") or "")
        )
    except uin_voucher.VoucherError as e:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail={"code": e.code}) from None

    cents = int(await server_settings.get("entry_price_cents") or 0)
    if cents <= 0:
        raise HTTPException(status.HTTP_409_CONFLICT, detail={"code": "not_for_sale"})
    addrs = await operator_addresses()
    if not addrs:
        raise HTTPException(status.HTTP_409_CONFLICT, detail={"code": "no_payout"})
    return EntryPayoutTargetOut(host=host, price_cents=cents, addresses=addrs)
