"""F3 deposit-auth endpoints — anonymous blinded deposit tokens (RFC 9474 RSABSSA).

  GET  /deposit-auth/params   public: the current epoch pubkey + PoW difficulty.
  POST /deposit-auth/issue    blind-sign a token, gated by proof-of-work.

The token is later spent on `/messages/sealed` (the sealed-deposit gate calls
`deposit_auth_store.verify_and_consume_token`). Crypto lives in
`app/core/deposit_auth.py` (pure, proven by `tools/test-deposit-auth.py`); the
redis-backed issuer key + spent-set + issuance logic live in
`app/core/deposit_auth_store.py` (proven by `tools/test-deposit-auth-flow.py`).
This file is just the HTTP surface. Design: `RCQ/docs/deposit-auth-design.md`.

Default OFF (`DEPOSIT_AUTH_ENABLED`). Additive + backward compatible: clients that
don't mint tokens keep working under the existing per-IP cap.
"""

from __future__ import annotations

import base64

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from app.core import deposit_auth_store as store
from app.core.config import settings
from app.core.rate_limit import rate_limit
from app.core.redis import get_redis

router = APIRouter(prefix="/deposit-auth", tags=["deposit-auth"])

_REASON_STATUS = {
    "stale_epoch": (status.HTTP_409_CONFLICT, "stale epoch — re-fetch /params"),
    "bad_base64": (status.HTTP_400_BAD_REQUEST, "blinded not base64"),
    "low_pow": (status.HTTP_400_BAD_REQUEST, "insufficient proof-of-work"),
    "malformed": (status.HTTP_400_BAD_REQUEST, "malformed blinded value"),
}


class ParamsOut(BaseModel):
    epoch_id: str
    suite: str
    pubkey: dict   # {"n": base64url, "e": int}
    pow: dict      # {"algo": "sha256-hashcash", "difficulty": int}


@router.get("/params", response_model=ParamsOut)
async def params() -> ParamsOut:
    """The current epoch issuer pubkey + the PoW difficulty a sender pays to mint a
    token. Clients PIN `epoch_id`+`pubkey` and refuse a per-request key (anti-
    tagging). Unauthenticated."""
    if not settings.DEPOSIT_AUTH_ENABLED:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "deposit-auth not enabled")
    return ParamsOut(**await store.current_params(await get_redis(), settings.DEPOSIT_AUTH_POW_BITS))


class IssueIn(BaseModel):
    epoch_id: str
    blinded: str     # base64 of the blinded representative (mod_len bytes)
    pow_nonce: str   # SHA-256 hashcash solution over f"{epoch_id}:{blinded}"


class IssueOut(BaseModel):
    epoch_id: str
    blind_sig: str   # base64 of blinded^d mod n


@router.post(
    "/issue",
    response_model=IssueOut,
    # PoW is the real limiter (one solve per token, bound to the blinded value);
    # this per-IP cap is a cheap backstop against a flood that hasn't solved yet.
    dependencies=[Depends(rate_limit("deposit_issue", 120, 60))],
)
async def issue(body: IssueIn) -> IssueOut:
    """Blind-sign one token. The caller proves work over the EXACT blinded value
    (so one PoW = one token, no precompute), then the issuer raw-RSA signs it. The
    issuer never sees the unblinded token, so issuance is unlinkable to the
    eventual deposit."""
    if not settings.DEPOSIT_AUTH_ENABLED:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "deposit-auth not enabled")
    blind_sig, reason = await store.sign_blinded(
        await get_redis(), body.epoch_id, body.blinded, body.pow_nonce, settings.DEPOSIT_AUTH_POW_BITS,
    )
    if reason is not None:
        raise HTTPException(*_REASON_STATUS[reason])
    assert blind_sig is not None
    return IssueOut(epoch_id=body.epoch_id, blind_sig=base64.b64encode(blind_sig).decode())
