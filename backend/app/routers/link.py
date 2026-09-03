"""Web-link relay — a one-time, short-TTL pass-through for the "connect to
web" flow (scan a QR on the web with the phone to log the web in as the same
account).

Flow:
  1. The web generates an ephemeral X25519 keypair + a random `token`, and
     shows {token, ephemeral pubkey} in a QR.
  2. The phone scans it, seals the account recovery seed to the web's
     ephemeral pubkey (anonymous sealed box), and POSTs the ciphertext here
     keyed by `token`.
  3. The web polls GET /link/{token}, decrypts with its ephemeral PRIVATE key
     (which never leaves the browser), derives the identity, and logs in.

The server only ever holds an OPAQUE sealed blob it cannot read — it is sealed
to the web's ephemeral key. The token is a random capability; the blob is
deleted on first read and expires after `_TTL_SECONDS`. No account identifier
is stored next to it, so the relay stays metadata-light.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from app.core.redis import get_redis
from app.core.security import current_uin

router = APIRouter(prefix="/link", tags=["link"])

# The QR is short-lived: the phone is expected to scan within a couple of
# minutes. A sealed seed is tiny, so cap the blob hard to stop the relay being
# abused as general storage.
_TTL_SECONDS = 120
_MAX_BLOB_B64 = 8192


def _key(token: str) -> str:
    return f"link:{token}"


def _valid_token(token: str) -> bool:
    # base64url of 32 random bytes is ~43 chars; allow a little slack and only
    # the base64url alphabet so the token can't smuggle anything into the key.
    if not (32 <= len(token) <= 128):
        return False
    return all(c.isalnum() or c in "-_" for c in token)


class DepositIn(BaseModel):
    # base64 sealed-box ciphertext: the recovery seed sealed to the web's
    # ephemeral X25519 pubkey. The server never decrypts it.
    blob: str = Field(min_length=1, max_length=_MAX_BLOB_B64)


@router.post("/{token}")
async def deposit(token: str, body: DepositIn, uin: int = Depends(current_uin)) -> dict:
    """Phone deposits the sealed seed for the web session [token].

    Authenticated: only a logged-in client links a web session, which also
    cheaply rate-limits abuse. We deliberately do NOT store the uin with the
    blob — the relay carries ciphertext only.
    """
    if not _valid_token(token):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail={"code": "bad_token"})
    redis = await get_redis()
    # NX: a token slot can't be overwritten once filled (first deposit wins);
    # the web reads + deletes, so a fresh link uses a fresh token anyway.
    ok = await redis.set(_key(token), body.blob, nx=True, ex=_TTL_SECONDS)
    if not ok:
        raise HTTPException(status.HTTP_409_CONFLICT, detail={"code": "slot_taken"})
    return {"ok": True}


@router.get("/{token}")
async def collect(token: str) -> dict:
    """Web collects (and consumes) the sealed seed for [token].

    Unauthenticated — the web isn't logged in yet (that's the whole point).
    Security is in the sealed blob (only the web's ephemeral private key
    decrypts it), not the token's secrecy. One-time: deleted on read so a
    leaked token can't be replayed.
    """
    if not _valid_token(token):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail={"code": "bad_token"})
    redis = await get_redis()
    blob = await redis.get(_key(token))
    if blob is None:
        # Not deposited yet (web keeps polling), or expired, or already read.
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail={"code": "empty"})
    await redis.delete(_key(token))
    if isinstance(blob, bytes):
        blob = blob.decode()
    return {"blob": blob}
