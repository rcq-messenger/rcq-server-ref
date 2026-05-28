"""Server metadata + capabilities discovery.

`GET /server/info` is unauthenticated and stable across versions. The iOS
client polls it once per active account on boot to decide which optional
surfaces to render. The flagship surface that depends on this today is
the UIN-shop: `api.rcq.app` advertises `uin_shop=true` and the in-app
shop opens; self-host operators running `rcq-server-ref` default to
`uin_shop=false` and the in-app shop tab disappears entirely (operators
sell / give out UINs via their own out-of-band channel — see
`project_rcq_monetization_model` for the design rationale).

Adding new capabilities is additive: add a key to the response, default
to a value that keeps old clients working, and gate the new client-side
feature behind the lookup.
"""

from fastapi import APIRouter
from pydantic import BaseModel

from app.core.config import settings


router = APIRouter(prefix="/server", tags=["server"])


class ServerCapabilities(BaseModel):
    # In-app UIN purchase via Apple IAP. Off by default on rcq-server-ref
    # because the Apple IAP transaction is bound to the App Store binary's
    # bundle id (us), which means money would flow to us regardless of
    # which backend the user is on — incoherent for self-host operators.
    # Prod sets UIN_SHOP_ENABLED=true in /opt/rcq/.env.
    uin_shop: bool


class ServerInfo(BaseModel):
    name: str
    capabilities: ServerCapabilities


@router.get("/info", response_model=ServerInfo)
async def server_info() -> ServerInfo:
    return ServerInfo(
        name=settings.APP_NAME,
        capabilities=ServerCapabilities(
            uin_shop=settings.UIN_SHOP_ENABLED,
        ),
    )
