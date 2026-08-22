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
from app.services import server_settings


router = APIRouter(prefix="/server", tags=["server"])


class ServerCapabilities(BaseModel):
    # In-app UIN purchase via Apple IAP. Off by default on rcq-server-ref
    # because the Apple IAP transaction is bound to the App Store binary's
    # bundle id (us), which means money would flow to us regardless of
    # which backend the user is on — incoherent for self-host operators.
    # Prod sets UIN_SHOP_ENABLED=true in /opt/rcq/.env.
    uin_shop: bool
    # Hall of Fame leaderboard surface. Off by default for self-hosters (a
    # flagship-community feature). Defaults false so old clients that ignore the
    # field hide it; prod sets HALL_OF_FAME_ENABLED=true. Clients hide the
    # Settings opt-in when this is false.
    hall_of_fame: bool = False
    # Server-join gate: "open" (anyone can register) or "invite" (a valid
    # invite token is required). Clients prompt for an invite when "invite".
    # Defaults to "open" so old clients that ignore the field are unaffected.
    registration_policy: str = "open"
    # Operator-toggled optional features (admin console -> Features). Each
    # defaults True so old clients that ignore the field keep showing the tab;
    # a client that reads these hides the tab when the operator turns it off.
    # The backing routers are ALSO gated server-side, so flipping these off is
    # enforced regardless of client version.
    random_chat: bool = True
    # Hood, Stories and People Nearby were deleted on 2026-08-22 (routers,
    # tables and settings keys all). All three stay on the wire as a permanent
    # False so a shipped client hides the tab instead of discovering the 404 by
    # tapping.
    #
    # ⚠⚠ NOT optional, and dropping the field is NOT the same as sending False.
    # Every client defaults an ABSENT capability to True on purpose, so that an
    # old island that never heard of a feature still shows it. Nearby was cut
    # from this model rather than pinned to False for a few hours, and the
    # result was worse than a dead button: tapping it asked for the location
    # permission FIRST, then 404'd, and told the person their GPS had failed.
    # A deleted feature has to keep answering "off" for as long as any shipped
    # client still asks.
    hood: bool = False
    stories: bool = False
    nearby: bool = False
    # Abuse + bug reports to this island's operator, and reading their answers
    # back. Off means the client hides "Report" and "Report a bug" entirely;
    # reports already filed stay readable on both sides, so switching it off
    # closes the desk without cutting off a conversation in progress.
    reports: bool = True
    # How many accounts one device may hold. Advisory to the client (the server
    # can't see which accounts share a device); clients cap the account switcher.
    max_accounts_per_device: int = 5
    # F3 deposit-auth: when true the island issues anonymous blinded deposit
    # tokens (GET /deposit-auth/params + POST /deposit-auth/issue) and clients
    # mint + attach them to sealed deposits. Default false so old clients ignore
    # it and self-hosters stay on the open mailbox + per-IP cap.
    deposit_auth: bool = False


class ServerInfo(BaseModel):
    name: str
    # Optional operator welcome / rules text ("" = none).
    welcome: str = ""
    capabilities: ServerCapabilities


@router.get("/info", response_model=ServerInfo)
async def server_info() -> ServerInfo:
    eff = await server_settings.effective()
    return ServerInfo(
        name=eff["island_name"] or settings.APP_NAME,
        welcome=eff["welcome_text"],
        capabilities=ServerCapabilities(
            uin_shop=settings.UIN_SHOP_ENABLED,
            hall_of_fame=settings.HALL_OF_FAME_ENABLED,
            registration_policy=eff["registration_policy"],
            random_chat=eff["random_enabled"],
            reports=eff["reports_enabled"],
            max_accounts_per_device=eff["max_accounts_per_device"],
            deposit_auth=settings.DEPOSIT_AUTH_ENABLED,
        ),
    )
