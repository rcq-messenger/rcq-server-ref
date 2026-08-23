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

from fastapi import APIRouter, Header, status
from fastapi.responses import Response as RawResponse
from pydantic import BaseModel

from app.core.config import settings
from app.routers import media, vault
from app.services import island_logo, server_settings


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
    # Group polls, removed on 2026-08-23 (routers/polls.py carries the why).
    #
    # ⚠ This key is NEW and False from birth, which is a different situation
    # from the three above: they already had a flag every client read, so
    # pinning it to False hid them the same day. Polls never had one, so not a
    # single build in the field can see this yet and all of them still show the
    # composer. The endpoints answer 410 Gone with `feature_removed` in the
    # meantime, which is the half of the promise that works today; this key is
    # the half that works from the next client release on, and it then stays on
    # the wire as a permanent False for exactly as long as any shipped client
    # still asks, same as hood/stories/nearby.
    polls: bool = False
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
    # Stage 2 metadata cut: this island understands the 3-value envelope CLASS.
    # It accepts `cls` + `ring` on POST /messages/sealed (envelope_type stays an
    # ingest alias forever), and serves `cls` + the durable per-mailbox `seq`
    # alongside envelope_type + id on the queue drain. A new client keys its
    # switch to reading `seq` / sending `cls` on this flag; islands upgrade
    # independently, so an OLDER peer that lacks the field is treated as "off" by
    # a new client and keeps getting envelope_type only. It is a permanent
    # capability of THIS codebase (not an operator toggle), so it is always True
    # here — the same reasoning that pins hood/stories/nearby to a constant.
    envelope_class: bool = True
    # Stage 3 metadata cut: GET /keys/{uin}/devices and the two bundle
    # lookups take no session token; a one-time prekey is handed out against
    # an anonymous deposit token (`X-Deposit-Token`) instead. A client that
    # sees this true stops authenticating those three calls. Permanent
    # capability of this codebase, like `envelope_class`; whether the island
    # also ISSUES tokens is `deposit_auth` (without it a sender still gets the
    # signed prekey anonymously and the OPK only under its session token).
    anon_keys: bool = True
    # Stage 5 metadata cut: rooms are served from one log per room
    # (POST /messages/group-log/fetch + /ack) instead of a per-member copy of
    # every post. A client that sees this true drains rooms from the log and
    # keeps draining /messages/queue for whatever legacy rows it still holds.
    # Permanent capability of this codebase, like `envelope_class`.
    group_log: bool = True
    # Stage 4a: PUT/GET/DELETE /vault/{slot}, opaque versioned client-sealed
    # slots per account (see routers/vault.py). Permanent capability of this
    # codebase. A client that sees it keeps its contact list in the vault and
    # on the device; one that does not keeps using /contacts.
    vault: bool = True
    vault_max_blob_bytes: int = 0
    vault_max_slots: int = 0
    # Stage 4b: this island understands the per-install `vault_contacts`
    # capability of SPEC 2.12 and serves `POST /users/lookup` (SPEC 4.10), so
    # a client can turn the numbers in its own vault slot into list rows
    # without the `/contacts` JOIN. Permanent capability of this codebase,
    # like `envelope_class` and `group_log`.
    users_lookup: bool = True
    # ⚠ FALSE, and it answers false rather than disappearing (the `hood` /
    # `stories` / `nearby` rule: a missing key is not the same message as an
    # explicit one). The read-only phase is NOT on. The island still records
    # both directed rows for every accepted pair, because the five
    # server-side rules that read them (calls, room invites, presence,
    # last_seen, the picture) only move at the DROP and their client halves
    # are not shipped -- `services/contact_source` has the long version. A
    # client must keep treating `GET /contacts` as a live list while this is
    # false; when it flips, its own vault slot is the truth.
    contacts_readonly: bool = False
    # The `/media` blob ceiling this island enforces while reading an upload
    # body (routers/media.py MAX_BLOB_SIZE, env-tunable per island). Purely
    # informational: nothing here changes what the endpoint does. It exists so
    # a client can refuse an oversize video in the composer instead of
    # discovering the limit at byte 536,870,913 of an upload the person has
    # been watching for twenty minutes. A client that does not read it behaves
    # exactly as before, and an island that predates the field omits it, which
    # a client reads as "did not say" and falls back to its own default.
    media_max_blob_bytes: int = 0


class ServerInfo(BaseModel):
    name: str
    # Optional operator welcome / rules text ("" = none).
    welcome: str = ""
    # The island's logo, as a 12-character digest of the picture. "" = this
    # island has no logo and the client draws the lettered tile it always drew.
    #
    # ⚠ A VERSION, NOT THE PICTURE, and not a URL either. Three reasons, in
    # order of how much they cost when got wrong:
    #
    #   1. This reply is fetched on every connect, for every account, and by
    #      the cross-island paths before a key lookup or a waking call. On the
    #      web it is awaited under the cross-tab provisioning lock before every
    #      v=2 send. Inlining even a 20 KB data URI puts the whole picture on
    #      that path, every time, with no way to revalidate it separately from
    #      the flags. As a digest it is 12 bytes and the picture is one
    #      `GET /server/logo` the client caches for as long as this string
    #      does not change.
    #   2. A URL would let an island point a client at a third-party host, and
    #      a client that loaded it would be handing its IP to whoever the
    #      operator named -- on an island it does not even have an account on,
    #      since these probes are made against strangers. Clients build the URL
    #      themselves from the host they were already talking to; the only
    #      thing this field decides is WHETHER, and WHICH.
    #   3. An island older than this field omits it, a client reads "" and
    #      falls back to the tile: the same permissive-default rule the
    #      capability flags follow.
    logo_version: str = ""
    capabilities: ServerCapabilities


@router.get("/info", response_model=ServerInfo)
async def server_info() -> ServerInfo:
    eff = await server_settings.effective()
    return ServerInfo(
        name=eff["island_name"] or settings.APP_NAME,
        welcome=eff["welcome_text"],
        logo_version=await island_logo.version(),
        capabilities=ServerCapabilities(
            uin_shop=settings.UIN_SHOP_ENABLED,
            hall_of_fame=settings.HALL_OF_FAME_ENABLED,
            registration_policy=eff["registration_policy"],
            random_chat=eff["random_enabled"],
            reports=eff["reports_enabled"],
            max_accounts_per_device=eff["max_accounts_per_device"],
            deposit_auth=settings.DEPOSIT_AUTH_ENABLED,
            vault_max_blob_bytes=vault.MAX_BLOB_BYTES,
            vault_max_slots=vault.MAX_SLOTS,
            media_max_blob_bytes=media.MAX_BLOB_SIZE,
        ),
    )


@router.get("/logo", include_in_schema=False)
async def server_logo(
    if_none_match: str | None = Header(default=None, alias="If-None-Match"),
) -> RawResponse:
    """This island's logo, as raw image bytes. Unauthenticated, like
    `/server/info`: it is the island's public face, drawn on a join confirm
    before anybody has an account here.

    404 when no logo is set, which is the common case and is not an error: a
    client that gets it draws the lettered tile, the same one it draws while
    this request is still in flight and the same one it draws if the bytes
    arrive corrupt. There is no state in which a client is left with a broken
    image or an empty box.

    Cached hard, and safely: clients are expected to append the
    `logo_version` from `/server/info` as `?v=`, so a changed logo is a
    changed URL. `ETag` covers the clients (and the CDN in front of the
    flagship) that ask again anyway -- a revalidation costs a 304 with no body.
    """
    row = await island_logo.current()
    if row is None:
        return RawResponse(status_code=status.HTTP_404_NOT_FOUND)
    mime, blob, version = row
    etag = f'"{version}"'
    headers = {
        "ETag": etag,
        # A day, not a year: an operator who fixes a logo without the client
        # re-reading /server/info (a long-lived desktop window, say) should not
        # be stuck with the old one until the app restarts. With `?v=` on the
        # URL the practical lifetime is unbounded anyway.
        "Cache-Control": "public, max-age=86400",
        # The picture is the same for everyone and carries no account, but the
        # header costs nothing and keeps a shared cache honest.
        "Vary": "Accept-Encoding",
    }
    if if_none_match and etag in [t.strip() for t in if_none_match.split(",")]:
        return RawResponse(status_code=status.HTTP_304_NOT_MODIFIED, headers=headers)
    return RawResponse(content=blob, media_type=mime, headers=headers)
