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

import json
import re
import logging
import time
from fastapi import APIRouter, Header, status
from fastapi.responses import Response as RawResponse
from pydantic import BaseModel

from sqlalchemy import func, select

from app.core.config import settings
from app.core.db import SessionLocal
from app.models.user import User
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
    # ⚠ A CLOSED ISLAND WITHHOLDS THE KEY that seals an envelope to a resident,
    # so knowing a number stops being enough to write to somebody. Published
    # because the refusal itself deliberately cannot say so: it is byte for
    # byte "no such number", or a closed island becomes a directory for
    # guessing which numbers exist. The client is the only thing that can tell
    # a person the truth ("this island is closed, you need a link from the
    # person"), and it can only do that if it was told in advance.
    #
    # Defaults FALSE, so an island older than the field, and every open island,
    # is unchanged.
    closed_island: bool = False
    #: Whether a person on ANOTHER island can start a conversation with someone
    #: here. A closed island answers yes: it withholds every word that
    #: describes a resident but still hands out the keys an envelope is sealed
    #: with, because without them it is not on the network at all. Only an
    #: operator who sets `federation_refuse_strangers` turns this off, and then
    #: the client can say so instead of showing a failure it cannot explain.
    #:
    #: Defaults TRUE, which is what every island older than this field does.
    cross_island: bool = True
    #: What this island charges to join, in US cents; 0 = not sold. Published
    #: so a person sees the price in the picker BEFORE they try to register and
    #: are refused, rather than after.
    entry_price_cents: int = 0
    #: Where entry is bought, when the island wants to name a page. Never shown
    #: on iOS: Apple does not allow an app to point at a purchase it does not
    #: handle.
    entry_url: str = ""
    #: This island's own till (the checkout worker, deploy/console-worker),
    #: https only, from the same `uin_till_url` setting that sells numbers: one
    #: till per island serves numbers, resale and entry, and there is no second
    #: URL to keep in step with it.
    #:
    #: THE RULE: a client renders the in-app entry gateway ONLY when the island
    #: names `till_url` here. There is no built-in fallback for entry in any
    #: client, on any platform, ever. The number shop needed `X-RCQ-Checkout`
    #: (routers/uin_shop.py) because shipped clients carried OUR till compiled
    #: in and would send a self-hoster's customer to pay us; entry avoids that
    #: by construction. Nothing older than this field draws the gateway, and an
    #: island with no till gets today's `entry_url` link or nothing at all.
    #:
    #: Defaults "" so every shipped client ignores it.
    till_url: str = ""
    #: The operator's own terms of sale and refund page, when they name one.
    #: A client that sells entry from inside the app links it beside the
    #: payment, because on a self-hosted island the OPERATOR is the seller and
    #: their terms apply; the RCQ team's terms at rcq.app cover the flagship
    #: only and must never be linked for somebody else's sale. Empty means the
    #: client says instead that refunds are the operator's decision.
    #:
    #: Defaults "" so every shipped client ignores it.
    terms_url: str = ""
    #: How many accounts live here. Published so the island picker can say it
    #: on the card, beside the price: a number is what makes a closed club read
    #: as a place rather than a paywall (founder, 09.09).
    #:
    #: ⚠ ON THIS REPLY RATHER THAN ITS OWN ENDPOINT, deliberately. The clients
    #: already fetch /server/info for every card the reader looks at, so the
    #: count costs no extra request and no extra island learns this device's
    #: address. `/public/stats` still exists and still answers; this is the
    #: same number where the callers already are.
    #:
    #: 0 means "not published" — an island older than this field, and the
    #: window after a restart before the first count — so a client draws
    #: nothing rather than claiming an empty island.
    user_count: int = 0
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
    #
    # ⚠⚠ TURNED OFF ON A CLOSED ISLAND, and that is a deliberate trade. A
    # closed island has to be able to tell a resident from an outsider at the
    # key doors, and an anonymous fetch names nobody by design — so either the
    # door lets every anonymous caller through, which is no door at all, or it
    # refuses residents using the anonymous path. Saying "not available here"
    # is the only honest third answer. The cost is real: the island learns
    # which resident asked about whom, metadata it does not learn on an open
    # island. A closed island already knows its residents; an open one is where
    # this feature earns its keep, and there it is untouched.
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


class BadgeText(BaseModel):
    """What this island calls one of its badges."""

    label: str = ""
    description: str = ""
    #: A hex colour, so an island can mint a kind the clients have never seen
    #: and still have it look like something. Empty means "use your own".
    color: str = ""


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
    #: The island's own words for its badges, keyed by kind.
    #:
    #: ⚠ PUBLIC on purpose, and needed before any account exists: a client
    #: draws a badge on a stranger's card and in a room's member list, both of
    #: which happen before you have anything to do with this island. The kinds
    #: themselves are an open dictionary, so an island can mint "resident" or
    #: "founder"; a client that has never heard of the slug renders whatever is
    #: here, and falls back to a plain mark from this island when it is empty.
    badges: dict[str, BadgeText] = {}


log = logging.getLogger(__name__)

_BADGE_KIND_RE = re.compile(r"^[a-z][a-z0-9_-]{0,15}$")


def _badge_texts(raw: str) -> dict[str, BadgeText]:
    """Parse the operator's badge JSON, forgivingly.

    Forgiving because this is on the path every client takes to draw anything,
    and an operator's typo in one badge must not blank the island's name. A
    value that will not parse is logged and dropped; the clients then use their
    own defaults, which is exactly what happens on an island that never set it.
    """
    raw = (raw or "").strip()
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
        if not isinstance(parsed, dict):
            raise ValueError("badge_labels must be an object keyed by kind")
        out: dict[str, BadgeText] = {}
        for kind, value in parsed.items():
            if not isinstance(kind, str) or not _BADGE_KIND_RE.match(kind):
                continue
            if isinstance(value, str):
                out[kind] = BadgeText(label=value[:64])
            elif isinstance(value, dict):
                out[kind] = BadgeText(
                    label=str(value.get("label") or "")[:64],
                    description=str(value.get("description") or "")[:280],
                    color=str(value.get("color") or "")[:16],
                )
        return out
    except Exception as exc:  # noqa: BLE001
        log.warning("[server-info] badge_labels is not usable (%s); clients will use their own", exc)
        return {}


def _https_only(raw: object) -> str:
    """A URL a client may send MONEY through, or "". Only https: a till named
    over plain http would hand every buyer's invoice to whoever sits on the
    wire, and "" makes every client draw no gateway at all, which is the safe
    answer. Trailing slashes are dropped so the clients can append paths."""
    value = str(raw or "").strip().rstrip("/")
    return value if value.lower().startswith("https://") else ""


def _http_or_https(raw: object) -> str:
    """A URL a client may OPEN, or "". A terms page is a link, not a payment
    path, so plain http is tolerated (a LAN island may have no certificate);
    anything without a web scheme is dropped rather than handed to a browser."""
    value = str(raw or "").strip()
    return value if value.lower().startswith(("https://", "http://")) else ""


#: `/server/info` is asked by every client on boot and by every island card a
#: person swipes past, so the headcount behind it is counted at most once a
#: minute and served from here in between. A minute-old number is right for a
#: figure that moves by ones.
_USER_COUNT: tuple[float, int] = (0.0, 0)
_USER_COUNT_TTL = 60.0


async def _user_count() -> int:
    """Accounts on this island, cached. Returns 0 if the count cannot be taken:
    the field's own contract is that 0 means "not published", and a card that
    draws nothing is better than one that says an island is empty."""
    global _USER_COUNT
    at, value = _USER_COUNT
    now = time.monotonic()
    if value and now - at < _USER_COUNT_TTL:
        return value
    try:
        async with SessionLocal() as db:
            count = int(await db.scalar(select(func.count(User.uin))) or 0)
    except Exception:
        return value
    _USER_COUNT = (now, count)
    return count


@router.get("/info", response_model=ServerInfo)
async def server_info() -> ServerInfo:
    eff = await server_settings.effective()
    return ServerInfo(
        name=await server_settings.island_name(),
        welcome=eff["welcome_text"],
        logo_version=await island_logo.version(),
        badges=_badge_texts(eff["badge_labels"]),
        capabilities=ServerCapabilities(
            # ⚠ From the console like every other capability on this reply.
            # It alone read the .env constant, so an operator who opened their
            # shop in the console moved the ENDPOINTS and not the clients: the
            # apps kept hiding the storefront because /server/info still said
            # off, and nothing explained why.
            uin_shop=eff["uin_shop_enabled"],
            hall_of_fame=settings.HALL_OF_FAME_ENABLED,
            registration_policy=eff["registration_policy"],
            closed_island=bool(eff["closed_island"]),
            # ⚠ A CLOSED ISLAND DOES SERVE ANONYMOUS KEY FETCHES, and saying
            # otherwise here was part of the same mistake as refusing them:
            # what a closed island withholds is everything that DESCRIBES a
            # resident, not the three keys an envelope cannot be sealed
            # without. Only an operator who has explicitly asked to be off the
            # network answers no.
            anon_keys=not (
                bool(eff["closed_island"])
                and bool(eff["federation_refuse_strangers"])
            ),
            cross_island=not (
                bool(eff["closed_island"])
                and bool(eff["federation_refuse_strangers"])
            ),
            # ⚠ Only on a CLOSED island. An open island that has a leftover
            # number in the setting must not quote a price for something
            # anybody can have for nothing.
            # ⚠⚠ PUBLISHED WHENEVER ENTRY IS FOR SALE, not only when the door
            # is locked. These were gated on `closed_island`, and the two are
            # different facts: an island can sell residency — a mark, invites,
            # a place — while still letting anybody in for free. The flagship is
            # exactly that today.
            #
            # Gating them here had a price paid in real money: the till was
            # selling entry codes, every client only draws the code field for an
            # island that REFUSES it, so a buyer registered successfully without
            # ever being asked for the code, and their payment bought nothing.
            # Selling something a client cannot show a box for is the bug.
            entry_price_cents=int(eff["entry_price_cents"]),
            entry_url=str(eff["entry_url"]),
            till_url=_https_only(eff["uin_till_url"]),
            terms_url=_http_or_https(eff["terms_url"]),
            user_count=await _user_count(),
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
