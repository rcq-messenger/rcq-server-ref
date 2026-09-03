from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


def _read_version() -> str:
    """Running server version, from the repo-root VERSION file. Bumped on each
    release; drives the admin-console 'update available' check."""
    try:
        return (Path(__file__).resolve().parents[2] / "VERSION").read_text().strip() or "unknown"
    except OSError:
        return "unknown"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    APP_NAME: str = "RCQ Backend"

    # Running version (VERSION file) + best-effort self-host update check. The
    # admin console compares SERVER_VERSION against the VERSION on the repo's
    # main branch and shows an "update available" banner when behind. The check
    # is a cached, fail-silent outbound GET to GitHub — set RCQ_UPDATE_CHECK=false
    # in .env to disable it entirely (air-gapped installs).
    SERVER_VERSION: str = _read_version()
    RCQ_UPDATE_CHECK: bool = True
    UPDATE_CHECK_URL: str = "https://raw.githubusercontent.com/rcq-messenger/rcq-server-ref/main/VERSION"
    REPO_URL: str = "https://github.com/rcq-messenger/rcq-server-ref"
    # Show the crash-reports tab in the admin console. Default OFF — auto crash
    # reports are an RCQ-app maintainer concern, not a self-host operator's; they
    # just see user reports. The maintainer's flagship sets RCQ_ADMIN_SHOW_CRASHES=true.
    RCQ_ADMIN_SHOW_CRASHES: bool = False
    ENV: str = "dev"

    # Identity-bearing debug logging. OFF, and it has to stay off anywhere real
    # people are: with it on, the delivery lines in routers/messages.py, the two
    # push senders name the RECIPIENT of every message and
    # the geographic bucket of every checkin. Journald is capped at 1G, so that
    # is a few days of the who-talks-to-whom graph the database is deliberately
    # built not to keep, written in plain text one file away from the code
    # that promises we do not keep it (metadata-map-2026-08-22 §1.3).
    #
    # It is a flag on the CONTENT of a WARNING rather than a log level on
    # purpose: uvicorn leaves the root logger at WARNING, so `log.debug` and
    # even `log.info` from our own modules are invisible in production and a
    # level-based switch would be a switch that does nothing. Turn this on for a
    # dev box, or for a short deliberate window on an island whose operator owns
    # every account on it, and turn it off again.
    RCQ_LOG_IDENTITIES: bool = False

    DATABASE_URL: str = "sqlite+aiosqlite:///./rcq.db"
    REDIS_URL: str = "redis://localhost:6379/0"
    JWT_SECRET: str = "change-me-in-prod"
    JWT_ALG: str = "HS256"
    JWT_TTL_SECONDS: int = 60 * 60 * 24 * 30
    UIN_MIN: int = 100_000
    UIN_MAX: int = 999_999_999


    # Surface flag advertised via /server/info → consumed by the iOS
    # client to decide whether to render the in-app UIN-shop tab. Off
    # by default for self-host operators because Apple IAP is bound to
    # the App Store binary's bundle id, which means in-app purchases
    # route money to the iOS app's developer account regardless of
    # which backend is serving — incoherent if you're an operator
    # running this code and want to monetize your own users.
    # Operators who want a custom flow (Telegram-channel manual
    # assignment, BTCPay invoice page, Patreon-tier rewards) handle
    # UIN allocation out of band via an admin endpoint or DB write.
    UIN_SHOP_ENABLED: bool = False

    # Prices live in `RCQ_UIN_PRICES` and are read where they are used
    # (routers/uin_shop.py), next to the till key they belong with.

    # Hall of Fame leaderboard surface (rcq.app/hof). Off by default for
    # self-hosters — it's a flagship-community feature the operator doesn't run
    # or curate. Prod sets HALL_OF_FAME_ENABLED=true in /opt/rcq/.env, same as
    # the UIN shop flag above.
    HALL_OF_FAME_ENABLED: bool = False

    # F3 deposit-auth — anonymous blinded deposit tokens (RFC 9474 RSABSSA) for
    # sealed-sender spam resistance. OFF by default (the island runs the open
    # mailbox + per-IP cap). When ENABLED the island serves /deposit-auth/params
    # + /issue and advertises `deposit_auth=true` in /server/info, so clients mint
    # + attach tokens; verification stays additive. POW_BITS is the stranger
    # first-contact cost knob (SHA-256 hashcash leading-zero-bits; raise under
    # abuse). REQUIRED makes /messages/sealed reject deposits lacking a valid
    # token — a deliberate flag-day flip ONLY after all clients mint tokens.
    #
    # ENABLED defaults to true since stage 3 of the metadata plan: the same
    # tokens price one-time prekeys on the now-anonymous key lookups, and a
    # client only drops its session token from those lookups on an island
    # that issues tokens. An island with it off keeps the old, named path.
    # The issuer key lives in Redis and is minted on first use; nothing to
    # configure. POW_BITS 18: about a quarter of a million hashes per token,
    # well under a second on a phone and a couple of seconds in a browser;
    # enough to make draining a 100-key pool cost minutes, not milliseconds.
    DEPOSIT_AUTH_ENABLED: bool = True
    DEPOSIT_AUTH_POW_BITS: int = 18
    DEPOSIT_AUTH_REQUIRED: bool = False

    # APNs config — populated in production via /opt/rcq/.env. Empty values
    # disable push (the sender no-ops cleanly), so dev environments without
    # the .p8 key just don't send pushes — they don't crash.
    APNS_KEY_ID: str = ""
    APNS_TEAM_ID: str = ""
    APNS_BUNDLE_ID: str = "app.rcq.client"
    APNS_KEY_PATH: str = ""
    # "production" → api.push.apple.com (live). "sandbox" → api.sandbox.push.apple.com
    # (dev/TestFlight before app is in App Store). Toggle when builds switch tracks.
    APNS_ENVIRONMENT: str = "production"

    # TURN server (coturn) for WebRTC NAT-traversal. Public hostname/IP that
    # the iOS client can reach + the static auth secret coturn shares with
    # us for the REST-API auth pattern (HMAC-SHA1 of "<expiry>:<uin>"). Empty
    # values disable the /turn-credentials endpoint cleanly — calls fall
    # back to STUN-only and only succeed when both peers are on permissive
    # networks.
    TURN_HOST: str = ""
    TURN_SECRET: str = ""
    # TURN-over-TLS (turns:) port. 0 = disabled (plain UDP/TCP 3478 only).
    # Set to 443 — to a DPI censor a turns:443 allocation looks like ordinary
    # HTTPS, so it survives the UDP/plain-TCP blocking that breaks calls on
    # hostile mobile networks (e.g. RU CGNAT). Requires coturn to actually
    # listen with TLS on this port (tls-listening-port) using a cert whose SAN
    # covers TURN_HOST. 5349 is the IANA-standard turns port if 443 is taken.
    TURN_TLS_PORT: int = 0
    # Single-call TTL — coturn issues fresh credentials on every call and
    # they're discarded once the call ends, but 24h gives plenty of slack
    # for long calls or weak clocks. Don't push much higher; a leaked
    # username/password is valid until expiry.
    TURN_TTL_SECONDS: int = 86_400

    # Admin dashboard auth. The web UI at admin.rcq.app sends HTTP Basic
    # against /admin/* endpoints; the user types the username + password
    # once and the browser holds it for the session. Empty `ADMIN_USERNAME`
    # disables every /admin/* route entirely (returns 503), so a dev box
    # with no credentials configured cannot accidentally expose the panel.
    # Set in production via /opt/rcq/.env; rotate by restarting the
    # service after editing the file.
    ADMIN_USERNAME: str = ""
    ADMIN_PASSWORD: str = ""

    # Hosts that are ROADS to an island, not islands: CDN/domain fronts that
    # proxy every request through to a real island (the flagship's
    # cdn.rcq.app). A home-island record naming one of these as a "home" is
    # fiction — the mailbox behind the front IS the fronted island — and old
    # clients that stamped the road instead of the island produced exactly such
    # records. Both record PUTs reject them; without this, one polluted record
    # keeps re-publishing forever via the clients' read-before-publish
    # carry-over. Comma-separated bare hosts. The default stays correct for
    # every operator: cdn.rcq.app is the project's CDN front and is never
    # anyone's island.
    FRONT_ALIAS_HOSTS: str = "cdn.rcq.app"

    # Server-join gate. "open" (default) = anyone can /auth/register on this
    # server (the current behaviour). "invite" = registration requires a valid
    # invite token (see app/models/invite.py); orgs/islands that want only
    # specific people set this in their .env. Additive + default-open, so the
    # central server and every existing self-host stay open until they opt in.
    REGISTRATION_POLICY: str = "open"

    # Closed-island network gate (masquerade). When the operator runs the
    # masquerade Caddyfile, Caddy asks /gate/check on every request and serves a
    # decoy on anything but a 2xx. RCQ_AUTH_TOKEN is the legacy single master
    # token — historically a Caddy-only var, now ALSO read by the app so
    # /gate/check can honor it (set it in the APP env too, or single-token
    # deployments lock out when they move to the forward_auth Caddyfile). Leaving
    # it set is a permanent, unrevocable, reshareable bypass that sits in front of
    # the per-user access_tokens machinery — recommend UNSETTING it once you issue
    # per-user tokens. Empty = no master token (per-user tokens only).
    RCQ_AUTH_TOKEN: str = ""
    # Disable FastAPI's /docs + /openapi.json — the loudest "this is RCQ"
    # fingerprint. Operators running a masquerade/closed island set this true.
    RCQ_DOCS_DISABLED: bool = False


settings = Settings()


def log_identity(value: object) -> str:
    """One field of a log line: `value` when RCQ_LOG_IDENTITIES is on, `-` when
    it is not.

    A placeholder rather than a dropped field, so the line keeps ONE format
    string and an operator reading `to=-` in the journal can see that there is
    a field there and that it is switched off, instead of wondering whether
    this build ever had one. Every caller is a line that used to name a person:
    the delivery lines in routers/messages.py, the two push senders, the Nearby
    debug prints.
    """
    return str(value) if settings.RCQ_LOG_IDENTITIES else "-"
