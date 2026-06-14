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
    DATABASE_URL: str = "sqlite+aiosqlite:///./rcq.db"
    REDIS_URL: str = "redis://localhost:6379/0"
    JWT_SECRET: str = "change-me-in-prod"
    JWT_ALG: str = "HS256"
    JWT_TTL_SECONDS: int = 60 * 60 * 24 * 30
    UIN_MIN: int = 100_000
    UIN_MAX: int = 999_999_999

    # Seed a catalogue of demo/fake users at first boot so an EMPTY directory
    # doesn't look dead during early development. OFF by default: self-hosted
    # islands must never silently grow phantom accounts their operators didn't
    # create. Set SEED_FAKE_USERS=true in .env to opt a server in.
    SEED_FAKE_USERS: bool = False

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

    # Server-join gate. "open" (default) = anyone can /auth/register on this
    # server (the current behaviour). "invite" = registration requires a valid
    # invite token (see app/models/invite.py); orgs/islands that want only
    # specific people set this in their .env. Additive + default-open, so the
    # central server and every existing self-host stay open until they opt in.
    REGISTRATION_POLICY: str = "open"


settings = Settings()
