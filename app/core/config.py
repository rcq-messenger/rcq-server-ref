from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    APP_NAME: str = "RCQ Backend"
    ENV: str = "dev"
    DATABASE_URL: str = "sqlite+aiosqlite:///./rcq.db"
    REDIS_URL: str = "redis://localhost:6379/0"
    JWT_SECRET: str = "change-me-in-prod"
    JWT_ALG: str = "HS256"
    JWT_TTL_SECONDS: int = 60 * 60 * 24 * 30
    UIN_MIN: int = 100_000
    UIN_MAX: int = 999_999_999

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


settings = Settings()
