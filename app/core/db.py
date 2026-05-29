from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from .config import settings


class Base(DeclarativeBase):
    pass


# Managed Postgres has a hard, small connection cap (DigitalOcean's
# smallest plan tops out at 25 total, 3 reserved for the superuser, and
# DO's own monitoring eats several more). SQLAlchemy's default pool
# (5 + 10 overflow) is *per process*, so 4 uvicorn workers can demand up
# to 60 connections and exhaust the DB — surfacing as
# asyncpg.TooManyConnectionsError turned into an HTTP 500 on EVERY
# endpoint (sends AND reads), intermittently under load. Cap each
# worker's pool so all 4 stay well under budget (4 × (2 + 1) = 12),
# pre-ping to drop connections DO closed under us, and recycle before
# the idle timeout. The pooling kwargs are Postgres-only: the SQLite
# self-host / test path uses a pool class that rejects them.
_engine_kwargs: dict = {"echo": False, "future": True}
if settings.DATABASE_URL.startswith(("postgresql", "postgres")):
    _engine_kwargs.update(
        pool_size=2,
        max_overflow=1,
        pool_timeout=20,
        pool_pre_ping=True,
        pool_recycle=1800,
    )
engine = create_async_engine(settings.DATABASE_URL, **_engine_kwargs)
SessionLocal = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)


async def get_db() -> AsyncSession:
    async with SessionLocal() as session:
        yield session


# Stage 3 in-place migration of additive columns on `users`. SQLAlchemy's
# `create_all` happily creates the new `one_time_prekeys` table from
# scratch but won't touch an existing `users` table — so we hand-roll
# `ALTER TABLE ADD COLUMN` for each column we added in this stage.
#
# Cross-dialect quirks:
#   - PostgreSQL supports `ADD COLUMN IF NOT EXISTS` (since 9.6), so the
#     statement is naturally idempotent and never raises. We use that.
#   - SQLite has no IF NOT EXISTS for ADD COLUMN — second boot would
#     raise "duplicate column name". Each ALTER runs in its own
#     transaction (`engine.begin()` per column) so a duplicate-column
#     error doesn't poison subsequent statements; we swallow the
#     exception. PG treats the same isolation as defensive
#     belt-and-suspenders if `IF NOT EXISTS` isn't honoured for some
#     reason.
#   - `TIMESTAMP WITH TIME ZONE` is PG's TIMESTAMPTZ; SQLite accepts
#     arbitrary type strings (dynamic typing) and just stores it as
#     text, which SQLAlchemy then re-parses as a tz-aware datetime via
#     the `DateTime(timezone=True)` column declaration on the model.
_USER_STAGE3_COLUMNS: list[tuple[str, str]] = [
    ("signal_identity_key", "TEXT"),
    ("signal_registration_id", "INTEGER"),
    ("signed_prekey_id", "INTEGER"),
    ("signed_prekey_public", "TEXT"),
    ("signed_prekey_signature", "TEXT"),
    ("signed_prekey_uploaded_at", "TIMESTAMP WITH TIME ZONE"),
    ("kyber_prekey_id", "INTEGER"),
    ("kyber_prekey_public", "TEXT"),
    ("kyber_prekey_signature", "TEXT"),
    ("kyber_prekey_uploaded_at", "TIMESTAMP WITH TIME ZONE"),
    # Last-seen visibility — additive. Default "everyone" matches the
    # column default in the model; existing rows pick that up via the
    # SQL `DEFAULT 'everyone'` clause. PG's DDL needs the literal in
    # the ALTER syntax, SQLite is happy either way.
    ("last_seen_visibility", "TEXT DEFAULT 'everyone'"),
    ("gender_visibility", "TEXT DEFAULT 'nobody'"),
    ("group_invite_policy", "TEXT DEFAULT 'everyone'"),
    ("trade_policy", "TEXT DEFAULT 'everyone'"),
    ("call_policy", "TEXT DEFAULT 'everyone'"),
    # Tri-state gate iOS uses to decide whether to send a
    # `.readReceipt` envelope. Enforced client-side only — server
    # mirrors the setting to the owner so Settings can show it.
    ("read_receipts_visibility", "TEXT DEFAULT 'everyone'"),
    # Tri-state gate for profile-card fields (name/age/city/etc).
    # Mirrors the other *_visibility columns; default "everyone"
    # keeps existing accounts unchanged.
    ("profile_visibility", "TEXT DEFAULT 'everyone'"),
    # Social reputation counter — bumped by `/reputation/grant`. Default 0
    # so every existing row defaults to zero rep without a backfill pass.
    ("reputation", "BIGINT DEFAULT 0"),
    # Tri-state visibility for the rep counter (everyone | contacts | nobody).
    # Display-only gate; the grant endpoint ignores it.
    ("reputation_visibility", "TEXT DEFAULT 'everyone'"),
    # Per-user push toggles + muted-uin list. NULL = use code-side
    # defaults (`_pref` in apns.py); writes flow through PUT
    # /users/me/push-preferences. JSON gets cross-dialect support
    # via SQLAlchemy's `JSON` type — PG stores as JSONB, SQLite as
    # text we re-decode on read.
    ("push_preferences", "JSON"),
    # Admin-set ban flag. Default false — only flipped via
    # /admin/users/{uin}/ban after a Reports-queue review.
    ("is_suspended", "BOOLEAN DEFAULT FALSE"),
    # Distinct-active-days counter + last-bumped day string. Drive
    # referral activation; additive so existing rows start at 0/NULL.
    ("active_days", "INTEGER DEFAULT 0"),
    ("last_active_day", "VARCHAR(10)"),
    # Note: GroupMessageView is a fresh table created via create_all
    # on first boot; no ALTER needed for additive-column case.
    # When TRUE, the user's chosen `status` (online/away/dnd) is
    # broadcast to contacts even when their WebSocket has been gone
    # for longer than PRESENCE_FRESHNESS_SECONDS. Lets users keep
    # showing as "around" without their app actually running. Default
    # FALSE preserves the historical "killed app = offline" semantics.
    ("presence_persistent", "BOOLEAN DEFAULT FALSE"),
    # Optional TTL cap (minutes) for presence_persistent. NULL/0 =
    # forever (legacy persistent behaviour). N>0 = appear "visible"
    # for N minutes past last_seen, then fall back to offline.
    ("presence_ttl_minutes", "INTEGER"),
]

# Additive columns on `nearby_checkins`. Same idempotent
# ADD COLUMN pattern as the user table — `create_all` doesn't
# touch tables that already exist.
_NEARBY_CHECKIN_COLUMNS: list[tuple[str, str]] = [
    ("display_name", "VARCHAR(64)"),
]

# Additive on `groups`. Pre-existing rows default to free + everyone-
# can-post, matching pre-feature behaviour. Avatar columns nullable —
# legacy groups keep rendering the generic placeholder.
_GROUP_COLUMNS: list[tuple[str, str]] = [
    ("post_policy", "VARCHAR(16) DEFAULT 'all'"),
    ("avatar_media_id", "VARCHAR(64)"),
    ("avatar_media_key", "VARCHAR(96)"),
    ("is_closed", "BOOLEAN DEFAULT FALSE"),
    # Owner/admin-editable free-text description. NULL for legacy
    # rows — clients render the group with no description blurb.
    ("description", "TEXT"),
    # Hide the member roster from Group Info (display-only gate).
    ("members_hidden", "BOOLEAN DEFAULT FALSE"),
    # Sticky group announcement. Plaintext on the server (see model
    # comment) so brand-new joiners can see rules / welcome without
    # waiting for X3DH to complete with every existing member.
    ("pinned_text", "VARCHAR(500)"),
    ("pinned_at", "TIMESTAMP WITH TIME ZONE"),
    ("pinned_by", "BIGINT"),
]

# Additive on `audio_rooms` — owner-only-speaking toggle. Pre-existing
# rows default false (anyone can speak), matching prior behaviour.
_AUDIO_ROOM_COLUMNS: list[tuple[str, str]] = [
    ("owner_only_speaking", "BOOLEAN DEFAULT FALSE"),
]

# Additive on `reports` — evidence-attachment fields for the
# premium / media report flow. Existing rows have NULL in all three;
# reason-only reports never populate them.
_REPORT_COLUMNS: list[tuple[str, str]] = [
    ("evidence_path", "VARCHAR(255)"),
    ("evidence_mime", "VARCHAR(64)"),
    ("message_id", "VARCHAR(36)"),
    # Bug-bounty multi-attachment lane. JSON array of
    # {media_id, key, mime, size}; each entry references an encrypted
    # blob in /media + carries the AES key for client-side decrypt in
    # the admin queue. NULL for legacy reason-only reports.
    ("attachments", "JSON"),
]

async def init_db() -> None:
    from app.models import user, contact, message, group, device_token, prekey, nearby, audio_room, report, poll, news, referral, story, hood_banner, hood_message  # noqa: F401  (register tables)

    dialect = engine.dialect.name  # 'postgresql' | 'sqlite' | ...

    # Serialise schema creation across uvicorn workers. Without the lock,
    # `--workers N` on a fresh Postgres DB races: every worker calls
    # `create_all()` simultaneously, and the second one crashes with
    # `UniqueViolationError` on `pg_class_relname_nsp_index` because the
    # first has already issued the CREATE SEQUENCE for `users_uin_seq`.
    # `pg_advisory_xact_lock` is session-level but auto-releases at end
    # of the transaction, so once create_all returns and the `begin()`
    # block exits, the lock is gone. Subsequent workers wake up, see
    # every table already present (create_all is idempotent with
    # checkfirst=True, the default), and proceed.
    #
    # SQLite has no analogue and doesn't need one — it doesn't run
    # multi-worker uvicorn realistically (writes serialise on the file
    # lock anyway), and the test suite hits it single-process.
    async with engine.begin() as conn:
        if dialect == "postgresql":
            # Two int32 args by convention. Constants are arbitrary;
            # 0x52435100 = "RCQ\0" packs the project name as a sentinel
            # so it's identifiable in pg_locks during debugging.
            await conn.execute(text("SELECT pg_advisory_xact_lock(0x52435100, 1)"))
        await conn.run_sync(Base.metadata.create_all)
    additive: list[tuple[str, list[tuple[str, str]]]] = [
        ("users", _USER_STAGE3_COLUMNS),
        ("nearby_checkins", _NEARBY_CHECKIN_COLUMNS),
        ("groups", _GROUP_COLUMNS),
        ("audio_rooms", _AUDIO_ROOM_COLUMNS),
        ("reports", _REPORT_COLUMNS),
    ]
    for table, columns in additive:
        for col, typ in columns:
            # Each ALTER in its own transaction. PG aborts the whole
            # transaction on a single statement error; running per-stmt
            # avoids one stray failure cascading.
            async with engine.begin() as conn:
                try:
                    if dialect == "postgresql":
                        await conn.execute(text(
                            f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {col} {typ}"
                        ))
                    else:
                        await conn.execute(text(
                            f"ALTER TABLE {table} ADD COLUMN {col} {typ}"
                        ))
                except Exception:
                    # Column already exists (SQLite duplicate-column path)
                    # or the DB is too old to know IF NOT EXISTS. Either
                    # way the column is there; downstream code will fail
                    # loudly if it actually isn't.
                    pass

    # ── Pivot 2026-05-27: drop tables for cut features ─────────────
    # Marketplace / trades / UIN auctions / casino games / items /
    # pet hunt / bounty credits / jeton reactions / daily QA /
    # reputation / hood banners / paid traffic — all stripped from
    # the codebase. Drop their tables (idempotent, no-op if absent)
    # so the managed Postgres stops accumulating dead rows + the
    # row-count graph in admin matches actual usage. Order honours
    # FK chains: leaf tables first, then parents.
    _PIVOT_DROP_TABLES: list[str] = [
        # casino / inventory leaves
        "item_history", "item_instances", "kind_mint_slots",
        "trades", "marketplace_listings",
        "owned_uins", "uin_auction_bids", "uin_auctions",
        "uin_marketplace_listings",
        "pet_hunt_state",
        "premium_unlocks",
        "message_jetons",
        "member_wallets", "inventory_settings",
        # economy leaves
        "bounty_credits", "daily_qa_progress",
        "reputation_grants",
        "traffic_usage",
        "admin_grants",
    ]
    for table in _PIVOT_DROP_TABLES:
        async with engine.begin() as conn:
            try:
                if dialect == "postgresql":
                    await conn.execute(text(f"DROP TABLE IF EXISTS {table} CASCADE"))
                else:
                    await conn.execute(text(f"DROP TABLE IF EXISTS {table}"))
            except Exception:
                pass
