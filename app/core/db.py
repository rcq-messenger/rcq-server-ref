import logging
import secrets

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from .config import settings

log = logging.getLogger(__name__)


class Base(DeclarativeBase):
    pass


# Managed Postgres has a hard, small connection cap (DigitalOcean's
# smallest plan tops out at 25 total, 3 reserved for the superuser, and
# DO's own monitoring eats several more). SQLAlchemy's default pool
# (5 + 10 overflow) is *per process*, so 4 uvicorn workers can demand up
# to 60 connections and exhaust the DB — surfacing as
# asyncpg.TooManyConnectionsError turned into an HTTP 500 on EVERY
# endpoint (sends AND reads), intermittently under load.
#
# BUT that budget applies to *backend* connections, and prod does not talk
# to Postgres directly: DATABASE_URL points at DO's PgBouncer pool
# (`rcq-pool`, TRANSACTION mode, port 25061, backend size 15). PgBouncer's
# whole job is to multiplex many client connections onto those 15 backends,
# so sizing the app pool as if each client connection were a backend one
# left the workers strangled: 4 × (2 + 1) = 12 client connections total,
# and prod logged 423 `QueuePool limit of size 2 overflow 1 reached` timeouts
# in 24h, each one an HTTP request or a background job (a retention sweep,
# a push fan-out) dying at the checkout, not at the database.
#
# 4 × (5 + 5) = 40 client connections queue at PgBouncer instead of erroring
# at SQLAlchemy, which is what PgBouncer is for. Pre-ping drops connections
# DO closed under us, and recycle beats the idle timeout. The pooling kwargs
# are Postgres-only: the SQLite self-host / test path uses a pool class that
# rejects them.
_engine_kwargs: dict = {"echo": False, "future": True}
if settings.DATABASE_URL.startswith(("postgresql", "postgres")):
    _engine_kwargs.update(
        pool_size=5,
        max_overflow=5,
        pool_timeout=20,
        pool_pre_ping=True,
        pool_recycle=1800,
        # PgBouncer (DO managed-Postgres connection pool, port 25061) runs in
        # TRANSACTION mode, which is incompatible with server-side prepared
        # statements: asyncpg caches them per backend connection, but PgBouncer
        # hands each transaction whatever backend conn is free, so a cached
        # statement may not exist there ("prepared statement ... does not
        # exist"). Disabling both caches makes every query a one-shot, which is
        # PgBouncer-safe — and harmless on a direct (:25060) connection too, so
        # this is correct whether DATABASE_URL points at the pool or direct.
        connect_args={"statement_cache_size": 0, "prepared_statement_cache_size": 0},
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
    # Privacy tri-states — additive. Each DEFAULT here must match the
    # column default in models/user.py; existing rows pick it up via the
    # SQL `DEFAULT` clause. PG's DDL needs the literal in the ALTER
    # syntax, SQLite is happy either way.
    #
    # ⚠ These four moved from 'everyone' to 'contacts' on 2026-08-11.
    # The clause only covers rows added AFTER the ALTER, so an existing
    # deployment also needs the one-off backfill in
    # `tools/backfill_privacy_defaults.py`. A fresh island gets private
    # defaults straight from here.
    ("last_seen_visibility", "TEXT DEFAULT 'contacts'"),
    ("gender_visibility", "TEXT DEFAULT 'nobody'"),
    ("group_invite_policy", "TEXT DEFAULT 'contacts'"),
    ("call_policy", "TEXT DEFAULT 'contacts'"),
    # Tri-state gate iOS uses to decide whether to send a
    # `.readReceipt` envelope. Enforced client-side only — server
    # mirrors the setting to the owner so Settings can show it.
    ("read_receipts_visibility", "TEXT DEFAULT 'contacts'"),
    # Tri-state gate for profile-card fields (name/age/city/etc).
    # Mirrors the other *_visibility columns; default "everyone"
    # keeps existing accounts unchanged.
    ("profile_visibility", "TEXT DEFAULT 'everyone'"),
    # Per-user push toggles + muted-uin list. NULL = use code-side
    # defaults (`_pref` in apns.py); writes flow through PUT
    # /users/me/push-preferences. JSON gets cross-dialect support
    # via SQLAlchemy's `JSON` type — PG stores as JSONB, SQLite as
    # text we re-decode on read.
    ("push_preferences", "JSON"),
    # Admin-set ban flag. Default false — only flipped via
    # /admin/users/{uin}/ban after a Reports-queue review.
    ("is_suspended", "BOOLEAN DEFAULT FALSE"),
    # Profile picture (see models/user.py). Additive: NULL on every existing
    # row means "no picture", which is exactly the old behaviour.
    ("avatar_media_id", "VARCHAR(64)"),
    ("avatar_media_key", "VARCHAR(96)"),
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
    # Hall of Fame (founder-curated wall of notable contributors). The user
    # opts IN from their client; the founder separately APPROVES from the
    # admin console. Both must be true to appear on the public /hof wall.
    ("hof_opt_in", "BOOLEAN DEFAULT FALSE"),
    ("hof_approved", "BOOLEAN DEFAULT FALSE"),
    # Optional public Hall-of-Fame avatar — a small data-URI (image/gif|png|
    # jpeg|webp, base64, capped ~256KB) the user uploads next to the opt-in.
    # Stored inline (no media bucket) and served ONLY for approved members via
    # GET /public/hof/{uin}/avatar, so it is never public before the founder
    # approves. NULL = the initial-letter fallback on the wall.
    ("hof_avatar", "TEXT"),
    # Founder-assigned wall rating: 'bronze' | 'silver' | 'gold'. Defaults to
    # 'gold' so the pre-existing all-gold wall is unchanged after the migration
    # (every current member keeps a gold flower until the founder re-grades).
    ("hof_tier", "VARCHAR(8) DEFAULT 'gold'"),
    # Founder-granted credit for bug reports filed outside the in-app form
    # (closed tester chat, comments). Added to the counts derived from real
    # report rows — see the note on User.hof_bonus_reports for why this is a
    # column and not synthesised rows.
    ("hof_bonus_reports", "INTEGER DEFAULT 0"),
    ("hof_bonus_confirmed", "INTEGER DEFAULT 0"),
]

# Additive columns on `nearby_checkins`. Same idempotent
# ADD COLUMN pattern as the user table — `create_all` doesn't
# touch tables that already exist.
_NEARBY_CHECKIN_COLUMNS: list[tuple[str, str]] = [
    ("display_name", "VARCHAR(64)"),
]

# Additive on `one_time_prekeys` — multi-device pool tagging. NULL = the
# primary device (phone); existing rows are all NULL so the primary OPK
# paths (which now scope to `device_id IS NULL`) stay back-compatible. The
# `devices` table itself is created fresh by create_all (new table, no ALTER).
# Additive on `broker_relays` — paid tenancy. NULL means the public pool, which
# is every row that existed before this, so the distribution behaviour of the
# free fleet is unchanged by the column's arrival.
_BROKER_RELAY_COLUMNS: list[tuple[str, str]] = [
    ("tenant_id", "TEXT"),
]

_ONE_TIME_PREKEY_COLUMNS: list[tuple[str, str]] = [
    ("device_id", "INTEGER"),
]

# Additive on `contact_requests`. When the row left `pending`, which the
# retention sweep measures its grace from — created_at is a different clock
# (a week-old request accepted a minute ago must not be swept at once).
# Nullable: existing rows are pending, or were resolved before this existed.
_CONTACT_REQUEST_COLUMNS: list[tuple[str, str]] = [
    ("resolved_at", "TIMESTAMP WITH TIME ZONE"),
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
    # Unguessable half of a share link (see the model comment). Backfilled
    # for existing rows by `_backfill_group_share_tokens` below.
    ("share_token", "VARCHAR(32)"),
    # Owner-set content policy (clients honor; see model comment) + the
    # server-enforced slowmode. Defaults preserve existing behaviour.
    ("links_allowed", "BOOLEAN DEFAULT TRUE"),
    ("files_allowed", "BOOLEAN DEFAULT TRUE"),
    ("slowmode_sec", "INTEGER DEFAULT 0"),
]

# Additive on `group_members` — granular moderator capabilities the owner
# grants per member (comma-joined subset of delete|members|info). Empty for
# legacy rows (= plain member, no powers), matching pre-feature behaviour.
_GROUP_MEMBER_COLUMNS: list[tuple[str, str]] = [
    ("permissions", "VARCHAR(128) DEFAULT ''"),
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
    # Operator's answer to the reporter + when it was written. See
    # Report.reply_text: this is the only column on `reports` that the
    # reporter can read back, through GET /reports/mine.
    ("reply_text", "TEXT DEFAULT ''"),
    ("replied_at", "TIMESTAMPTZ"),
]

# Additive on `invites` — an optional reserved UIN so an invite can grant a
# specific (vanity) number at registration. NULL on existing rows = the prior
# random-allocation behaviour.
_INVITE_COLUMNS: list[tuple[str, str]] = [
    ("uin", "BIGINT"),
]

# Additive on `device_tokens` — a stable per-install id (kept in the client
# Keychain across reinstalls) so a reinstall REPLACES that device's token
# instead of piling up a duplicate row (= duplicate push banners). NULL on
# existing rows = pre-device-id clients, handled by the legacy (uin, token)
# upsert.
_QUEUE_CURSOR_COLUMNS: list[tuple[str, str]] = [
    ("updated_at", "TIMESTAMP WITH TIME ZONE"),
]

# Fan-out addressing: which of the recipient's libsignal devices a queued
# ciphertext is for. NULL on every row written before fan-out existed, which is
# exactly the "any device may read it" meaning the drain gives it.
_OFFLINE_MESSAGE_COLUMNS: list[tuple[str, str]] = [
    ("to_device_id", "INTEGER"),
]

_DEVICE_TOKEN_COLUMNS: list[tuple[str, str]] = [
    ("device_id", "VARCHAR(64)"),
    # Push health (UnifiedPush sender). NULL error = healthy / never tried.
    ("push_last_error", "VARCHAR(32)"),
    ("push_last_ok", "TIMESTAMP WITH TIME ZONE"),
]

async def init_db() -> None:
    from app.models import user, contact, message, group, device_token, prekey, device, nearby, audio_room, report, poll, news, invite, queue_cursor, federation, capability, broker, access_token, server_setting, uin_epoch, owned_uin, relay_inquiry  # noqa: F401  (register tables)

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
    # SQLite has no analogue and doesn't need one. Prod hasn't actually
    # tripped this race (managed DO Postgres + only 4 workers booting in
    # rapid sequence, not parallel enough), but mirroring the ref repo
    # keeps the two codebases in lockstep so future self-host operators
    # don't see "they have it, we don't, why".
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
        ("group_members", _GROUP_MEMBER_COLUMNS),
        ("audio_rooms", _AUDIO_ROOM_COLUMNS),
        ("reports", _REPORT_COLUMNS),
        ("one_time_prekeys", _ONE_TIME_PREKEY_COLUMNS),
        ("offline_messages", _OFFLINE_MESSAGE_COLUMNS),
        ("invites", _INVITE_COLUMNS),
        ("device_tokens", _DEVICE_TOKEN_COLUMNS),
        ("queue_cursors", _QUEUE_CURSOR_COLUMNS),
        ("broker_relays", _BROKER_RELAY_COLUMNS),
        ("contact_requests", _CONTACT_REQUEST_COLUMNS),
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

    # Self-heal drifted column DEFAULTs (Postgres). `ADD COLUMN IF NOT
    # EXISTS` above SKIPS a column that already exists — so a deployment
    # that upgraded ACROSS a schema change can carry an OLD column without
    # the default the add-list intends. That bit a self-hoster: the
    # vestigial `reputation` was left NOT NULL with no default by a
    # pre-pivot model, the ORM no longer sets it, so every /auth/register
    # INSERT NULL-violated and 500'd. Re-assert the intended DEFAULT on
    # every add-list column that declares one. Idempotent (a column already
    # at the right default = no-op), per-statement so a stray failure can't
    # abort startup. Postgres only — SQLite can't ALTER an existing
    # column's default, and its ADD COLUMN already carries the default so
    # it never drifts.
    if dialect == "postgresql":
        for table, columns in additive:
            for col, typ in columns:
                if " DEFAULT " not in typ:
                    continue
                default_expr = typ.split(" DEFAULT ", 1)[1].strip()
                async with engine.begin() as conn:
                    try:
                        await conn.execute(text(
                            f"ALTER TABLE {table} ALTER COLUMN {col} SET DEFAULT {default_expr}"
                        ))
                    except Exception:
                        pass

    # Backfill share tokens for groups created before the column existed, so
    # every group has an unguessable half to its share link. Done here (rather
    # than lazily on first share) because the preview gate treats a NULL token
    # as "cannot verify" and falls back to the redacted card — leaving legacy
    # groups permanently un-shareable would be a worse bug than the one the
    # token closes. Idempotent: only touches rows still NULL.
    async with engine.begin() as conn:
        try:
            rows = (await conn.execute(
                text("SELECT id FROM groups WHERE share_token IS NULL")
            )).fetchall()
            for (gid,) in rows:
                await conn.execute(
                    text("UPDATE groups SET share_token = :t WHERE id = :i"),
                    {"t": secrets.token_urlsafe(16)[:22], "i": gid},
                )
        except Exception:
            pass

    # ── Columns the model no longer has, still NOT NULL in an old database ──
    #
    # ⚠⚠ This is the same failure as the DEFAULT self-heal above, and it bit
    # twice. A column REMOVED from the model keeps living in a database that
    # predates the removal. The ORM stops filling it, so if it is NOT NULL
    # with no default, EVERY insert into that table dies — and the error comes
    # out as a 500 on /auth/register, i.e. "nobody can create an account here
    # any more", with nothing on the client saying why.
    #
    # First time: `reputation`, fixed by re-asserting defaults (above), which
    # only works for columns still in the add-list. Second time, 2026-08-16:
    # `is_fake` on is2 — dropped from the model with the demo accounts on
    # 07.08, left NOT NULL in the database, and registration there had been
    # 500ing for who knows how long. Reported by a user, not by us.
    #
    # So: stop listing them. Ask the database which NOT NULL columns have no
    # default and are unknown to the model, and drop the constraint. Anything
    # the model DOES know keeps its constraint — this only ever touches
    # columns nothing can fill.
    if dialect == "postgresql":
        for table_name, table in Base.metadata.tables.items():
            known = {c.name for c in table.columns}
            async with engine.begin() as conn:
                try:
                    rows = (await conn.execute(
                        text(
                            "SELECT column_name FROM information_schema.columns "
                            "WHERE table_name = :t AND is_nullable = 'NO' "
                            "AND column_default IS NULL"
                        ),
                        {"t": table_name},
                    )).fetchall()
                except Exception:
                    continue
            for (col,) in rows:
                if col in known:
                    continue
                async with engine.begin() as conn:
                    try:
                        await conn.execute(text(
                            f'ALTER TABLE {table_name} ALTER COLUMN "{col}" DROP NOT NULL'
                        ))
                        log.warning(
                            "[db] %s.%s is NOT NULL but no longer in the model — "
                            "dropped the constraint so inserts work", table_name, col
                        )
                    except Exception:
                        pass

    # Account-recovery lookup: /auth/recover finds the UIN by signing_key.
    # Without an index that's a seq scan holding one of the (deliberately tiny)
    # pooled connections longer than it should — under concurrent recovery load
    # that exhausts the pool. Idempotent; safe on SQLite + Postgres.
    async with engine.begin() as conn:
        try:
            await conn.execute(text(
                "CREATE INDEX IF NOT EXISTS ix_users_signing_key ON users (signing_key)"
            ))
        except Exception:
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
        # `owned_uins` was on this list from the 2026-05-27 cut and is BACK in
        # use as the UIN vault (app/models/owned_uin.py). Leaving it here meant
        # create_all built the table on boot and the very next statement
        # dropped it again — silently, every restart, taking everyone's held
        # numbers with it. The rest of the old marketplace tables are still
        # dead and still dropped.
        "uin_auction_bids", "uin_auctions",
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
        # ── Missed by the 2026-05-27 sweep, found by the metadata audit on
        # 2026-08-22. Four tables with no ORM model at all, unreachable from
        # the application and present in every nightly dump: the two halves of
        # the UIN-for-UIN trade graph (who traded with whom) and the two halves
        # of the paid-content purchase graph (who bought whose content, with a
        # per-buyer wrapped decryption key). `trades` and `premium_unlocks`
        # above were dropped at the time; their siblings were not.
        "trade_items", "trade_uins",
        "premium_content_keys", "premium_contents",
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

    # ── Metadata cut 2026-08-22: tables whose feature was deleted ──────────
    #
    # These DID have a model until this release, which is exactly the shape
    # that destroyed `owned_uins`: create_all builds a table from the model on
    # boot and the drop loop removes it again, silently, every restart. That
    # cannot happen to anything here as long as the model is really gone, so
    # the loop CHECKS rather than trusting the comment: a name that is still in
    # `Base.metadata` is a live table somebody re-added, and it is skipped with
    # a loud line instead of dropped.
    #
    # Unlike the pivot list this one is not gated on emptiness. The rows ARE
    # the thing being deleted:
    #   group_message_views: a per-person reading log, 4 rows, no FK, no sweep
    #   story_views, stories: a posting timeline plus an attention graph, and
    #                         `media_key_b64` sat in the row beside the blob,
    #                         so the island could decrypt every story it held
    #   hood_messages:        "anonymous" speech stored against a real UIN with
    #                         a geohash, soft-deleted bodies kept forever, and
    #                         reactions published as plaintext UIN lists
    #   hood_banners:         a dead board still carrying a mock IAP receipt
    #   referrals:            a permanent recruitment genealogy, zero rows ever
    #   audio_room_mutes:     a dated record of who muted whom, now in Redis
    _DEAD_DROP_TABLES: list[str] = [
        "group_message_views",
        "story_views", "stories",
        "hood_messages", "hood_banners",
        "referrals",
        "audio_room_mutes",
    ]
    for table in _DEAD_DROP_TABLES:
        if table in Base.metadata.tables:
            log.error(
                "[db] refusing to drop %s: it is still in the ORM metadata, so "
                "create_all would recreate it on the next boot and this loop "
                "would delete it again. Remove it from this list or from the "
                "models, but not neither", table
            )
            continue
        async with engine.begin() as conn:
            try:
                if dialect == "postgresql":
                    await conn.execute(text(f"DROP TABLE IF EXISTS {table} CASCADE"))
                else:
                    await conn.execute(text(f"DROP TABLE IF EXISTS {table}"))
            except Exception:
                pass

    # ── Columns the ORM stopped mapping on 2026-08-22 ──────────────────────
    #
    # Dead metadata, each verified to have no reader before it was unmapped.
    # What happens to the physical column now DEPENDS ON THE DIALECT, and the
    # difference is not tidiness, it is which failure each one is exposed to.
    #
    # POSTGRES (the flagship, is2, every docker-compose island): the column
    # STAYS for one release. Unmapping alone is safe there because the
    # NOT-NULL self-heal above asks the database which unknown columns would
    # block an insert and drops the constraint, and because a rollback to the
    # previous release finds its columns still present. Dropping in the same
    # release that unmaps would also leave a window during the restart where an
    # old worker inserts a column the new schema no longer has. So the physical
    # DROP is queued for the release AFTER this one:
    #
    #   users.trade_policy, users.active_days, users.last_active_day
    #   groups.entry_price_tokens, groups.pinned_by
    #   group_members.joined_at
    #   contacts.created_at
    #   user_capabilities.updated_at
    #   audio_room_memberships.joined_at
    #
    # ⚠⚠ SQLITE (the default `DATABASE_URL`, so a real self-host shape): the
    # column must GO NOW, because none of that safety net exists. SQLite cannot
    # ALTER a column's NOT NULL away, so the self-heal skips it entirely, and
    # four of these columns are NOT NULL with no default on any island whose
    # tables `create_all` built. Leaving them unmapped there would mean the
    # next added contact, the next group join and the next capability ping all
    # die on a NOT NULL violation. Dropping the column removes the constraint
    # with it. SQLite has had DROP COLUMN since 3.35 (2021); an island older
    # than that gets a loud line rather than a silent breakage, because that is
    # the one case where the operator has to act.
    _UNMAPPED_DEAD_COLUMNS: list[tuple[str, str]] = [
        ("users", "trade_policy"),
        ("users", "active_days"),
        ("users", "last_active_day"),
        ("groups", "entry_price_tokens"),
        ("groups", "pinned_by"),
        ("group_members", "joined_at"),
        ("contacts", "created_at"),
        ("user_capabilities", "updated_at"),
        ("audio_room_memberships", "joined_at"),
    ]
    # Unmapped by the 2026-05-27 pivot, not by this cut, which is why these two
    # are the pair that drops on Postgres today: they have already spent months
    # in the "model gone, column orphaned" state this release puts the others
    # into. Their only remaining effect was `init_db` re-asserting a DEFAULT on
    # every boot so inserts would not NULL-violate.
    _PIVOT_DEAD_COLUMNS: list[tuple[str, str]] = [
        ("users", "reputation"),
        ("users", "reputation_visibility"),
    ]
    if dialect == "postgresql":
        _drop_now = _PIVOT_DEAD_COLUMNS
    else:
        _drop_now = _UNMAPPED_DEAD_COLUMNS + _PIVOT_DEAD_COLUMNS
    for table, col in _drop_now:
        if table not in Base.metadata.tables:
            continue
        if col in {c.name for c in Base.metadata.tables[table].columns}:
            log.error(
                "[db] refusing to drop %s.%s: the ORM maps it again, so this "
                "would delete a live column on every boot", table, col
            )
            continue
        if dialect == "postgresql":
            async with engine.begin() as conn:
                try:
                    await conn.execute(text(
                        f'ALTER TABLE {table} DROP COLUMN IF EXISTS "{col}"'
                    ))
                except Exception:
                    pass
            continue
        # SQLite has no IF EXISTS on DROP COLUMN, and a fresh island never had
        # these columns at all, so ask before swinging: without this every boot
        # of a clean database logs eleven "no such column" warnings and the one
        # warning that matters is buried in them.
        async with engine.begin() as conn:
            try:
                info = (await conn.execute(text(f"PRAGMA table_info({table})"))).all()
            except Exception:
                continue
        if col not in {row[1] for row in info}:
            continue
        async with engine.begin() as conn:
            try:
                await conn.execute(text(f'ALTER TABLE {table} DROP COLUMN "{col}"'))
            except Exception as exc:  # noqa: BLE001
                # The column is there and would not go. On SQLite older than
                # 3.35 that is the end of the road for an automatic migration,
                # and writes to this table are about to start failing, so name
                # the table rather than swallowing it.
                log.warning(
                    "[db] could not drop %s.%s (%s: %s). On SQLite older than "
                    "3.35 the column has to be removed by hand, and until it "
                    "is, inserts into %s will fail if it is NOT NULL",
                    table, col, type(exc).__name__, exc, table,
                )
