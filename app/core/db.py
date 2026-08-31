import hashlib
import logging
import secrets
from datetime import datetime, timezone

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from .config import settings

log = logging.getLogger(__name__)


class Base(DeclarativeBase):
    pass


# The two tables the polls removal (2026-08-23) left physically behind, mapped
# to the column in each that names a person. Their MODELS are gone, so nothing
# can reach these rows through the ORM, and an account burn has to clear them
# by raw SQL or not at all. See the block in `init_db` for why the tables are
# still here and why the burn could not wait for the manual DROP.
_LEGACY_POLL_TABLES: dict[str, str] = {
    "poll_votes": "voter_uin",
    "polls": "creator_uin",
}

# Which of the above this island ACTUALLY has, decided once at boot by `init_db`
# and read by `services/uin_rows.purge_uin_rows`. Empty on any island created
# from this release on, and empty again the moment an operator runs the DROP.
#
# ⚠ It has to be settled up front rather than discovered on the burn: a
# statement against a table that does not exist aborts the surrounding
# transaction on Postgres, and the surrounding transaction there is somebody's
# account deletion.
LEGACY_POLL_TABLES: dict[str, str] = {}


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
    # Who may OPEN the card at all (founder item 22) — the tri-state that
    # decides whether a name in a member list, a reactions sheet or over a
    # photo is a link. Distinct from `profile_visibility` above, which only
    # blanks the optional fields and still lets an empty card open. Default
    # "everyone" so an existing account is unchanged by the ALTER and so a
    # fresh one matches the value the shipped clients seed their picker with.
    ("profile_card_policy", "TEXT DEFAULT 'everyone'"),
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
    # (`presence_persistent` and `presence_ttl_minutes` left this list on
    # 2026-08-23 with the feature, see models/user.py. They are queued for the
    # physical DROP in `_UNMAPPED_DEAD_COLUMNS` below.)
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
    # When the key was handed to a sender, which is a different clock from the
    # upload in `created_at`. `services/prekey_sweep` measures its horizon from
    # this and explains at length why the difference matters.
    ("consumed_at", "TIMESTAMP WITH TIME ZONE"),
]

# Additive on `contact_requests`. When the row left `pending`, which the
# retention sweep measures its grace from — created_at is a different clock
# (a week-old request accepted a minute ago must not be swept at once).
# Nullable: existing rows are pending, or were resolved before this existed.
_CONTACT_REQUEST_COLUMNS: list[tuple[str, str]] = [
    ("resolved_at", "TIMESTAMP WITH TIME ZONE"),
]

# Additive on `gossip_records`: the demand clock the gossip sweep runs on.
# Deliberately NULL on every pre-existing row rather than backfilled to now by
# the ALTER: the sweep stamps them on its first pass, which is the same thing
# but visible in the log line, and NULL is the only honest value for "we have
# never seen anyone touch this". See models/federation.GossipRecord.
_GOSSIP_RECORD_COLUMNS: list[tuple[str, str]] = [
    ("touched_at", "TIMESTAMP WITH TIME ZONE"),
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
    ("pinned_text", "VARCHAR(4096)"),
    ("pinned_at", "TIMESTAMP WITH TIME ZONE"),
    # Unguessable half of a share link (see the model comment). Backfilled
    # for existing rows by `_backfill_group_share_tokens` below.
    ("share_token", "VARCHAR(32)"),
    # Owner-set content policy (clients honor; see model comment) + the
    # server-enforced slowmode. Defaults preserve existing behaviour.
    ("links_allowed", "BOOLEAN DEFAULT TRUE"),
    ("files_allowed", "BOOLEAN DEFAULT TRUE"),
    ("slowmode_sec", "INTEGER DEFAULT 0"),
    # Voluntary catalog (metadata stage 6, founder decision 30.08): the name
    # and description are PUBLIC LISTING fields, held openly only because the
    # owner chose to publish the room. Search returns catalog rows only.
    # Unlisted rooms will keep their identity in state_blob (sealed, room-key
    # under the skdm channel) once clients learn to write it; the columns are
    # added now so the schema is ready and the toggle can ship first.
    ("in_catalog", "BOOLEAN DEFAULT FALSE"),
    ("min_account_age_hours", "INTEGER DEFAULT 0"),
    ("state_blob", "BYTEA"),
    ("state_ver", "BIGINT DEFAULT 0"),
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
    # Soft delete on the REPORTER's side (see Report.hidden_at). NULL on every
    # existing row = still visible, which is what they all are today. The row
    # has to survive the user's delete because the Hall of Fame counts these
    # rows live, and a hard DELETE was a way to erase your own dismissed
    # reports and lift your standing on the wall.
    ("hidden_at", "TIMESTAMPTZ"),
    # When the reporter last rewrote their own text. NULL = never edited.
    ("edited_at", "TIMESTAMPTZ"),
]

# Additive on `invites` — an optional reserved UIN so an invite can grant a
# specific (vanity) number at registration. NULL on existing rows = the prior
# random-allocation behaviour.
_INVITE_COLUMNS: list[tuple[str, str]] = [
    ("uin", "BIGINT"),
    # When the last use was spent, so `services/credential_sweep` can measure a
    # horizon from the moment the invite stopped admitting anyone rather than
    # from when it was minted.
    ("spent_at", "TIMESTAMP WITH TIME ZONE"),
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
#
# Stage 2: `cls` is the 3-value storage class beside envelope_type (2a) and
# `seq` is the durable per-mailbox sequence beside id (2b). Both nullable and
# additive: the ~4331 rows live at the time of the migration keep NULL in both
# and are read back through the envelope_type / id fallbacks. envelope_type and
# id keep being written; they are dropped only in a later release, after every
# client reads the new fields.
_OFFLINE_MESSAGE_COLUMNS: list[tuple[str, str]] = [
    ("to_device_id", "INTEGER"),
    ("cls", "SMALLINT"),
    ("seq", "BIGINT"),
]

# Stage 2a on `offline_group_messages`: the same 3-value class beside
# envelope_type. The dormant sweep and `_keep_for` branch on it (cls == 2 is
# key-distribution material that must survive the sweep), falling back to
# envelope_type for the legacy rows that carry NULL. No `seq` here: the group
# queue gets its own per-room log in stage 5, not a per-mailbox sequence.
_OFFLINE_GROUP_MESSAGE_COLUMNS: list[tuple[str, str]] = [
    ("cls", "SMALLINT"),
]

# Report #695: the bridge from a key slot to the auth session that claimed it.
_DEVICE_COLUMNS: list[tuple[str, str]] = [
    ("auth_device_id", "TEXT"),
]

_DEVICE_TOKEN_COLUMNS: list[tuple[str, str]] = [
    ("device_id", "VARCHAR(64)"),
    # Push health (UnifiedPush sender). NULL error = healthy / never tried.
    ("push_last_error", "VARCHAR(32)"),
    ("push_last_ok", "TIMESTAMP WITH TIME ZONE"),
]

async def init_db() -> None:
    from app.models import user, contact, message, group, device_token, prekey, device, audio_room, report, news, invite, queue_cursor, federation, capability, broker, access_token, server_setting, uin_epoch, owned_uin, relay_inquiry, mailbox_seq, group_log, vault, island_logo  # noqa: F401  (register tables)

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
        ("groups", _GROUP_COLUMNS),
        ("group_members", _GROUP_MEMBER_COLUMNS),
        ("audio_rooms", _AUDIO_ROOM_COLUMNS),
        ("reports", _REPORT_COLUMNS),
        ("one_time_prekeys", _ONE_TIME_PREKEY_COLUMNS),
        ("offline_messages", _OFFLINE_MESSAGE_COLUMNS),
        ("offline_group_messages", _OFFLINE_GROUP_MESSAGE_COLUMNS),
        ("invites", _INVITE_COLUMNS),
        ("device_tokens", _DEVICE_TOKEN_COLUMNS),
        ("devices", _DEVICE_COLUMNS),
        ("queue_cursors", _QUEUE_CURSOR_COLUMNS),
        ("broker_relays", _BROKER_RELAY_COLUMNS),
        ("contact_requests", _CONTACT_REQUEST_COLUMNS),
        ("gossip_records", _GOSSIP_RECORD_COLUMNS),
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

    # Widened columns (Postgres). `ADD COLUMN IF NOT EXISTS` skips a column
    # that already exists, so an install that predates a width bump keeps the
    # old cap forever unless it is re-asserted here. Widening is metadata-only
    # in PG (no table rewrite, no lock worth naming) and idempotent. SQLite
    # never enforced VARCHAR length in the first place, so it needs nothing.
    # The one entry so far: the group pin, 500 -> 4096 (megalist A6 - the
    # 500 cap was making clients silently 422 on real announcements).
    if dialect == "postgresql":
        for table, col, new_type in [("groups", "pinned_text", "VARCHAR(4096)")]:
            async with engine.begin() as conn:
                try:
                    await conn.execute(text(
                        f"ALTER TABLE {table} ALTER COLUMN {col} TYPE {new_type}"
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

    # The consumed-prekey sweep's only query. `create_all` is checkfirst=True,
    # so it skips the whole table and never adds an index to one that already
    # exists. It has to be issued by hand or the hourly pass seq-scans a
    # quarter of a million rows to find the ~7% that are tombstones.
    async with engine.begin() as conn:
        try:
            await conn.execute(text(
                "CREATE INDEX IF NOT EXISTS ix_one_time_prekeys_consumed_at "
                "ON one_time_prekeys (consumed, consumed_at)"
            ))
        except Exception:
            pass

    # Stage 2b: (to_uin, seq) is unique — the loud backstop the plan requires so
    # a drifted per-mailbox counter raises (503, the client retries) instead of
    # silently overwriting a queued envelope. Added by hand for the same reason
    # as the two indexes above: `create_all` is checkfirst=True and skips a table
    # that already exists, so it never touches the live `offline_messages`. The
    # ~4331 rows that predate `seq` all carry NULL, and NULLs are distinct in a
    # unique index on both Postgres and SQLite, so none of them collide.
    async with engine.begin() as conn:
        try:
            await conn.execute(text(
                "CREATE UNIQUE INDEX IF NOT EXISTS ix_offline_messages_to_uin_seq "
                "ON offline_messages (to_uin, seq)"
            ))
        except Exception:
            pass

    # ── One-shot 2026-08-22: hash the invite codes in place ────────────────
    #
    # `invites.code` held the raw entry credential, so a dump of an
    # invite-gated island MINTED ACCESS to it. It now holds the sha256-hex,
    # matching the `access_tokens.token_hash` precedent next door.
    #
    # Rewriting the primary key of live rows is the one genuinely destructive
    # step in this release, so it is a real one-shot with a marker rather than
    # a loop that runs forever: `server_settings` gets a row nothing else reads
    # (the service iterates its own typed REGISTRY, so an unknown key is inert),
    # and a second boot skips the block entirely. Every code already handed out
    # keeps working, because `/auth/register` hashes what the client presents
    # and lands on the same row.
    #
    # ⚠ The operator's cost, and it is real: the admin list can no longer
    # re-display the join URL for an invite minted before today. Both panels
    # show "code shown once at creation" for those. Accepted in
    # docs/metadata-map-2026-08-22.md under the `invites.code` HASH verdict.
    _INVITE_HASH_MARKER = "_migration_invite_code_hashed"
    async with engine.begin() as conn:
        try:
            done = (await conn.execute(
                text("SELECT value FROM server_settings WHERE key = :k"),
                {"k": _INVITE_HASH_MARKER},
            )).scalar_one_or_none()
        except Exception:
            done = "skip"  # table not ready on this boot; try again next time
        if done is None:
            try:
                rows = (await conn.execute(text("SELECT code FROM invites"))).fetchall()
                converted = 0
                for (raw,) in rows:
                    # A 64-char lowercase hex string is already a hash. Belt to
                    # the marker's braces: if the marker row is ever lost, a
                    # re-run must not hash the hashes and lock everyone out.
                    if raw is None or (len(raw) == 64 and all(
                        c in "0123456789abcdef" for c in raw
                    )):
                        continue
                    await conn.execute(
                        text("UPDATE invites SET code = :new WHERE code = :old"),
                        {"new": hashlib.sha256(raw.strip().encode()).hexdigest(), "old": raw},
                    )
                    converted += 1
                # ⚠ Every uvicorn worker runs init_db, and they all read the
                # marker as absent before any of them has written it. The
                # UPDATEs are safe to race (the second worker's `WHERE code =
                # :old` finds nothing once the first has committed), but a plain
                # INSERT of the marker is not: on is2 (2 workers) the loser hit
                # the primary key and printed a full traceback on the first
                # boot after the upgrade. Ignore the duplicate instead; the
                # winner's value is the one that counts.
                if engine.dialect.name == "postgresql":
                    marker_sql = (
                        "INSERT INTO server_settings (key, value, updated_at) "
                        "VALUES (:k, :v, :t) ON CONFLICT (key) DO NOTHING"
                    )
                else:
                    marker_sql = (
                        "INSERT OR IGNORE INTO server_settings (key, value, updated_at) "
                        "VALUES (:k, :v, :t)"
                    )
                await conn.execute(
                    text(marker_sql),
                    {
                        "k": _INVITE_HASH_MARKER,
                        "v": str(converted),
                        "t": datetime.now(timezone.utc),
                    },
                )
                if converted:
                    log.warning(
                        "[db] hashed %d plaintext invite code(s); the join URL for "
                        "those can no longer be re-displayed in the admin list",
                        converted,
                    )
            except Exception:
                log.exception("[db] invite code hashing did not complete; will retry")

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
        # People Nearby, retired 22.08 on the founder's word. It was the most
        # revealing row on the island: an account number against a geohash
        # tile about 1.5 km across, and it had never been used once (zero
        # check-ins, ever). Bounded by a TTL and swept, which made it look
        # harmless, but the shape is the point: nothing else here tied a
        # person to a place.
        "nearby_checkins",
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

    # ── Polls, removed 2026-08-23: the tables are deliberately NOT dropped ──
    #
    # `polls` and `poll_votes` lost their models in this release (why the
    # feature went at all is in routers/polls.py), so `create_all` stops
    # building them and an island created from here on never has them. An
    # island that already does KEEPS ITS ROWS for now, and that is a decision:
    #
    # * A drop from a list in code happens on a RESTART, before anybody has
    #   looked at anything, and cannot be undone. That is the shape that
    #   silently destroyed `owned_uins`. The 22.08 cut above could afford it
    #   because every feature in it was gated by a capability flag the clients
    #   already read, so their traffic was at zero before the drop ran. Polls
    #   have no such gate: every shipped build still has the composer and still
    #   calls the endpoints, which is why routers/polls.py is a 410 tombstone
    #   rather than nothing. This release is the FIRST moment anybody learns
    #   polls are gone, and it is the wrong moment to also make it irreversible
    #   on two production islands at once.
    # * Waiting costs nothing that is still growing. Nothing in the application
    #   can read or write these two tables any more: no model, no query, no
    #   sweep, no burn. The only reader left is somebody at a psql prompt, and
    #   that is the same person who runs the DROP.
    #
    # ⚠ THE DROP IS WORK STILL OWED, not a nicety. Until it runs, `poll_votes`
    # holds the full ballot list of every poll ever created on this island, the
    # anonymous ones included (anonymity was only ever a filter in the response
    # builder). Run this on prod and on is2 once the `/polls/{rest:path}` and
    # `/groups/{group_id}/polls` rows in the admin request table have sat at
    # zero long enough to believe the field has updated:
    #
    #     DROP TABLE IF EXISTS poll_votes;
    #     DROP TABLE IF EXISTS polls;
    #
    # Children first, because `poll_votes.poll_id` still carries its physical
    # FK. On Postgres `DROP TABLE IF EXISTS polls CASCADE;` alone does both;
    # the two-statement form is the one a SQLite self-hoster can also run.
    #
    # ⚠⚠ WHAT COULD NOT WAIT FOR THAT: erasure. Losing the models also lost both
    # entries in `services/uin_rows`, so for one release `DELETE /auth/account`
    # stopped reaching `poll_votes.voter_uin` and `polls.creator_uin` and a
    # burned account stayed named in them. A deletion promise that quietly does
    # nothing is not a debt an operator can be asked to carry for a few weeks,
    # least of all in the release that justified itself as metadata
    # minimisation, so the burn reaches these two by raw SQL instead. That needs
    # to know whether the tables are actually here, and it must never be the
    # thing that finds out: a failing statement inside the burn's transaction
    # aborts the whole burn on Postgres. So the probe below is also the
    # detection, once, at boot, and it records what it found in
    # LEGACY_POLL_TABLES for uin_rows.purge_uin_rows to read.
    #
    # Count what is left and say so on every boot, so the debt lives in the
    # operator's log rather than in a comment nobody re-reads. It goes quiet by
    # itself the moment the tables are gone.
    LEGACY_POLL_TABLES.clear()
    for _dead_table, _uin_column in _LEGACY_POLL_TABLES.items():
        left = None
        async with engine.begin() as conn:
            try:
                left = (await conn.execute(
                    text(f"SELECT count(*) FROM {_dead_table}")
                )).scalar_one()
            except Exception:
                # Already dropped, or this island never had the feature. Stays
                # out of LEGACY_POLL_TABLES, so nothing tries to delete from it.
                continue
        LEGACY_POLL_TABLES[_dead_table] = _uin_column
        if left:
            log.warning(
                "[db] %s still holds %d row(s) from the polls feature removed "
                "on 2026-08-23. Nothing reads them, and an account burn clears "
                "the rows that name it, but the table itself is dropped by "
                "hand: DROP TABLE IF EXISTS poll_votes; "
                "DROP TABLE IF EXISTS polls;",
                _dead_table, left,
            )

    # ── Columns the ORM stopped mapping on 2026-08-22 and 2026-08-23 ───────
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
    # DROP is queued for the release AFTER this one.
    #
    # ✅ The 22-23.08 batch was DROPPED on both islands on 31.08, a week and
    # several releases later, which is what "the release after" was waiting
    # for: users.trade_policy, users.active_days, users.last_active_day,
    # users.presence_persistent, users.presence_ttl_minutes,
    # groups.entry_price_tokens, groups.pinned_by, contacts.created_at,
    # user_capabilities.updated_at, audio_room_memberships.joined_at.
    # Unmapping stops the writing; only the DROP stops the KEEPING, and the
    # 31.08 seizure audit found 1502 dated friendships and 2597 activity
    # counters still sitting there long after the code forgot them. If you
    # unmap something, put it here AND come back for it.
    #
    # ⚠⚠ After any DROP, terminate every pooled backend through the DIRECT
    # port: DDL poisons PgBouncer's plans exactly like pg_dump does
    # ([[project_rcq_pgdump_pool_poisoning_2026_08_24]]). The pooled URL names
    # the database "rcq-pool", which exists only on 25061 - on 25060 it is
    # "rcq", so swap BOTH the port and the name or the terminate silently
    # connects nowhere.
    #
    # Still queued (nothing today):
    #
    #   (empty - group_members.joined_at came BACK on 31.08 for the anti-spam
    #    floor, stamped only for armed rooms and floored to the day, so it is
    #    no longer a drop candidate. See models/group.py.)
    #
    # The presence pair joined on 2026-08-23 and the same reasoning is what
    # keeps it here rather than in the drop-now list: the flagship runs
    # `--workers 4` and a deploy restarts them one by one, so for a few seconds
    # a worker still mapping `presence_persistent` shares the database with the
    # new schema. Every ORM read of `users` names its columns explicitly, so
    # the drop does not just lose a field, it makes every profile fetch, every
    # roster read and every socket connect on the old worker fail on "column
    # users.presence_persistent does not exist". The same goes for a rollback,
    # which is the one moment we least want the previous release to be broken.
    # A column nothing reads costs a dump a few bytes per row for one release;
    # that is the cheaper half of the trade.
    #
    # ⚠⚠ SQLITE (the default `DATABASE_URL`, so a real self-host shape): the
    # column must GO NOW, because none of that safety net exists. SQLite cannot
    # ALTER a column's NOT NULL away, so the self-heal skips it entirely, and
    # five of these columns are NOT NULL with no default on any island whose
    # tables `create_all` built. Leaving them unmapped there would mean the
    # next registration, the next added contact, the next group join and the
    # next capability ping all die on a NOT NULL violation (the count went from
    # four to five on 2026-08-23 with `users.presence_persistent`, which is why
    # it is on this list and not only in the queue above). Dropping the column
    # removes the constraint with it. SQLite has had DROP COLUMN since 3.35
    # (2021); an island older than that gets a loud line rather than a silent
    # breakage, because that is the one case where the operator has to act.
    _UNMAPPED_DEAD_COLUMNS: list[tuple[str, str]] = [
        ("users", "trade_policy"),
        ("users", "active_days"),
        ("users", "last_active_day"),
        # `presence_persistent` is one of the NOT NULL ones on a create_all
        # island (the model had it as a plain `Mapped[bool]`), so on SQLite it
        # is not a tidiness drop: leave it and the next /auth/register dies on
        # a NOT NULL violation. On Postgres the self-heal above drops the
        # constraint instead, which is why the column can wait a release there.
        ("users", "presence_persistent"),
        ("users", "presence_ttl_minutes"),
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
