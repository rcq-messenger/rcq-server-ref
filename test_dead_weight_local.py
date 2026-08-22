"""Local-only verification of the 2026-08-22 dead-weight cut (stage 1a).

What this guards, in order of how badly it would hurt to get wrong:

1. `init_db` really removes the eleven dead tables from a database that
   already has them, and the drop loop REFUSES to touch a name that is still
   in the ORM metadata. That refusal is the whole safety net: `owned_uins` was
   created by `create_all` and dropped by the very next statement on every
   restart, silently, taking everyone's held numbers with it.
2. `services/uin_rows.py` is still a TRUE inventory. Every mapped table that
   names a person is either in `PER_UIN_COLUMNS`, cascades off `users.uin`, or
   is on the explicit allowlist below with a reason. A feature deleted without
   its entry, or added without one, fails here rather than in an erasure
   complaint months later.
3. The unmapped columns are actually unmapped, and the code paths that used to
   write them still work: owner succession without `group_members.joined_at`,
   the capability upsert without `user_capabilities.updated_at`.
4. Burn and migrate still run clean over the reduced list.
5. `/server/info` reports Hood and Stories as off no matter what an operator
   left in `server_settings`, because the routers are gone.

Direct unit test against a throwaway SQLite DB, no HTTP: what is under test is
the schema and the row bookkeeping, not the routing.
Run: cd backend && PYTHONPATH=. .venv/bin/python test_dead_weight_local.py
"""
import asyncio
import os

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test_dead_weight.db"
os.environ["ENV"] = "dev"
os.environ.setdefault("JWT_SECRET", "t" * 64)

for f in ("test_dead_weight.db",):
    try:
        os.remove(f)
    except FileNotFoundError:
        pass

from sqlalchemy import func, select, text  # noqa: E402

from app.core.db import Base, SessionLocal, engine, init_db  # noqa: E402
from app.models.audio_room import AudioRoom, AudioRoomMembership  # noqa: E402
from app.models.capability import UserCapability  # noqa: E402
from app.models.contact import Contact  # noqa: E402
from app.models.group import Group, GroupMember  # noqa: E402
from app.models.user import User  # noqa: E402
from app.services.uin_rows import (  # noqa: E402
    DROP_ON_REKEY,
    PER_UIN_COLUMNS,
    purge_uin_rows,
    rekey_uin_rows,
)

PASS, FAIL = [], []


def check(name: str, ok: bool, detail: str = "") -> None:
    (PASS if ok else FAIL).append(name)
    print(f"  {'ok  ' if ok else 'FAIL'} {name}{'' if ok else '  ← ' + detail}")


# Every table the cut deleted, with the shape it had before, so `init_db` has
# something real to drop rather than a no-op `DROP TABLE IF EXISTS`.
_LEGACY_TABLES: dict[str, str] = {
    "trade_uins": "CREATE TABLE trade_uins (id INTEGER PRIMARY KEY, trade_id INTEGER, uin BIGINT, side TEXT)",
    "trade_items": "CREATE TABLE trade_items (id INTEGER PRIMARY KEY, trade_id INTEGER, item_id INTEGER, side TEXT)",
    "premium_contents": "CREATE TABLE premium_contents (id INTEGER PRIMARY KEY, owner_uin BIGINT, price_tokens BIGINT)",
    "premium_content_keys": "CREATE TABLE premium_content_keys (id INTEGER PRIMARY KEY, content_id INTEGER, recipient_uin BIGINT, wrapped_key TEXT)",
    "group_message_views": "CREATE TABLE group_message_views (id INTEGER PRIMARY KEY, group_id BIGINT, message_id TEXT, viewer_uin BIGINT, viewed_at TEXT)",
    "stories": "CREATE TABLE stories (id TEXT PRIMARY KEY, owner_uin BIGINT, media_id TEXT, media_key_b64 TEXT, caption TEXT)",
    "story_views": "CREATE TABLE story_views (story_id TEXT, viewer_uin BIGINT, viewed_at TEXT, PRIMARY KEY (story_id, viewer_uin))",
    "hood_messages": "CREATE TABLE hood_messages (id INTEGER PRIMARY KEY, bucket_id TEXT, owner_uin BIGINT, body TEXT, reactions TEXT)",
    "hood_banners": "CREATE TABLE hood_banners (id INTEGER PRIMARY KEY, bucket_id TEXT, owner_uin BIGINT, text TEXT, iap_receipt TEXT)",
    "referrals": "CREATE TABLE referrals (id INTEGER PRIMARY KEY, inviter_uin BIGINT, invitee_uin BIGINT, activated_at TEXT)",
    "audio_room_mutes": "CREATE TABLE audio_room_mutes (id INTEGER PRIMARY KEY, room_id INTEGER, uin BIGINT, muted_at TEXT)",
}

# Four LIVE tables in the shape a pre-cut island has them: with the dead column
# still there and NOT NULL. This is the case that breaks a SQLite self-hoster,
# because SQLite cannot drop a NOT NULL constraint, so `init_db` has to drop the
# whole column or the next insert into each of these dies. `create_all` skips a
# table that already exists, so writing them by hand here is what puts the old
# shape in front of the migration.
_LEGACY_SHAPES: dict[str, tuple[str, str]] = {
    "contacts": ("created_at", """
        CREATE TABLE contacts (
            id INTEGER PRIMARY KEY, owner_uin BIGINT NOT NULL,
            contact_uin BIGINT NOT NULL, blocked BOOLEAN NOT NULL,
            created_at DATETIME NOT NULL,
            CONSTRAINT uq_owner_contact UNIQUE (owner_uin, contact_uin))"""),
    "group_members": ("joined_at", """
        CREATE TABLE group_members (
            id INTEGER PRIMARY KEY, group_id INTEGER NOT NULL, uin BIGINT NOT NULL,
            role VARCHAR(16) NOT NULL, permissions VARCHAR(128) NOT NULL DEFAULT '',
            joined_at DATETIME NOT NULL)"""),
    "user_capabilities": ("updated_at", """
        CREATE TABLE user_capabilities (
            uin BIGINT NOT NULL PRIMARY KEY, sender_keys BOOLEAN NOT NULL,
            updated_at DATETIME NOT NULL)"""),
    "audio_room_memberships": ("joined_at", """
        CREATE TABLE audio_room_memberships (
            id INTEGER PRIMARY KEY, room_id INTEGER NOT NULL, uin BIGINT NOT NULL,
            joined_at DATETIME NOT NULL)"""),
}

# uin-bearing columns that are deliberately NOT in `PER_UIN_COLUMNS`. Each one
# is a decision, so each one needs a reason here or the inventory test fails.
_UIN_COLUMN_ALLOWLIST: dict[str, str] = {
    "users.uin": "the row itself; burn deletes it, migrate creates the new one",
    "uin_epochs.uin": "MUST outlive the user row, or a recycled number inherits sessions",
    "owned_uins.uin": "the number HELD, not its holder; the holder is owner_uin, which is listed",
    "invites.uin": "a reserved vanity number, not an owner. Known gap in the audit "
                   "(burn strands an unspent invite); the invite sweep owns it, not this list",
    "report_messages.author_uin": "cascades off reports.id, which IS listed. Re-key leaves the "
                                  "old number on the thread turns, which only the admin console "
                                  "sees; noted rather than fixed here",
}


async def main() -> None:
    # ── 0. a database that still has every dead table, then init_db ─────────
    async with engine.begin() as conn:
        for ddl in _LEGACY_TABLES.values():
            await conn.execute(text(ddl))
        for _col, ddl in _LEGACY_SHAPES.values():
            await conn.execute(text(ddl))
        # One row each, so a drop that silently no-ops is visible.
        await conn.execute(text("INSERT INTO referrals (inviter_uin, invitee_uin) VALUES (1, 2)"))
        await conn.execute(text(
            "INSERT INTO group_message_views (group_id, message_id, viewer_uin) VALUES (7, 'm', 1)"
        ))
        await conn.execute(text("INSERT INTO audio_room_mutes (room_id, uin) VALUES (3, 1)"))

    await init_db()

    async with engine.begin() as conn:
        present = {
            r[0] for r in (await conn.execute(
                text("SELECT name FROM sqlite_master WHERE type = 'table'")
            )).all()
        }
    survivors = sorted(set(_LEGACY_TABLES) & present)
    check("init_db drops every dead table", not survivors, f"still there: {survivors}")

    # The SQLite half of the column migration: the NOT NULL column has to be
    # physically gone, not merely unmapped, or every insert below fails.
    async with engine.begin() as conn:
        left_behind = []
        for tname, (col, _ddl) in _LEGACY_SHAPES.items():
            cols = {
                r[1] for r in (await conn.execute(text(f"PRAGMA table_info({tname})"))).all()
            }
            if col in cols:
                left_behind.append(f"{tname}.{col}")
    check("init_db drops the dead NOT NULL columns off a pre-cut SQLite island",
          not left_behind, f"still there: {left_behind}")

    # ── 1. the drop loop's guard: nothing on the list may be a live model ───
    import app.core.db as dbmod  # noqa: PLC0415  (source read, see below)
    import inspect

    src = inspect.getsource(dbmod.init_db)
    listed = set()
    for name in _LEGACY_TABLES:
        if f'"{name}"' in src:
            listed.add(name)
    check("all eleven dead tables are on a drop list", listed == set(_LEGACY_TABLES),
          f"missing from db.py: {sorted(set(_LEGACY_TABLES) - listed)}")
    still_mapped = sorted(set(_LEGACY_TABLES) & set(Base.metadata.tables))
    check("no dead table is still an ORM model", not still_mapped,
          f"create_all would rebuild: {still_mapped}")

    # ── 2. uin_rows is a true inventory of every table naming a person ──────
    covered = {
        f"{model.__tablename__}.{col.key}"
        for model, col in PER_UIN_COLUMNS + DROP_ON_REKEY
    }
    gaps: list[str] = []
    for tname, table in sorted(Base.metadata.tables.items()):
        for c in table.columns:
            if not (c.name == "uin" or c.name.endswith("_uin")):
                continue
            key = f"{tname}.{c.name}"
            if key in covered or key in _UIN_COLUMN_ALLOWLIST:
                continue
            if any(fk.target_fullname == "users.uin" for fk in c.foreign_keys):
                continue  # ON DELETE CASCADE handles it
            gaps.append(key)
    check("every uin-bearing column is covered, cascaded or allowlisted", not gaps,
          f"unaccounted: {gaps}")
    stale = sorted(
        k for k in _UIN_COLUMN_ALLOWLIST
        if k.split(".")[0] not in Base.metadata.tables
    )
    check("the allowlist has no entries for tables that no longer exist", not stale,
          f"stale: {stale}")

    # ── 3. the columns really are unmapped ──────────────────────────────────
    unmapped = {
        "users": ("trade_policy", "active_days", "last_active_day",
                  "reputation", "reputation_visibility"),
        "groups": ("entry_price_tokens", "pinned_by"),
        "group_members": ("joined_at",),
        "contacts": ("created_at",),
        "user_capabilities": ("updated_at",),
        "audio_room_memberships": ("joined_at",),
    }
    leftovers = [
        f"{t}.{c}"
        for t, cols in unmapped.items()
        for c in cols
        if c in {x.name for x in Base.metadata.tables[t].columns}
    ]
    check("the dead columns are gone from the ORM", not leftovers, f"still mapped: {leftovers}")

    async with SessionLocal() as db:
        # ── 4. owner succession without joined_at ───────────────────────────
        for uin, nick in ((2001, "owner"), (2002, "second"), (2003, "third")):
            db.add(User(uin=uin, nickname=nick, identity_key="k", signing_key="s"))
        g = Group(name="room", owner_uin=2001, avatar_seed=0)
        db.add(g)
        await db.flush()
        # Insert order IS the join order, which is the whole argument for `id`.
        for uin in (2001, 2002, 2003):
            db.add(GroupMember(group_id=g.id, uin=uin,
                               role="owner" if uin == 2001 else "member"))
        await db.commit()

        oldest = await db.scalar(
            select(GroupMember).where(GroupMember.group_id == g.id)
            .order_by(GroupMember.id.asc())
        )
        check("succession by id picks the first member to have joined",
              oldest is not None and oldest.uin == 2001,
              f"picked {oldest.uin if oldest else None}")
        # And the runner-up once the owner is gone, which is the real query.
        await db.delete(oldest)
        await db.commit()
        heir = await db.scalar(
            select(GroupMember).where(GroupMember.group_id == g.id)
            .order_by(GroupMember.id.asc())
        )
        check("the crown goes to the next-oldest, not an arbitrary row",
              heir is not None and heir.uin == 2002,
              f"picked {heir.uin if heir else None}")

        # ── 5. capability upsert with no timestamp column ───────────────────
        db.add(UserCapability(uin=2002, sender_keys=True))
        await db.commit()
        cap = await db.get(UserCapability, 2002)
        check("a capability row writes without updated_at",
              cap is not None and cap.sender_keys is True)

        # ── 6. contacts + audio-room membership without their timestamps ────
        db.add(Contact(owner_uin=2002, contact_uin=2003))
        room = AudioRoom(name="voice", owner_uin=2002, join_key="ABCD2345")
        db.add(room)
        await db.flush()
        db.add(AudioRoomMembership(room_id=room.id, uin=2002))
        await db.commit()
        check("a contact edge writes without created_at",
              (await db.scalar(select(func.count(Contact.id)).where(
                  Contact.owner_uin == 2002))) == 1)

        # ── 7. burn still reaches everything on the reduced list ────────────
        await purge_uin_rows(db, 2002)
        await db.commit()
        left = {
            "contacts": await db.scalar(select(func.count(Contact.id)).where(
                Contact.owner_uin == 2002)),
            "group_members": await db.scalar(select(func.count(GroupMember.id)).where(
                GroupMember.uin == 2002)),
            "audio_room_memberships": await db.scalar(
                select(func.count(AudioRoomMembership.id)).where(
                    AudioRoomMembership.uin == 2002)),
            "audio_rooms": await db.scalar(select(func.count(AudioRoom.id)).where(
                AudioRoom.owner_uin == 2002)),
            "user_capabilities": await db.scalar(
                select(func.count(UserCapability.uin)).where(UserCapability.uin == 2002)),
        }
        check("burn leaves nothing behind for the burned number",
              all(v == 0 for v in left.values()),
              ", ".join(f"{k}={v}" for k, v in left.items() if v))

        # ── 8. migrate re-keys without touching a column that is gone ───────
        db.add(Contact(owner_uin=2003, contact_uin=2001))
        await db.commit()
        db.add(User(uin=2004, nickname="moved", identity_key="k", signing_key="s"))
        await db.commit()
        await rekey_uin_rows(db, 2003, 2004)
        await db.commit()
        moved = await db.scalar(select(func.count(Contact.id)).where(
            Contact.owner_uin == 2004))
        stayed = await db.scalar(select(func.count(Contact.id)).where(
            Contact.owner_uin == 2003))
        check("migrate moves the rows and leaves none on the old number",
              moved == 1 and stayed == 0, f"moved={moved} stayed={stayed}")

    # ── 9. the retired feature flags cannot be switched back on ─────────────
    from app.services import server_settings
    from app.routers.server import ServerCapabilities

    check("hood_enabled and stories_enabled are out of the settings registry",
          "hood_enabled" not in server_settings.REGISTRY
          and "stories_enabled" not in server_settings.REGISTRY)
    try:
        server_settings.validate({"hood_enabled": True})
        rejected = False
    except ValueError:
        rejected = True
    check("an operator override for a deleted feature is refused", rejected)
    caps = ServerCapabilities(
        uin_shop=False, hall_of_fame=False, registration_policy="open",
        nearby=True, random_chat=True, reports=True, max_accounts_per_device=5,
    )
    check("/server/info advertises Hood and Stories as off",
          caps.hood is False and caps.stories is False)

    print(f"\n{len(PASS)}/{len(PASS) + len(FAIL)} pass")
    if FAIL:
        raise SystemExit("FAILED: " + ", ".join(FAIL))


asyncio.run(main())
