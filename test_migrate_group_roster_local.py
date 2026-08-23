"""Local-only verification that a migration TELLS THE GROUPS.

`POST /account/migrate` re-keys `Group.owner_uin` and `GroupMember.uin` onto
the new number correctly and, until 2026-08-23, told nobody: the only socket
traffic it produced was `account_burned` to the migrating account's OWN
sessions. Everybody else in every group kept a cached roster naming the OLD
number, and that is not cosmetic, because `POST /messages/group-sealed`
filters the sender's payload entries against the LIVE roster: an entry
addressed to the number that no longer exists is dropped without an error (it
cannot error, sealed sender means the island does not know who is asking), so
the migrated member received nothing at all and the sender saw only a smaller
`delivered` count. It lasted until each sender independently refetched.

Pins:
  * a migration fans one `group_membership_changed` per group the account is
    in, the same event and the same shape as any other roster change (§7.4.5),
    so no client needs new code;
  * a small group gets the SNAPSHOT, and its roster carries the new number and
    not the old one, which is the whole point, since the snapshot is what a
    client upserts;
  * migrating as the OWNER moves `owner_uin` in that snapshot too;
  * a group over SNAPSHOT_BROADCAST_LIMIT members gets the COMPACT form, with
    `group_id` and `owner_uin` and no roster at all. That is the fan-out cost
    decision: the roster of a 1750-member room is never serialised for a
    migration, and its members learn the new number on their next `GET
    /groups`, exactly as they do for an ordinary join;
  * delivery goes through `manager.fanout`, which publishes to the ONLINE
    subset only, so the bytes scale with who is connected rather than with how
    big the groups are;
  * and the failure this exists to stop: a send addressed to the OLD number is
    dropped silently after the migration, and one addressed to the NEW number
    lands, which is what an informed roster produces;
  * a broken nudge never fails a committed migration.

Runs the real FastAPI stack in-process on a throwaway SQLite DB with Redis
db 15. NOT deployed.
Run: PYTHONPATH=. /Users/tager/Documents/RCQ/backend/.venv/bin/python test_migrate_group_roster_local.py
"""
import asyncio
import base64
import os
from datetime import datetime, timezone

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test_migrate_groups.db"
os.environ["ENV"] = "dev"
os.environ["REDIS_URL"] = "redis://localhost:6379/15"
for f in ("test_migrate_groups.db",):
    try:
        os.remove(f)
    except FileNotFoundError:
        pass

import httpx  # noqa: E402
from sqlalchemy import func, select  # noqa: E402

from app.core.db import SessionLocal, init_db  # noqa: E402
from app.core.redis import close_redis, get_redis  # noqa: E402
from app.core.security import issue_token  # noqa: E402
from app.main import app  # noqa: E402
from app.models.group import Group, GroupMember, OfflineGroupMessage  # noqa: E402
from app.models.user import User  # noqa: E402
from app.routers.groups import SNAPSHOT_BROADCAST_LIMIT  # noqa: E402
from app.services.connection_manager import manager  # noqa: E402

fails = 0


def check(name, cond):
    global fails
    print(f"  {'PASS' if cond else 'FAIL'}  {name}")
    if not cond:
        fails += 1


def b64(n=32):
    return base64.b64encode(os.urandom(n)).decode()


# MOVER migrates. P1 and P2 are the members whose cached roster used to rot;
# P1 also owns the second small group, so MOVER is pinned as a plain member
# somewhere as well as as an owner. BIGOWNER owns the oversized room.
MOVER, P1, P2, BIGOWNER = 7301, 7302, 7303, 7304
# In a handful of small groups at once: the account that proves the fan-out
# budget, since SNAPSHOT_BROADCAST_LIMIT bounds ONE group and a migration
# multiplies by however many the account is in.
MANY = 7306
# A second account for the "a broken nudge does not fail the migration" case,
# so a raising stub cannot disturb anything asserted above it.
SPARE = 7305
# Filler membership rows for the big room. They deliberately have NO `users`
# row: the compact branch reads `group_members.uin` and the owner and nothing
# else, so if it ever started serialising the roster this room would notice.
FILL_BASE = 7400
FILL_N = SNAPSHOT_BROADCAST_LIMIT + 5

# Everything the migration published, so the fan-out can be asserted without
# standing up a hundred sockets.
broadcasts: list[tuple[list[int], dict]] = []
# And every per-recipient group envelope that reached the fan-out, which is
# where a dropped entry actually disappears.
sealed: list[list[int]] = []


async def _record_fanout(uins, payload):
    broadcasts.append(([int(u) for u in uins], payload))
    return set()


async def _record_fanout_each(items):
    sealed.append([int(u) for u, _ in items])
    return set()


def events_for(gid: int) -> list[tuple[list[int], dict]]:
    return [
        (uins, body)
        for uins, body in broadcasts
        if body.get("type") == "group_membership_changed"
        and (body.get("group_id") == gid or (body.get("group") or {}).get("id") == gid)
    ]


def event_for(gid: int) -> tuple[list[int], dict]:
    """The one event for `gid`, or an empty pair, so that a build which publishes
    nothing reports every check below as a failure instead of an IndexError
    three lines into the section."""
    evs = events_for(gid)
    return evs[0] if evs else ([], {})


async def send_sealed(c, gid: int, to_uin: int) -> dict:
    r = await c.post(
        "/messages/group-sealed",
        json={
            "group_id": gid,
            # cls 2, so `_keep_for` stores a copy for every recipient
            # regardless of how recently they were seen. What is being tested
            # is the ROSTER FILTER, not the dormancy rules.
            "envelope_type": "skdm",
            "payloads": [{"to_uin": to_uin, "payload": b64(48)}],
        },
    )
    assert r.status_code == 200, r.text
    return r.json()


async def queued_for(uin: int) -> int:
    async with SessionLocal() as db:
        return await db.scalar(
            select(func.count())
            .select_from(OfflineGroupMessage)
            .where(OfflineGroupMessage.to_uin == uin)
        )


async def main():
    global fails
    await init_db()
    # The limiters live in the shared dev Redis, not in the throwaway DB.
    await (await get_redis()).flushdb()

    now = datetime.now(timezone.utc)
    async with SessionLocal() as db:
        for u in (MOVER, P1, P2, BIGOWNER, SPARE, MANY):
            db.add(User(
                uin=u, nickname=f"u{u}", identity_key=b64(), signing_key=b64(),
                # The column default is "contacts", which would 403 the
                # create-group invite for accounts with no contact rows.
                group_invite_policy="everyone",
                last_seen=now,
            ))
        await db.commit()

    tok = {u: issue_token(u, 0, "phone") for u in (MOVER, P1, P2, BIGOWNER, SPARE, MANY)}
    H = lambda t: {"Authorization": f"Bearer {t}"}  # noqa: E731
    real_fanout = manager.fanout
    manager.fanout = _record_fanout  # type: ignore[assignment]
    manager.fanout_each = _record_fanout_each  # type: ignore[assignment]

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        print("\nSetup:")
        r = await c.post(
            "/groups", headers=H(tok[MOVER]),
            json={"name": "owned by the mover", "member_uins": [P1, P2]},
        )
        check("a small group the mover OWNS", r.status_code == 201)
        owned_gid = r.json()["id"]
        r = await c.post(
            "/groups", headers=H(tok[P1]),
            json={"name": "the mover is just a member", "member_uins": [MOVER, P2]},
        )
        check("a small group the mover is only a MEMBER of", r.status_code == 201)
        member_gid = r.json()["id"]
        async with SessionLocal() as db:
            big = Group(name="the flagship room", owner_uin=BIGOWNER)
            db.add(big)
            await db.flush()
            big_gid = big.id
            db.add(GroupMember(group_id=big_gid, uin=BIGOWNER, role="owner"))
            db.add(GroupMember(group_id=big_gid, uin=MOVER, role="member"))
            for i in range(FILL_N):
                db.add(GroupMember(group_id=big_gid, uin=FILL_BASE + i, role="member"))
            await db.commit()
            n_big = await db.scalar(
                select(func.count()).select_from(GroupMember)
                .where(GroupMember.group_id == big_gid)
            )
        check(f"a room over the snapshot limit ({n_big} > {SNAPSHOT_BROADCAST_LIMIT})",
              n_big > SNAPSHOT_BROADCAST_LIMIT)

        print("\nBefore the migration a send addressed to the mover lands:")
        sealed.clear()
        await send_sealed(c, owned_gid, MOVER)
        check("the entry reaches the fan-out", sealed == [[MOVER]])
        check("  ... and a copy is stored", await queued_for(MOVER) == 1)

        print("\nThe migration:")
        broadcasts.clear()
        r = await c.post("/account/migrate", headers=H(tok[MOVER]))
        check(f"migrate -> 200 ({r.status_code})", r.status_code == 200)
        moved = r.json()["new_uin"]
        moved_tok = r.json()["token"]
        check("★ every group the account is in was told, exactly once",
              sorted(gid for gid in (owned_gid, member_gid, big_gid)
                     if len(events_for(gid)) == 1) == sorted([owned_gid, member_gid, big_gid]))
        check("  ... and nothing else was published",
              len(broadcasts) == 3)

        print("\nThe small groups get the snapshot, and it names the NEW number:")
        for gid, label in ((owned_gid, "owned"), (member_gid, "member-of")):
            uins, body = event_for(gid)
            roster = [m["uin"] for m in (body.get("group") or {}).get("members", [])]
            check(f"[{label}] the full snapshot rides the event",
                  "group" in body and body["group"].get("id") == gid)
            check(f"[{label}] ★ the roster carries the new number", moved in roster)
            check(f"[{label}] ★ and not the old one", MOVER not in roster)
            check(f"[{label}] the other members are the ones told", P1 in uins and P2 in uins)
        owner_body = event_for(owned_gid)[1]
        check("★ migrating as the owner moves `owner_uin` in the payload too",
              (owner_body.get("group") or {}).get("owner_uin") == moved)
        member_body = event_for(member_gid)[1]
        check("  ... and leaves somebody else's group with its own owner",
              (member_body.get("group") or {}).get("owner_uin") == P1)

        print("\nThe big room gets the compact form, and no roster is built for it:")
        uins, body = event_for(big_gid)
        check("★ compact, exactly the three documented keys",
              set(body) == {"type", "group_id", "owner_uin"})
        check("  ... naming the room and its owner",
              body.get("group_id") == big_gid and body.get("owner_uin") == BIGOWNER)
        check("  ... addressed to every member row, the account-less ones included",
              len(uins) == n_big and FILL_BASE in uins and moved in uins)

        print("\nWhat the silence used to cost:")
        sealed.clear()
        before = await queued_for(MOVER)
        res = await send_sealed(c, owned_gid, MOVER)
        check("★ a send from a STALE roster is accepted with no error at all",
              res["queued"] is True)
        check("  ... and the entry never reaches the fan-out", sealed == [[]])
        check("  ... nor the queue: the message is simply gone",
              await queued_for(MOVER) == before)
        sealed.clear()
        # The copy stored before the migration was re-keyed onto the new number
        # with everything else (§10.1.1), so count the delta rather than the
        # total.
        before_moved = await queued_for(moved)
        await send_sealed(c, owned_gid, moved)
        check("★ the same send from a REFRESHED roster lands", sealed == [[moved]])
        check("  ... and is stored under the new number",
              await queued_for(moved) == before_moved + 1)

        print("\nOne migration cannot spend the cluster on snapshots:")
        # ⚠ The per-group limit bounds ONE group; nothing bounds how many
        # groups an account is in (being ADDED to one is free), and the
        # snapshot is priced per member AND per online recipient, so the two
        # multiply. Past the call's byte budget the remaining groups take the
        # compact branch, which does not depend on the roster at all.
        from app.routers import groups as groups_mod  # noqa: PLC0415

        small_gids: list[int] = []
        async with SessionLocal() as db:
            for i in range(3):
                g = Group(name=f"small room {i}", owner_uin=P1)
                db.add(g)
                await db.flush()
                small_gids.append(g.id)
                db.add(GroupMember(group_id=g.id, uin=P1, role="owner"))
                db.add(GroupMember(group_id=g.id, uin=MANY, role="member"))
            await db.commit()

        broadcasts.clear()
        budget = groups_mod.REKEY_SNAPSHOT_BUDGET_BYTES
        groups_mod.REKEY_SNAPSHOT_BUDGET_BYTES = 1
        try:
            async with SessionLocal() as db:
                await groups_mod.broadcast_roster_rekey(db, MANY)
        finally:
            groups_mod.REKEY_SNAPSHOT_BUDGET_BYTES = budget
        told = [event_for(gid)[1] for gid in small_gids]
        check("every group is still told", all(b for b in told))
        check("★ the first spends the budget and carries the roster",
              "group" in told[0] and told[0]["group"]["id"] == small_gids[0])
        check("★ the rest degrade to the compact form rather than serialising a roster",
              all("group" not in b and b.get("group_id") == gid
                  for b, gid in zip(told[1:], small_gids[1:])))
        check("  ... and the compact ones still name the owner",
              all(b.get("owner_uin") == P1 for b in told[1:]))

        broadcasts.clear()
        async with SessionLocal() as db:
            await groups_mod.broadcast_roster_rekey(db, MANY)
        told = [event_for(gid)[1] for gid in small_gids]
        check("with the real budget every small group gets its snapshot",
              all("group" in b for b in told))

        print("\nA broken nudge never fails a committed migration:")

        async def _boom(uins, payload):
            raise RuntimeError("redis is having a day")

        async with SessionLocal() as db:
            db.add(GroupMember(group_id=owned_gid, uin=SPARE, role="member"))
            await db.commit()
        manager.fanout = _boom  # type: ignore[assignment]
        try:
            r = await c.post("/account/migrate", headers=H(tok[SPARE]))
        finally:
            manager.fanout = _record_fanout  # type: ignore[assignment]
        check(f"★ the migration still answers 200 ({r.status_code})", r.status_code == 200)
        spare_moved = r.json()["new_uin"]
        async with SessionLocal() as db:
            rekeyed = await db.scalar(
                select(GroupMember.uin).where(
                    GroupMember.group_id == owned_gid, GroupMember.uin == spare_moved
                )
            )
        check("  ... and the re-key it committed stands", rekeyed == spare_moved)

        # The migrated account is still the one holding the room.
        r = await c.get(f"/groups/{owned_gid}", headers=H(moved_tok))
        check("the mover still owns the room under the new number",
              r.status_code == 200 and r.json()["owner_uin"] == moved)

    manager.fanout = real_fanout  # type: ignore[assignment]
    await close_redis()
    print("\nALL MIGRATE-ROSTER CHECKS PASSED" if fails == 0 else f"\n{fails} CHECK(S) FAILED")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
