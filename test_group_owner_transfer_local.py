"""Local-only verification of group ownership transfer.

`POST /groups/{id}/transfer-owner` is the only way `Group.owner_uin` moves
without the owner walking out of the room. Until it existed, "make this person
an admin" could only be answered with the granular caps of SPEC 6.6, which are
not ownership: every owner-only lever reads `g.owner_uin`, so a moderator could
moderate and still not change post_policy, close the group, grant caps or
delete it, and the owner had no way to hand those over before migrating.

Pins:
  * the owner can transfer to a member, and `owner_uin` + both `role` values
    move together;
  * a non-owner (plain member AND a member holding every granular cap) cannot;
  * a target who is not a member is refused, and so is a membership row whose
    account does not exist on this island (the ghost / cross-island case);
  * a suspended target is refused;
  * the roster served by `GET /groups/{id}` reflects the new owner for a
    THIRD member, not just for the two principals;
  * the old owner stays in the group, as a plain member, with no caps, and
    loses every owner power (owner-only PATCH, granting caps, delete, and
    transferring back);
  * the new owner has those powers;
  * members are told through the same `group_membership_changed` broadcast
    every other group mutation uses, carrying the new `owner_uin`;
  * and the SUCCESSION path (`DELETE /{id}/members/{me}` by the owner) refuses
    the same two candidates the transfer refuses: a ghost row with no account
    behind it, and a suspended member. That path used to take the oldest
    membership row with no join to `users` and no look at suspension, so the
    room could be handed to a UIN nobody answers for: invisible on every
    roster, every owner lever 403 for everyone, forever.

Runs the real FastAPI stack in-process on a throwaway SQLite DB with Redis
db 15. NOT deployed.
Run: PYTHONPATH=. /Users/tager/Documents/RCQ/backend/.venv/bin/python test_group_owner_transfer_local.py
"""
import asyncio
import base64
import os

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test_group_transfer.db"
os.environ["ENV"] = "dev"
os.environ["REDIS_URL"] = "redis://localhost:6379/15"
for f in ("test_group_transfer.db",):
    try:
        os.remove(f)
    except FileNotFoundError:
        pass

import httpx  # noqa: E402
from sqlalchemy import select  # noqa: E402

from app.core.db import SessionLocal, init_db  # noqa: E402
from app.core.redis import close_redis, get_redis  # noqa: E402
from app.core.security import issue_token  # noqa: E402
from app.main import app  # noqa: E402
from app.models.group import Group, GroupMember  # noqa: E402
from app.models.user import User  # noqa: E402
from app.services.connection_manager import manager  # noqa: E402

fails = 0


def check(name, cond):
    global fails
    print(f"  {'PASS' if cond else 'FAIL'}  {name}")
    if not cond:
        fails += 1


def b64(n=32):
    return base64.b64encode(os.urandom(n)).decode()


# OLD = creator, NEW = the account the group is handed to, MOD = a member
# holding every granular cap (the "admin" of the founder's question), THIRD =
# an ordinary bystander who must also see the change, GHOST = a membership row
# with no account, BANNED = a suspended account.
OLD, NEW, MOD, THIRD, GHOST, BANNED = 7101, 7102, 7103, 7104, 7105, 7106
# The succession cast, in a second room: LEAVER owns it, GHOST2 and BANNED2 are
# older rows than HEIR, and HEIR is the only member who can actually own it.
LEAVER, HEIR, GHOST2, BANNED2 = 7201, 7202, 7203, 7204

# Everything `_broadcast_membership` published, so the propagation half can be
# asserted without standing up sockets.
broadcasts: list[tuple[list[int], dict]] = []


async def _record_fanout(uins, payload):
    broadcasts.append((list(uins), payload))
    return set()


async def role_of(gid: int, uin: int) -> str | None:
    async with SessionLocal() as db:
        return await db.scalar(
            select(GroupMember.role).where(
                GroupMember.group_id == gid, GroupMember.uin == uin
            )
        )


async def perms_of(gid: int, uin: int) -> str | None:
    async with SessionLocal() as db:
        return await db.scalar(
            select(GroupMember.permissions).where(
                GroupMember.group_id == gid, GroupMember.uin == uin
            )
        )


async def owner_of(gid: int) -> int | None:
    async with SessionLocal() as db:
        return await db.scalar(select(Group.owner_uin).where(Group.id == gid))


async def main():
    global fails
    await init_db()
    # `groups_transfer_owner` is 10/hour per identity and the bucket lives in
    # Redis, so a second run inside the hour would 429 on the real transfer
    # rather than test it. Throwaway db, so wipe it.
    await (await get_redis()).flushdb()
    async with SessionLocal() as db:
        for u in (OLD, NEW, MOD, THIRD, BANNED, LEAVER, HEIR, BANNED2):
            db.add(User(
                uin=u, nickname=f"u{u}", identity_key=b64(), signing_key=b64(),
                # The column default is "contacts", which would 403 the
                # create-group invite for accounts with no contact rows.
                group_invite_policy="everyone",
            ))
        await db.flush()
        (await db.get(User, BANNED)).is_suspended = True
        (await db.get(User, BANNED2)).is_suspended = True
        await db.commit()

    tok = {
        u: issue_token(u, 0, "phone")
        for u in (OLD, NEW, MOD, THIRD, BANNED, LEAVER, HEIR, BANNED2)
    }
    H = lambda t: {"Authorization": f"Bearer {t}"}  # noqa: E731
    manager.fanout = _record_fanout  # type: ignore[assignment]
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        print("\nSetup:")
        r = await c.post(
            "/groups",
            headers=H(tok[OLD]),
            json={"name": "handover", "member_uins": [NEW, MOD, THIRD, BANNED]},
        )
        check("group created", r.status_code == 201)
        gid = r.json()["id"]
        check("  ... creator is the owner", r.json()["owner_uin"] == OLD)
        r = await c.post(
            f"/groups/{gid}/members/{MOD}/permissions",
            headers=H(tok[OLD]),
            json={"permissions": ["delete", "members", "info"]},
        )
        check("MOD holds every granular cap", r.status_code == 200)
        # A membership row with no user behind it: what a burned or migrated
        # account leaves, and the only shape a "member on another island"
        # could ever have here.
        async with SessionLocal() as db:
            db.add(GroupMember(group_id=gid, uin=GHOST, role="member"))
            await db.commit()

        print("\nWho may NOT transfer:")
        r = await c.post(
            f"/groups/{gid}/transfer-owner", headers=H(tok[THIRD]), json={"to_uin": THIRD}
        )
        check("a plain member cannot transfer", r.status_code == 403)
        check("  ... with code owner_only", r.json().get("detail", {}).get("code") == "owner_only")
        r = await c.post(
            f"/groups/{gid}/transfer-owner", headers=H(tok[MOD]), json={"to_uin": MOD}
        )
        check("a member with ALL THREE caps cannot transfer", r.status_code == 403)
        check("  ... owner_uin untouched", await owner_of(gid) == OLD)

        print("\nWho may NOT receive:")
        r = await c.post(
            f"/groups/{gid}/transfer-owner", headers=H(tok[OLD]), json={"to_uin": 999111}
        )
        check("a non-member is refused", r.status_code == 404)
        check("  ... with code not_a_member", r.json().get("detail", {}).get("code") == "not_a_member")
        r = await c.post(
            f"/groups/{gid}/transfer-owner", headers=H(tok[OLD]), json={"to_uin": GHOST}
        )
        check("a membership row with no account here is refused", r.status_code == 404)
        check("  ... with code no_such_user (this is the cross-island refusal)",
              r.json().get("detail", {}).get("code") == "no_such_user")
        r = await c.post(
            f"/groups/{gid}/transfer-owner", headers=H(tok[OLD]), json={"to_uin": BANNED}
        )
        check("a suspended member is refused", r.status_code == 409)
        check("  ... with code target_suspended", r.json().get("detail", {}).get("code") == "target_suspended")
        r = await c.post(
            f"/groups/{gid}/transfer-owner", headers=H(tok[OLD]), json={"to_uin": OLD}
        )
        check("transferring to yourself is refused", r.status_code == 400)
        check("  ... with code already_owner", r.json().get("detail", {}).get("code") == "already_owner")
        check("owner_uin still untouched after every refusal", await owner_of(gid) == OLD)

        print("\nThe transfer:")
        broadcasts.clear()
        r = await c.post(
            f"/groups/{gid}/transfer-owner", headers=H(tok[OLD]), json={"to_uin": NEW}
        )
        check("owner can transfer to a member", r.status_code == 200)
        check("  ... response carries the new owner", r.json()["owner_uin"] == NEW)
        check("  ... groups.owner_uin moved", await owner_of(gid) == NEW)
        check("  ... NEW's role is owner", await role_of(gid, NEW) == "owner")
        check("  ... OLD's role is member", await role_of(gid, OLD) == "member")
        check("  ... OLD is still IN the group", await role_of(gid, OLD) is not None)
        check("  ... OLD holds no granular caps", (await perms_of(gid, OLD) or "") == "")
        check("  ... NEW's owner row holds no explicit caps", (await perms_of(gid, NEW) or "") == "")
        check("  ... MOD keeps the caps they were granted",
              (await perms_of(gid, MOD) or "") == "delete,members,info")

        print("\nThe rest of the group learns:")
        r = await c.get(f"/groups/{gid}", headers=H(tok[THIRD]))
        check("a third member's roster read shows the new owner", r.json()["owner_uin"] == NEW)
        roles = {m["uin"]: m["role"] for m in r.json()["members"]}
        check("  ... and both roles on the roster", roles.get(NEW) == "owner" and roles.get(OLD) == "member")
        pushed = [p for _, p in broadcasts if p.get("type") == "group_membership_changed"]
        check("one group_membership_changed was broadcast", len(pushed) == 1)
        check("  ... carrying the whole group with the new owner_uin",
              bool(pushed) and pushed[0].get("group", {}).get("owner_uin") == NEW)
        told = set(broadcasts[-1][0]) if broadcasts else set()
        check("  ... addressed to every member, not just the two principals",
              {OLD, NEW, MOD, THIRD, BANNED} <= told)

        print("\nThe old owner has lost the owner powers:")
        r = await c.patch(f"/groups/{gid}", headers=H(tok[OLD]), json={"post_policy": "owner_only"})
        check("owner-only PATCH refused for OLD", r.status_code == 403)
        r = await c.post(
            f"/groups/{gid}/members/{THIRD}/permissions",
            headers=H(tok[OLD]),
            json={"permissions": ["info"]},
        )
        check("granting caps refused for OLD", r.status_code == 403)
        r = await c.post(
            f"/groups/{gid}/transfer-owner", headers=H(tok[OLD]), json={"to_uin": THIRD}
        )
        check("transferring back refused for OLD", r.status_code == 403)
        check("  ... with code owner_only", r.json().get("detail", {}).get("code") == "owner_only")
        r = await c.delete(f"/groups/{gid}", headers=H(tok[OLD]))
        check("deleting the group refused for OLD", r.status_code == 403)
        check("the group still exists", await owner_of(gid) == NEW)

        print("\nThe new owner has them:")
        r = await c.patch(f"/groups/{gid}", headers=H(tok[NEW]), json={"post_policy": "owner_only"})
        check("owner-only PATCH accepted for NEW", r.status_code == 200 and r.json()["post_policy"] == "owner_only")
        r = await c.post(
            f"/groups/{gid}/members/{OLD}/permissions",
            headers=H(tok[NEW]),
            json={"permissions": ["info"]},
        )
        check("NEW can hand the ex-owner a moderator seat back", r.status_code == 200)
        check("  ... which is a grant from the CURRENT owner", (await perms_of(gid, OLD) or "") == "info")
        r = await c.post(
            f"/groups/{gid}/transfer-owner", headers=H(tok[NEW]), json={"to_uin": THIRD}
        )
        check("NEW can transfer onward", r.status_code == 200 and await owner_of(gid) == THIRD)
        check("  ... and NEW is demoted in turn", await role_of(gid, NEW) == "member")

        print("\nSuccession when the owner LEAVES (the sibling of transfer):")
        r = await c.post(
            "/groups", headers=H(tok[LEAVER]), json={"name": "succession", "member_uins": []}
        )
        check("second group created", r.status_code == 201)
        gid2 = r.json()["id"]
        # Inserted in the order the bug needs, so `order_by(id)` alone would
        # hand the room to the ghost, and failing that to the banned account:
        # both rows are OLDER than the one member who can actually own it.
        async with SessionLocal() as db:
            for u in (GHOST2, BANNED2, HEIR):
                db.add(GroupMember(group_id=gid2, uin=u, role="member"))
            await db.commit()
        r = await c.delete(f"/groups/{gid2}/members/{LEAVER}", headers=H(tok[LEAVER]))
        check("the owner can leave", r.status_code == 200)
        owner2 = await owner_of(gid2)
        check("  ... the room is NOT handed to a ghost row", owner2 != GHOST2)
        check("  ... nor to a suspended member", owner2 != BANNED2)
        check("  ... but to the oldest member who can actually act", owner2 == HEIR)
        check("  ... whose row says owner", await role_of(gid2, HEIR) == "owner")
        check("  ... and nobody else's does",
              await role_of(gid2, BANNED2) == "member" and await role_of(gid2, GHOST2) == "member")
        r = await c.patch(f"/groups/{gid2}", headers=H(tok[HEIR]), json={"post_policy": "owner_only"})
        check("  ... and the new owner can use an owner lever", r.status_code == 200)

    await close_redis()
    print(f"\n{'ALL PASS' if fails == 0 else str(fails) + ' FAILED'}")
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
