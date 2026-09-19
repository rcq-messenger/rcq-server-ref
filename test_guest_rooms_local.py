"""Local-only verification of guest copies in rooms, their lifetimes, and what
the operator sees (spec 2026-09-15, sections 8, 14 and 17).

Pins:
  * succession never picks a guest: an owner leaving a room with an OLDER
    guest and a newer native hands it to the native, and with a guest and a
    suspended native, to the suspended native;
  * the last resident leaving a room that still has guests DELETES it (founder,
    question 1): the room, its memberships and its log go, and every guest
    still inside is told `group_deleted` with `reason: no_resident`;
  * a guest cannot create a room;
  * the poll stamp: a guest's `GET /messages/queue` moves `last_seen` to about
    an hour ago, at most once per window; a seat and a native are never
    stamped;
  * the three sweeps: (a) a seat past its TTL, (b) a guest that never polled a
    week after its mint (a polled one stays), (c) an idle guest; each purge
    removes the row and its memberships, bumps the epoch (the old token dies),
    unmarks the cache, tells the room, and is counted; a candidate that
    settles between the scan and the delete is NOT deleted; dry run deletes
    nothing;
  * `dead_account_sweep` leaves a guest row alone that it would otherwise
    take;
  * the admin API: `guest_status` / `guest_since` on users, `kind=` filters,
    the stats split into residents, guests and seats, the daily guest
    counters, "Delete guest copy", `allow_guests` and the guest count on
    rooms, the `guest` field on the hourly activity;
  * `tools/guest_rows_hold.py`: refuses while admission is open, deletes seats
    and suspends guests, and `--release` lifts exactly those suspensions.

Runs the real FastAPI stack in-process on a throwaway SQLite DB with Redis
db 15. NOT deployed.
Run: PYTHONPATH=. PYTHONPATH=. .venv/bin/python test_guest_rooms_local.py
"""
import asyncio
import base64
import os
from datetime import datetime, timedelta, timezone

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test_guest_rooms.db"
os.environ["ENV"] = "dev"
os.environ["REDIS_URL"] = "redis://localhost:6379/15"
for var in ("RCQ_GUEST_ADMISSION", "RCQ_ISLAND_HOST", "RCQ_FOUNDER_UIN", "RCQ_FOUNDER_BETA_GROUP_ID",
            "RCQ_GUEST_SWEEP_DRY_RUN"):
    os.environ.pop(var, None)
HOLD_LIST = "test_guest_rooms_hold.txt"
for f in ("test_guest_rooms.db", HOLD_LIST):
    try:
        os.remove(f)
    except FileNotFoundError:
        pass

import httpx  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat  # noqa: E402
from sqlalchemy import func, select, update  # noqa: E402

import app.routers.groups as groups_mod  # noqa: E402
from app.core import guest_policy as gp  # noqa: E402
from app.core.config import settings as cfg  # noqa: E402
from app.core.db import SessionLocal, init_db  # noqa: E402
from app.core.rate_limit import bucket_name  # noqa: E402
from app.core.redis import close_redis, get_redis  # noqa: E402
from app.core.security import uin_epoch  # noqa: E402
from app.main import app  # noqa: E402
from app.models.group import Group, GroupMember  # noqa: E402
from app.models.user import User  # noqa: E402
from app.services import dead_account_sweep, guest_proof, guest_sweep, server_settings  # noqa: E402
from app.services.connection_manager import manager  # noqa: E402
from tools import guest_rows_hold as hold_tool  # noqa: E402

HOST = "island-a.example"
fails = 0


def check(name, cond):
    global fails
    print(f"  {'PASS' if cond else 'FAIL'}  {name}")
    if not cond:
        fails += 1


def H(tok):
    return {"Authorization": f"Bearer {tok}"}


def code_of(r):
    try:
        detail = r.json().get("detail")
    except ValueError:
        return None
    return detail.get("code") if isinstance(detail, dict) else None


def aware(v):
    if v is None:
        return None
    return v if v.tzinfo is not None else v.replace(tzinfo=timezone.utc)


class Keys:
    def __init__(self) -> None:
        self.priv = Ed25519PrivateKey.generate()
        self.sk_raw = self.priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.ik_raw = os.urandom(32)

    @property
    def sk(self) -> str:
        return base64.b64encode(self.sk_raw).decode()

    @property
    def ik(self) -> str:
        return base64.b64encode(self.ik_raw).decode()

    def sign(self, data: bytes) -> str:
        return base64.b64encode(self.priv.sign(data)).decode()


async def clear(*patterns):
    redis = await get_redis()
    for pattern in patterns:
        keys = [k async for k in redis.scan_iter(match=pattern)]
        if keys:
            await redis.delete(*keys)


async def stat(name: str) -> int:
    raw = await (await get_redis()).get(f"stat:{name}:{datetime.now(timezone.utc):%Y%m%d}")
    return int(raw or 0)


async def set_settings(**values):
    async with SessionLocal() as db:
        await server_settings.apply(db, server_settings.validate(values))
        await db.commit()
    server_settings._cache.at = -1e9


async def user(uin):
    async with SessionLocal() as db:
        return await db.get(User, uin)


async def set_row(uin, **values):
    async with SessionLocal() as db:
        await db.execute(update(User).where(User.uin == uin).values(**values))
        await db.commit()


async def owner_of(gid):
    async with SessionLocal() as db:
        g = await db.get(Group, gid)
        return g.owner_uin if g else None


async def role_of(gid, uin):
    async with SessionLocal() as db:
        return await db.scalar(
            select(GroupMember.role).where(GroupMember.group_id == gid, GroupMember.uin == uin)
        )


async def rooms_of(uin) -> int:
    async with SessionLocal() as db:
        return await db.scalar(select(func.count()).select_from(GroupMember).where(GroupMember.uin == uin))


async def members_of(gid) -> int:
    async with SessionLocal() as db:
        return await db.scalar(select(func.count()).select_from(GroupMember).where(GroupMember.group_id == gid))


async def main() -> int:
    await init_db()
    await (await get_redis()).flushdb()
    cfg.ADMIN_USERNAME, cfg.ADMIN_PASSWORD = "admin", "test-admin-password"
    admin = ("admin", "test-admin-password")

    sent: list[tuple[int, dict]] = []
    real_send = manager.send

    async def send_recorder(uin, payload, *a, **kw):
        sent.append((uin, payload))
        return await real_send(uin, payload, *a, **kw)

    manager.send = send_recorder
    told_rooms: list[int] = []
    real_broadcast = groups_mod._broadcast_membership

    async def broadcast_recorder(group_id, members, payload, extra_uins=None):
        told_rooms.append(group_id)
        return await real_broadcast(group_id, members, payload, extra_uins=extra_uins)

    groups_mod._broadcast_membership = broadcast_recorder

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:

        async def register(nick: str):
            await clear("rl:*")
            k = Keys()
            r = await c.post("/auth/register", json={"nickname": nick, "identity_key": k.ik, "signing_key": k.sk})
            assert r.status_code == 201, r.text
            return r.json()["uin"], r.json()["token"]

        async def room(tok, name):
            await clear("rl:*")
            r = await c.post("/groups", headers=H(tok), json={"name": name, "member_uins": []})
            assert r.status_code == 201, r.text
            return r.json()["id"]

        async def guest(gid: int, nick="guest") -> tuple[int, str]:
            keys = Keys()
            await clear("rl:*")
            ch = (await c.post("/auth/guest/challenge", json={"signing_key": keys.sk})).json()["challenge"]
            data = guest_proof.proof_bytes(HOST, gid, keys.ik_raw, keys.sk_raw, ch)
            r = await c.post("/auth/guest", json={
                "v": 1, "host": HOST, "group_id": gid, "nickname": nick,
                "identity_key": keys.ik, "signing_key": keys.sk, "challenge": ch, "signature": keys.sign(data)})
            assert r.status_code == 201, r.text
            return r.json()["uin"], r.json()["token"]

        async def seat(tok, gid, nick="seat") -> int:
            await clear("rl:*")
            r = await c.post(f"/groups/{gid}/guests", headers=H(tok), json={
                "identity_key": base64.b64encode(os.urandom(32)).decode(),
                "signing_key": Keys().sk, "nickname": nick})
            assert r.status_code == 200, r.text
            return r.json()["added_uin"]

        async def leave(tok, gid, uin):
            await clear("rl:*")
            return await c.delete(f"/groups/{gid}/members/{uin}", headers=H(tok))

        # Natives first, while the island is open; then the paid door.
        O1, tok_o1 = await register("owner-one")
        N1, tok_n1 = await register("native-heir")
        O2, tok_o2 = await register("owner-two")
        O3, tok_o3 = await register("owner-three")
        S3, tok_s3 = await register("suspended-heir")
        O4, tok_o4 = await register("owner-four")
        await set_settings(island_host=HOST, registration_policy="paid")

        # ── succession ───────────────────────────────────────────────────
        print("Succession never picks a guest:")
        R1 = await room(tok_o1, "rooms-succession")
        G1, _ = await guest(R1)
        await clear("rl:*")
        r = await c.post(f"/groups/{R1}/join", headers=H(tok_n1))
        check(f"a native joins AFTER the guest ({r.status_code})", r.status_code == 200)
        r = await leave(tok_o1, R1, O1)
        check(f"the owner leaves ({r.status_code})", r.status_code == 200 and r.json().get("deleted") is False)
        check("★ the room goes to the NEWER native, not the older guest", await owner_of(R1) == N1)
        check("  ... whose row says owner, and the guest's does not",
              await role_of(R1, N1) == "owner" and await role_of(R1, G1) == "member")

        R3 = await room(tok_o3, "rooms-suspended")
        G3, _ = await guest(R3)
        await clear("rl:*")
        await c.post(f"/groups/{R3}/join", headers=H(tok_s3))
        await set_row(S3, is_suspended=True)
        r = await leave(tok_o3, R3, O3)
        check("★ with a guest and a suspended native left, the suspended native inherits",
              r.status_code == 200 and await owner_of(R3) == S3)
        await set_row(S3, is_suspended=False)

        print("\nThe last resident leaves a room that still has guests:")
        R2 = await room(tok_o2, "rooms-last-resident")
        G2a, _ = await guest(R2)
        G2b, _ = await guest(R2)
        sent.clear()
        r = await leave(tok_o2, R2, O2)
        check(f"★ the leave answers deleted:true ({r.status_code} {r.text[:60]})",
              r.status_code == 200 and r.json().get("deleted") is True)
        async with SessionLocal() as db:
            gone = await db.get(Group, R2) is None
        check("  ... the room is gone", gone)
        check("  ... and so are the guests' memberships", await members_of(R2) == 0 and await rooms_of(G2a) == 0)
        frames = {u: p for u, p in sent if p.get("type") == "group_deleted" and p.get("group_id") == R2}
        check("★ every guest still inside is told group_deleted reason no_resident",
              set(frames) == {G2a, G2b} and all(p.get("reason") == "no_resident" for p in frames.values()))

        print("\nGuests own nothing:")
        _, tok_g4 = await guest(R1)
        await clear("rl:*")
        r = await c.post("/groups", headers=H(tok_g4), json={"name": "mine", "member_uins": []})
        check(f"★ a guest creating a room -> 403 guest_restricted ({r.status_code})",
              r.status_code == 403 and code_of(r) == "guest_restricted")

        # ── poll stamp ───────────────────────────────────────────────────
        print("\nPoll stamp:")
        G5, tok_g5 = await guest(R1)
        minted = aware((await user(G5)).last_seen)
        check("a fresh guest starts backdated (dormant)",
              minted < datetime.now(timezone.utc) - timedelta(days=1))
        await clear("rl:*", "gpoll:*")
        r = await c.get("/messages/queue", headers=H(tok_g5))
        stamped = aware((await user(G5)).last_seen)
        want = datetime.now(timezone.utc) - timedelta(hours=1)
        check(f"★ the first poll stamps last_seen about an hour ago ({r.status_code})",
              r.status_code == 200 and abs((stamped - want).total_seconds()) < 120)
        old = datetime.now(timezone.utc) - timedelta(days=5)
        await set_row(G5, last_seen=old)
        await clear("rl:*")
        await c.get("/messages/queue", headers=H(tok_g5))
        check("★ a second poll inside the window writes nothing",
              abs((aware((await user(G5)).last_seen) - old).total_seconds()) < 2)
        seat_uin = await seat(tok_n1, R1, "poll-seat")
        seat_seen = aware((await user(seat_uin)).last_seen)
        await gp.touch_poll(None, seat_uin)
        check("an unclaimed seat is never stamped",
              abs((aware((await user(seat_uin)).last_seen) - seat_seen).total_seconds()) < 2)
        await clear("rl:*")
        await c.get("/messages/queue", headers=H(tok_n1))
        redis = await get_redis()
        check("a native's poll leaves no stamp key", not await redis.exists(f"gpoll:{bucket_name('uin:' + str(N1))}"))

        # ── sweeps ───────────────────────────────────────────────────────
        print("\nSweeps:")
        now = datetime.now(timezone.utc)
        R5 = await room(tok_o4, "rooms-sweep")
        A_old = await seat(tok_o4, R5, "seat-old")
        A_new = await seat(tok_o4, R5, "seat-new")
        await set_row(A_old, guest_since=now - timedelta(days=8))
        B_never, tok_b_never = await guest(R5, "never-polled")
        await set_row(B_never, guest_since=now - timedelta(days=8), last_seen=now - timedelta(days=21))
        B_polled, _ = await guest(R5, "polled")
        await set_row(B_polled, guest_since=now - timedelta(days=8), last_seen=now - timedelta(days=3))
        C_idle, _ = await guest(R5, "idle")
        await set_row(C_idle, guest_since=now - timedelta(days=100), last_seen=now - timedelta(days=61))
        C_recent, _ = await guest(R5, "recent")
        await set_row(C_recent, guest_since=now - timedelta(days=100), last_seen=now - timedelta(days=59))
        await set_row(O4, last_seen=now - timedelta(days=400))

        guest_sweep.DRY_RUN = True
        done = await guest_sweep.sweep_once()
        guest_sweep.DRY_RUN = False
        check(f"dry run finds one of each and deletes nothing ({done})",
              done == {"a": 1, "b": 1, "c": 1} and all([await user(u) for u in (A_old, B_never, C_idle)]))

        epochs = {u: await uin_epoch(u) for u in (A_old, B_never, C_idle)}
        swept = {k: await stat(f"guest_swept_{k}") for k in "abc"}
        told_rooms.clear()
        done = await guest_sweep.sweep_once()
        check(f"★ one seat, one never-polled and one idle guest removed ({done})", done == {"a": 1, "b": 1, "c": 1})
        for label, u in (("(a) the old seat", A_old), ("(b) the never-polled guest", B_never), ("(c) the idle guest", C_idle)):
            check(f"  {label}: row and memberships gone, epoch bumped, unmarked",
                  await user(u) is None and await rooms_of(u) == 0
                  and await uin_epoch(u) > epochs[u] and await gp.is_guest(u) is False)
        check("  ... each counted", all([await stat(f"guest_swept_{k}") == swept[k] + 1 for k in "abc"]))
        check("  ... the room was told", R5 in told_rooms)
        await clear("rl:*")
        r = await c.get("/groups", headers=H(tok_b_never))
        check(f"  ... the swept guest's token is dead ({r.status_code})", r.status_code == 401)
        check("★ kept: the fresh seat, the guest that polled, the guest idle 59 days, the native",
              all([await user(u) for u in (A_new, B_polled, C_recent, O4)]))

        C_race, _ = await guest(R5, "race")
        await set_row(C_race, last_seen=now - timedelta(days=90))
        picked = await guest_sweep.find_candidates()
        check("a candidate is picked", (C_race, "c") in picked)
        await clear("rl:*")
        r = await c.post(f"/admin/users/{C_race}/settle", auth=admin)
        check(f"  ... then made a resident before its delete ({r.status_code})", r.status_code == 200)
        deleted = await guest_sweep.purge_if_still_eligible(C_race, "c")
        check("★ the delete re-checks and leaves the new resident alone",
              deleted is False and (await user(C_race)) is not None)

        print("\ndead_account_sweep and guests:")
        old = now - timedelta(days=40)
        async with SessionLocal() as db:
            db.add(User(uin=880000001, nickname="user-880000001", identity_key=Keys().ik, signing_key=Keys().sk,
                        created_at=old, last_seen=old + timedelta(minutes=5)))
            db.add(User(uin=880000002, nickname="user-880000002", identity_key=Keys().ik, signing_key=Keys().sk,
                        created_at=old, last_seen=old + timedelta(minutes=5), entered_via="guest",
                        guest_status="proven", guest_since=old))
            await db.commit()
        await dead_account_sweep._sweep_once()
        check("the control: an unused native of that shape is taken", await user(880000001) is None)
        check("★ a guest row of the same shape is left to guest_sweep", await user(880000002) is not None)
        await set_row(880000002, last_seen=now)

        # ── the operator ─────────────────────────────────────────────────
        print("\nAdmin API:")
        r = await c.get("/admin/users?q=polled", auth=admin)
        row = next((u for u in r.json().get("items", []) if u["uin"] == B_polled), {})
        check(f"★ users carry guest_status and guest_since ({r.status_code})",
              row.get("guest_status") == "proven" and row.get("guest_since"))
        r = await c.get("/admin/users?q=native-heir", auth=admin)
        row = next((u for u in r.json().get("items", []) if u["uin"] == N1), {})
        check("  ... null for a native", "guest_status" in row and row["guest_status"] is None)
        r = await c.get("/admin/users?kind=guest&limit=100", auth=admin)
        kinds = {u["guest_status"] for u in r.json()["items"]}
        check(f"★ kind=guest lists proven guests only ({r.status_code})", r.status_code == 200 and kinds == {"proven"})
        r = await c.get("/admin/users?kind=invited&limit=100", auth=admin)
        check("  ... kind=invited seats only", {u["guest_status"] for u in r.json()["items"]} == {"added"})
        r = await c.get("/admin/users?kind=native&limit=100", auth=admin)
        check("  ... kind=native no guest rows", {u["guest_status"] for u in r.json()["items"]} == {None})
        r = await c.get("/admin/users", auth=admin)
        check(f"  ... neither q nor kind is still 422 ({r.status_code})", r.status_code == 422)

        async with SessionLocal() as db:
            natives = await db.scalar(select(func.count()).select_from(User).where(User.guest_status.is_(None)))
            proven = await db.scalar(select(func.count()).select_from(User).where(User.guest_status == "proven"))
            added = await db.scalar(select(func.count()).select_from(User).where(User.guest_status == "added"))
        r = await c.get("/admin/stats", auth=admin)
        s = r.json()
        check(f"★ stats: total_users counts residents, guests and seats beside it ({s.get('total_users')}/{s.get('guest_users')}/{s.get('guest_seats')})",
              r.status_code == 200 and s["total_users"] == natives and s["guest_users"] == proven and s["guest_seats"] == added)

        r = await c.get("/admin/guests?days=7", auth=admin)
        g = r.json()
        series = {x["name"]: x for x in g.get("series", [])}
        check(f"★ the guest counters by day ({r.status_code})",
              r.status_code == 200 and "guest_mint" in series and len(series["guest_mint"]["points"]) == 7)
        check("  ... today's mint count is the counter's",
              series["guest_mint"]["points"][-1]["count"] == await stat("guest_mint")
              and series["guest_mint"]["total"] >= series["guest_mint"]["points"][-1]["count"])
        check("  ... every sweep and the settle are there",
              all(n in series for n in ("guest_swept_a", "guest_swept_b", "guest_swept_c", "guest_settle", "guest_restricted")))
        check("  ... with the admission state and the counts",
              g.get("admission_open") is True and g.get("guest_users") == proven and g.get("guest_seats") == added)

        r = await c.delete(f"/admin/users/{N1}/guest", auth=admin)
        check(f"★ delete guest copy on a native -> 409 not_a_guest ({r.status_code})",
              r.status_code == 409 and code_of(r) == "not_a_guest" and await user(N1) is not None)
        told_rooms.clear()
        epoch = await uin_epoch(C_recent)
        r = await c.delete(f"/admin/users/{C_recent}/guest", auth=admin)
        check(f"★ delete guest copy on a guest ({r.status_code})", r.status_code == 200 and r.json().get("deleted") is True)
        check("  ... gone like a burn: row, rooms, epoch, cache; room told",
              await user(C_recent) is None and await rooms_of(C_recent) == 0 and await uin_epoch(C_recent) > epoch
              and await gp.is_guest(C_recent) is False and R5 in told_rooms)

        async with SessionLocal() as db:
            await db.execute(update(Group).where(Group.id == R5).values(allow_guests=False))
            await db.commit()
        r = await c.get("/admin/groups?q=rooms-sweep", auth=admin)
        row = next((x for x in r.json().get("items", []) if x["id"] == R5), {})
        async with SessionLocal() as db:
            want_guests = await db.scalar(
                select(func.count()).select_from(GroupMember).join(User, User.uin == GroupMember.uin)
                .where(GroupMember.group_id == R5, User.guest_status.is_not(None)))
        check(f"★ rooms carry allow_guests and the guest count ({row.get('allow_guests')}, {row.get('guest_count')})",
              row.get("allow_guests") is False and row.get("guest_count") == want_guests and want_guests > 0)
        r = await c.get("/admin/activity-hourly?hours=24", auth=admin)
        check(f"the hourly activity carries the guest field ({r.status_code})",
              r.status_code == 200 and all("guest" in p for p in r.json()["points"]))

        # ── rollback hold ────────────────────────────────────────────────
        print("\ntools/guest_rows_hold.py:")
        try:
            await hold_tool.hold(True, HOLD_LIST)
            refused = False
        except hold_tool.HoldRefused:
            refused = True
        check("★ refuses to apply while admission is open", refused and not os.path.exists(HOLD_LIST))
        await set_settings(guest_admission="off")
        # A guest the operator suspended for their own reasons BEFORE the hold:
        # not the hold's to lift later.
        await set_row(G1, is_suspended=True)
        async with SessionLocal() as db:
            added = await db.scalar(select(func.count()).select_from(User).where(User.guest_status == "added"))
            live_guests = (await db.execute(select(User.uin).where(
                User.guest_status == "proven", User.is_suspended.is_(False)))).scalars().all()
        report = await hold_tool.hold(False, None)
        check(f"a dry run counts and changes nothing ({report})",
              report["seats"] == added and report["guests"] == len(live_guests) and added > 0
              and not os.path.exists(HOLD_LIST))
        report = await hold_tool.hold(True, HOLD_LIST)
        async with SessionLocal() as db:
            seats_left = await db.scalar(select(func.count()).select_from(User).where(User.guest_status == "added"))
            unsuspended = await db.scalar(select(func.count()).select_from(User).where(
                User.guest_status == "proven", User.is_suspended.is_(False)))
        check(f"★ apply: seats deleted, guests suspended ({report})",
              seats_left == 0 and unsuspended == 0 and report["purged"] == added and report["suspended"] == len(live_guests))
        with open(HOLD_LIST, encoding="utf-8") as fh:
            listed = {int(x) for x in fh.read().split()}
        check("  ... the list names exactly the guests it suspended", listed == set(live_guests))
        await clear("rl:*")
        r = await c.get("/groups", headers=H(tok_g5))
        check(f"  ... a held guest's token is refused ({r.status_code})", r.status_code in (401, 403))
        report = await hold_tool.release(HOLD_LIST)
        check(f"★ release lifts the listed suspensions ({report})", report["released"] == len(live_guests))
        check("  ... and leaves alone a suspension the hold did not make", (await user(G1)).is_suspended is True)
        await clear("rl:*")
        r = await c.get("/groups", headers=H(tok_g5))
        check(f"  ... the guest's token works again ({r.status_code})", r.status_code == 200)

    groups_mod._broadcast_membership = real_broadcast
    manager.send = real_send
    await manager.shutdown()
    await close_redis()
    for f in ("test_guest_rooms.db", HOLD_LIST):
        try:
            os.remove(f)
        except FileNotFoundError:
            pass
    print("\n" + ("ALL PASS" if fails == 0 else f"{fails} FAILED"))
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
