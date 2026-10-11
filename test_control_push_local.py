"""Local-only verification that control envelopes are stored but never pushed.

Stage 2 (2026-08-22) turned "push" into "content class", and every content kind
the island does not list went with it. Clients label their control envelopes
with their own type, so a reaction, an edit, a delete for everyone and a home
record each woke the recipient with an alert, and a TestFlight iPhone showed
"<contact> / Message" for every one of them. In a group the same happened to
every offline member, and a sender-keys broadcast cannot even be opened by the
iOS extension, so it read "New group message" on every platform.

Pinned here:
  1:1      reaction, edit, delete, homerec (and carbon, as before) are stored as
           content (cls 1) and served by the drain under their own type, and
           neither APNs nor UnifiedPush is called for them, whether the client
           sent `cls` or let the island derive it;
           message, system, secscreen and an unknown future kind still push on
           both transports; a ring still takes the call wake.
  group    on /messages/group-sealed and /messages/group-broadcast a control
           kind is kept for EXACTLY the members a message would be kept for
           (a dormant member with a push endpoint included, so an edit or a
           delete still reaches whoever holds the original), and no wake goes
           out; a message in the same room still wakes the same members.

In-process ASGI against a throwaway SQLite DB, Redis db 15 for the limiters.
The push senders and the connection manager are stubbed (nobody is online).
NOT deployed.
Run: cd backend && PYTHONPATH=. .venv/bin/python test_control_push_local.py
"""
import asyncio
import base64
import os

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test_control_push.db"
os.environ["ENV"] = "dev"
os.environ["REDIS_URL"] = "redis://localhost:6379/15"
os.environ.setdefault("JWT_SECRET", "t" * 64)

for f in ("test_control_push.db",):
    try:
        os.remove(f)
    except FileNotFoundError:
        pass

from datetime import datetime, timedelta, timezone  # noqa: E402

import httpx  # noqa: E402
from sqlalchemy import select  # noqa: E402

from app.core.db import SessionLocal, init_db  # noqa: E402
from app.core.redis import close_redis  # noqa: E402
from app.core.security import issue_token  # noqa: E402
from app.main import app  # noqa: E402
from app.models.capability import UserCapability  # noqa: E402
from app.models.device_token import DeviceToken  # noqa: E402
from app.models.group import Group, GroupMember, OfflineGroupMessage  # noqa: E402
from app.models.message import OfflineMessage  # noqa: E402
from app.models.user import User  # noqa: E402
from app.routers import messages as M  # noqa: E402

fails = 0


def check(name: str, ok: bool, detail: str = "") -> None:
    global fails
    print(f"  {'PASS' if ok else 'FAIL'}  {name}{'' if ok else '  <- ' + detail}")
    if not ok:
        fails += 1


def b64(n: int = 40) -> str:
    return base64.b64encode(os.urandom(n)).decode()


class FakeManager:
    """Nobody is online, so every deposit reaches the push decision."""

    async def send(self, uin, pkt):
        return False

    async def online_devices(self, uin):
        return []

    async def fanout(self, uins, pkt):
        return set()

    async def fanout_each(self, items):
        return set()


APNS: list[tuple[int, str | None]] = []
UP: list[tuple[int, str | None]] = []
RANG: list[int] = []


async def fake_apns(uin, **kw):
    APNS.append((uin, kw.get("envelope_type")))
    return 1


async def fake_up(uin, **kw):
    UP.append((uin, kw.get("envelope_type")))
    return 1


async def fake_wake(to_uin, payload):
    RANG.append(to_uin)
    return 1


def reset():
    APNS.clear()
    UP.clear()
    RANG.clear()


CONTROL = ("reaction", "edit", "delete", "homerec", "carbon")
ANNOUNCED = ("message", "system", "secscreen", "teleport")

R = 6001                 # 1:1 recipient, push endpoints on both transports
OWNER = 6100             # room owner, recent
RECENT = 6101            # recent member with an endpoint
DORMANT_WAKE = 6102      # away for months, still has an endpoint
DORMANT_NONE = 6103      # away for months, no endpoint


async def main() -> None:
    await init_db()
    M.manager = FakeManager()
    M.apns_send = fake_apns
    M.up_send = fake_up
    M._wake_for_sealed_call = fake_wake

    now = datetime.now(timezone.utc)
    long_ago = now - timedelta(days=120)
    async with SessionLocal() as db:
        db.add(User(uin=R, nickname="r", identity_key=b64(32), signing_key=b64(32), last_seen=now))
        for uin, seen in ((OWNER, now), (RECENT, now), (DORMANT_WAKE, long_ago), (DORMANT_NONE, long_ago)):
            db.add(User(uin=uin, nickname=f"u{uin}", identity_key=b64(32), signing_key=b64(32), last_seen=seen))
            db.add(UserCapability(uin=uin, sender_keys=True))
        db.add(DeviceToken(uin=R, token="ios-r", platform="ios", device_id="r-phone"))
        db.add(DeviceToken(uin=R, token="https://up.example/r", platform="android-up", device_id="r-tab"))
        db.add(DeviceToken(uin=RECENT, token="ios-recent", platform="ios", device_id="p1"))
        db.add(DeviceToken(uin=DORMANT_WAKE, token="https://up.example/d", platform="android-up", device_id="p2"))
        g = Group(name="room", owner_uin=OWNER)
        db.add(g)
        await db.flush()
        gid = g.id
        for uin in (OWNER, RECENT, DORMANT_WAKE, DORMANT_NONE):
            db.add(GroupMember(group_id=gid, uin=uin, role="owner" if uin == OWNER else "member"))
        await db.commit()

    H = lambda t: {"Authorization": f"Bearer {t}"}  # noqa: E731
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        # ── 1:1 ────────────────────────────────────────────────────────────
        print("\n1:1 control kinds: stored, not pushed")
        for t in CONTROL:
            reset()
            r = await c.post("/messages/sealed", json={"to_uin": R, "envelope_type": t, "payload": b64()})
            check(f"{t}: accepted", r.status_code == 200, r.text[:200])
            check(f"{t}: queued", r.status_code == 200 and r.json().get("queued") is True)
            check(f"{t}: no APNs push", APNS == [], str(APNS))
            check(f"{t}: no UnifiedPush wake", UP == [], str(UP))
            check(f"{t}: no ring", RANG == [], str(RANG))

        print("\n1:1 control kinds with an explicit cls 1, as every current client sends them")
        for t in ("reaction", "edit", "delete", "homerec"):
            reset()
            r = await c.post("/messages/sealed", json={"to_uin": R, "envelope_type": t, "cls": 1, "payload": b64()})
            check(f"{t} cls=1: accepted", r.status_code == 200, r.text[:200])
            check(f"{t} cls=1: not pushed anywhere", APNS == [] and UP == [], f"{APNS} {UP}")

        print("\n1:1 kinds a person must hear about still push on both transports")
        for t in ANNOUNCED:
            reset()
            r = await c.post("/messages/sealed", json={"to_uin": R, "envelope_type": t, "payload": b64()})
            check(f"{t}: accepted", r.status_code == 200, r.text[:200])
            check(f"{t}: APNs push", APNS == [(R, t)], str(APNS))
            check(f"{t}: UnifiedPush wake", UP == [(R, t)], str(UP))

        print("\n1:1 a ring still rings")
        reset()
        r = await c.post("/messages/sealed", json={"to_uin": R, "envelope_type": "message", "ring": True, "payload": b64()})
        check("ring: call wake taken", r.status_code == 200 and RANG == [R], str(RANG))
        check("ring: no message push beside it", APNS == [] and UP == [], f"{APNS} {UP}")

        print("\n1:1 the drain serves the control rows under their own type and class")
        async with SessionLocal() as db:
            stored = (await db.execute(
                select(OfflineMessage.envelope_type, OfflineMessage.cls).where(OfflineMessage.to_uin == R)
            )).all()
        by_type: dict[str, set] = {}
        for t, cl in stored:
            by_type.setdefault(t, set()).add(cl)
        for t in CONTROL:
            check(f"{t}: stored as content (cls 1)", by_type.get(t) == {1}, str(by_type.get(t)))
        r = await c.get("/messages/queue?ack=true", headers=H(issue_token(R, 0, "r-phone")))
        check("drain answered", r.status_code == 200, r.text[:200])
        served = {(row["envelope_type"], row["cls"]) for row in (r.json() if r.status_code == 200 else [])}
        for t in CONTROL:
            check(f"{t}: served by the drain", (t, 1) in served, str(sorted(served)))

        # ── group-sealed ───────────────────────────────────────────────────
        async def group_rows(env_type: str) -> set[int]:
            async with SessionLocal() as db:
                return {u for (u,) in (await db.execute(
                    select(OfflineGroupMessage.to_uin).where(
                        OfflineGroupMessage.group_id == gid,
                        OfflineGroupMessage.envelope_type == env_type,
                    )
                )).all()}

        members = (RECENT, DORMANT_WAKE, DORMANT_NONE)
        print("\ngroup-sealed: a message wakes and keeps for the members with an endpoint")
        reset()
        r = await c.post("/messages/group-sealed", json={
            "group_id": gid, "envelope_type": "message",
            "payloads": [{"to_uin": u, "payload": b64()} for u in members],
        })
        await asyncio.sleep(0.2)
        check("message accepted", r.status_code == 200, r.text[:200])
        woken = {u for u, _ in APNS} | {u for u, _ in UP}
        check("message woke the recent and the dormant-with-endpoint member",
              woken == {RECENT, DORMANT_WAKE}, str(woken))
        msg_kept = await group_rows("message")
        check("message kept for the same two", msg_kept == {RECENT, DORMANT_WAKE}, str(msg_kept))

        for t in ("reaction", "edit", "delete", "homerec"):
            reset()
            r = await c.post("/messages/group-sealed", json={
                "group_id": gid, "envelope_type": t,
                "payloads": [{"to_uin": u, "payload": b64()} for u in members],
            })
            await asyncio.sleep(0.2)
            check(f"group-sealed {t}: accepted", r.status_code == 200, r.text[:200])
            check(f"group-sealed {t}: nobody pushed", APNS == [] and UP == [], f"{APNS} {UP}")
            kept = await group_rows(t)
            check(f"group-sealed {t}: kept for exactly the members a message is kept for",
                  kept == msg_kept, f"{kept} vs {msg_kept}")

        # ── group-broadcast ────────────────────────────────────────────────
        async def gmsg_rows() -> list[int]:
            async with SessionLocal() as db:
                return [u for (u,) in (await db.execute(
                    select(OfflineGroupMessage.to_uin).where(
                        OfflineGroupMessage.group_id == gid,
                        OfflineGroupMessage.envelope_type == "gmsg",
                    )
                )).all()]

        tok = issue_token(OWNER, 0, "owner-phone")
        print("\ngroup-broadcast: a message wakes the offline members with an endpoint")
        reset()
        before = len(await gmsg_rows())
        r = await c.post("/messages/group-broadcast", headers=H(tok),
                         json={"group_id": gid, "envelope_type": "message", "payload": b64()})
        await asyncio.sleep(0.2)
        check("broadcast message accepted", r.status_code == 200, r.text[:200])
        woken = {u for u, _ in APNS} | {u for u, _ in UP}
        check("broadcast message woke the two members with an endpoint",
              woken == {RECENT, DORMANT_WAKE}, str(woken))
        after = await gmsg_rows()
        msg_kept_b = set(after[before:]) if len(after) > before else set()
        check("broadcast message kept for owner, recent and dormant-with-endpoint",
              msg_kept_b == {OWNER, RECENT, DORMANT_WAKE}, str(msg_kept_b))

        for t in ("reaction", "edit", "delete"):
            reset()
            before = len(await gmsg_rows())
            r = await c.post("/messages/group-broadcast", headers=H(tok),
                             json={"group_id": gid, "envelope_type": t, "payload": b64()})
            await asyncio.sleep(0.2)
            check(f"broadcast {t}: accepted", r.status_code == 200, r.text[:200])
            check(f"broadcast {t}: nobody pushed", APNS == [] and UP == [], f"{APNS} {UP}")
            after = await gmsg_rows()
            kept = set(after[before:])
            check(f"broadcast {t}: kept for exactly the members a message is kept for",
                  kept == msg_kept_b, f"{kept} vs {msg_kept_b}")

    await close_redis()
    print("\nALL CONTROL-PUSH CHECKS PASSED" if fails == 0 else f"\n{fails} CHECK(S) FAILED")
    raise SystemExit(0 if fails == 0 else 1)


asyncio.run(main())
