"""Local-only verification of the Stage 2 SERVER HALF (the additive one).

Stage 2 gives the 1:1 queue row a 3-value CLASS beside envelope_type (2a) and a
durable per-mailbox SEQUENCE beside id (2b), WITHOUT dropping either old field.
Everything here is about proving the additive property holds and that the three
things the server actually branches on now key off `cls` / `ring`:

  round-trip     envelope_type + id keep being written and served, unchanged,
                 so an old client that never learns about cls/seq loses nothing
  derivation     the ingest alias maps every envelope_type to the right class,
                 and a new client's explicit `cls` wins over it
  call/ring      a call is a CONTENT row that rings; the ring is a request flag,
                 never a stored "call" class
  push branch    cls == 1 pushes, cls 0/2 do not, ring takes the call wake
  sweep spare    the group dormant sweep spares cls == 2 (new) AND legacy skdm,
                 and still reaps content for a dormant recipient
  seq durable    per-mailbox, independent across mailboxes, and — the loss case
                 the whole design exists to prevent — it does NOT reseed to 0
                 after the sweep empties a mailbox and it refills
  seq backstop   (to_uin, seq) is unique: a collision raises, never overwrites
  capability     /server/info advertises envelope_class so a client can switch

Direct unit + ASGI-HTTP test against a throwaway SQLite DB. The push senders and
the connection manager are stubbed so the deposit path's branch decisions are
observable without a live socket or APNs.

Run: cd backend && PYTHONPATH=. .venv/bin/python test_stage2_server_local.py
"""
import asyncio
import base64
import os

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test_stage2.db"
os.environ["ENV"] = "dev"
os.environ.setdefault("JWT_SECRET", "t" * 64)

for f in ("test_stage2.db",):
    try:
        os.remove(f)
    except FileNotFoundError:
        pass

from datetime import datetime, timedelta, timezone  # noqa: E402

import httpx  # noqa: E402
from sqlalchemy import delete, select, text  # noqa: E402

from app.core.db import SessionLocal, init_db  # noqa: E402
from app.core.security import issue_token  # noqa: E402
from app.main import app  # noqa: E402
from app.models.group import Group, GroupMember, OfflineGroupMessage  # noqa: E402
from app.models.message import OfflineMessage  # noqa: E402
from app.models.user import User  # noqa: E402
from app.routers import messages as M  # noqa: E402
from app.services import offline_queue_sweep as SW  # noqa: E402

PASS, FAIL = [], []


def check(name: str, ok: bool, detail: str = "") -> None:
    (PASS if ok else FAIL).append(name)
    print(f"  {'ok  ' if ok else 'FAIL'} {name}{'' if ok else '  <- ' + detail}")


def b64(n: int = 33) -> str:
    return base64.b64encode(os.urandom(n)).decode()


# ── stubs: make the deposit path's branch decisions observable ──────────────
class FakeManager:
    """Nothing is ever online, so every deposit falls into the offline
    push/ring branch where we can watch which one it takes."""

    async def send(self, uin, pkt):
        return False

    async def online_devices(self, uin):
        return []

    async def fanout(self, uins, pkt):
        return set()

    async def fanout_each(self, items):
        return set()


PUSHED: list[tuple[int, str]] = []   # (uin, envelope_type) for message-class pushes
RANG: list[int] = []                 # uins that took the ring wake


async def fake_apns(uin, **kw):
    PUSHED.append((uin, kw.get("envelope_type")))
    return 1


async def fake_up(uin, **kw):
    return 0


async def fake_wake(to_uin, payload):
    RANG.append(to_uin)
    return 1


async def count(model, *where) -> int:
    from sqlalchemy import func
    async with SessionLocal() as db:
        return int(await db.scalar(select(func.count()).select_from(model).where(*where)) or 0)


async def main() -> None:
    await init_db()

    M.manager = FakeManager()
    M.apns_send = fake_apns
    M.up_send = fake_up
    M._wake_for_sealed_call = fake_wake

    # ── 0. pure derivation: a sample of each class ──────────────────────────
    print("\n_cls_for derivation")
    check("ephemeral: read -> 0", M._cls_for("read") == 0)
    check("ephemeral: typing -> 0", M._cls_for("typing") == 0)
    check("content: message -> 1", M._cls_for("message") == 1)
    check("content: reaction -> 1", M._cls_for("reaction") == 1)
    check("content: secscreen -> 1 (still pushable)", M._cls_for("secscreen") == 1)
    check("content: call -> 1 (never its own class)", M._cls_for("call") == 1)
    check("critical: skdm -> 2", M._cls_for("skdm") == 2)
    check("critical: sknack -> 2", M._cls_for("sknack") == 2)
    check("unknown future kind -> 1 (fail toward keeping)", M._cls_for("teleport") == 1)

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        # recipients
        async with SessionLocal() as db:
            for uin in (5001, 5002, 5003, 5004, 5005):
                db.add(User(uin=uin, nickname=f"u{uin}", identity_key=b64(32), signing_key=b64(32)))
            await db.commit()

        # ── 1. envelope_type + id still round-trip; cls + seq ride alongside ─
        print("\nround-trip + both shapes on the drain")
        r = await c.post("/messages/sealed", json={
            "to_uin": 5001, "envelope_type": "message", "payload": b64(),
        })
        check("deposit accepted", r.status_code == 200, r.text)
        tok = issue_token(5001, 0, "phone")
        rows = (await c.get("/messages/queue?ack=0&dev=1",
                            headers={"Authorization": f"Bearer {tok}"})).json()
        check("exactly one row drained", len(rows) == 1, str(rows))
        row = rows[0] if rows else {}
        check("old field envelope_type served unchanged", row.get("envelope_type") == "message")
        check("old field id still served", isinstance(row.get("id"), int) and row["id"] > 0)
        check("new field cls served (content=1)", row.get("cls") == 1)
        check("new field seq served (first in this mailbox = 1)", row.get("seq") == 1)

        # ── 2. deposit-time class: derived vs explicit; ephemeral/critical ──
        print("\ndeposit stores the class (ingest alias + explicit cls)")
        PUSHED.clear(); RANG.clear()
        # ephemeral, aliased from envelope_type
        await c.post("/messages/sealed", json={"to_uin": 5002, "envelope_type": "read", "payload": b64()})
        # critical, aliased from envelope_type (artificial on the 1:1 path, but
        # proves the derivation files it as cls 2)
        await c.post("/messages/sealed", json={"to_uin": 5002, "envelope_type": "skdm", "payload": b64()})
        # a new client's EXPLICIT cls wins over a mismatched envelope_type
        await c.post("/messages/sealed", json={
            "to_uin": 5002, "envelope_type": "message", "cls": 0, "payload": b64(),
        })
        async with SessionLocal() as db:
            stored = (await db.execute(
                select(OfflineMessage.envelope_type, OfflineMessage.cls)
                .where(OfflineMessage.to_uin == 5002)
                .order_by(OfflineMessage.seq.asc())
            )).all()
        by_type = {t: cl for t, cl in stored}
        check("read stored as cls 0", by_type.get("read") == 0)
        check("skdm stored as cls 2", by_type.get("skdm") == 2)
        check("explicit cls=0 overrides envelope_type=message", by_type.get("message") == 0)
        check("read (cls 0) was not pushed", (5002, "read") not in PUSHED)
        check("skdm (cls 2) was not pushed", (5002, "skdm") not in PUSHED)

        # ── 3. a call: content-class row, rings via `ring`, never a "call" cls ─
        print("\ncall deposits (old-style type + new-style ring)")
        PUSHED.clear(); RANG.clear()
        # old client: types "call", no ring flag
        await c.post("/messages/sealed", json={"to_uin": 5003, "envelope_type": "call", "payload": b64()})
        # new client: content type + ring=true
        await c.post("/messages/sealed", json={
            "to_uin": 5003, "envelope_type": "message", "ring": True, "payload": b64(),
        })
        async with SessionLocal() as db:
            call_rows = (await db.execute(
                select(OfflineMessage.envelope_type, OfflineMessage.cls)
                .where(OfflineMessage.to_uin == 5003).order_by(OfflineMessage.seq.asc())
            )).all()
        check("both call deposits stored as content class (cls 1)",
              [cl for _, cl in call_rows] == [1, 1], str(call_rows))
        check("old-style keeps envelope_type 'call' (alias), new-style 'message'",
              sorted(t for t, _ in call_rows) == ["call", "message"])
        check("both rang (took the call wake)", RANG.count(5003) == 2, str(RANG))
        check("neither raised a message push", (5003, "message") not in PUSHED and (5003, "call") not in PUSHED)

        # a plain content message DOES push and does NOT ring
        PUSHED.clear(); RANG.clear()
        await c.post("/messages/sealed", json={"to_uin": 5004, "envelope_type": "message", "payload": b64()})
        check("content message pushed", (5004, "message") in PUSHED)
        check("content message did not ring", 5004 not in RANG)

        # ── 6. seq: per-mailbox, independent across mailboxes ───────────────
        print("\nseq is per-mailbox and independent")
        # 5005 is fresh; deposit two
        await c.post("/messages/sealed", json={"to_uin": 5005, "envelope_type": "message", "payload": b64()})
        await c.post("/messages/sealed", json={"to_uin": 5005, "envelope_type": "message", "payload": b64()})
        async with SessionLocal() as db:
            seqs_5005 = (await db.execute(
                select(OfflineMessage.seq).where(OfflineMessage.to_uin == 5005).order_by(OfflineMessage.seq.asc())
            )).scalars().all()
            # 5004 got a single content deposit earlier and was never drained,
            # so its own counter sits at 1 while 5005 has climbed to 2.
            seqs_5004 = (await db.execute(
                select(OfflineMessage.seq).where(OfflineMessage.to_uin == 5004).order_by(OfflineMessage.seq.asc())
            )).scalars().all()
        check("mailbox 5005 counts 1,2 on its own", seqs_5005 == [1, 2], str(seqs_5005))
        check("mailbox 5004 counts from 1 independently", seqs_5004 == [1], str(seqs_5004))

        # ── 7. THE LOSS CASE: seq must NOT reseed after the mailbox empties ──
        print("\nseq does not reseed after the mailbox is emptied and refilled")
        async with SessionLocal() as db:
            await db.execute(delete(OfflineMessage).where(OfflineMessage.to_uin == 5005))
            await db.commit()
            left = int(await db.scalar(
                select(text("count(*)")).select_from(OfflineMessage).where(OfflineMessage.to_uin == 5005)
            ) or 0)
        check("mailbox 5005 is now empty (sweep simulation)", left == 0)
        await c.post("/messages/sealed", json={"to_uin": 5005, "envelope_type": "message", "payload": b64()})
        async with SessionLocal() as db:
            refill_seq = (await db.execute(
                select(OfflineMessage.seq).where(OfflineMessage.to_uin == 5005)
            )).scalars().all()
        check("refilled row is seq 3, NOT reseeded to 1 (would bury below the cursor)",
              refill_seq == [3], str(refill_seq))

        # ── capability advertised ───────────────────────────────────────────
        print("\ncapability")
        info = (await c.get("/server/info")).json()
        check("envelope_class advertised true", info["capabilities"].get("envelope_class") is True)
        check("old capabilities still present (deposit_auth key)",
              "deposit_auth" in info["capabilities"])

    # ── 8. (to_uin, seq) collision raises rather than overwrites ────────────
    print("\n(to_uin, seq) uniqueness backstop")
    from sqlalchemy.exc import IntegrityError
    raised = False
    async with SessionLocal() as db:
        db.add(OfflineMessage(to_uin=6001, envelope_type="message", cls=1, seq=1, payload=b64()))
        await db.commit()
    try:
        async with SessionLocal() as db:
            db.add(OfflineMessage(to_uin=6001, envelope_type="message", cls=1, seq=1, payload=b64()))
            await db.commit()
    except IntegrityError:
        raised = True
    check("a duplicate (to_uin, seq) raises IntegrityError", raised)
    check("the original row was NOT overwritten (still exactly one)",
          await count(OfflineMessage, OfflineMessage.to_uin == 6001) == 1)

    # ── 4 + 5. group dormant sweep spares cls==2 and legacy skdm, reaps content
    print("\ngroup dormant sweep (mixed cls / envelope_type table)")
    DORMANT = 7001   # last_seen far in the past -> a sweep candidate
    async with SessionLocal() as db:
        db.add(User(uin=DORMANT, nickname="dorm", identity_key=b64(32), signing_key=b64(32),
                    last_seen=datetime.now(timezone.utc) - timedelta(days=90)))
        await db.commit()
        # four rows to one dormant recipient: two new (cls set), two legacy (cls NULL)
        db.add(OfflineGroupMessage(to_uin=DORMANT, group_id=42, envelope_type="skdm",
                                   cls=2, payload=b64(), received_at=datetime.now(timezone.utc)))
        db.add(OfflineGroupMessage(to_uin=DORMANT, group_id=42, envelope_type="gmsg",
                                   cls=1, payload=b64(), received_at=datetime.now(timezone.utc)))
        db.add(OfflineGroupMessage(to_uin=DORMANT, group_id=42, envelope_type="skdm",
                                   cls=None, payload=b64(), received_at=datetime.now(timezone.utc)))
        db.add(OfflineGroupMessage(to_uin=DORMANT, group_id=42, envelope_type="message",
                                   cls=None, payload=b64(), received_at=datetime.now(timezone.utc)))
        await db.commit()

    cutoff = datetime.now(timezone.utc) - timedelta(days=SW.DORMANT_DAYS)
    reaped = await SW._sweep_dormant(cutoff)
    async with SessionLocal() as db:
        survivors = (await db.execute(
            select(OfflineGroupMessage.envelope_type, OfflineGroupMessage.cls)
            .where(OfflineGroupMessage.to_uin == DORMANT)
        )).all()
    surv_set = {(t, cl) for t, cl in survivors}
    check("dormant sweep reaped the two content rows", reaped == 2, f"reaped={reaped}")
    check("new skdm (cls 2) survived", ("skdm", 2) in surv_set)
    check("legacy skdm (cls NULL) survived via envelope_type fallback", ("skdm", None) in surv_set)
    check("new content (cls 1) was swept", ("gmsg", 1) not in surv_set)
    check("legacy content (cls NULL, 'message') was swept", ("message", None) not in surv_set)

    # ── group deposit path writes cls onto offline_group_messages ───────────
    print("\ngroup deposit writes cls")
    async with SessionLocal() as db:
        # a recent member so a content post is kept (not dormant-skipped)
        db.add(User(uin=8001, nickname="m", identity_key=b64(32), signing_key=b64(32),
                    last_seen=datetime.now(timezone.utc)))
        db.add(Group(id=99, owner_uin=8001, name="g"))
        db.add(GroupMember(group_id=99, uin=8001, role="owner"))
        await db.commit()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        r = await c.post("/messages/group-sealed", json={
            "group_id": 99, "envelope_type": "message",
            "payloads": [{"to_uin": 8001, "payload": b64()}],
        })
        check("group-sealed accepted", r.status_code == 200, r.text)
        r2 = await c.post("/messages/group-sealed", json={
            "group_id": 99, "envelope_type": "skdm",
            "payloads": [{"to_uin": 8001, "payload": b64()}],
        })
        check("group-sealed skdm accepted", r2.status_code == 200, r2.text)
    async with SessionLocal() as db:
        gstored = {t: cl for t, cl in (await db.execute(
            select(OfflineGroupMessage.envelope_type, OfflineGroupMessage.cls)
            .where(OfflineGroupMessage.to_uin == 8001)
        )).all()}
    check("group content row stored with cls 1", gstored.get("message") == 1)
    check("group skdm row stored with cls 2", gstored.get("skdm") == 2)

    # ── _keep_for branches on cls==2, not the type string ───────────────────
    print("\n_keep_for keeps critical class for everyone")
    everyone = [1, 2, 3]
    check("cls 2 kept for all recipients regardless of dormancy",
          M._keep_for(everyone, set(), 2, []) == {1, 2, 3})
    check("cls 1 kept only for queueable | wake",
          M._keep_for(everyone, {1}, 1, [2]) == {1, 2})

    total = len(PASS) + len(FAIL)
    print(f"\n{'ALL' if not FAIL else str(len(FAIL)) + ' FAILED of'} {total} STAGE-2 CHECKS "
          f"{'PASSED' if not FAIL else ''}".rstrip())
    if FAIL:
        print("FAILURES:", ", ".join(FAIL))
    raise SystemExit(0 if not FAIL else 1)


asyncio.run(main())
