"""Local-only verification that an ACCEPTED contact request leaves no record,
while a DECLINED one survives because it is the only way the sender finds out.

Until 2026-08-19 every resolved request stayed on the island for good: 515
accepted rows going back to April, saying who asked whom on what day, with no
reader anywhere (both list endpoints exclude the state, no client compares
against it). The accepted relationship is the pair of `contacts` rows.

⚠⚠ The declined half is NOT symmetric and must never be swept with it: no push
is sent for a decline on purpose, GET /contacts/outgoing serves exactly
pending+declined, and all three clients render that state. Delete it and the
request silently reverts to looking like it was never sent.

Runs the real FastAPI stack in-process via httpx ASGITransport on a throwaway
SQLite DB. NOT part of the prod suite; NOT deployed.
Run: cd backend && PYTHONPATH=. .venv/bin/python test_contact_request_retention_local.py
"""
import asyncio
import base64
import os
from datetime import datetime, timedelta, timezone

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test_contact_req.db"
os.environ["ENV"] = "dev"

for f in ("test_contact_req.db",):
    try:
        os.remove(f)
    except FileNotFoundError:
        pass

import httpx  # noqa: E402
from sqlalchemy import func, select, update  # noqa: E402

from app.core.db import SessionLocal, init_db  # noqa: E402
from app.main import app  # noqa: E402
from app.models.contact import ContactRequest  # noqa: E402

PASS, FAIL = [], []


def check(name: str, ok: bool, detail: str = "") -> None:
    (PASS if ok else FAIL).append(name)
    print(f"  {'ok  ' if ok else 'FAIL'} {name}{'' if ok else '  ← ' + detail}")


def keypair(seed: int) -> tuple[str, str]:
    """Any 32 well-formed bytes: registration only stores them."""
    raw = bytes([(seed + i) % 251 for i in range(32)])
    return base64.b64encode(raw).decode(), base64.b64encode(raw[::-1]).decode()


async def register(c: httpx.AsyncClient, nick: str, seed: int) -> tuple[int, str]:
    ident, sign = keypair(seed)
    r = await c.post("/auth/register", json={"nickname": nick, "identity_key": ident, "signing_key": sign})
    r.raise_for_status()
    d = r.json()
    return d["uin"], d["token"]


async def rows_between(a: int, b: int) -> list[ContactRequest]:
    async with SessionLocal() as db:
        return (await db.execute(
            select(ContactRequest).where(ContactRequest.from_uin.in_((a, b)),
                                         ContactRequest.to_uin.in_((a, b)))
        )).scalars().all()


async def main() -> None:
    await init_db()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        alice, at = await register(c, "alice", 1)
        bob, bt = await register(c, "bob", 40)
        carol, ct = await register(c, "carol", 80)
        dave, dt = await register(c, "dave", 120)
        erin, et = await register(c, "erin", 160)

        A = {"Authorization": f"Bearer {at}"}
        B = {"Authorization": f"Bearer {bt}"}
        C = {"Authorization": f"Bearer {ct}"}
        D = {"Authorization": f"Bearer {dt}"}
        E = {"Authorization": f"Bearer {et}"}

        # ── 1. accept marks the row and stamps it; the sweep takes it later ──
        r = await c.post("/contacts/request", json={"to_uin": bob}, headers=A)
        rid = r.json()["id"]
        r = await c.post("/contacts/respond", json={"request_id": rid, "accept": True}, headers=B)
        check("accept answers 'accepted'", r.json().get("state") == "accepted", r.text[:120])
        left = await rows_between(alice, bob)
        check("row is marked accepted and stamped",
              len(left) == 1 and left[0].state == "accepted" and left[0].resolved_at is not None,
              f"{[(x.state, x.resolved_at) for x in left]}")
        lst = (await c.get("/contacts", headers=A)).json()
        uins = {x["uin"] for x in (lst if isinstance(lst, list) else lst.get("contacts", []))}
        check("they are contacts", bob in uins, str(uins))

        # A second tap on Accept — slow network, impatient finger — must not
        # 404 on a request that succeeded. This is why the row is not deleted
        # inline; the web client turns any exception into an error banner.
        r2 = await c.post("/contacts/respond", json={"request_id": rid, "accept": True}, headers=B)
        check("a repeated Accept stays calm", r2.status_code == 200 and r2.json().get("state") == "accepted",
              f"{r2.status_code} {r2.text[:120]}")

        # ── 2. decline KEEPS the row: it is how the sender finds out ────────
        r = await c.post("/contacts/request", json={"to_uin": dave}, headers=C)
        rid = r.json()["id"]
        r = await c.post("/contacts/respond", json={"request_id": rid, "accept": False}, headers=D)
        check("decline answers 'declined'", r.json().get("state") == "declined", r.text[:120])
        left = await rows_between(carol, dave)
        check("declined row survives", len(left) == 1 and left[0].state == "declined",
              f"{[x.state for x in left]}")
        out = (await c.get("/contacts/outgoing", headers=C)).json()
        rows = out if isinstance(out, list) else out.get("requests", [])
        check("sender sees it as declined", any(x.get("to_uin") == dave and x.get("state") == "declined" for x in rows),
              str(rows)[:200])

        # ── 3. re-requesting after an accept works (no unique-index ghost) ──
        await c.delete(f"/contacts/{bob}", headers=A)
        r = await c.post("/contacts/request", json={"to_uin": bob}, headers=A)
        # 202: the island accepted the request for delivery. What matters here
        # is that it opens a FRESH pending row rather than colliding with the
        # unique index the deleted accepted row used to occupy.
        check("can request again after removal", r.status_code in (200, 202) and r.json().get("state") == "pending",
              f"{r.status_code} {r.text[:140]}")

        # ── 4. mutual add auto-accepts and leaves nothing behind ────────────
        await c.post("/contacts/request", json={"to_uin": erin}, headers=A)
        r = await c.post("/contacts/request", json={"to_uin": alice}, headers=E)
        body = r.json()
        check("mutual add auto-accepts", body.get("state") == "accepted" and body.get("auto") is True,
              str(body)[:140])
        left = await rows_between(alice, erin)
        check("auto-accepted row is marked, not left pending",
              len(left) == 1 and left[0].state == "accepted", f"{[x.state for x in left]}")

        # ── 5. the sweep is what actually removes them ──────────────────────
        # Fresh acceptances are inside the grace and must survive it...
        from app.services.contact_request_sweep import sweep_once

        n = await sweep_once()
        async with SessionLocal() as db:
            fresh = int(await db.scalar(
                select(func.count(ContactRequest.id)).where(ContactRequest.state == "accepted")
            ) or 0)
        check("the sweep spares acceptances inside the grace", n == 0 and fresh > 0,
              f"swept {n}, {fresh} accepted left")

        # ...and go once the grace has passed. Backdated rather than slept.
        async with SessionLocal() as db:
            await db.execute(
                update(ContactRequest)
                .where(ContactRequest.state == "accepted")
                .values(resolved_at=datetime.now(timezone.utc) - timedelta(hours=3))
            )
            await db.commit()
        n = await sweep_once()
        check("the sweep takes them after the grace", n == fresh, f"swept {n}, expected {fresh}")

        # What is left island-wide: the one declined row, and the fresh pending
        # re-request from step 3. Nothing accepted survives.
        async with SessionLocal() as db:
            states = sorted(s for (s,) in (await db.execute(select(ContactRequest.state))).all())
        check("no accepted row survives the sweep", states == ["declined", "pending"], str(states))
        check("the declined row is still there afterwards", "declined" in states, str(states))

    print(f"\n{len(PASS)}/{len(PASS) + len(FAIL)} pass")
    if FAIL:
        raise SystemExit("FAILED: " + ", ".join(FAIL))


asyncio.run(main())
