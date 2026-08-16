"""Local-only verification that a report is a conversation now.

A report used to be a box with a lid: one message in, one answer back. People
who were asked a question filed a SECOND report to answer it, which is what the
queue actually looked like. This covers the half that was missing.

Runs the real FastAPI stack in-process on a throwaway SQLite DB.
NOT part of the prod suite; NOT deployed.
Run: cd backend && PYTHONPATH=. .venv/bin/python test_ticket_thread_local.py
"""
import asyncio
import base64
import os

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test_ticket_thread.db"
os.environ["ENV"] = "dev"
os.environ["ADMIN_USERNAME"] = "admin"
os.environ["ADMIN_PASSWORD"] = "test-pass"

for f in ("test_ticket_thread.db",):
    try:
        os.remove(f)
    except FileNotFoundError:
        pass

import httpx  # noqa: E402
from app.main import app  # noqa: E402
from app.core.db import init_db  # noqa: E402

fails = 0
ADMIN = "Basic " + base64.b64encode(b"admin:test-pass").decode()


def check(name, cond):
    global fails
    print(f"  {'PASS' if cond else 'FAIL'}  {name}")
    if not cond:
        fails += 1


def b64(n=32):
    return base64.b64encode(os.urandom(n)).decode()


async def main():
    await init_db()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        r = await c.post("/auth/register", json={
            "nickname": "reporter", "identity_key": b64(), "signing_key": b64(),
        })
        uin, token = r.json()["uin"], r.json()["token"]
        auth = {"Authorization": f"Bearer {token}"}

        r = await c.post("/reports", json={
            "target_uin": uin, "reason": "[Android 0.124] the thing does the thing",
            "context": "bug_bounty", "attachments": [],
        }, headers=auth)
        check("a report is filed", r.status_code == 201)
        rid = r.json()["id"]

        # --- the operator answers -------------------------------------------
        r = await c.post(f"/admin/reports/{rid}/reply",
                         json={"text": "Which version exactly?"},
                         headers={"Authorization": ADMIN})
        check("the operator can answer", r.status_code == 200)

        mine = (await c.get("/reports/mine", headers=auth)).json()[0]
        check("★ the answer is in the thread", len(mine["thread"]) == 1)
        check("and it is marked as the operator's", mine["thread"][0]["from_admin"] is True)
        check("the old single-answer field still works for old clients",
              mine["reply"] == "Which version exactly?")

        # --- the reporter writes BACK — the half that did not exist ---------
        r = await c.post(f"/reports/mine/{rid}/messages", json={"body": "0.124, arm64"},
                         headers=auth)
        check("★ the reporter can write back", r.status_code == 201)
        check("and it is not marked as the operator's", r.json()["from_admin"] is False)

        mine = (await c.get("/reports/mine", headers=auth)).json()[0]
        check("both turns are in the thread, in order", [t["from_admin"] for t in mine["thread"]] == [True, False])

        # The operator sees the follow-up in the queue, which is the point of
        # allowing it at all.
        q = (await c.get("/admin/reports?status=open&kind=all",
                         headers={"Authorization": ADMIN})).json()
        row = next(x for x in q["items"] if x["id"] == rid)
        check("★ the operator sees the reply in the queue", len(row["thread"]) == 2)
        check("with the reporter's own words", row["thread"][1]["body"] == "0.124, arm64")

        # --- somebody else's report is not yours to write on ----------------
        r2 = await c.post("/auth/register", json={
            "nickname": "stranger", "identity_key": b64(), "signing_key": b64(),
        })
        other = {"Authorization": f"Bearer {r2.json()['token']}"}
        r = await c.post(f"/reports/mine/{rid}/messages", json={"body": "hello"}, headers=other)
        check("★ a stranger cannot write on it", r.status_code == 404)

        # --- a closed report stops accepting text ---------------------------
        await c.post(f"/admin/reports/{rid}/resolve", json={"action": "fixed", "notes": ""},
                     headers={"Authorization": ADMIN})
        r = await c.post(f"/reports/mine/{rid}/messages", json={"body": "one more thing"},
                         headers=auth)
        check("★ a closed report refuses new turns", r.status_code == 409)
        check("and says why", (r.json().get("detail") or {}).get("code") == "closed")

        # --- and the thread survives being read after closing ---------------
        mine = (await c.get("/reports/mine", headers=auth)).json()[0]
        check("the exchange is still readable when closed", len(mine["thread"]) == 2)

    print("\n" + ("ALL PASS" if fails == 0 else f"{fails} FAILED"))
    raise SystemExit(1 if fails else 0)


asyncio.run(main())
