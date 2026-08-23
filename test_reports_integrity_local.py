"""Local-only verification of report integrity: the number, the soft delete,
and editing your own text.

The headline is the second one. `services/hof_stats` counts a contributor's
bug-bounty reports (how many filed, how many confirmed) LIVE over the `reports`
table, and DELETE /reports/mine/{id} used to be a real DELETE. So the way to
look like a contributor who is never wrong was to file everything you could
think of and delete whatever came back dismissed: `total` fell, `confirmed`
stayed, and `confirmed**2 / total` (the podium ranking) went up. Nobody has to
be caught doing it for the wall to stop meaning anything.

The rule this proves, and it has no exceptions on purpose: once filed, a report
counts as filed. Deleting it hides it from the reporter's own list and changes
nothing else. Including a report still PENDING, because the operator says "это
не баг" in the thread before he flips the status, so any pending carve-out just
moves the exploit into the window between the answer and the verdict.

Also covered: the number the reporter sees is the number the founder answers by
(they must not be two numbers), the admin keeps the row he rejected, editing is
possible while nobody has answered and refused afterwards, and the retention
sweep neither defeats the soft delete nor loses the [CRASH] flag it redacts
over (which would quietly add every swept crash dump to its filer's tally).

Runs the real FastAPI stack in-process on a throwaway SQLite DB.
NOT part of the prod suite; NOT deployed.
Run: cd backend && PYTHONPATH=. .venv/bin/python test_reports_integrity_local.py
"""
import asyncio
import base64
import os

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test_reports_integrity.db"
os.environ["ENV"] = "dev"
os.environ["ADMIN_USERNAME"] = "admin"
os.environ["ADMIN_PASSWORD"] = "test-pass"

for f in ("test_reports_integrity.db",):
    try:
        os.remove(f)
    except FileNotFoundError:
        pass

from datetime import datetime, timedelta, timezone  # noqa: E402

import httpx  # noqa: E402

from app.core.db import SessionLocal, init_db  # noqa: E402
from app.main import app  # noqa: E402
from app.models.report import Report  # noqa: E402
from app.services.hof_stats import bug_report_stats, podium_score  # noqa: E402

fails = 0
ADMIN = {"Authorization": "Basic " + base64.b64encode(b"admin:test-pass").decode()}


def check(name, cond, detail=""):
    global fails
    print(f"  {'PASS' if cond else 'FAIL'}  {name}{'' if cond else '  <- ' + detail}")
    if not cond:
        fails += 1


def b64(n=32):
    return base64.b64encode(os.urandom(n)).decode()


async def stats(uin: int) -> tuple[int, int]:
    async with SessionLocal() as db:
        return (await bug_report_stats(db, [uin])).get(uin, (0, 0))


async def main():
    await init_db()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        r = await c.post("/auth/register", json={
            "nickname": "tester", "identity_key": b64(), "signing_key": b64(),
        })
        uin, token = r.json()["uin"], r.json()["token"]
        auth = {"Authorization": f"Bearer {token}"}

        async def file_bug(text):
            resp = await c.post("/reports", json={
                "target_uin": uin, "reason": text,
                "context": "bug_bounty", "attachments": [],
            }, headers=auth)
            assert resp.status_code == 201, resp.text
            return resp.json()

        # ── the number ──────────────────────────────────────────────────────
        print("\nreport number")
        good = await file_bug("[Android 0.146] album viewer opens on the wrong photo")
        check("a filed report answers with a number", isinstance(good.get("number"), int))
        check("and it is the id, not a second numbering", good["number"] == good["id"])

        mine = (await c.get("/reports/mine", headers=auth)).json()
        check("the reporter's own list carries the number",
              mine[0]["number"] == good["number"])

        q = (await c.get("/admin/reports?status=open&kind=all", headers=ADMIN)).json()
        admin_ids = {x["id"] for x in q["items"]}
        check("* the number the reporter sees is the number the founder answers by",
              good["number"] in admin_ids)

        # ── the exploit ─────────────────────────────────────────────────────
        print("\nhall of fame integrity")
        rejected = await file_bug("[Android 0.146] the app is slow")
        pending = await file_bug("[Android 0.146] the keyboard covers the field")
        crash = await file_bug("[Android 0.146] [CRASH] java.lang.IllegalStateException")

        await c.post(f"/admin/reports/{good['id']}/resolve",
                     json={"action": "fixed", "notes": "real, fixed in 0.147"},
                     headers=ADMIN)
        await c.post(f"/admin/reports/{rejected['id']}/resolve",
                     json={"action": "dismissed", "notes": "not a bug"},
                     headers=ADMIN)

        before = await stats(uin)
        check("baseline: 3 filed, 1 confirmed (the crash dump is not effort)",
              before == (3, 1), str(before))

        r = await c.delete(f"/reports/mine/{rejected['id']}", headers=auth)
        check("a dismissed report can be dropped from the list", r.status_code == 204)

        after = await stats(uin)
        check("*** deleting a DISMISSED report leaves the counters untouched",
              after == before, f"{before} -> {after}")
        check("...so the podium ranking cannot be raised by deleting failures",
              podium_score(*after) == podium_score(*before))

        mine = (await c.get("/reports/mine", headers=auth)).json()
        check("...and it really is off the reporter's list",
              rejected["id"] not in {m["id"] for m in mine})
        check("...while the rest of the list is intact", len(mine) == 3)

        q = (await c.get("/admin/reports?status=dismissed&kind=all", headers=ADMIN)).json()
        row = next((x for x in q["items"] if x["id"] == rejected["id"]), None)
        check("*** the founder keeps the report he rejected", row is not None)
        check("...with the text he rejected it over",
              row is not None and row["reason"].endswith("the app is slow"))

        r = await c.delete(f"/reports/mine/{pending['id']}", headers=auth)
        check("a PENDING report can be dropped too", r.status_code == 204)
        check("*** but it still counts as filed (no window between the "
              "operator's answer and his verdict)",
              await stats(uin) == before, str(await stats(uin)))

        # Dropping twice must not restamp the row: a client retrying a 204 it
        # never saw would otherwise rewrite when this happened.
        async with SessionLocal() as db:
            first_stamp = (await db.get(Report, rejected["id"])).hidden_at
        r = await c.delete(f"/reports/mine/{rejected['id']}", headers=auth)
        async with SessionLocal() as db:
            second_stamp = (await db.get(Report, rejected["id"])).hidden_at
        check("dropping a report twice is idempotent",
              r.status_code == 204 and first_stamp == second_stamp)

        r = await c.post(f"/reports/mine/{rejected['id']}/messages",
                         json={"body": "actually, one more thing"}, headers=auth)
        check("a dropped report is not writable (404, like any id you cannot see)",
              r.status_code == 404)

        # A live complaint ABOUT SOMEBODY still waits for its verdict: the
        # reporter is a party to that case and the thread is the operator's
        # only way to ask them anything.
        r2 = await c.post("/auth/register", json={
            "nickname": "stranger", "identity_key": b64(), "signing_key": b64(),
        })
        other_uin, other_token = r2.json()["uin"], r2.json()["token"]
        other = {"Authorization": f"Bearer {other_token}"}
        abuse = (await c.post("/reports", json={
            "target_uin": other_uin, "reason": "he said a thing",
            "context": "contact", "attachments": [],
        }, headers=auth)).json()
        r = await c.delete(f"/reports/mine/{abuse['id']}", headers=auth)
        check("an OPEN report about another user still refuses to be dropped",
              r.status_code == 409)
        check("and says why", (r.json().get("detail") or {}).get("code") == "under_review")

        # ── editing ─────────────────────────────────────────────────────────
        print("\nediting your own report")
        draft = await file_bug("[iOS 0.9] the thing is broekn")
        r = await c.patch(f"/reports/mine/{draft['id']}",
                          json={"reason": "[iOS 0.9] the export button is broken on iPad"},
                          headers=auth)
        check("* an unanswered report can be rewritten", r.status_code == 200)
        body = r.json() if r.status_code == 200 else {}
        check("the answer carries the number", body.get("number") == draft["id"])
        check("and the edit is stamped", body.get("edited_at") is not None)

        q = (await c.get("/admin/reports?status=open&kind=bug", headers=ADMIN)).json()
        row = next((x for x in q["items"] if x["id"] == draft["id"]), None)
        check("the operator sees the corrected text, not the typo",
              row is not None and row["reason"].endswith("broken on iPad"))

        r = await c.patch(f"/reports/mine/{draft['id']}",
                          json={"reason": "[iOS 0.9] [CRASH] pretend this was automatic"},
                          headers=auth)
        check("* the [CRASH] flag cannot be typed in by hand "
              "(it would take the report out of the tally)", r.status_code == 400)
        r = await c.patch(f"/reports/mine/{crash['id']}",
                          json={"reason": "on second thought this is a real bug"},
                          headers=auth)
        check("and a crash dump is not editable at all", r.status_code == 400)

        r = await c.patch(f"/reports/mine/{draft['id']}",
                          json={"reason": "hello"}, headers=other)
        check("a stranger cannot rewrite your report", r.status_code == 404)

        await c.post(f"/admin/reports/{draft['id']}/reply",
                     json={"text": "Which iPad model?"}, headers=ADMIN)
        r = await c.patch(f"/reports/mine/{draft['id']}",
                          json={"reason": "changed my mind about everything"},
                          headers=auth)
        check("* once answered, the text the operator replied to is frozen",
              r.status_code == 409)
        check("and says why",
              (r.json().get("detail") or {}).get("code") == "already_answered")

        await c.post(f"/admin/reports/{draft['id']}/resolve",
                     json={"action": "fixed", "notes": ""}, headers=ADMIN)
        r = await c.patch(f"/reports/mine/{draft['id']}",
                          json={"reason": "still one more idea"}, headers=auth)
        check("a closed report is not editable either", r.status_code == 409)

    # ── the sweep must not undo any of this ─────────────────────────────────
    print("\nretention sweep")
    from app.services.report_sweep import (  # noqa: E402
        REDACTED_REASON_CRASH,
        RESOLVED_MAX_AGE_DAYS,
        sweep_once as report_sweep,
    )

    swept_uin = 909090
    old = datetime.now(timezone.utc) - timedelta(days=RESOLVED_MAX_AGE_DAYS + 5)
    async with SessionLocal() as db:
        hidden_bug = Report(
            reporter_uin=swept_uin, target_uin=swept_uin, context="bug_bounty",
            reason="[Android 0.140] dropped by its author, confirmed anyway",
            status="resolved", resolved_at=old,
            hidden_at=datetime.now(timezone.utc),
            edited_at=datetime.now(timezone.utc),
        )
        swept_crash = Report(
            reporter_uin=swept_uin, target_uin=swept_uin, context="bug_bounty",
            reason="[Android 0.140] [CRASH] NullPointerException",
            status="dismissed", resolved_at=old,
        )
        # ⚠ The shape with NO resolution clock at all: withdrawn while still
        # open, which is what happens when somebody files a bug report, notices
        # their text names a friend, and drops it. The operator never closes it,
        # because nobody is asking about it any more. On the resolution clock
        # alone this row keeps its free text forever, and the reporter cannot
        # even reach it to ask for it to be closed.
        withdrawn_open = Report(
            reporter_uin=swept_uin, target_uin=swept_uin, context="bug_bounty",
            reason="[iOS 0.9] my friend 100200300 sees my drafts",
            status="open", resolved_at=None, hidden_at=old,
        )
        # The same drop, made TODAY. Withdrawing is not a request to delete
        # early: this one has to survive the pass.
        withdrawn_fresh = Report(
            reporter_uin=swept_uin, target_uin=swept_uin, context="bug_bounty",
            reason="[iOS 0.9] dropped a minute ago",
            status="open", resolved_at=None, hidden_at=datetime.now(timezone.utc),
        )
        db.add_all([hidden_bug, swept_crash, withdrawn_open, withdrawn_fresh])
        await db.commit()
        hidden_id, crash_id = hidden_bug.id, swept_crash.id
        withdrawn_id, fresh_id = withdrawn_open.id, withdrawn_fresh.id
        withdrawn_reason, fresh_reason = withdrawn_open.reason, withdrawn_fresh.reason

    check("before the sweep: 3 filed, 1 confirmed (the crash dump is not effort)",
          await stats(swept_uin) == (3, 1), str(await stats(swept_uin)))
    _, redacted, _ = await report_sweep()
    async with SessionLocal() as db:
        kept = await db.get(Report, hidden_id)
        crashed = await db.get(Report, crash_id)
        withdrawn = await db.get(Report, withdrawn_id)
        fresh = await db.get(Report, fresh_id)
    check("* a report its author dropped is still redacted on the normal horizon "
          "(hiding is not a retention event)",
          kept is not None and kept.reason != hidden_bug.reason)
    check("...and its row survives, so the wall still counts it",
          await stats(swept_uin) == (3, 1), str(await stats(swept_uin)))
    check("*** a report withdrawn while still OPEN is redacted too "
          "(otherwise nothing on the island would ever reach its text)",
          withdrawn is not None and withdrawn.reason != withdrawn_reason)
    check("...and it is still off the reporter's list, so hiding was not undone",
          withdrawn is not None and withdrawn.hidden_at is not None)
    check("...while a drop made today is untouched (withdrawing is not delete-now)",
          fresh is not None and fresh.reason == fresh_reason)
    check("...and the edit stamp goes with the drafts it distinguished",
          kept is not None and kept.edited_at is None)
    check("* a redacted CRASH row keeps its marker",
          crashed is not None and crashed.reason == REDACTED_REASON_CRASH)
    check("...so redaction does not quietly add crash dumps to the tally",
          await stats(swept_uin) == (3, 1), str(await stats(swept_uin)))
    again = await report_sweep()
    check("a second pass is still a no-op with two redaction markers in play",
          again == (0, 0, 0), str(again))
    check("the pass redacted exactly the three expired rows", redacted == 3, str(redacted))

    print("\n" + ("ALL PASS" if fails == 0 else f"{fails} FAILED"))
    raise SystemExit(1 if fails else 0)


asyncio.run(main())
