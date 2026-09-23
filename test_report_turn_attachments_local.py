"""Local-only verification: pictures on a reporter's follow-up turn (#1039).

The reporter asked to add a screenshot to a report he had already filed, and
could not: the reply box took text only, and the island dropped `attachments`
on a turn in silence even when a client sent them (pydantic ignores unknown
keys, so the text was stored, 201 came back and the picture was gone). He
filed a second report to carry one image.

Pins:
  * a turn on a BUG report keeps its pictures, and hands them back;
  * a turn on a report about a PERSON keeps none — the filing rule, which
    drops attachments on anything that is not a bug report; otherwise a
    complaint could collect images one turn at a time that it could never
    have been filed with;
  * a picture-only turn is accepted on a bug report, and on a person report
    (where the picture is dropped) it is the same 422 as an empty text turn;
  * the reporter's own view says which of their reports take pictures;
  * /server/info advertises it, because an island without it ignores the
    field silently and the client must know not to offer the button;
  * the media sweep protects a turn's pictures like the report's own.

Runs the real FastAPI stack in-process on a throwaway SQLite DB with Redis
db 15. NOT deployed.
Run: PYTHONPATH=. .venv/bin/python test_report_turn_attachments_local.py
"""
import asyncio
import base64
import os

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test_report_turn_attachments.db"
os.environ["ENV"] = "dev"
os.environ["REDIS_URL"] = "redis://localhost:6379/15"
try:
    os.remove("test_report_turn_attachments.db")
except FileNotFoundError:
    pass

import httpx  # noqa: E402

from app.core.db import SessionLocal, init_db  # noqa: E402
from app.core.redis import close_redis, get_redis  # noqa: E402
from app.core.security import issue_token  # noqa: E402
from app.main import app  # noqa: E402
from app.models.user import User  # noqa: E402

fails = 0


def check(name, cond):
    global fails
    print(f"  {'PASS' if cond else 'FAIL'}  {name}")
    if not cond:
        fails += 1


def b64(n=32):
    return base64.b64encode(os.urandom(n)).decode()


REPORTER, OTHER = 8201, 8202
PIC = {"media_id": "a" * 32, "key": b64(), "mime": "image/jpeg", "size": 38076}
PIC2 = {"media_id": "b" * 32, "key": b64(), "mime": "image/jpeg", "size": 51829}


async def main():
    global fails
    await init_db()
    await (await get_redis()).flushdb()
    async with SessionLocal() as db:
        for u in (REPORTER, OTHER):
            db.add(User(uin=u, nickname=f"u{u}", identity_key=b64(), signing_key=b64()))
        await db.commit()
    H = {"Authorization": f"Bearer {issue_token(REPORTER, 0, 'phone')}"}
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        print("\nThe island says it can:")
        info = (await c.get("/server/info")).json()
        check("/server/info advertises report_turn_attachments", (info.get("capabilities") or {}).get("report_turn_attachments") is True)

        print("\nFiling:")
        r = await c.post("/reports", headers=H, json={"target_uin": REPORTER, "reason": "voice does not send", "context": "bug_bounty"})
        check("a bug report is filed", r.status_code in (200, 201))
        bug_id = r.json()["id"]
        r = await c.post("/reports", headers=H, json={"target_uin": OTHER, "reason": "spam", "context": ""})
        check("a report about a person is filed", r.status_code in (200, 201))
        person_id = r.json()["id"]

        print("\nA turn on the bug report:")
        r = await c.post(f"/reports/mine/{bug_id}/messages", headers=H, json={"body": "here it is", "attachments": [PIC]})
        check("text plus a picture is accepted", r.status_code == 201)
        check("and the picture comes back on the turn", [a["media_id"] for a in r.json().get("attachments", [])] == [PIC["media_id"]])
        r = await c.post(f"/reports/mine/{bug_id}/messages", headers=H, json={"body": "", "attachments": [PIC2]})
        check("a picture with no words is accepted", r.status_code == 201)
        r = await c.post(f"/reports/mine/{bug_id}/messages", headers=H, json={"body": "   "})
        check("an empty turn is still refused", r.status_code == 422)

        print("\nA turn on the report about a person:")
        r = await c.post(f"/reports/mine/{person_id}/messages", headers=H, json={"body": "more", "attachments": [PIC]})
        check("the text is kept", r.status_code == 201 and r.json()["body"] == "more")
        check("the picture is dropped, as at filing", r.json().get("attachments") == [])
        r = await c.post(f"/reports/mine/{person_id}/messages", headers=H, json={"body": "", "attachments": [PIC]})
        check("a picture-only turn there is the empty-turn 422", r.status_code == 422)

        print("\nThe reporter's own view:")
        mine = {x["id"]: x for x in (await c.get("/reports/mine", headers=H)).json()}
        check("the bug report takes pictures", mine[bug_id]["attachments_allowed"] is True)
        check("the report about a person does not", mine[person_id]["attachments_allowed"] is False)
        pics = [a["media_id"] for t in mine[bug_id]["thread"] for a in t.get("attachments", [])]
        check("the thread carries both pictures", sorted(pics) == sorted([PIC["media_id"], PIC2["media_id"]]))
        check("the person report's thread carries none", all(not t.get("attachments") for t in mine[person_id]["thread"]))

    print("\nThe media sweep:")
    from app.services.media_sweep import _referenced_ids  # noqa: E402
    ids = await _referenced_ids()
    check("a turn's picture is protected from the sweep", PIC2["media_id"] in ids)

    await close_redis()
    print(f"\n{'ALL PASS' if fails == 0 else str(fails) + ' FAILED'}")
    raise SystemExit(1 if fails else 0)


if __name__ == "__main__":
    asyncio.run(main())
