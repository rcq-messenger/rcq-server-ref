"""Local-only verification of what a site may be CALLED, and of the one line
the catalogue shows next to it.

Three rules, each of which the shop was getting wrong in a different way
(founder, 2026-09-03):

  * ⚠ a name is at least three characters. One and two are the part of this
    namespace nobody can make more of - 36 of one, about 1300 of two - and they
    were free to whoever typed first. The shelf is empty today, which is why the
    door closes now;
  * a name that would read as the island speaking (`support`, `admin`,
    `security`, `rcq`...) is refused, because a page carries no scripts and no
    outward links, so the only thing such an address buys an impostor is trust:
    "recovery, write to #NNN" and the rest happens in a chat with a human. An
    account that ALREADY holds such a name keeps updating it, so the operator's
    own page is not locked out by its own rule;
  * ⚠⚠ `available` answers with the same rules `put_site` enforces. It knew
    neither the digits rule nor the reserved names, so the panel said "free",
    the publish came back 403, and the person had no way to tell which of the
    two had happened;
  * the catalogue title loses the characters that make a string read
    differently from its bytes: the bidi overrides and isolates, the
    zero-widths, the soft hyphen. Done on the ISLAND, so it fixes the three
    clients already in people's hands.

Runs the real FastAPI stack in-process on a throwaway SQLite DB with Redis
db 15. NOT deployed.
Run: PYTHONPATH=. /Users/tager/Documents/RCQ/backend/.venv/bin/python test_site_names_local.py
"""
import asyncio
import base64
import json
import os
import shutil
import tempfile

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test_site_names.db"
os.environ["ENV"] = "dev"
os.environ["REDIS_URL"] = "redis://localhost:6379/15"
os.environ.setdefault("ADMIN_USERNAME", "admin")
os.environ.setdefault("ADMIN_PASSWORD", "adminpw")
SITES_TMP = tempfile.mkdtemp(prefix="rcq-sites-names-")
os.environ["RCQ_SITES_DIR"] = SITES_TMP
for f in ("test_site_names.db",):
    try:
        os.remove(f)
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


ALICE, BOB, CAROL, DAVE = 700200001, 700200002, 700200003, 700200004


async def publish(c, token, name, *, title="a page", version=1):
    return await c.put(
        f"/sites/{name}",
        data={"manifest": json.dumps({"version": version}), "owner_key": f"key-{name}",
              "title": title, "listed": "true"},
        files=[("files", ("index.html", b"<h1>hi</h1>", "text/html"))],
        headers={"Authorization": f"Bearer {token}"},
    )


def code(r):
    try:
        return (r.json().get("detail") or {}).get("code")
    except Exception:  # noqa: BLE001
        return None


async def main() -> int:
    await init_db()
    await (await get_redis()).flushdb()
    async with SessionLocal() as db:
        db.add(User(uin=ALICE, nickname="alice", identity_key=b64(), signing_key=b64()))
        db.add(User(uin=BOB, nickname="bob", identity_key=b64(), signing_key=b64()))
        db.add(User(uin=CAROL, nickname="carol", identity_key=b64(), signing_key=b64()))
        db.add(User(uin=DAVE, nickname="dave", identity_key=b64(), signing_key=b64()))
        await db.commit()
    t_alice = issue_token(ALICE, 0, "phone")
    t_bob = issue_token(BOB, 0, "phone")
    t_carol = issue_token(CAROL, 0, "phone")
    t_dave = issue_token(DAVE, 0, "phone")

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:

        print("\nHow short a name may be:")
        for short in ("a", "ab", "1", "42"):
            r = await publish(c, t_alice, short)
            check(f"`{short}` is refused ({r.status_code} {code(r)})",
                  r.status_code == 400 and code(r) == "invalid_name")
            a = await c.get(f"/sites/available/{short}")
            check(f"  ... and `available` agrees it is invalid",
                  a.json()["available"] is False and a.json()["reason"] == "invalid")
        r = await publish(c, t_alice, "abc")
        check(f"three characters publish ({r.status_code})", r.status_code == 200)

        print("\nNames that would read as the island speaking:")
        for word in ("support", "admin", "security", "rcq"):
            a = await c.get(f"/sites/available/{word}")
            check(f"`{word}`: available says reserved",
                  a.json()["available"] is False and a.json()["reason"] == "reserved")
            r = await publish(c, t_bob, word)
            check(f"  ... and publishing is refused ({r.status_code} {code(r)})",
                  r.status_code == 403 and code(r) == "reserved_name")

        print("\nAn account that already holds such a name keeps it:")
        # Placed the way the operator's own page got there: by hand, before the
        # rule existed. Carol then updates it, which must not be refused.
        from app.models.site import Site  # noqa: PLC0415
        async with SessionLocal() as db:
            db.add(Site(name="rcq-team", owner_uin=CAROL, version=1, manifest="{}",
                        owner_key="key-rcq-team", size_bytes=1, title="ours", listed=False))
            await db.commit()
        # The row is at version 1, so an update is version 2.
        r = await publish(c, t_carol, "rcq-team", title="ours, updated", version=2)
        check(f"the holder re-publishes their own reserved name ({r.status_code})",
              r.status_code == 200)
        r = await publish(c, t_alice, "rcq-team")
        check(f"  ... and a stranger still cannot ({r.status_code} {code(r)})",
              r.status_code == 403 and code(r) == "reserved_name")

        print("\nA name of digits belongs to the holder of that number:")
        a = await c.get(f"/sites/available/{ALICE}")
        check("available says reserved, not free",
              a.json()["available"] is False and a.json()["reason"] == "reserved")
        r = await publish(c, t_bob, str(ALICE))
        check(f"somebody else is refused ({r.status_code} {code(r)})",
              r.status_code == 403 and code(r) == "reserved_for_uin")

        print("\nAn ordinary free name:")
        a = await c.get("/sites/available/weathervane")
        check("available says free, with no reason",
              a.json()["available"] is True and a.json()["reason"] is None)
        a = await c.get("/sites/available/abc")
        check("a name already published says taken",
              a.json()["available"] is False and a.json()["reason"] == "taken")

        print("\nThe catalogue line loses what reads differently from its bytes:")
        # U+202E flips the rest of the line, U+200B and the soft hyphen hide
        # inside it, U+2066 isolates a run.
        dirty = "gro​cer­y‮ moc.live⁦ x"
        r = await publish(c, t_dave, "grocery", title=dirty)
        check(f"published ({r.status_code})", r.status_code == 200)
        rows = (await c.get("/sites")).json()
        row = next((s for s in rows if s["name"] == "grocery"), None)
        got = (row or {}).get("title") or ""
        check("no bidi or invisible characters survive",
              row is not None and not any(ch in got for ch in "​­‮⁦"))
        check(f"  ... and the visible text is kept ({got!r})", got.startswith("grocery"))
        r = await publish(c, t_dave, "grocery", title="‮​", version=2)
        rows = (await c.get("/sites")).json()
        row = next((s for s in rows if s["name"] == "grocery"), None)
        check("a title of nothing but invisibles becomes no title at all",
              row is not None and row["title"] is None)

    await close_redis()
    shutil.rmtree(SITES_TMP, ignore_errors=True)
    try:
        os.remove("test_site_names.db")
    except FileNotFoundError:
        pass
    print("\n" + ("ALL PASS" if fails == 0 else f"{fails} FAILED"))
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
