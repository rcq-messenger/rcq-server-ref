"""Local-only verification that news posts are signed by the ISLAND, not by
"RCQ Team" (founder, 2026-09-02).

A self-hosted island used to publish every announcement under a fixed team
name that its operator is not part of. The default author is now whatever the
island calls itself, resolved at publish time through the same chain
/server/info answers with. Pins:

  * a fresh island with no override signs with the server's own name, and the
    proof that no team string is left in the chain is that APP_NAME is set to
    something made up here and THAT is what comes back;
  * an operator's `island_name` override wins, and an empty or blank label
    means "no label", not an empty signature;
  * a label typed for one post is kept, trimmed;
  * readers see the same name on the public feed as the admin list;
  * the name is written into the row, so renaming the island afterwards does
    not rewrite the posts already signed with the old name;
  * clearing the override falls back to the server's own name, the way the
    settings help promises;
  * a whitespace-only override is unset for /server/info AND the signature:
    one chain, not two;
  * a long island name is written whole: the name is the signature, and a
    name cut to fit a column is a label no client recognises as the island's
    own (they drop the author line only on equality), so every unlabelled
    post read as a guest post. ⚠ The column is as wide as the setting (2048);
    the width bump for a Postgres island that created it at 64 is in
    app/core/db.py's widened-columns list, and SQLite enforces no width, so
    this test pins only that the router no longer cuts.

In-process ASGI against a throwaway SQLite DB, Redis db 15 for the realtime
nudge a publish sends (falls back to local fan-out if Redis is down). NOT
deployed.
Run: PYTHONPATH=. /Users/tager/Documents/RCQ/backend/.venv/bin/python test_news_author_local.py
"""
import asyncio
import os
import tempfile

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test_news_author.db"
os.environ["ENV"] = "dev"
os.environ["REDIS_URL"] = "redis://localhost:6379/15"
os.environ.setdefault("JWT_SECRET", "t" * 64)
os.environ.setdefault("ADMIN_USERNAME", "admin")
os.environ.setdefault("ADMIN_PASSWORD", "adminpw")
# A name nothing in the tree could have hardcoded: if a fresh island signs
# with this, the fallback really is the server's own name and not a string.
os.environ["APP_NAME"] = "Island Under Test"
# Keep the media dir out of the repo root; the router mkdirs it at import.
os.environ["RCQ_NEWS_MEDIA_DIR"] = tempfile.mkdtemp(prefix="rcq-news-test-")

for f in ("test_news_author.db",):
    try:
        os.remove(f)
    except FileNotFoundError:
        pass

import httpx  # noqa: E402

from app.core.config import settings  # noqa: E402
from app.core.db import init_db  # noqa: E402
from app.core.redis import close_redis  # noqa: E402
from app.main import app  # noqa: E402

fails = 0


def check(name: str, ok: bool, detail: str = "") -> None:
    global fails
    print(f"  {'PASS' if ok else 'FAIL'}  {name}{'' if ok else '  <- ' + detail}")
    if not ok:
        fails += 1


ADMIN = ("admin", "adminpw")


async def publish(c: httpx.AsyncClient, body: str, **extra) -> dict:
    r = await c.post("/admin/news", auth=ADMIN, json={"body": body, **extra})
    check(f"POST /admin/news ({body!r}) is 201", r.status_code == 201,
          f"got {r.status_code} {r.text[:200]}")
    return r.json() if r.status_code == 201 else {}


async def rename(c: httpx.AsyncClient, name: str) -> None:
    r = await c.patch("/admin/settings", auth=ADMIN, json={"island_name": name})
    check(f"PATCH /admin/settings island_name={name!r} is 200", r.status_code == 200,
          f"got {r.status_code} {r.text[:200]}")


async def main() -> None:
    await init_db()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        print("\na fresh island, no override")
        check("APP_NAME is the made-up name", settings.APP_NAME == "Island Under Test",
              settings.APP_NAME)
        info = (await c.get("/server/info")).json()
        check("/server/info names the island by APP_NAME", info.get("name") == "Island Under Test",
              str(info.get("name")))
        p = await publish(c, "first post, no label")
        check("*** a post without a label is signed with the server's own name",
              p.get("author_label") == "Island Under Test", str(p.get("author_label")))
        check("...which is exactly what /server/info says",
              p.get("author_label") == info.get("name"))

        print("\nthe operator names the island")
        await rename(c, "Ostrov Krym")
        info = (await c.get("/server/info")).json()
        check("/server/info follows the override", info.get("name") == "Ostrov Krym",
              str(info.get("name")))
        p_missing = await publish(c, "no label field at all")
        check("*** a post without a label is signed with the island's name",
              p_missing.get("author_label") == "Ostrov Krym", str(p_missing.get("author_label")))
        p_empty = await publish(c, "empty label", author_label="")
        check("an empty label means no label",
              p_empty.get("author_label") == "Ostrov Krym", str(p_empty.get("author_label")))
        p_blank = await publish(c, "blank label", author_label="   ")
        check("a blank label means no label",
              p_blank.get("author_label") == "Ostrov Krym", str(p_blank.get("author_label")))

        print("\na label typed for one post is kept")
        p_guest = await publish(c, "guest post", author_label="  Guest Author  ")
        check("*** the typed label wins over the island's name",
              p_guest.get("author_label") == "Guest Author", str(p_guest.get("author_label")))

        print("\nreaders see the same signature")
        feed = (await c.get("/news")).json()
        by_id = {it["id"]: it for it in feed.get("items", [])}
        check("the public feed lists the posts", p_missing.get("id") in by_id and p_guest.get("id") in by_id,
              str(sorted(by_id)))
        check("...with the island's name on the unlabelled one",
              by_id.get(p_missing.get("id"), {}).get("author_label") == "Ostrov Krym")
        check("...and the guest's on the labelled one",
              by_id.get(p_guest.get("id"), {}).get("author_label") == "Guest Author")
        admin_feed = (await c.get("/admin/news", auth=ADMIN)).json()
        admin_by_id = {it["id"]: it for it in admin_feed.get("items", [])}
        check("the admin list agrees",
              admin_by_id.get(p_missing.get("id"), {}).get("author_label") == "Ostrov Krym"
              and admin_by_id.get(p_guest.get("id"), {}).get("author_label") == "Guest Author")

        print("\nrenaming the island afterwards")
        await rename(c, "Renamed Island")
        p_new = await publish(c, "after the rename")
        check("a new post carries the new name",
              p_new.get("author_label") == "Renamed Island", str(p_new.get("author_label")))
        feed = (await c.get("/news")).json()
        by_id = {it["id"]: it for it in feed.get("items", [])}
        check("*** the old post keeps the name it was signed with",
              by_id.get(p_missing.get("id"), {}).get("author_label") == "Ostrov Krym",
              str(by_id.get(p_missing.get("id"), {}).get("author_label")))

        print("\nclearing the override")
        await rename(c, "")
        info = (await c.get("/server/info")).json()
        check("/server/info falls back to APP_NAME", info.get("name") == "Island Under Test",
              str(info.get("name")))
        p_cleared = await publish(c, "after clearing the name")
        check("...and so does the signature",
              p_cleared.get("author_label") == "Island Under Test", str(p_cleared.get("author_label")))
        await rename(c, "   ")
        info = (await c.get("/server/info")).json()
        check("a whitespace-only island name is unset for /server/info",
              info.get("name") == "Island Under Test", repr(info.get("name")))
        p_ws = await publish(c, "whitespace island name")
        check("*** ...and for the signature: the same chain",
              p_ws.get("author_label") == "Island Under Test", str(p_ws.get("author_label")))

        print("\na long island name")
        long_name = "Island " + "x" * 100
        await rename(c, long_name)
        info = (await c.get("/server/info")).json()
        p_long = await publish(c, "long island name")
        label = p_long.get("author_label") or ""
        check("*** a long island name does not break publishing", bool(p_long),
              "no post came back")
        check("*** the signature is the whole name, never cut", label == long_name,
              f"{len(label)} chars: {label[:40]}…")
        check("...and exactly what /server/info says", label == info.get("name"))
        feed = (await c.get("/news")).json()
        by_id = {it["id"]: it for it in feed.get("items", [])}
        check("readers get the whole name too",
              by_id.get(p_long.get("id"), {}).get("author_label") == long_name)

    await close_redis()
    print(f"\n{'ALL PASS' if not fails else str(fails) + ' FAILED'}")
    raise SystemExit(1 if fails else 0)


asyncio.run(main())
