"""Local-only verification of featured sites.

An operator can pin a listed `.rcq` site to the top of the catalogue, and
`GET /sites` says so with `featured: true` and by putting it first, so every
client can give it its own section above recents and the rest (founder,
2026-09-02: the network's own page `home.rcq`). Pins:

  * a fresh site is not featured, and the catalogue orders by freshness;
  * ⚠ the owner has no way in: `featured` on the upload form is ignored. A
    self-service flag would be the front row of the shop window for sale;
  * POST /admin/sites/{name}/featured {"featured": true} puts the site FIRST
    in the catalogue, ahead of a fresher one, and the flag rides on the
    catalogue, on /admin/sites and on the owner's /sites/mine;
  * {"featured": false} takes it off the top and the catalogue goes back to
    freshness order;
  * ⚠ featured never outlives listed. Unlisting by the operator, a freeze,
    and the owner's own re-upload with `listed=false` all clear it, and a
    later re-listing does NOT bring it back: coming back is a listing, not
    a promotion;
  * featuring an unlisted site is 409 `not_listed`, a frozen one 409
    `frozen`, a name nobody holds 404, and without admin credentials 401.

Runs the real FastAPI stack in-process on a throwaway SQLite DB with Redis
db 15. NOT deployed.
Run: PYTHONPATH=. /Users/tager/Documents/RCQ/backend/.venv/bin/python test_site_featured_local.py
"""
import asyncio
import base64
import json
import os
import shutil
import sys
import tempfile

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test_site_featured.db"
os.environ["ENV"] = "dev"
os.environ["REDIS_URL"] = "redis://localhost:6379/15"
os.environ.setdefault("ADMIN_USERNAME", "admin")
os.environ.setdefault("ADMIN_PASSWORD", "adminpw")
# Bundles land on disk at import time; keep them out of the repo's `sites/`.
SITES_TMP = tempfile.mkdtemp(prefix="rcq-sites-featured-")
os.environ["RCQ_SITES_DIR"] = SITES_TMP
for f in ("test_site_featured.db",):
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


ADMIN = ("admin", "adminpw")
ALICE, BOB = 700100001, 700100002


async def publish(c, token, name, version, listed=True, extra=None):
    """One upload in the shape the client sends: manifest + owner key + files."""
    data = {"manifest": json.dumps({"version": version}), "owner_key": f"key-{name}",
            "title": f"{name} title", "listed": "true" if listed else "false"}
    if extra:
        data.update(extra)
    return await c.put(
        f"/sites/{name}", data=data,
        files=[("files", ("index.html", f"<h1>{name} v{version}</h1>".encode(), "text/html"))],
        headers={"Authorization": f"Bearer {token}"},
    )


async def catalogue(c):
    r = await c.get("/sites")
    assert r.status_code == 200, r.text
    return r.json()


async def feature(c, name, on, auth=ADMIN):
    return await c.post(f"/admin/sites/{name}/featured", json={"featured": on}, auth=auth)


async def main() -> int:
    await init_db()
    # `site_put` is 10/hour per identity and the bucket lives in Redis: a
    # second run inside the hour would measure the limiter, not the pin.
    await (await get_redis()).flushdb()
    async with SessionLocal() as db:
        db.add(User(uin=ALICE, nickname="alice", identity_key=b64(), signing_key=b64()))
        db.add(User(uin=BOB, nickname="bob", identity_key=b64(), signing_key=b64()))
        await db.commit()
    t_alice = issue_token(ALICE, 0, "phone")
    t_bob = issue_token(BOB, 0, "phone")
    H_A = {"Authorization": f"Bearer {t_alice}"}

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:

        print("\nTwo listed sites, `beta` fresher than `alpha`:")
        r = await publish(c, t_alice, "alpha", 1, extra={"featured": "true"})
        check(f"alpha published ({r.status_code})", r.status_code == 200)
        check("  ★ `featured=true` on the upload form is ignored", r.json()["featured"] is False)
        await asyncio.sleep(0.01)
        r = await publish(c, t_bob, "beta", 1)
        check(f"beta published ({r.status_code})", r.status_code == 200)
        rows = await catalogue(c)
        check("catalogue is by freshness: beta, alpha",
              [s["name"] for s in rows] == ["beta", "alpha"])
        check("  ... and nothing is featured", all(s["featured"] is False for s in rows))
        check("  ... every row carries the field at all", all("featured" in s for s in rows))

        print("\nFeaturing alpha:")
        r = await feature(c, "alpha", True)
        check(f"POST /admin/sites/alpha/featured -> {r.status_code}", r.status_code == 200)
        check("  the reply says featured", r.json()["featured"] is True and r.json()["listed"] is True)
        rows = await catalogue(c)
        check("  ★ alpha is FIRST in the catalogue now, ahead of the fresher beta",
              [s["name"] for s in rows] == ["alpha", "beta"])
        check("  ... with featured=true, and beta still false",
              rows[0]["featured"] is True and rows[1]["featured"] is False)
        r = await c.get("/admin/sites", auth=ADMIN)
        check("  /admin/sites shows the pin",
              next(s for s in r.json() if s["name"] == "alpha")["featured"] is True)
        r = await c.get("/sites/mine", headers=H_A)
        check("  the owner sees it on /sites/mine too",
              r.status_code == 200 and r.json()[0]["featured"] is True)
        r = await feature(c, "alpha", True)
        check("  featuring twice is a no-op, not an error", r.status_code == 200)

        print("\nUnfeaturing alpha:")
        r = await feature(c, "alpha", False)
        check(f"POST {{featured: false}} -> {r.status_code}", r.status_code == 200 and r.json()["featured"] is False)
        rows = await catalogue(c)
        check("  ★ alpha is gone from the top: beta, alpha again",
              [s["name"] for s in rows] == ["beta", "alpha"])
        check("  ... and nothing is featured", all(s["featured"] is False for s in rows))

        print("\n★ featured never outlives listed:")
        await feature(c, "alpha", True)
        r = await c.post("/admin/sites/alpha/listed?listed=false", auth=ADMIN)
        check("operator unlists a featured site: featured goes false with it",
              r.status_code == 200 and r.json()["listed"] is False and r.json()["featured"] is False)
        r = await c.post("/admin/sites/alpha/listed?listed=true", auth=ADMIN)
        check("  ... re-listing does NOT bring the pin back",
              r.json()["listed"] is True and r.json()["featured"] is False)
        check("  ... and the catalogue agrees",
              next(s for s in await catalogue(c) if s["name"] == "alpha")["featured"] is False)

        await feature(c, "alpha", True)
        r = await c.post("/admin/sites/alpha/freeze?frozen=true", auth=ADMIN)
        check("a freeze clears the pin the way it clears the listing",
              r.status_code == 200 and r.json()["frozen"] is True
              and r.json()["listed"] is False and r.json()["featured"] is False)
        check("  ... a frozen site is out of the catalogue entirely",
              "alpha" not in [s["name"] for s in await catalogue(c)])
        r = await feature(c, "alpha", True)
        check(f"  featuring a frozen site is 409 frozen ({r.status_code})",
              r.status_code == 409 and r.json()["detail"]["code"] == "frozen")
        r = await c.post("/admin/sites/alpha/freeze?frozen=false", auth=ADMIN)
        check("  unfreezing brings back neither listed nor featured",
              r.json()["frozen"] is False and r.json()["listed"] is False and r.json()["featured"] is False)
        r = await feature(c, "alpha", True)
        check(f"  featuring an unlisted site is 409 not_listed ({r.status_code})",
              r.status_code == 409 and r.json()["detail"]["code"] == "not_listed")
        r = await feature(c, "alpha", False)
        check("  ... but taking a pin off an unlisted site is fine", r.status_code == 200)

        await c.post("/admin/sites/alpha/listed?listed=true", auth=ADMIN)
        await feature(c, "alpha", True)
        r = await publish(c, t_alice, "alpha", 2, listed=False)
        check("the owner re-uploads with listed=false: the pin goes with the listing",
              r.status_code == 200 and r.json()["listed"] is False and r.json()["featured"] is False)
        r = await publish(c, t_alice, "alpha", 3, listed=True)
        check("  ... and the owner's re-listing is a listing, not a promotion",
              r.json()["listed"] is True and r.json()["featured"] is False)
        await feature(c, "alpha", True)
        r = await publish(c, t_alice, "alpha", 4, listed=True)
        check("  a re-upload that STAYS listed keeps the operator's pin",
              r.json()["featured"] is True)
        rows = await catalogue(c)
        check("  ... and alpha is first", rows[0]["name"] == "alpha" and rows[0]["featured"] is True)

        print("\nRefusals:")
        r = await feature(c, "nobody", True)
        check(f"a name nobody holds is 404 ({r.status_code})", r.status_code == 404)
        r = await c.post("/admin/sites/alpha/featured", json={"featured": False})
        check(f"no admin credentials: {r.status_code}", r.status_code == 401)
        check("  ... and the pin survived the attempt",
              next(s for s in await catalogue(c) if s["name"] == "alpha")["featured"] is True)
        r = await c.post("/admin/sites/alpha/featured", json={}, auth=ADMIN)
        check(f"an empty body is 422, not a silent unfeature ({r.status_code})", r.status_code == 422)

        # The fourth writer of `listed`: the operator's own publish tool, the
        # path home.rcq actually takes. `--listed` is a plain flag, so a
        # re-publish that forgets it unlists, and the pin has to go with it
        # here too, or the row reads featured on a site the catalogue does
        # not carry and neither console can take the pin off.
        print("\nThe operator's publish tool (app.tools.publish_site):")
        from app.tools.publish_site import main as publish_tool
        pages = tempfile.mkdtemp(prefix="rcq-tool-pages-")
        with open(os.path.join(pages, "index.html"), "w") as f:
            f.write("<h1>gamma</h1>")
        # Beside the pages, not among them: the tool bundles every file in
        # --dir, and a key is not a type a bundle may carry.
        keyfile = os.path.join(SITES_TMP, "gamma.key")

        async def tool(*flags):
            argv = sys.argv
            sys.argv = ["publish_site", "--name", "gamma", "--dir", pages,
                        "--uin", str(ALICE), "--key", keyfile, *flags]
            try:
                await publish_tool()
            finally:
                sys.argv = argv

        async def gamma():
            r = await c.get("/admin/sites", auth=ADMIN)
            return next(s for s in r.json() if s["name"] == "gamma")

        await tool("--listed")
        r = await feature(c, "gamma", True)
        check(f"a site the tool published can be pinned ({r.status_code})", r.status_code == 200)
        await tool()
        g = await gamma()
        check("a re-publish without --listed unlists AND takes the pin off",
              g["listed"] is False and g["featured"] is False)
        await tool("--listed")
        g = await gamma()
        check("  ... and a re-publish with --listed is a listing, not a promotion",
              g["listed"] is True and g["featured"] is False)
        await feature(c, "gamma", True)
        await tool("--listed")
        check("  a re-publish that stays listed keeps the operator's pin", (await gamma())["featured"] is True)
        shutil.rmtree(pages, ignore_errors=True)

    await close_redis()
    shutil.rmtree(SITES_TMP, ignore_errors=True)
    # The throwaway DB is not in .gitignore; leave the tree as it was found.
    try:
        os.remove("test_site_featured.db")
    except FileNotFoundError:
        pass
    print(f"\n{'ALL PASS' if fails == 0 else f'{fails} FAILED'}")
    return fails


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
