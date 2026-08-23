"""Local-only verification of the island logo.

An operator sets one picture for their island from the admin console; every
client draws it next to the island's NAME wherever the island is identified,
and falls back to the lettered tile it already drew when there is none. Pins:

  * an island with no logo answers `logo_version: ""` on /server/info and 404
    on /server/logo, which is a normal state and not an error;
  * ⚠ the PICTURE never rides on /server/info. That reply is fetched on every
    connect by every client and by cross-island probes, so it carries a
    12-character digest and nothing else. This test measures the reply with a
    logo set against the reply without one and refuses a meaningful growth,
    because the cheap way to get this wrong is to "just inline it, it is only
    20 KB";
  * a set logo is served raw from /server/logo with its own content type, an
    ETag equal to the version, and a 304 on revalidation;
  * the version changes when the picture does, so `?v=` busts every cache in
    the chain, and does NOT change on a re-upload of identical bytes;
  * ⚠ the size cap is a REFUSAL, never a truncation: an oversize logo is 400
    with the limit named, and the island keeps the logo it already had. A
    truncated data URI is an image that will not open, which is precisely the
    broken picture the fallback rule forbids;
  * a non-image, an unsupported type and undecodable base64 are all refused,
    and the mime that comes back out is one from the allow-list rather than
    anything the caller chose (it is echoed as a Content-Type on a public
    endpoint);
  * DELETE puts the island back to the lettered tile and is idempotent;
  * the logo is NOT in the settings registry, so the generic PATCH /settings
    cannot be used to write a truncated one.

Runs the real FastAPI stack in-process on a throwaway SQLite DB with Redis
db 15. NOT deployed.
Run: PYTHONPATH=. /Users/tager/Documents/RCQ/backend/.venv/bin/python test_island_logo_local.py
"""
import asyncio
import base64
import os
import struct
import zlib

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test_island_logo.db"
os.environ["ENV"] = "dev"
os.environ["REDIS_URL"] = "redis://localhost:6379/15"
os.environ.setdefault("ADMIN_USERNAME", "admin")
os.environ.setdefault("ADMIN_PASSWORD", "adminpw")
for f in ("test_island_logo.db",):
    try:
        os.remove(f)
    except FileNotFoundError:
        pass

import httpx  # noqa: E402

from app.core.db import init_db  # noqa: E402
from app.core.redis import close_redis  # noqa: E402
from app.main import app  # noqa: E402
from app.services import island_logo, server_settings  # noqa: E402

fails = 0


def check(name, cond):
    global fails
    print(f"  {'PASS' if cond else 'FAIL'}  {name}")
    if not cond:
        fails += 1


ADMIN = ("admin", "adminpw")


def png(width: int, height: int, rgb=(0x16, 0xA3, 0x4A)) -> bytes:
    """A real, decodable PNG of the requested size. Built by hand rather than
    with Pillow so the test has no dependency the server does not have: the
    point is only that the bytes are a genuine image an operator could pick."""

    def chunk(tag: bytes, payload: bytes) -> bytes:
        return (
            struct.pack(">I", len(payload))
            + tag
            + payload
            + struct.pack(">I", zlib.crc32(tag + payload) & 0xFFFFFFFF)
        )

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    raw = b"".join(b"\x00" + bytes(rgb) * width for _ in range(height))
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", ihdr)
        + chunk(b"IDAT", zlib.compress(raw, 9))
        + chunk(b"IEND", b"")
    )


def data_uri(blob: bytes, mime="image/png") -> str:
    return f"data:{mime};base64," + base64.b64encode(blob).decode()


async def main() -> int:
    await init_db()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:

        print("\nAn island with no logo:")
        r = await c.get("/server/info")
        bare_info = r.text
        check("/server/info answers logo_version: \"\"", r.json().get("logo_version") == "")
        r = await c.get("/server/logo")
        check("  ... and /server/logo is 404, not an empty 200", r.status_code == 404)
        r = await c.get("/admin/server/logo", auth=ADMIN)
        st = r.json()
        check("the console is told there is none, plus the cap and the types",
              st["has_logo"] is False and st["max_bytes"] == island_logo.MAX_LOGO_BYTES
              and "image/png" in st["mimes"])

        print("\nSetting one:")
        mark = png(64, 64)
        r = await c.put("/admin/server/logo", auth=ADMIN, json={"data_uri": data_uri(mark)})
        check(f"PUT accepts a real PNG ({r.status_code})", r.status_code == 200)
        version = r.json()["version"]
        check("  ... and answers a version", bool(version) and r.json()["has_logo"] is True)

        # The service caches per worker for 5s; the writing worker is busted on
        # write, which is the behaviour being relied on here.
        r = await c.get("/server/info")
        check("/server/info now carries that exact version", r.json().get("logo_version") == version)

        print("\n★ the picture does NOT ride on /server/info:")
        grew = len(r.text) - len(bare_info)
        check(f"  the reply grew by {grew} bytes, not by the image ({len(mark)})",
              0 < grew < 64)
        check("  no data URI anywhere in it", "base64" not in r.text and "data:image" not in r.text)
        check("  and no absolute URL either (a client must build its own)",
              "http://" not in r.text and "https://" not in r.text)

        print("\nServing it:")
        r = await c.get("/server/logo")
        check("raw bytes come back byte-identical", r.content == mark)
        check("  ... with the stored content type", r.headers.get("content-type") == "image/png")
        check("  ... an ETag equal to the version", r.headers.get("etag") == f'"{version}"')
        check("  ... and a public cache header", "public" in (r.headers.get("cache-control") or ""))
        r2 = await c.get("/server/logo", headers={"If-None-Match": f'"{version}"'})
        check("a revalidation costs a 304 with no body",
              r2.status_code == 304 and not r2.content)
        r2 = await c.get("/server/logo", headers={"If-None-Match": '"stale0000000"'})
        check("  ... a stale ETag gets the bytes", r2.status_code == 200 and r2.content == mark)
        r2 = await c.get(f"/server/logo?v={version}")
        check("the ?v= a client appends is ignored by the route", r2.status_code == 200)

        print("\nVersioning:")
        r = await c.put("/admin/server/logo", auth=ADMIN, json={"data_uri": data_uri(mark)})
        check("re-uploading identical bytes keeps the version (no cache stampede)",
              r.json()["version"] == version)
        other = png(64, 64, rgb=(0xE5, 0x48, 0x4D))
        r = await c.put("/admin/server/logo", auth=ADMIN, json={"data_uri": data_uri(other)})
        v2 = r.json()["version"]
        check("a different picture gets a different version", v2 != version)
        r = await c.get("/server/logo")
        check("  ... and /server/logo serves the new one at once", r.content == other)

        print("\n★ the cap refuses, it does not truncate:")
        # Random bytes so zlib cannot compress them back under the cap.
        big = png(1, 1)[:8] + os.urandom(island_logo.MAX_LOGO_BYTES + 1024)
        r = await c.put("/admin/server/logo", auth=ADMIN, json={"data_uri": data_uri(big)})
        check(f"an oversize logo is refused ({r.status_code})", r.status_code == 400)
        detail = r.json().get("detail") or {}
        check("  ... with the limit named, so the operator can act on it",
              detail.get("code") == "logo_too_large"
              and detail.get("max_bytes") == island_logo.MAX_LOGO_BYTES)
        r = await c.get("/server/logo")
        check("  ★ and the island keeps the logo it had", r.content == other)
        r = await c.get("/server/info")
        check("  ★ ... at the same version", r.json()["logo_version"] == v2)

        print("\nAnything a client could not draw is refused:")
        for name, body in (
            ("plain text", "not a data uri"),
            ("a non-image mime", "data:text/html;base64," + base64.b64encode(b"<b>x").decode()),
            ("an SVG (scriptable, and not on the allow-list)",
             "data:image/svg+xml;base64," + base64.b64encode(b"<svg/>").decode()),
            ("base64 that does not decode", "data:image/png;base64,!!!!"),
            ("an empty body", "data:image/png;base64,"),
        ):
            r = await c.put("/admin/server/logo", auth=ADMIN, json={"data_uri": body})
            check(f"  {name} -> 400", r.status_code == 400)
        r = await c.get("/server/logo")
        check("  ★ none of them replaced the good logo", r.content == other)

        print("\nClearing it:")
        r = await c.delete("/admin/server/logo", auth=ADMIN)
        check("DELETE reports no logo", r.status_code == 200 and r.json()["has_logo"] is False)
        r = await c.get("/server/logo")
        check("  ... /server/logo is 404 again (back to the lettered tile)", r.status_code == 404)
        r = await c.get("/server/info")
        check("  ... and /server/info says so", r.json()["logo_version"] == "")
        r = await c.delete("/admin/server/logo", auth=ADMIN)
        check("  ... a second delete is a no-op", r.status_code == 200)

        print("\nIt is not a settings-registry string:")
        check("no logo key in the registry",
              not [k for k in server_settings.REGISTRY if "logo" in k])
        r = await c.patch("/admin/settings", auth=ADMIN,
                          json={"island_logo": data_uri(png(8, 8))})
        check("  ★ PATCH /settings refuses it rather than truncating to 2048",
              r.status_code == 400)

        print("\nThe cap, stated:")
        check(f"  MAX_LOGO_BYTES is {island_logo.MAX_LOGO_BYTES} "
              f"({island_logo.MAX_LOGO_BYTES // 1024} KB)",
              island_logo.MAX_LOGO_BYTES == 64 * 1024)

    await close_redis()
    print(f"\n{'ALL PASS' if fails == 0 else f'{fails} FAILED'}")
    return fails


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
