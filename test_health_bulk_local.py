"""Local-only verification of /health/bulk, the probe that must move data.

The Android watchdog lowers an automatic relay tunnel only after this body
came through on the direct route. A handshake-only probe calls a route healthy
on networks that freeze a connection after about 16 KB, so the probe is only
worth anything if it really is bigger than that and cannot be shrunk on the
way. Pins:

  * 200, exactly 64 KiB, application/octet-stream;
  * Cache-Control: no-store, so no proxy or CDN answers it from a cache;
  * the bytes do not compress (zlib gains under 1%), so Caddy's encode or a
    CDN cannot turn it into a small transfer;
  * the same bytes on every call of one worker (drawn once, not per request);
  * no auth needed, and no database touched (it answers with no DB at all).

Runs the real FastAPI app in-process. NOT deployed.
Run: PYTHONPATH=. .venv/bin/python test_health_bulk_local.py
"""
import asyncio
import os
import zlib

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test_health_bulk.db"
os.environ["ENV"] = "dev"
os.environ["REDIS_URL"] = "redis://localhost:6379/15"
try:
    os.remove("test_health_bulk.db")
except FileNotFoundError:
    pass

import httpx  # noqa: E402

from app.main import app  # noqa: E402

fails = 0


def check(name, cond):
    global fails
    print(f"  {'PASS' if cond else 'FAIL'}  {name}")
    if not cond:
        fails += 1


async def main() -> int:
    # No init_db on purpose: the probe must not need the database.
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        print("\n/health/bulk:")
        r = await c.get("/health/bulk")
        check("answers 200 without auth or a database", r.status_code == 200)
        check("exactly 64 KiB", len(r.content) == 64 * 1024)
        check("octet-stream", r.headers.get("content-type", "").startswith("application/octet-stream"))
        check("Cache-Control: no-store", "no-store" in r.headers.get("cache-control", ""))
        packed = zlib.compress(r.content, 9)
        check("does not compress (zlib saves under 1%)", len(packed) > len(r.content) * 0.99)
        r2 = await c.get("/health/bulk")
        check("the same bytes on a second call of this worker", r2.content == r.content)
        r3 = await c.get("/health")
        check("/health itself is unchanged", r3.status_code == 200 and r3.json().get("ok") is True)
    print(f"\n{'ALL PASS' if fails == 0 else f'{fails} FAILED'}")
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
