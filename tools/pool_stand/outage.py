"""A database outage on the local pool stand, with a verdict (README.md).

PgBouncer is PAUSEd for PAUSE_S seconds while 60 database requests, a
/server/info loop and a /health/db loop run; then RESUMEd, and recovery is
measured.

VERDICT. Exit 0 only when:

  * /server/info answered 200 every time, within 1 s (a warm worker serves it
    from memory, database or not);
  * /health/db answered 503 `{"ok": false}` within 3.5 s while paused, and 200
    again after the resume;
  * every database request ended as a 200 or a 503 island_busy, never as a
    client timeout or a 500;
  * with a server log given: no "Traceback" in it during the run, and one
    "Pool exhausted" line per 503 at most.

usage: outage.py <out.json> [--server-log <log>] [--secret ...]
"""
import argparse
import asyncio
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone

import httpx
from jose import jwt

BASE = "http://127.0.0.1:18000"
PAUSE_S = 28.0


def token(secret: str, uin: int) -> str:
    now = datetime.now(timezone.utc)
    return jwt.encode({"sub": str(uin), "iat": now, "exp": now + timedelta(days=30)}, secret, algorithm="HS256")


def bouncer(cmd: str) -> str:
    return subprocess.run(
        ["docker", "exec", "rcqstand-pg", "psql", "-h", "rcqstand-pgb", "-p", "6432", "-U", "rcq",
         "pgbouncer", "-c", cmd],
        capture_output=True, text=True, timeout=30,
    ).stdout.strip()


async def timed(c, url, t0, **kw):
    s = time.monotonic()
    try:
        r = await c.get(url, **kw)
        st, body = r.status_code, r.text[:100]
    except Exception as exc:  # noqa: BLE001
        st, body = 0, type(exc).__name__
    return {"url": url.split("?")[0], "status": st, "start": round(s - t0, 2),
            "secs": round(time.monotonic() - s, 3), "body": body}


async def loop(c, url, t0, until, out):
    tasks = []
    while time.monotonic() - t0 < until:
        tasks.append(asyncio.create_task(timed(c, url, t0, timeout=60)))
        await asyncio.sleep(1.0)
    out.extend(await asyncio.gather(*tasks))


async def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("out")
    ap.add_argument("--secret", default="stand-local-secret-0123456789abcdef")
    ap.add_argument("--server-log", default=None)
    a = ap.parse_args()
    offset = os.path.getsize(a.server_log) if a.server_log and os.path.exists(a.server_log) else 0
    async with httpx.AsyncClient(base_url=BASE, limits=httpx.Limits(max_connections=400, max_keepalive_connections=0)) as c:
        t0 = time.monotonic()
        print("PAUSE:", bouncer("PAUSE rcq"), flush=True)
        si, hdb = [], []
        loops = [asyncio.create_task(loop(c, "/server/info", t0, PAUSE_S + 8, si)),
                 asyncio.create_task(loop(c, "/health/db", t0, PAUSE_S + 8, hdb))]
        reqs = [asyncio.create_task(timed(c, f"/users/{500_000 + 1500 + i}/info", t0,
                                          headers={"Authorization": f"Bearer {token(a.secret, 500_000 + 200 + i % 6)}"},
                                          timeout=90)) for i in range(60)]
        await asyncio.sleep(PAUSE_S)
        resumed_at = time.monotonic() - t0
        print("RESUME:", bouncer("RESUME rcq"), "at", round(resumed_at, 1), flush=True)
        burst = await asyncio.gather(*reqs)
        await asyncio.gather(*loops)
    codes: dict = {}
    for r in burst:
        codes[r["status"]] = codes.get(r["status"], 0) + 1
    rep = {
        "db_requests": {"codes": codes, "max_secs": max(r["secs"] for r in burst),
                        "503_secs": sorted({r["secs"] for r in burst if r["status"] == 503})[:3]},
        "server_info": [(r["start"], r["status"], r["secs"]) for r in si],
        "health_db": [(r["start"], r["status"], r["secs"], r["body"]) for r in hdb],
    }
    print(json.dumps(rep, indent=1))

    failures = []
    if any(r["status"] != 200 or r["secs"] > 1.0 for r in si):
        failures.append("/server/info was not always a 200 within 1 s")
    paused = [r for r in hdb if r["start"] + r["secs"] < resumed_at - 0.5]
    after = [r for r in hdb if r["start"] > resumed_at + 1.0]
    if not paused or any(r["status"] != 503 or r["secs"] > 3.5 for r in paused):
        failures.append("/health/db was not a fast 503 while paused")
    if not after or any(r["status"] != 200 for r in after):
        failures.append("/health/db did not come back to 200 after the resume")
    if set(codes) - {200, 503}:
        failures.append(f"database requests ended as {codes} (only 200 and 503 are acceptable)")
    if a.server_log:
        with open(a.server_log, "rb") as f:
            f.seek(offset)
            text = f.read().decode("utf-8", "replace")
        tb, pe = text.count("Traceback"), text.count("Pool exhausted")
        print(f"server log during the run: {tb} Traceback, {pe} 'Pool exhausted'")
        if tb:
            failures.append(f"{tb} Traceback(s) in the server log")
        if pe > codes.get(503, 0):
            failures.append(f"{pe} 'Pool exhausted' lines for {codes.get(503, 0)} refusals")
    json.dump({"burst": burst, "server_info": si, "health_db": hdb, "failures": failures},
              open(a.out, "w"), indent=1)
    print("VERDICT: " + ("PASS" if not failures else "FAIL\n  " + "\n  ".join(failures)))
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
