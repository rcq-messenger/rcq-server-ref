"""Burst load against the local pool stand, with a verdict (README.md).

Each round: stay idle long enough for every worker's 5 s settings cache to go
stale (optionally also drop the 300 s Redis markers, as happens every five
minutes on the flagship), then fire one burst from one account, the shape a
client sends right after opening room 21 (2271 members):

  * BURST x (GET /users/{uin}/info + GET /keys/{uin}/devices), one pair per
    member, which is the pair Android's encryptFor asks for a peer outside
    its roster;
  * plus a few GET /contacts/outgoing and GET /users/search, two more of the
    handlers that held a connection while a cache reloaded itself;

while a /server/info loop, a /health loop and a /health/db loop run beside
it. Every request is measured to completion (generous client timeouts), and
the round ends when the burst is done and at least MIN_WINDOW seconds have
passed.

VERDICT. Exit 0 only when every round passes all of:

  * the whole burst is done within --max-burst-s (default 1 s);
  * every burst request answered 200;
  * /server/info never took longer than --max-info-s (default 1 s) and always
    answered 200; /health/db always answered 200;
  * with --server-log: the server wrote no "Pool exhausted", no "[db-nesting]"
    and no "Traceback" line during the run (start the server with
    RCQ_DB_NESTING_CHECK=1 for the second one to mean anything).

Exit 1 otherwise, naming what failed. The code before the 28.09 fix fails
this in at least one round of four (README.md has the reference numbers).
"""
import argparse
import asyncio
import json
import os
import statistics
import sys
import time
from datetime import datetime, timedelta, timezone

import httpx
import redis.asyncio as aioredis
from jose import jwt

BASE_UIN = 500_000


def token(secret: str, uin: int) -> str:
    now = datetime.now(timezone.utc)
    return jwt.encode(
        {"sub": str(uin), "iat": now, "exp": now + timedelta(days=30)}, secret, algorithm="HS256"
    )


async def timed(client: httpx.AsyncClient, method: str, url: str, t0: float, **kw) -> dict:
    start = time.monotonic()
    try:
        r = await client.request(method, url, **kw)
        status = r.status_code
        body = r.text[:120] if status >= 400 else ""
    except Exception as exc:  # noqa: BLE001
        status, body = 0, f"{type(exc).__name__}"
    end = time.monotonic()
    return {"url": url, "status": status, "start": round(start - t0, 3),
            "secs": round(end - start, 3), "err": body}


async def poller(client, url, t0, stop: asyncio.Event, every: float, timeout: float, out: list):
    pending = []
    while not stop.is_set():
        pending.append(asyncio.create_task(timed(client, "GET", url, t0, timeout=timeout)))
        try:
            await asyncio.wait_for(stop.wait(), every)
        except asyncio.TimeoutError:
            pass
    out.extend(await asyncio.gather(*pending))


def summ(rows: list[dict]) -> dict:
    if not rows:
        return {}
    secs = sorted(r["secs"] for r in rows)
    codes: dict[str, int] = {}
    for r in rows:
        codes[str(r["status"])] = codes.get(str(r["status"]), 0) + 1
    return {
        "n": len(rows),
        "p50": round(statistics.median(secs), 3),
        "p95": round(secs[max(0, int(len(secs) * 0.95) - 1)], 3),
        "max": round(secs[-1], 3),
        "over_10s": sum(1 for s in secs if s > 10),
        "over_15s": sum(1 for s in secs if s > 15),
        "codes": codes,
    }


def burst_requests(c, a, rnd: int, tok: str, t0: float) -> list:
    """The burst of one round, as coroutines."""
    hdr = {"Authorization": f"Bearer {tok}"}
    targets = [BASE_UIN + 1000 + rnd * a.burst + i for i in range(a.burst)]
    mix = {m.strip() for m in a.mix.split(",") if m.strip()}
    reqs = []
    for u in targets:
        if "info" in mix:
            reqs.append(timed(c, "GET", f"/users/{u}/info", t0, headers=hdr, timeout=200))
        if "devices" in mix:
            reqs.append(timed(c, "GET", f"/keys/{u}/devices", t0, headers=hdr, timeout=200))
    for i in range(a.extras):
        if "outgoing" in mix:
            reqs.append(timed(c, "GET", "/contacts/outgoing", t0, headers=hdr, timeout=200))
        if "search" in mix:
            reqs.append(timed(c, "GET", "/users/search", t0, headers=hdr, timeout=200,
                              params={"q": f"user{rnd * 10 + i}"}))
    return reqs


def log_offset(path: str | None) -> int:
    if not path:
        return 0
    try:
        return os.path.getsize(path)
    except OSError:
        return 0


def log_counts(path: str | None, offset: int) -> dict:
    if not path:
        return {}
    with open(path, "rb") as f:
        f.seek(offset)
        text = f.read().decode("utf-8", "replace")
    return {
        "pool_exhausted": text.count("Pool exhausted"),
        "db_nesting": text.count("[db-nesting]"),
        "traceback": text.count("Traceback"),
        "lines": text.count("\n"),
    }


def round_failures(rep: dict, a) -> list[str]:
    out = []
    if rep["burst_done_after_s"] > a.max_burst_s:
        out.append(f"burst took {rep['burst_done_after_s']} s (> {a.max_burst_s})")
    codes = rep["burst"].get("codes", {})
    if set(codes) != {"200"}:
        out.append(f"burst answers {codes}")
    si = rep["server_info"]
    if si and (si["max"] > a.max_info_s or set(si["codes"]) != {"200"}):
        out.append(f"/server/info max {si['max']} s, answers {si['codes']}")
    hdb = rep["health_db"]
    if hdb and set(hdb["codes"]) != {"200"}:
        out.append(f"/health/db answers {hdb['codes']}")
    return out


async def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1:18000")
    ap.add_argument("--redis", default="redis://127.0.0.1:16379/0")
    ap.add_argument("--secret", default="stand-local-secret-0123456789abcdef")
    ap.add_argument("--rounds", type=int, default=4)
    ap.add_argument("--burst", type=int, default=30, help="members per burst (one info + one devices each)")
    ap.add_argument("--extras", type=int, default=5, help="/contacts/outgoing and /users/search per burst, each")
    ap.add_argument("--mix", default="info,devices,outgoing,search",
                    help="which requests make up the burst; 'info' alone is the burst of the first stand runs")
    ap.add_argument("--idle", type=float, default=8.0)
    ap.add_argument("--drop-markers", default="0,1", help="per round, cycled: 1 = drop the Redis markers too")
    ap.add_argument("--min-window", type=float, default=12.0)
    ap.add_argument("--max-burst-s", type=float, default=1.0)
    ap.add_argument("--max-info-s", type=float, default=1.0)
    ap.add_argument("--server-log", default=None, help="the log start_server.sh writes, to count bad lines in")
    ap.add_argument("--out", required=True)
    ap.add_argument("--label", default="")
    a = ap.parse_args()
    drop_cycle = [x.strip() == "1" for x in a.drop_markers.split(",")]

    r = aioredis.from_url(a.redis)
    limits = httpx.Limits(max_connections=400, max_keepalive_connections=0)
    report: dict = {"label": a.label, "rounds": []}
    offset = log_offset(a.server_log)
    failures: list[str] = []
    async with httpx.AsyncClient(base_url=a.base, limits=limits) as c:
        # Warm every worker's pool and caches, as on a running island.
        warm_tok = token(a.secret, BASE_UIN + 2500)
        for _ in range(3):
            await asyncio.gather(*[
                c.get(f"/users/{BASE_UIN + 1 + i}/info", headers={"Authorization": f"Bearer {warm_tok}"}, timeout=180)
                for i in range(40)
            ], return_exceptions=True)
            await asyncio.gather(*[c.get("/server/info", timeout=180) for _ in range(20)], return_exceptions=True)
        for rnd in range(a.rounds):
            drop = drop_cycle[rnd % len(drop_cycle)]
            await asyncio.sleep(a.idle)
            keys = [k async for k in r.scan_iter(match="rl:*")]
            if keys:
                await r.delete(*keys)
            if drop:
                await r.delete("guest_uins:loaded", "uin_epochs:loaded", "suspended_uins:loaded")
            caller = BASE_UIN + 100 + rnd
            tok = token(a.secret, caller)
            t0 = time.monotonic()
            wall0 = datetime.now(timezone.utc).isoformat()
            stop = asyncio.Event()
            si, hl, hdb = [], [], []
            pollers = [
                asyncio.create_task(poller(c, "/server/info", t0, stop, 0.5, 200, si)),
                asyncio.create_task(poller(c, "/health", t0, stop, 0.5, 30, hl)),
                asyncio.create_task(poller(c, "/health/db", t0, stop, 0.5, 30, hdb)),
            ]
            burst = await asyncio.gather(*burst_requests(c, a, rnd, tok, t0))
            done_at = time.monotonic() - t0
            left = a.min_window - done_at
            if left > 0:
                await asyncio.sleep(left)
            stop.set()
            await asyncio.gather(*pollers)
            rnd_rep = {
                "round": rnd + 1,
                "wall_start": wall0,
                "markers_dropped": drop,
                "burst_done_after_s": round(done_at, 3),
                "burst": summ(burst),
                "server_info": summ(si),
                "health": summ(hl),
                "health_db": summ(hdb),
                "raw": {"burst": burst, "server_info": si, "health_db": hdb},
            }
            bad = round_failures(rnd_rep, a)
            rnd_rep["failures"] = bad
            failures.extend(f"round {rnd + 1}: {b}" for b in bad)
            report["rounds"].append(rnd_rep)
            print(json.dumps({k: v for k, v in rnd_rep.items() if k != "raw"}), flush=True)
    await r.aclose()
    counts = log_counts(a.server_log, offset)
    report["server_log"] = counts
    for key in ("pool_exhausted", "db_nesting", "traceback"):
        if counts.get(key):
            failures.append(f"server log: {counts[key]} x {key}")
    report["verdict"] = "PASS" if not failures else "FAIL"
    report["failures"] = failures
    with open(a.out, "w") as f:
        json.dump(report, f, indent=1)
    if counts:
        print(f"server log during the run: {json.dumps(counts)}")
    print(f"VERDICT: {report['verdict']}" + ("" if not failures else "\n  " + "\n  ".join(failures)))
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
