# Pool stand: the 28.09 stall, reproducible on a laptop

From 11.09 to 28.09 the flagship went dark for 2-11 minutes at a time, 24
times in 30 days, while the droplet sat 90% idle. The mechanism was
hold-and-wait on the database pool: a handler ran its first query (holding a
pooled connection and, behind PgBouncer in transaction mode, one of 15
backends), then a cached helper reloaded itself on a SECOND session. A burst
of ~30 such requests filled the pool with holders waiting on each other.
`app/core/single_flight.py` has the long version.

None of that shows in the local `test_*_local.py` files: they run on SQLite,
where the pool settings of `app/core/db.py` do not even apply. It takes
Postgres, PgBouncer in TRANSACTION mode with a small backend pool, four
uvicorn workers and a real burst. This directory is that, on 127.0.0.1 only.

`test_pool_nesting_local.py` is the fast in-process guard (the nesting
tripwire over the real handlers). This stand is the slow end-to-end one: run
it before a release that touches `app/core/db.py`, the caches in
`app/services/server_settings.py` / `island_logo.py`, the Redis mirrors in
`app/core/guest_policy.py` / `security.py`, or the order of queries in the
hot handlers (`/users/{uin}/info`, `/keys/*`, `/contacts/*`, `/users/search`,
`/groups/{id}/join`, `/auth/*`).

## What it is

| piece | where | why |
|---|---|---|
| Postgres 16 | `rcqstand-pg`, 127.0.0.1:15432 | the database |
| PgBouncer | `rcqstand-pgb`, 127.0.0.1:16432 | TRANSACTION mode, 15 backends, `query_wait_timeout` 120 s: DigitalOcean's managed pool as far as it is known |
| Redis 7 | `rcqstand-redis`, 127.0.0.1:16379 | its own, never the system Redis on 6379 |
| the server | 127.0.0.1:18000 | 4 uvicorn workers, `ENV=production`, the app's own pool (5+5 per worker, `pool_timeout` 20 s) |
| seed | `seed.py` | 3000 accounts, room 21 with 2271 members, settings unlike every env default, 262 epoch rows, two guests |

⚠ The PgBouncer here is 1.25 from Alpine, and 120 s is inferred from the
errors on the flagship (121 s after the triggers on 26.09 and 27.09), not
read from DigitalOcean. The stall depends on timing: on the pre-fix code one or
two rounds in four went through without it, a different one each run.

## Run it

From the repository root, with Docker running and a Python that has
`requirements.txt` installed (`PY`, `UVICORN` below):

```sh
PY=/path/to/venv/bin/python tools/pool_stand/up.sh

# terminal 1: the tree under test, with the nesting tripwire on
UVICORN=/path/to/venv/bin/uvicorn tools/pool_stand/start_server.sh "$PWD" /tmp/stand-server.log RCQ_DB_NESTING_CHECK=1

# terminal 2: four rounds of bursts, then the verdict (exit code 0 or 1)
/path/to/venv/bin/python tools/pool_stand/load.py --out /tmp/stand-load.json --server-log /tmp/stand-server.log

# optional: a 28 s database outage (PgBouncer PAUSE), then the verdict
/path/to/venv/bin/python tools/pool_stand/outage.py /tmp/stand-outage.json --server-log /tmp/stand-server.log

# stop the server (Ctrl-C in terminal 1), then
tools/pool_stand/down.sh
```

For the reference run on older code, check the commit out into a separate
tree (`git worktree add /tmp/rcq-old <commit>`) and pass that tree to
`start_server.sh`. `load.py --mix info` fires the burst of the first stand
runs (30 x `/users/{uin}/info` only), for comparing with the numbers below.

## Pass thresholds (`load.py`, exit code 1 on any)

Per round, all of:

* the whole burst is done in under **1 s** (`--max-burst-s`);
* every burst request answered **200**;
* `/server/info` always **200**, never slower than **1 s** (`--max-info-s`);
* `/health/db` always **200**.

Over the run, with `--server-log` and the server started with
`RCQ_DB_NESTING_CHECK=1`:

* **0** `Pool exhausted`, **0** `[db-nesting]`, **0** `Traceback` lines.

`outage.py` passes when `/server/info` stays a 200 under 1 s through the
pause, `/health/db` is a 503 `{"ok": false}` within 3.5 s while paused and a
200 after, every database request ends as 200 or 503 (never a client timeout
or a 500), and the log has no traceback and at most one `Pool exhausted`
line per 503.

## Reference numbers

Pre-fix code (`12a1dc6`), `--mix info`, 4 rounds of 30, 8 s idle, markers
dropped in rounds 2 and 4, first stand run (28.09):

| round | burst done after | burst > 15 s | `/server/info` max |
|---|---|---|---|
| 1 | 40.1 s | 10 of 30 | 38.6 s |
| 2 (markers dropped) | 80.4 s | 29 of 30, 10 x 503 | 79.8 s |
| 3 | 40.1 s | 21 of 30, 11 x 503 | 39.7 s |
| 4 (markers dropped) | 0.145 s | 0 | fast |

45 `Pool exhausted` lines, each followed by a ~100-line uvicorn traceback, and
the warm-up burst itself stalled.

The same code on this directory's scripts, same options (28.09, second run):
rounds 1 and 3 went through (0.1 s), rounds 2 and 4 stalled (burst done after
40.4 s and 40.1 s, 16 and 4 answers 503, `/server/info` up to 39.8 s); 20
`Pool exhausted` lines with account numbers in the path, 60 tracebacks.
`load.py` exits 1 (it also fails every round on `/health/db`, which that code
does not have). Which rounds stall moves from run to run.

Fixed code, `RCQ_DB_NESTING_CHECK=1`, 28.09:

| run | burst per round | burst done after | `/server/info` max | `/health/db` max |
|---|---|---|---|---|
| default mix, 4 rounds | 70 (30 info + 30 devices + 5 + 5) | 0.13-0.17 s, all 200 | 0.04 s | 0.06 s |
| `--mix info`, 4 rounds | 30 | 0.08-0.11 s, all 200 | 0.03 s | 0.04 s |
| `--burst 60`, 2 rounds | 130 | 0.21-0.30 s, all 200 | 0.03 s | 0.06 s |
| `--burst 90 --extras 10`, 2 rounds | 200 | 0.34-0.43 s, all 200 | 0.04 s | 0.21 s |

0 `Pool exhausted`, 0 `[db-nesting]`, 0 tracebacks; `load.py` exits 0.
`outage.py`: `/server/info` 36 of 36 answered 200 through the 28 s pause (max
15 ms); `/health/db` 503 within 3.1 s while paused, 200 after; of 60 database
requests 24 answered 200 after the resume and 36 got 503 at 20.0 s, with 36
`Pool exhausted` lines and no traceback; exit 0.
