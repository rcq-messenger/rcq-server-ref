#!/bin/bash
# Bring the local pool stand up: Postgres 16, Redis 7 and PgBouncer in
# TRANSACTION mode with 15 backends, on a private docker network, published
# on 127.0.0.1 only (15432 Postgres direct, 16432 PgBouncer, 16379 Redis),
# then seed it. Nothing here touches the system Redis on 6379 or any other
# container. See README.md; `down.sh` removes all of it.
#
# usage: tools/pool_stand/up.sh          (from the repo root)
#   PY=/path/to/python   the interpreter with the server's requirements
#                        (default: python3)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
PY="${PY:-python3}"
NET=rcqstand

docker network inspect "$NET" >/dev/null 2>&1 || docker network create "$NET" >/dev/null
docker run -d --name rcqstand-pg --network "$NET" -p 127.0.0.1:15432:5432 \
  -e POSTGRES_USER=rcq -e POSTGRES_PASSWORD=rcqpw -e POSTGRES_DB=rcq postgres:16 >/dev/null
docker run -d --name rcqstand-redis --network "$NET" -p 127.0.0.1:16379:6379 redis:7-alpine >/dev/null
docker build -q -t rcqstand-pgbouncer:local "$HERE/pgbouncer" >/dev/null
docker run -d --name rcqstand-pgb --network "$NET" -p 127.0.0.1:16432:6432 rcqstand-pgbouncer:local >/dev/null

for _ in $(seq 1 60); do
  # Over TCP: during its first-boot init the image runs a temporary server
  # on the unix socket only, which a plain pg_isready would call ready.
  if docker exec rcqstand-pg pg_isready -h 127.0.0.1 -U rcq -d rcq >/dev/null 2>&1; then break; fi
  sleep 1
done
# The seed talks to Postgres DIRECTLY (DDL in init_db), never through the
# transaction-mode pool.
cd "$ROOT"
ENV=production JWT_SECRET=stand-local-secret-0123456789abcdef \
  DATABASE_URL=postgresql+asyncpg://rcq:rcqpw@127.0.0.1:15432/rcq \
  REDIS_URL=redis://127.0.0.1:16379/0 PYTHONPATH="$ROOT" "$PY" "$HERE/seed.py"
echo "stand up: PgBouncer 127.0.0.1:16432, Postgres 127.0.0.1:15432, Redis 127.0.0.1:16379"
