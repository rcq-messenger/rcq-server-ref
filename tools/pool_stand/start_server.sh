#!/bin/bash
# Run a server tree against the stand the way the flagship runs: four uvicorn
# workers, ENV=production, the app's own pool settings (5+5 per worker,
# pool_timeout 20 s), DATABASE_URL through PgBouncer.
#
# usage: tools/pool_stand/start_server.sh <tree> <logfile> [VAR=value ...]
#   <tree>     a checkout of this repository (the working tree, or a
#              `git worktree` of an older commit for the reference run)
#   VAR=value  extra environment, e.g. RCQ_DB_NESTING_CHECK=1
#   UVICORN=/path/to/uvicorn  the uvicorn with the server's requirements
#                             (default: uvicorn on PATH)
TREE=$1; LOG=$2; shift 2
UVICORN="${UVICORN:-uvicorn}"
cd "$TREE" || exit 1
exec env ENV=production JWT_SECRET=stand-local-secret-0123456789abcdef \
  DATABASE_URL=postgresql+asyncpg://rcq:rcqpw@127.0.0.1:16432/rcq \
  REDIS_URL=redis://127.0.0.1:16379/0 "$@" \
  "$UVICORN" app.main:app \
  --host 127.0.0.1 --port 18000 --workers 4 --timeout-graceful-shutdown 10 > "$LOG" 2>&1
