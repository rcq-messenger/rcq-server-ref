#!/bin/bash
# Remove everything up.sh created: the three containers, the network and the
# PgBouncer image. Stop the server started by start_server.sh first (Ctrl-C,
# or kill the uvicorn it started on 127.0.0.1:18000).
docker rm -f rcqstand-pgb rcqstand-redis rcqstand-pg >/dev/null 2>&1 || true
docker network rm rcqstand >/dev/null 2>&1 || true
docker rmi rcqstand-pgbouncer:local >/dev/null 2>&1 || true
echo "stand removed"
