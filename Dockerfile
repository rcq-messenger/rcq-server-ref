# RCQ backend — minimal FastAPI image.
#
# Build:    docker build -t rcq-server .
# Run:      docker run --rm -p 8000:8000 --env-file .env rcq-server
#
# For a full local stack with Postgres + Redis + Caddy, see
# docker-compose.yml in this repo.

FROM python:3.12-slim

# Install system deps for asyncpg + libsignal-related crypto builds
# (the FastAPI app itself doesn't need libsignal, but the requirements
# include cryptography which links against OpenSSL via build-time
# headers). `--no-install-recommends` keeps the image small.
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        libpq-dev \
        libffi-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# VERSION is read at runtime by app/core/config.py, two levels up from
# itself — without it in the image every /health and /server/info reports
# an unknown version, which is exactly what a self-hoster is asked for
# when they report a problem.
COPY VERSION ./VERSION
COPY app ./app

# Media / news / evidence dirs are per-deployment data. Mount these
# as volumes from docker-compose or your orchestrator.
RUN mkdir -p /app/media/uploads /app/news_media /app/evidence

EXPOSE 8000

# uvicorn worker count is small by default; tune via the docker
# command override if you've got the CPU to spare.
# --timeout-graceful-shutdown for the same reason as the systemd unit: a
# websocket never closes by itself, so without it the container ignores
# SIGTERM until docker loses patience and kills it, and every restart is a
# minute of downtime instead of a few seconds.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--timeout-graceful-shutdown", "10", "--workers", "2"]
