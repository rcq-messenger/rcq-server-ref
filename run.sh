#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
# Use the venv's uvicorn directly so the script works from any shell, even
# without `source .venv/bin/activate`.
exec ./.venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
