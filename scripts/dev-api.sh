#!/usr/bin/env bash
# Start the AICore API for local development.
#
# Loads the repository-root .env (database credentials etc.) and runs uvicorn
# with autoreload. Configuration is validated at startup: a missing or invalid
# AICORE_DATABASE_URL fails here, not on the first request.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [ -f .env ]; then
  echo "[dev-api] loading .env" >&2
  set -a
  # shellcheck disable=SC1091
  . ./.env
  set +a
else
  echo "[dev-api] no .env found — copy .env.example to .env first" >&2
  exit 1
fi

export PYTHONPATH="$ROOT/apps/api/src${PYTHONPATH:+:$PYTHONPATH}"
PY="$ROOT/apps/api/.venv/bin/python"

if [ ! -x "$PY" ]; then
  bash "$ROOT/scripts/py.sh" -c "pass"
fi

exec "$PY" -m uvicorn aicore_api.main:app \
  --reload \
  --host "${AICORE_API_HOST:-0.0.0.0}" \
  --port "${AICORE_API_PORT:-8000}"
