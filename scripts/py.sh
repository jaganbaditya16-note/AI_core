#!/usr/bin/env bash
# Run a Python tool (pytest, ruff, mypy, …) against the API virtualenv.
#
#   bash scripts/py.sh -m pytest -c apps/api/pyproject.toml apps/api/tests
#
# Creates the virtualenv on first use so a fresh clone works with one command.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV="$ROOT/apps/api/.venv"
PY="$VENV/bin/python"

if [ ! -x "$PY" ]; then
  echo "[py] creating virtualenv at apps/api/.venv" >&2
  python3 -m venv "$VENV"
  "$VENV/bin/python" -m pip install --quiet --upgrade pip
  "$VENV/bin/python" -m pip install --quiet -e "$ROOT/apps/api[dev]"
fi

export PYTHONPATH="$ROOT/apps/api/src${PYTHONPATH:+:$PYTHONPATH}"
exec "$PY" "$@"
