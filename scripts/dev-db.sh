#!/usr/bin/env bash
# Start a local PostgreSQL for development, no Docker required.
#
# Uses pgserver (bundled PostgreSQL binaries) and provisions the same role and
# database the Compose stack creates. Prints the AICORE_DATABASE_URL to export.
# Ctrl-C stops the server.
#
#   bash scripts/dev-db.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
export AICORE_REPO_ROOT="$ROOT"
export AICORE_TEST_PGDATA="${AICORE_TEST_PGDATA:-$ROOT/.pgdata}"

PY="$ROOT/apps/api/.venv/bin/python"
if [ ! -x "$PY" ]; then
  bash "$ROOT/scripts/py.sh" -c "pass"
fi
if ! "$PY" -c "import pgserver" >/dev/null 2>&1; then
  "$PY" -m pip install --quiet pgserver
fi

exec "$PY" - <<'PY'
import os
import pgserver
import psycopg
import signal
import sys
import time

pgdata = os.environ["AICORE_TEST_PGDATA"]
server = pgserver.get_server(pgdata, cleanup_mode=None)

with psycopg.connect(server.get_uri(), autocommit=True) as conn, conn.cursor() as cur:
    cur.execute("SELECT 1 FROM pg_roles WHERE rolname = 'aicore'")
    if cur.fetchone() is None:
        cur.execute("CREATE ROLE aicore LOGIN PASSWORD 'aicore'")
    cur.execute("SELECT 1 FROM pg_database WHERE datname = 'aicore'")
    if cur.fetchone() is None:
        cur.execute("CREATE DATABASE aicore OWNER aicore")
    cur.execute("SELECT version()")
    version = cur.fetchone()
    assert version is not None
    print(f"[dev-db] {version[0].split(',')[0]} running on {pgdata}", flush=True)

print("\n[dev-db] export this for the API:\n", flush=True)
print(
    f'  export AICORE_DATABASE_URL="postgresql+psycopg://aicore:aicore@/aicore?host={pgdata}"\n',
    flush=True,
)
print("[dev-db] ready — press Ctrl-C to stop", flush=True)


def _stop(*_: object) -> None:
    server.cleanup()
    print("\n[dev-db] stopped", flush=True)
    sys.exit(0)


signal.signal(signal.SIGTERM, _stop)
signal.signal(signal.SIGINT, _stop)

while True:
    time.sleep(3600)
PY
