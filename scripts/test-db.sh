#!/usr/bin/env bash
# Start a real PostgreSQL, point the API at it, and prove readiness succeeds.
#
# Used to verify the database foundation without Docker (some sandboxes have no
# Docker). Uses the `pgserver` dev dependency, which ships real PostgreSQL
# binaries, and psycopg (already an API dependency) for provisioning.
#
#   bash scripts/test-db.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="$ROOT/apps/api/.venv/bin/python"
PGDATA="${AICORE_TEST_PGDATA:-$ROOT/.pgdata}"

cd "$ROOT"
export AICORE_REPO_ROOT="$ROOT"

if [ ! -x "$PY" ]; then
  echo "[test-db] creating API virtualenv first" >&2
  bash "$ROOT/scripts/py.sh" -c "pass"
fi

if ! "$PY" -c "import pgserver" >/dev/null 2>&1; then
  echo "[test-db] installing pgserver (bundled PostgreSQL binaries)" >&2
  "$PY" -m pip install --quiet pgserver
fi

echo "[test-db] starting PostgreSQL (data directory: $PGDATA)"
AICORE_TEST_PGDATA="$PGDATA" "$PY" - <<'PY'
import asyncio
import os
import sys

import pgserver
import psycopg

pgdata = os.environ["AICORE_TEST_PGDATA"]
server = pgserver.get_server(pgdata, cleanup_mode=None)

try:
    # ── Provision the application role and database (idempotent) ─────────────
    with psycopg.connect(server.get_uri(), autocommit=True) as conn, conn.cursor() as cur:
        cur.execute("SELECT 1 FROM pg_roles WHERE rolname = 'aicore'")
        if cur.fetchone() is None:
            cur.execute("CREATE ROLE aicore LOGIN PASSWORD 'aicore'")
            print("[test-db] created role 'aicore'")

        cur.execute("SELECT 1 FROM pg_database WHERE datname = 'aicore'")
        if cur.fetchone() is None:
            cur.execute("CREATE DATABASE aicore OWNER aicore")
            print("[test-db] created database 'aicore'")

        cur.execute("SELECT version()")
        version_row = cur.fetchone()
        assert version_row is not None
        print(f"[test-db] server ready: {version_row[0].split(',')[0]}")

    # ── Point the application at the live server ─────────────────────────────
    os.environ["AICORE_ENVIRONMENT"] = "test"
    os.environ["AICORE_LOG_LEVEL"] = "warning"
    os.environ["AICORE_DATABASE_URL"] = f"postgresql+psycopg://aicore:aicore@/aicore?host={pgdata}"
    sys.path.insert(0, os.path.join(os.environ["AICORE_REPO_ROOT"], "apps", "api", "src"))

    from aicore_api.config import Settings
    from aicore_api.db.session import check_database, dispose_engine

    settings = Settings()
    reachable, detail = asyncio.run(
        check_database(timeout_seconds=settings.database_connect_timeout_seconds)
    )
    print(f"[test-db] app connectivity check: reachable={reachable} detail={detail}")
    if not reachable:
        sys.exit("[test-db] FAILED: the API could not reach PostgreSQL")

    # ── Prove /health/ready reports healthy against a live database ──────────
    from fastapi.testclient import TestClient

    from aicore_api.main import create_app

    dispose_engine()
    with TestClient(create_app(settings), raise_server_exceptions=False) as client:
        response = client.get("/health/ready")

    body = response.json()
    print(f"[test-db] GET /health/ready -> {response.status_code} {body}")
    if response.status_code != 200 or body["status"] != "ok":
        sys.exit("[test-db] FAILED: readiness did not report ok against a live database")

    dispose_engine()
    print("[test-db] PASS: PostgreSQL reachable, readiness reports ok")
finally:
    server.cleanup()
    print("[test-db] server stopped")
PY
