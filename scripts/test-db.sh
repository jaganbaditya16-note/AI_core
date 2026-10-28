#!/usr/bin/env bash
# Verify the database foundation against a real PostgreSQL.
#
# Starts PostgreSQL (via the `pgserver` dev dependency, which ships real binaries),
# provisions the application role and database, applies the Alembic migrations,
# proves `/health/ready` reports healthy, and runs the integration tests — the
# tenant-isolation and constraint tests that only a real database can verify.
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

# A fresh venv needs the dev extras (alembic, pgserver, pytest) declared in pyproject.
if ! "$PY" -c "import alembic, pgserver" >/dev/null 2>&1; then
  echo "[test-db] installing API dev extras (alembic, pgserver)"
  "$PY" -m pip install --quiet -e "$ROOT/apps/api[dev]"
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
            # No password: this server is ephemeral and reachable only through a
            # local socket (trust auth), so there is no credential to store. The
            # Docker stack and every other environment require POSTGRES_PASSWORD.
            cur.execute("CREATE ROLE aicore LOGIN")
            print("[test-db] created role 'aicore' (local socket, trust auth)")

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
    # Local socket + trust auth: the URL needs no credentials, so none exist to leak.
    os.environ["AICORE_DATABASE_URL"] = f"postgresql+psycopg:///aicore?host={pgdata}&user=aicore"
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

    # ── Apply the schema the way production will ─────────────────────────────
    import subprocess

    root = os.environ["AICORE_REPO_ROOT"]
    child_env = {
        **os.environ,
        "PYTHONPATH": os.path.join(root, "apps", "api", "src"),
        # Integration tests connect to the same server, through the same URL.
        "AICORE_TEST_DATABASE_URL": os.environ["AICORE_DATABASE_URL"],
    }

    alembic_ini = os.path.join(root, "alembic.ini")

    def alembic(*args: str, env: dict[str, str]) -> None:
        """Run a migration step in a child process, failing the script on error."""
        result = subprocess.run(
            [sys.executable, "-m", "alembic", "-c", alembic_ini, *args],
            cwd=root,
            env=env,
            check=False,
        )
        if result.returncode != 0:
            sys.exit(f"[test-db] FAILED: alembic {' '.join(args)} did not run cleanly")

    def app_tables(dsn: str) -> list[str]:
        with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT table_name FROM information_schema.tables "
                "WHERE table_schema = 'aicore' ORDER BY table_name"
            )
            return [row[0] for row in cur.fetchall()]

    print("[test-db] applying migrations (alembic upgrade head)")
    alembic("upgrade", "head", env=child_env)

    # Inspect the *application* database (server.get_uri() points at the
    # maintenance database, where the migrations never ran).
    app_dsn = f"postgresql:///aicore?host={pgdata}&user=aicore"
    with psycopg.connect(app_dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT table_name FROM information_schema.tables "
            "WHERE table_schema = 'aicore' ORDER BY table_name"
        )
        tables = [row[0] for row in cur.fetchall()]
        cur.execute(
            "SELECT column_name, data_type FROM information_schema.columns "
            "WHERE table_schema = 'aicore' AND table_name = 'organizations' ORDER BY ordinal_position"
        )
        columns = cur.fetchall()
    print(f"[test-db] schema after migration: {tables}")
    print(f"[test-db] aicore.organizations columns: {[name for name, _ in columns]}")
    if "organizations" not in tables or "alembic_version" not in tables:
        sys.exit("[test-db] FAILED: the organizations table or version table is missing")

    # ── The models and the migration must describe the same schema ───────────
    print("[test-db] checking for schema drift (alembic check)")
    drift = subprocess.run(
        [sys.executable, "-m", "alembic", "-c", os.path.join(root, "alembic.ini"), "check"],
        cwd=root,
        env=child_env,
        check=False,
    )
    if drift.returncode != 0:
        sys.exit("[test-db] FAILED: the models and the migrations disagree")

    # ── Both directions of the migration must actually run ───────────────────
    # A downgrade path nobody has executed is a claim, not a fact. The round trip
    # runs in a scratch database, so the application's own data is untouched.
    print("[test-db] checking the migration round trip (upgrade → downgrade → upgrade)")
    scratch = "aicore_migration_roundtrip"
    scratch_dsn = f"postgresql:///{scratch}?host={pgdata}&user=aicore"
    scratch_env = {**child_env, "AICORE_DATABASE_URL": scratch_dsn.replace("postgresql://", "postgresql+psycopg://", 1)}

    with psycopg.connect(server.get_uri(), autocommit=True) as conn, conn.cursor() as cur:
        cur.execute(f"DROP DATABASE IF EXISTS {scratch} WITH (FORCE)")
        cur.execute(f"CREATE DATABASE {scratch} OWNER aicore")

    alembic("upgrade", "head", env=scratch_env)
    applied = app_tables(scratch_dsn)
    alembic("downgrade", "base", env=scratch_env)
    reversed_tables = app_tables(scratch_dsn)
    alembic("upgrade", "head", env=scratch_env)
    reapplied = app_tables(scratch_dsn)

    with psycopg.connect(server.get_uri(), autocommit=True) as conn, conn.cursor() as cur:
        cur.execute(f"DROP DATABASE {scratch}")

    print(f"[test-db]   upgrade:   {applied}")
    print(f"[test-db]   downgrade: {reversed_tables}")
    print(f"[test-db]   upgrade:   {reapplied}")
    for table in (
        "organizations",
        "assets",
        "agents",
        "policies",
        "policy_versions",
        "action_executions",
        "audit_events",
        "anomaly_detections",
    ):
        if table not in applied:
            sys.exit(f"[test-db] FAILED: the migration did not create {table}")
        if table in reversed_tables:
            sys.exit(f"[test-db] FAILED: the downgrade left {table} behind")
        if table not in reapplied:
            sys.exit(f"[test-db] FAILED: the re-applied migration did not recreate {table}")

    # ── The tests that need a real database ──────────────────────────────────
    print("[test-db] running the test suite against the live database")
    tested = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-c",
            os.path.join(root, "apps", "api", "pyproject.toml"),
            os.path.join(root, "apps", "api", "tests"),
            "-q",
        ],
        cwd=root,
        env=child_env,
        check=False,
    )
    if tested.returncode != 0:
        sys.exit("[test-db] FAILED: the test suite did not pass against a live database")

    print(
        "[test-db] PASS: migrations applied and reversible, schema correct, "
        "readiness ok, tests pass"
    )
finally:
    server.cleanup()
    print("[test-db] server stopped")
PY
