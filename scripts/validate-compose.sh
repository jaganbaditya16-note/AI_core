#!/usr/bin/env bash
# Validate the Compose stack without Docker.
#
# `docker compose config` is the authoritative check and runs in CI. Where Docker
# is unavailable, this script still verifies the parts that matter for security
# and correctness: structure, health gating, secret handling and that every
# ${VARIABLE} the stack references is documented in .env.example.
#
#   bash scripts/validate-compose.sh
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PY="$ROOT/apps/api/.venv/bin/python"
if [ ! -x "$PY" ]; then
  echo "[compose] API virtualenv missing — run: bash scripts/py.sh -c pass" >&2
  exit 1
fi

# docker compose is authoritative when Docker exists.
if command -v docker >/dev/null 2>&1; then
  if POSTGRES_PASSWORD=validate-placeholder docker compose -f infrastructure/docker-compose.yml config --quiet; then
    echo "PASS  docker compose config (authoritative)"
    exit 0
  fi
  echo "FAIL  docker compose config rejected the stack" >&2
  exit 1
fi

echo "WARN  docker not available — falling back to structural validation"
exec "$PY" - "$@" <<'PY'
import re
import sys
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover - dependency is declared in dev extras
    sys.exit("FAIL  PyYAML is not installed (pip install pyyaml)")

COMPOSE = Path("infrastructure/docker-compose.yml")
ENV_EXAMPLE = Path(".env.example")

failures: list[str] = []
warnings: list[str] = []


def ok(msg: str) -> None:
    print(f"PASS  {msg}")


def fail(msg: str) -> None:
    failures.append(msg)
    print(f"FAIL  {msg}")


def warn(msg: str) -> None:
    warnings.append(msg)
    print(f"WARN  {msg}")


document = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
services = document.get("services", {})

# ── Structure ────────────────────────────────────────────────────────────────
for name in ("db", "api", "web"):
    if name in services:
        ok(f"service '{name}' is defined")
    else:
        fail(f"service '{name}' is missing")

# ── Health gating ────────────────────────────────────────────────────────────
if services.get("db", {}).get("healthcheck"):
    ok("db has a healthcheck (pg_isready)")
else:
    fail("db has no healthcheck")

for name, expected in (("api", "db"), ("web", "api")):
    depends = services.get(name, {}).get("depends_on", {})
    condition = depends.get(expected, {}).get("condition") if isinstance(depends, dict) else None
    if condition == "service_healthy":
        ok(f"{name} waits for {expected} to be healthy")
    else:
        fail(f"{name} does not gate on {expected} health (got: {condition!r})")

# ── No hardcoded credentials ─────────────────────────────────────────────────
db_env = services.get("db", {}).get("environment", {})
password = str(db_env.get("POSTGRES_PASSWORD", ""))
if "${" in password:
    ok("db password comes from the environment (no literal secret)")
else:
    fail("db password is not environment-driven")

api_url = str(services.get("api", {}).get("environment", {}).get("AICORE_DATABASE_URL", ""))
if "${POSTGRES_PASSWORD" in api_url:
    ok("api database URL is assembled from POSTGRES_* variables")
else:
    fail("api database URL does not reference POSTGRES_PASSWORD")

# ── Frontend must not receive database credentials ───────────────────────────
web_service = services.get("web", {})
web_env = web_service.get("environment", {})
leaked = [key for key in web_env if "DATABASE" in key.upper() or "POSTGRES" in key.upper()]
if "env_file" in web_service:
    # An env_file would inject the repository .env (and therefore database
    # credentials) into the frontend container.
    leaked.append("env_file")
if leaked:
    fail(f"web service receives database configuration: {leaked}")
else:
    ok("web service receives no database credentials (no env_file, no POSTGRES_*)")

# ── Every referenced variable is documented ──────────────────────────────────
referenced = set(re.findall(r"\$\{([A-Z0-9_]+)", COMPOSE.read_text(encoding="utf-8")))
documented = set(re.findall(r"^([A-Z0-9_]+)=", ENV_EXAMPLE.read_text(encoding="utf-8"), re.MULTILINE))
undocumented = sorted(var for var in referenced - documented if var != "POSTGRES_PASSWORD")
if undocumented:
    warn(f"referenced but not in .env.example: {', '.join(undocumented)}")
else:
    ok(f"all {len(referenced)} referenced variables are documented in .env.example")

# ── Volume is declared ───────────────────────────────────────────────────────
volumes = document.get("volumes", {})
if "aicore-db-data" in volumes:
    ok("database volume is declared (data survives restarts)")
else:
    fail("database volume is not declared")

print()
if failures:
    print(f"FAIL  {len(failures)} structural issue(s) in the Compose stack")
    sys.exit(1)
print(f"PASS  Compose stack is structurally valid ({len(warnings)} warning(s))")
PY
