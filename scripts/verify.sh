#!/usr/bin/env bash
# Phase 0 verification — one command that checks everything this phase claims.
#
#   bash scripts/verify.sh            # lint, types, tests, build, secrets, LICENSE
#   bash scripts/verify.sh --full     # + PostgreSQL check and (if possible) E2E
#
# Every check prints PASS / WARN / FAIL and the script exits non-zero on FAIL.
# WARNs are environment limits (no Docker, no browser) — they are never hidden.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

FULL=0
[ "${1:-}" = "--full" ] && FULL=1

pass=0; warn=0; fail=0
ok()   { printf '  \033[1;32mPASS\033[0m %s\n' "$*"; pass=$((pass + 1)); }
meh()  { printf '  \033[1;33mWARN\033[0m %s\n' "$*"; warn=$((warn + 1)); }
bad()  { printf '  \033[1;31mFAIL\033[0m %s\n' "$*"; fail=$((fail + 1)); }
hdr()  { printf '\n\033[1;37m%s\033[0m\n' "$*"; }
run()  { local label="$1"; shift; if "$@" >/tmp/aicore-check.log 2>&1; then ok "$label"; else bad "$label (see /tmp/aicore-check.log)"; fi; }

hdr "1. dependencies"
[ -d node_modules ] && ok "node_modules present" || bad "node_modules missing — run: npm install"
[ -x apps/api/.venv/bin/python ] && ok "API virtualenv present" || bad "apps/api/.venv missing — run: bash scripts/py.sh -c pass"

hdr "2. frontend"
run "lint"      npm run --silent lint
run "typecheck" npm run --silent typecheck
run "build"     npm run --silent build
run "framer-motion runtime check" npm run --silent verify:motion

hdr "3. backend"
run "ruff (lint)"        bash scripts/py.sh -m ruff check apps/api/src apps/api/tests
run "ruff (format check)" bash scripts/py.sh -m ruff format --check apps/api/src apps/api/tests
run "mypy (types)"       bash scripts/py.sh -m mypy apps/api/src
run "pytest"             bash scripts/py.sh -m pytest -c apps/api/pyproject.toml apps/api/tests -q

hdr "4. security"
run "secret scan" bash scripts/check-secrets.sh

if [ -f LICENSE ]; then
  expected="5eb9c79e6b8d868580aea46452f7631934847735685e99ca68892e53d1a7928a"
  actual="$(sha256sum LICENSE | cut -d' ' -f1)"
  if [ "$actual" = "$expected" ]; then
    ok "LICENSE unchanged (sha256 verified)"
  else
    bad "LICENSE differs from the original (expected $expected, got $actual)"
  fi
else
  bad "LICENSE is missing"
fi

hdr "5. infrastructure"
if command -v docker >/dev/null 2>&1; then
  if POSTGRES_PASSWORD=placeholder docker compose -f infrastructure/docker-compose.yml config >/dev/null 2>&1; then
    ok "docker compose configuration is valid"
  else
    bad "docker compose configuration is invalid"
  fi
else
  meh "docker not available here — Compose config not executed (CI validates it)"
fi

if [ "$FULL" = "1" ]; then
  hdr "6. live database"
  if bash scripts/test-db.sh >/tmp/aicore-db.log 2>&1; then
    ok "PostgreSQL reachable, readiness reports ok"
  else
    bad "database verification failed (see /tmp/aicore-db.log)"
  fi

  hdr "7. end-to-end"
  playwright_browser_ready=0
  if [ -d "$HOME/.cache/ms-playwright" ] || [ -n "${PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH:-}" ]; then
    playwright_browser_ready=1
  fi
  if [ "$playwright_browser_ready" = "1" ]; then
    run "playwright" npx playwright test
  else
    meh "no browser available (cdn.playwright.dev unreachable, no system Chromium) — E2E is configured and discovered (.github/workflows/ci.yml runs it); point PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH at a local Chromium to run it here"
  fi
fi

printf '\n\033[1m────────────────────────────────────────\033[0m\n'
printf ' \033[1;32m%d PASS\033[0m   \033[1;33m%d WARN\033[0m   \033[1;31m%d FAIL\033[0m\n\n' "$pass" "$warn" "$fail"
[ "$fail" -eq 0 ]
