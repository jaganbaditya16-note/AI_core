#!/usr/bin/env bash
# Scan tracked files for credentials and other secrets.
#
# Phase 0 rule: no secret is ever committed. This script fails if something
# looks like a real credential, or if a .env file has been committed.
#
#   bash scripts/check-secrets.sh
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

failures=0
note() { printf '  \033[1;31m✗\033[0m %s\n' "$*"; failures=$((failures + 1)); }
ok() { printf '  \033[1;32m✓\033[0m %s\n' "$*"; }
hdr() { printf '\n\033[1;37m%s\033[0m\n' "$*"; }

# Files that legitimately contain placeholder/example credentials.
ALLOWLIST='^(\.env\.example|apps/web/\.env\.example|.*\.md|scripts/check-secrets\.sh|database/.*\.sql|tests/.*|apps/api/tests/.*)$'

mapfile -t tracked < <(git ls-files)

hdr "committed .env files"
if printf '%s\n' "${tracked[@]}" | grep -E '(^|/)\.env(\.|$)' | grep -v '\.example$' | grep -q .; then
  printf '%s\n' "${tracked[@]}" | grep -E '(^|/)\.env(\.|$)' | grep -v '\.example$' | while read -r f; do note "committed environment file: $f"; done
  failures=$((failures + 1))
else
  ok "no .env files are tracked"
fi

hdr "credential patterns"

check_pattern() {
  local label="$1" pattern="$2"
  local hits
  hits=$(printf '%s\n' "${tracked[@]}" \
    | grep -vE "$ALLOWLIST" \
    | grep -vE '^(package-lock\.json|tools\.lock\.json)$' \
    | xargs -r grep -nIE "$pattern" 2>/dev/null || true)
  if [ -n "$hits" ]; then
    printf '%s\n' "$hits" | head -10 | while read -r line; do note "$label: $line"; done
    failures=$((failures + 1))
  else
    ok "no $label"
  fi
}

check_pattern "private key material"      '-----BEGIN [A-Z ]*PRIVATE KEY-----'
check_pattern "AWS access key id"         'AKIA[0-9A-Z]{16}'
check_pattern "GitHub token"              'gh[pousr]_[A-Za-z0-9]{36,}'
check_pattern "OpenAI-style secret key"   'sk-[A-Za-z0-9]{32,}'
check_pattern "Anthropic key"             'sk-ant-[A-Za-z0-9_-]{20,}'
check_pattern "Slack token"               'xox[baprs]-[A-Za-z0-9-]{10,}'
check_pattern "Google API key"            'AIza[0-9A-Za-z_-]{35}'
check_pattern "hardcoded password value"  '(password|passwd|secret|api_key|apikey|token)[[:space:]]*[=:][[:space:]]*["'"'"'][^"'"'"'{}$[:space:]]{6,}["'"'"']'
check_pattern "credentialed database URL" 'postgres(ql)?(\+psycopg)?://[^:/@[:space:]]+:[^@/[:space:]]+@'

hdr "runtime images"
if [ -f .dockerignore ]; then
  if grep -qE '^\*\*/?\.env|^\.env' .dockerignore; then
    ok ".dockerignore excludes .env from image build contexts"
  else
    note ".dockerignore exists but does not exclude .env"
  fi
else
  note ".dockerignore is missing"
fi

printf '\n\033[1m────────────────────────────\033[0m\n'
if [ "$failures" -eq 0 ]; then
  printf ' \033[1;32mNo secrets detected.\033[0m\n\n'
  exit 0
fi
printf ' \033[1;31m%d potential secret issue(s).\033[0m\n\n' "$failures"
exit 1
