#!/usr/bin/env bash
# Restore this workspace after a fresh clone / sandbox reset.
#
# The sandbox does NOT persist node_modules, so run this once per fresh
# checkout (or whenever `npm run dev` complains about missing packages).
#
#   bash scripts/bootstrap.sh            # deps only
#   bash scripts/bootstrap.sh --tools    # deps + external tool checkouts + skills
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

log() { printf '\033[1;36m[bootstrap]\033[0m %s\n' "$*"; }

log "installing npm dependencies (react, vite, tailwind, framer-motion, shadcn utils)"
if [ -f package-lock.json ]; then
  npm ci || npm install
else
  npm install
fi

if [ "${1:-}" = "--tools" ]; then
  bash "$ROOT/scripts/install-tools.sh"
  bash "$ROOT/scripts/sync-skills.sh"
fi

log "done. start the app with: npm run dev -- --host 0.0.0.0"
log "check every integration with: bash scripts/toolkit-status.sh"
