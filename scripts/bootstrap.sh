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

# Native modules (better-sqlite3, used by ruflo for persistent memory) compile
# against Node's C++ headers. node-gyp normally downloads them from nodejs.org,
# which is unreachable in this sandbox — but the headers ship with the local
# Node install, so point node-gyp at them. `npm config set nodedir` is rejected
# by npm 10, so this must be an environment variable.
if [ -z "${npm_config_nodedir:-}" ]; then
  for hdr in /usr/local/include/node /usr/include/node "$(dirname "$(command -v node)")/../include/node"; do
    if [ -f "$hdr/node.h" ]; then
      export npm_config_nodedir="$hdr"
      log "using local Node headers: $hdr"
      break
    fi
  done
fi

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
