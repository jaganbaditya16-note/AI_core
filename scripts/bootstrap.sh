#!/usr/bin/env bash
# Restore this workspace after a fresh clone / sandbox reset.
#
#   bash scripts/bootstrap.sh            # dependencies only
#   bash scripts/bootstrap.sh --full     # + local PostgreSQL check
#
# `node_modules` and the Python virtualenv are not preserved by every
# environment, so run this once per fresh checkout.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

log() { printf '\033[1;36m[bootstrap]\033[0m %s\n' "$*"; }

# Native modules compile against Node's C++ headers. node-gyp normally downloads
# them from nodejs.org, which is unreachable in some sandboxes — but the headers
# ship with the local Node install, so point node-gyp at them.
# (`npm config set nodedir` is rejected by npm 10; it must be an environment variable.)
if [ -z "${npm_config_nodedir:-}" ]; then
  for hdr in /usr/local/include/node /usr/include/node "$(dirname "$(command -v node)")/../include/node"; do
    if [ -f "$hdr/node.h" ]; then
      export npm_config_nodedir="$hdr"
      log "using local Node headers: $hdr"
      break
    fi
  done
fi

log "installing workspace dependencies (web + shared types)"
if [ -f package-lock.json ]; then
  npm ci || npm install
else
  npm install
fi

log "preparing the API virtualenv"
bash "$ROOT/scripts/py.sh" -c "pass"

if [ "${1:-}" = "--full" ]; then
  log "checking the database foundation against a real PostgreSQL"
  bash "$ROOT/scripts/test-db.sh"
fi

log "done."
log "  start a database:  bash scripts/dev-db.sh"
log "  start the API:     npm run dev:api"
log "  start the web app: npm run dev"
log "  verify the phase:  npm run verify"
