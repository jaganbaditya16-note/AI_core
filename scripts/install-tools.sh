#!/usr/bin/env bash
# Clone / refresh the external agent tooling this workspace depends on.
# Idempotent: re-running pulls the latest and re-installs skills.
#
#   bash scripts/install-tools.sh
#
# Installs:
#   gstack      -> ~/.claude/skills/gstack      (55 skills, browsers skipped)
#   superpowers -> tools/superpowers            (14 skills, vendored copy already in repo)
#   ruflo       -> tools/ruflo                  (source checkout, CLI runs via npx)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
mkdir -p tools
log() { printf '\033[1;36m[tools]\033[0m %s\n' "$*"; }

# ── gstack ────────────────────────────────────────────────────────────────────
GSTACK_DIR="${HOME}/.claude/skills/gstack"
if [ -d "$GSTACK_DIR/.git" ]; then
  log "gstack present — fetching updates"
  git -C "$GSTACK_DIR" fetch --depth 1 origin main && git -C "$GSTACK_DIR" reset --hard origin/main
else
  log "cloning gstack"
  mkdir -p "$(dirname "$GSTACK_DIR")"
  git clone --single-branch --depth 1 https://github.com/garrytan/gstack.git "$GSTACK_DIR"
fi
log "running gstack setup (Chromium + CSO build skipped: this sandbox has no browser/docker)"
( cd "$GSTACK_DIR" && GSTACK_SKIP_PLAYWRIGHT=1 GSTACK_SKIP_CSO_BUILD=1 GSTACK_SKIP_FONTS=1 \
    ./setup --no-team --no-plan-tune-hooks --no-timeline-stop-hook --quiet < /dev/null )

# ── superpowers ───────────────────────────────────────────────────────────────
if [ -d tools/superpowers/.git ]; then
  log "superpowers present — fetching updates"
  git -C tools/superpowers fetch --depth 1 origin main && git -C tools/superpowers reset --hard origin/main
else
  log "cloning superpowers"
  git clone --single-branch --depth 1 https://github.com/obra/superpowers.git tools/superpowers
fi
bash "$ROOT/scripts/sync-skills.sh"

# ── ruflo ─────────────────────────────────────────────────────────────────────
if [ -d tools/ruflo/.git ]; then
  log "ruflo source present — fetching updates"
  git -C tools/ruflo fetch --depth 1 origin main && git -C tools/ruflo reset --hard origin/main
else
  log "cloning ruflo source"
  git clone --single-branch --depth 1 https://github.com/ruvnet/ruflo.git tools/ruflo
fi

# ── ruflo project scaffolding ─────────────────────────────────────────────────
# NOTE: the full `init` (and --all-agents / hybrid AgentDB memory) aborts on
# machines with < ~5 GB RAM: "memory allocation of 4158883080 bytes failed".
# `--minimal` + the sqlite memory backend in .mcp.json is the working path.
if [ ! -d .claude-flow ]; then
  log "running ruflo init --dual --minimal"
  npx --yes ruflo@latest init --dual --minimal --no-skills-sh
else
  log "ruflo scaffolding present — verifying with doctor"
  npx --yes ruflo@latest doctor || true
fi

log "done."
