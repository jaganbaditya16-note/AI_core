#!/usr/bin/env bash
# Mirror the skills committed in .agents/skills/ into .claude/skills/ so that
# Claude Code (and any harness that reads .claude/skills) picks them up.
#
# .agents/skills/ is the committed source of truth.
# .claude/skills/ is generated (gitignored where it duplicates).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLAUDE_SKILLS="${HOME}/.claude/skills"
GLOBAL="${1:-}"

log() { printf '\033[1;36m[skills]\033[0m %s\n' "$*"; }

mkdir -p "$ROOT/.claude/skills"

count=0
for dir in "$ROOT"/.agents/skills/*/; do
  [ -d "$dir" ] || continue
  name="$(basename "$dir")"
  rm -rf "$ROOT/.claude/skills/$name"
  cp -R "$dir" "$ROOT/.claude/skills/$name"
  count=$((count + 1))
done
log "mirrored $count skill(s) into .claude/skills/"

if [ "$GLOBAL" = "--global" ]; then
  mkdir -p "$CLAUDE_SKILLS"
  for dir in "$ROOT"/.agents/skills/*/; do
    [ -d "$dir" ] || continue
    name="$(basename "$dir")"
    rm -rf "$CLAUDE_SKILLS/$name"
    cp -R "$dir" "$CLAUDE_SKILLS/$name"
  done
  log "mirrored $count skill(s) into $CLAUDE_SKILLS/"
fi
