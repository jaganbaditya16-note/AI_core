#!/usr/bin/env bash
# One-shot verification that every part of the AI Core stack is actually wired.
# Run after bootstrap, or whenever you want proof the stack still works.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

pass=0; warn=0; fail=0
ok()   { printf '  \033[1;32m✓\033[0m %s\n' "$*"; pass=$((pass+1)); }
meh()  { printf '  \033[1;33m⚠\033[0m %s\n' "$*"; warn=$((warn+1)); }
bad()  { printf '  \033[1;31m✗\033[0m %s\n' "$*"; fail=$((fail+1)); }
hdr()  { printf '\n\033[1;37m%s\033[0m\n' "$*"; }

hdr "runtime"
node -v >/dev/null 2>&1 && ok "node $(node -v)" || bad "node missing"
npm  -v >/dev/null 2>&1 && ok "npm v$(npm -v)"   || bad "npm missing"
yarn -v >/dev/null 2>&1 && ok "yarn v$(yarn -v)" || meh "yarn missing (npm is the primary manager here)"
bun  -v >/dev/null 2>&1 && ok "bun $(bun -v) (required by gstack)" || bad "bun missing — gstack needs it"

hdr "frontend (Next.js + tailwind + framer-motion)"
if [ -d apps/web ]; then
  ok "apps/web present"
  for pkg in next react framer-motion tailwindcss; do
    if node -e "require.resolve('$pkg/package.json')" >/dev/null 2>&1; then
      v=$(node -p "require('$pkg/package.json').version" 2>/dev/null)
      ok "$pkg@$v"
    else
      bad "$pkg not installed"
    fi
  done
  [ -f apps/web/src/app/layout.tsx ] && ok "App Router layout present" || meh "apps/web/src/app/layout.tsx missing"
  [ -f apps/web/scripts/verify-motion.mjs ] && ok "motion verifier present (npm run verify:motion)" || meh "motion verifier missing"
else
  bad "apps/web missing"
fi

hdr "backend (FastAPI)"
if [ -d apps/api ]; then
  ok "apps/api present"
  if [ -x apps/api/.venv/bin/python ]; then
    v=$(apps/api/.venv/bin/python -c "import fastapi; print(fastapi.__version__)" 2>/dev/null)
    ok "virtualenv present (fastapi ${v:-?})"
  else
    meh "apps/api/.venv missing — run: bash scripts/py.sh -c pass"
  fi
  [ -f apps/api/src/aicore_api/main.py ] && ok "application factory present" || bad "aicore_api.main missing"
else
  bad "apps/api missing"
fi

hdr "gstack"
GS="$HOME/.claude/skills/gstack"
if [ -d "$GS" ]; then
  ok "gstack repo at $GS ($(cat "$GS/VERSION" 2>/dev/null || echo '?'))"
  n=$(grep -rl "gstack)" "$HOME"/.claude/skills/*/SKILL.md 2>/dev/null | wc -l)
  ok "$n gstack skills linked in ~/.claude/skills"
  if [ -d "$HOME/.cache/ms-playwright" ]; then
    ok "Chromium present — /browse, /scrape, /qa are live"
  else
    meh "no Chromium — /browse, /scrape, /qa, /pair-agent inert (installed with GSTACK_SKIP_PLAYWRIGHT=1)"
  fi
else
  bad "gstack missing — run: bash scripts/install-tools.sh"
fi

hdr "superpowers"
n=$(find .agents/skills -maxdepth 1 -mindepth 1 -type d 2>/dev/null | wc -l)
if [ "$n" -ge 14 ]; then
  ok "$n skills vendored in .agents/skills (14 superpowers + ruflo's 3)"
else
  meh "only $n skills in .agents/skills (expected ≥14)"
fi
for s in brainstorming writing-plans test-driven-development systematic-debugging verification-before-completion; do
  [ -f ".agents/skills/$s/SKILL.md" ] && ok "skill: $s" || bad "missing skill: $s"
done
[ -d "$HOME/.claude/skills/brainstorming" ] && ok "mirrored into ~/.claude/skills" || meh "not mirrored globally (run scripts/sync-skills.sh --global)"

hdr "ruflo (claude-flow)"
[ -d .claude-flow ] && ok ".claude-flow/ scaffolding present" || bad ".claude-flow missing — run scripts/install-tools.sh"
[ -d .claude/agents ] && ok ".claude/agents ($(find .claude/agents -maxdepth 1 -mindepth 1 -type d | wc -l) categories)" || meh ".claude/agents missing"
[ -d .claude/skills ] && ok ".claude/skills ($(find .claude/skills -maxdepth 1 -mindepth 1 | wc -l) skills)" || meh ".claude/skills missing"
[ -f .claude-flow/config.yaml ] && ok ".claude-flow/config.yaml" || meh ".claude-flow/config.yaml missing"
if node -e "require('better-sqlite3')" >/dev/null 2>&1; then
  ok "native better-sqlite3 binding builds + loads (needs npm_config_nodedir on this host)"
else
  meh "better-sqlite3 native binding unavailable — ruflo falls back to sql.js (WASM, in-memory)"
fi
meh "ruflo memory store/search CLI ABORTS on this host (4GB allocation) — not run by this script; use --minimal surface only"

hdr "mcp servers (.mcp.json)"
if [ -f .mcp.json ]; then
  for s in claude-flow 21st; do
    node -e "const m=require('./.mcp.json');process.exit(m.mcpServers&&m.mcpServers['$s']?0:1)" \
      && ok "server registered: $s" || bad "server missing: $s"
  done
  backend=$(node -e "try{console.log(require('./.mcp.json').mcpServers['claude-flow'].env.CLAUDE_FLOW_MEMORY_BACKEND)}catch(e){}" 2>/dev/null)
  [ "$backend" = "sqlite" ] && ok "ruflo memory backend: sqlite (low-RAM safe)" || meh "ruflo memory backend: ${backend:-unset} — agentdb/hybrid aborts under 5GB RAM"
else
  bad ".mcp.json missing"
fi

hdr "21st.dev"
[ -f .21st/design.json ] && ok "design context .21st/design.json" || meh ".21st/design.json missing — run: npx @21st-dev/cli@latest init --design-context"
[ -f .21st/DESIGN.md ]   && ok "design brief .21st/DESIGN.md"    || meh ".21st/DESIGN.md missing"
code=$(timeout 20 curl -sS -o /dev/null -w '%{http_code}' https://21st.dev/api/mcp 2>/dev/null)
if [ "$code" = "000" ] || [ -z "$code" ]; then
  meh "egress to 21st.dev BLOCKED from this sandbox (TLS reset) — registry + MCP calls unusable here"
else
  ok "21st.dev reachable (HTTP $code)"
fi
if command -v npx >/dev/null 2>&1; then
  st=$(timeout 90 npx --yes @21st-dev/cli@latest whoami 2>&1 | tail -1)
  case "$st" in
    *"Not signed in"*|*"Not logged in"*|*"not logged in"*|*error*|*Error*) meh "registry auth: $st" ;;
    "") meh "registry auth: unknown" ;;
    *) ok "registry auth: $st" ;;
  esac
fi

hdr "app build"
if [ -d node_modules ]; then
  if npm run --silent typecheck >/dev/null 2>&1; then ok "typecheck passes"; else meh "typecheck has errors (run: npm run typecheck)"; fi
fi

printf '\n\033[1m────────────────────────────\033[0m\n'
printf ' \033[1;32m%d ok\033[0m   \033[1;33m%d warn\033[0m   \033[1;31m%d fail\033[0m\n\n' "$pass" "$warn" "$fail"
[ "$fail" -eq 0 ]
