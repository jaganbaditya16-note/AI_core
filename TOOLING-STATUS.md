# Tooling verification report

**Date:** 2026-09-17 · **Branch:** `arena/01a0ae29-ai-core` · **Scope:** tooling install + verification only.
**No AICore development was started.** `LICENSE` is byte-identical to its original commit
(`sha256 5eb9c79e…928a`, `git diff 4a9f289 -- LICENSE` = 0 lines).

Verify everything yourself in one command:

```bash
bash scripts/toolkit-status.sh     # → 32 ok · 4 warn · 0 fail
```

---

## 1. Session recovery (what this run had to rebuild)

The sandbox was reset between sessions: the checkout came back at base commit `4a9f289` and these
were wiped — `node_modules`, `~/.claude/skills` (gstack + skill mirrors), global `bun`, and the
`/tmp` source clones. Only the repo snapshot survived.

| Recovered | How |
|---|---|
| Git history (`722763f`, `82af7ed`) | `git fetch` + `reset --hard origin/arena/01a0ae29-ai-core` — was already pushed, so nothing was lost |
| `node_modules` | `npm ci` (with the `nodedir` fix below) |
| gstack + skill mirrors | `bash scripts/install-tools.sh` + `bash scripts/sync-skills.sh --global` |
| superpowers source | cloned to `tools/superpowers` (gitignored) |

The installer scripts written last session are exactly what performed this recovery — that is their
first real test, and they passed.

**New fix (native builds).** `node-gyp` cannot reach `nodejs.org` from this sandbox
(`TLS connection refused`), which broke `npm ci` on `better-sqlite3`. Node's C++ headers ship
locally, so `scripts/bootstrap.sh` now exports `npm_config_nodedir=/usr/local/include/node`
automatically. Result: the native SQLite binding compiles and loads:
`native sqlite OK, rows: 1`. (`npm config set nodedir` is rejected by npm 10 — it must be an env var.)

---

## 2. Summary matrix

| Tool | Status | Version | Location | Usable in Arena? |
|---|---|---|---|---|
| **superpowers** | ✅ installed | 6.3.0 (`b36e082`) | `.agents/skills/` + `.claude/skills/` + `~/.claude/skills/`; source `tools/superpowers` | ✅ fully |
| **gstack** | ✅ installed | 1.87.4.0 (`a6b3a57`) | `~/.claude/skills/gstack` (51 skills linked into `~/.claude/skills`) | ⚠ mostly — browser + Docker skills inert |
| **framer-motion** | ✅ installed | 13.4.0 | `node_modules/framer-motion`, used by `src/` | ✅ fully |
| **21st.dev** | ⚠ partially | CLI 1.17.1 | `.21st/`, `.mcp.json`, CLI via `npx` | ❌ registry/MCP blocked (egress) — local CLI features ✅ |
| **ruflo** | ⚠ partially | 3.42.3 (MCP server `ruflo 3.0.0`) | `.claude/`, `.claude-flow/`, `.agents/skills/`, `.mcp.json` | ⚠ `--minimal` surface ✅ — memory CLI ✗ (4 GB) |

Underlying runtime: node v22.22.3 · npm 10.9.8 · yarn 1.22.22 · bun 1.4.2 · react 19.3.0 ·
vite 8.3.0 · tailwindcss 4.3.3 · typescript 7.0.2.

---

## 3. Per-tool detail

### 3.1 Superpowers — ✅ installed

| | |
|---|---|
| Version | 6.3.0, commit `b36e0829c6d0140e93cfef2ca599b1b07d4a7797` (2026-08-12) |
| Location | `.agents/skills/` (committed source of truth, 14 upstream skills), mirrored to `.claude/skills/` and `~/.claude/skills/` (73 entries total incl. gstack); source checkout `tools/superpowers` |
| Verification | `diff -rq tools/superpowers/skills .agents/skills` → **no drift** (only ruflo's 3 extra skills); frontmatter parse on all 17 skills → `all 17 skills have valid frontmatter`; `CLAUDE_PLUGIN_ROOT=… bash tools/superpowers/hooks/run-hook.cmd session-start` → **exit 0**, valid JSON `{"hookSpecificOutput":{…"additionalContext":"<EXTREMELY_IMPORTANT>You have superpowers…"}}` |
| Arena usability | ✅ Fully usable. Skills are plain Markdown read from disk — no network, no auth. The SessionStart hook is what auto-injects them in Claude Code. |
| Env / login | None required. |

### 3.2 gstack — ✅ installed (browser- and Docker-dependent skills inert)

| | |
|---|---|
| Version | 1.87.4.0, commit `a6b3a57512ca6d5c6aa5b68f74f736195021f96e` |
| Location | `~/.claude/skills/gstack` (repo + state in `~/.gstack`), **51 skills** linked at `~/.claude/skills/<skill>` |
| Verification | `cat gstack/VERSION` → `1.87.4.0`; skill count via `grep -rl 'gstack)' ~/.claude/skills/*/SKILL.md` → **51**; binaries built: `browse/dist/browse` (78 MB) and `make-pdf/dist/pdf` (80 MB). `browse --help` → exit 0 (prints full command list). Live navigation attempt → `launch: Executable doesn't exist at …/chromium_headless_shell-1234/…` |
| Arena usability | ⚠ Plan/review/ship skills (`/office-hours`, `/autoplan`, `/plan-*-review`, `/review`, `/spec`, `/ship`, `/investigate`, `/design-*`, `/health`, `/retro`, `/learn`, `/diagram`, `/document-*`, `/careful`, `/guard`, `/freeze`) ✅ work — they are instructions over repo + git. Browser skills (`/browse`, `/scrape`, `/qa`, `/qa-only`, `/pair-agent`, `/open-gstack-browser`, `/skillify`, `/setup-browser-cookies`) and `/make-pdf` need Chromium; `/cso` needs Docker. None of those exist in this sandbox. |
| Env / login | Browser skills would need cookies via `/setup-browser-cookies`. Installed with `GSTACK_SKIP_PLAYWRIGHT=1`, `GSTACK_SKIP_CSO_BUILD=1`, `GSTACK_SKIP_FONTS=1`. Unblock by re-running `./setup` on a machine with Chromium/Docker, or set `GSTACK_CHROMIUM_PATH`. |

### 3.3 framer-motion — ✅ installed

| | |
|---|---|
| Version | `framer-motion@13.4.0` (range `^13.4.0` in `package.json`) |
| Location | `node_modules/framer-motion`; used by `src/App.tsx`, `src/main.tsx` |
| Verification | `node -p "require('framer-motion/package.json').version"` → `13.4.0`; **`npm run verify:motion`** (new, committed as `scripts/verify-motion.tsx`) → **8/8 checks pass**: renders `motion.div` (`style="opacity:0;transform:translateY(18px)"` emitted), variants + `staggerChildren`, `AnimatePresence`, and `useSpring`/`useTransform`/`useMotionValue`/`motion` exports; `npm run typecheck` exit 0; `npm run build` → `✓ built in 423ms` (359 kB bundle) |
| Arena usability | ✅ Fully usable — it is an ordinary dependency; the headless SSR test above proves it runs without a browser, and the Vite dev server proves it runs in the browser. |
| Env / login | None. Install forms: `npm install framer-motion` · `yarn add framer-motion` · `bun add framer-motion`. |

### 3.4 21st.dev — ⚠ partially installed (registry unreachable from this sandbox)

| | |
|---|---|
| Version | `@21st-dev/cli` **1.17.1** (via `npx @21st-dev/cli@latest`); MCP endpoint `https://21st.dev/api/mcp` |
| Location | `.21st/design.json` + `.21st/DESIGN.md` (committed design context), `21st` server in `.mcp.json`, component target `src/components/ui/` with `components.json` + `src/lib/utils.ts` |
| Verification | MCP config: `npx @21st-dev/cli@latest init --client claude --write` → `Updated .mcp.json (merged the "21st" server)`; servers after merge: `['claude-flow','21st']` (claude-flow preserved). Local review works: `21st review src/` → `5 file(s), 4 finding(s), 0 fixed` (4 × `design-hardcoded-color` in `src/styles.css`). Design context: `init --design-context --check` → runs, reports drift vs. the hand-authored brief (expected). **Registry calls fail: `21st logo github` → `fetch failed`; `curl https://21st.dev/api/mcp` → `000`; node fetch → `ECONNRESET`** (DNS resolves: `216.150.1.193`). `whoami` → `Not logged in` |
| Arena usability | ❌ **Not usable from this Arena environment** — egress to `21st.dev` is blocked at the network layer, so the registry, AI generation, component install, and the MCP server cannot work here **even with valid credentials**. ✅ Local-only features work: design context generation/check, `review`, `init --client … --write`. |
| Env / login | Needs **both** network access **and** auth: `npx @21st-dev/cli@latest login`, or `API_KEY_21ST` / `TWENTYFIRST_TOKEN` (key from <https://21st.dev/mcp>). Documented in `.env.example`. **Logging in here will not help** — the block is the connection, not the credentials. |

### 3.5 ruflo — ⚠ partially installed (`--minimal` stable config; memory CLI unavailable)

| | |
|---|---|
| Version | `ruflo@3.42.3` (npm `latest`); MCP server self-reports `ruflo 3.0.0` |
| Location | project scaffold `.claude/` (agents/6 categories, 46 skills, 16 commands, helpers, hooks), `.claude-flow/` (config.yaml, data, logs, sessions, workflows), `.agents/skills/{ruflo,memory-management,swarm-orchestration}`, MCP server `claude-flow` in `.mcp.json` |
| Config used | **`npx ruflo@latest init --dual --minimal --no-skills-sh`** — chosen deliberately; the full init is never retried |
| Verification | `doctor` → **16 passed, 12 warnings** (warnings = optional packages: agentic-flow, TypeScript local, AIDefence, API keys, encryption-at-rest, Cognitum identity). MCP handshake over stdin JSON-RPC: `initialize` → `{'name':'ruflo','version':'3.0.0'}`, `tools/list` → **353 tools** (`agent_spawn`, `agent_execute`, `swarm_*`, `memory_*`…). `swarm init --topology hierarchical` → `Swarm initialized successfully`. Native driver: `require('better-sqlite3')` builds + loads. Memory CLI: `memory store/search` → **`memory allocation of 4158883080 bytes failed` / `Aborted`** (twice, then stopped as instructed) |
| Arena usability | ⚠ Partial. ✅ Usable: project scaffold + hooks + skills, `doctor`, `swarm init`, the MCP server (353 tools), `metaharness`, agent catalogs. ❌ Not usable: `memory store` / `memory search` (and any agentdb/hybrid/vector work) — they abort identically to the full init because the memory substrate asks for ~4 GB on a 3.9 GB host. Memory persistence therefore has to happen on a larger machine (or via the MCP layer there). |
| Env / login | `CLAUDE_FLOW_MEMORY_BACKEND=sqlite` (pinned in `.mcp.json`), `CLAUDE_FLOW_TOPOLOGY=hierarchical-mesh`, `CLAUDE_FLOW_MAX_AGENTS=15`. Optional: LLM/API keys for model calls (`doctor`: "No API keys found"), `CLAUDE_FLOW_DB_PATH` to relocate memory. All documented in `.env.example`. |

---

## 4. Full verification output

```
runtime
  ✓ node v22.22.3        ✓ npm v10.9.8        ✓ yarn v1.22.22        ✓ bun 1.4.2
frontend (vite + react + tailwind + framer-motion)
  ✓ node_modules present (214M)   ✓ react@19.3.0        ✓ react-dom@19.3.0
  ✓ framer-motion@13.4.0          ✓ tailwindcss@4.3.3   ✓ vite@8.3.0
  ✓ shadcn helper src/lib/utils.ts ✓ components.json
gstack
  ✓ repo at ~/.claude/skills/gstack (1.87.4.0)   ✓ 51 skills linked
  ⚠ no Chromium — /browse, /scrape, /qa, /pair-agent inert
superpowers
  ✓ 17 skills vendored in .agents/skills   ✓ brainstorming ✓ writing-plans
  ✓ test-driven-development ✓ systematic-debugging ✓ verification-before-completion
  ✓ mirrored into ~/.claude/skills
ruflo (claude-flow)
  ✓ .claude-flow/ scaffolding   ✓ .claude/agents (6)   ✓ .claude/skills (46)
  ✓ .claude-flow/config.yaml    ✓ native better-sqlite3 binding builds + loads
  ⚠ memory store/search CLI aborts on this host (documented, not retried)
mcp servers (.mcp.json)
  ✓ claude-flow   ✓ 21st   ✓ ruflo memory backend: sqlite
21st.dev
  ✓ .21st/design.json   ✓ .21st/DESIGN.md
  ⚠ egress to 21st.dev BLOCKED from this sandbox
  ⚠ registry auth: not logged in
app build
  ✓ typecheck passes

32 ok   4 warn   0 fail
```

All four warnings are environment limits, not install failures — each is detected and reported by
the script rather than failing silently.

---

## 5. What is unavailable here, and how to unblock it

| Blocked | Cause | Unblock |
|---|---|---|
| 21st.dev registry + MCP | Sandbox blocks TLS to `21st.dev` | Run on your own machine (egress is not blocked there) + `21st login` / `API_KEY_21ST` |
| gstack browser + `/cso` | No Chromium, no Docker | `./setup` on a machine with Chromium/Docker, or `GSTACK_CHROMIUM_PATH=/usr/bin/chromium` |
| ruflo memory CLI / agentdb / full init | 3.9 GB RAM, ~4 GB allocation | Host with ≥8 GB RAM → `npx ruflo@latest init --full --with-embeddings` |
| Persistence of `node_modules`, `~/.claude`, `tools/` | Sandbox resets between sessions | `bash scripts/bootstrap.sh --tools` (now handles the `nodedir` fix itself) |

---

## 6. Repo changes in this run (tooling only)

| File | Change |
|---|---|
| `.mcp.json` | Regenerated by the 21st CLI `--write` merge; both servers verified after |
| `scripts/verify-motion.tsx` *(new)* + `package.json` | `npm run verify:motion` — 8-check headless framer-motion test |
| `.env.example` *(new)* | Documents `API_KEY_21ST` / `TWENTYFIRST_TOKEN`, `CLAUDE_FLOW_*`, `GSTACK_*`, `npm_config_nodedir` |
| `scripts/bootstrap.sh` | Auto-detects local Node headers for node-gyp (`npm_config_nodedir`) |
| `scripts/install-tools.sh` | ruflo's 131 MB source checkout is now opt-in (`--with-ruflo-source`); runtime is `npx` |
| `scripts/toolkit-status.sh` | Added native-sqlite, ruflo-memory-limit, and 21st.dev egress checks |
| `TOOLKIT.md`, `README.md` | Corrected the ruflo limitation (memory CLI also aborts) and added the 21st.dev egress block |
| `LICENSE` | **Untouched** — verified by hash against the original commit |
