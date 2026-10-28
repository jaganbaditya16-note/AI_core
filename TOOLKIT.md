# Toolkit reference

Everything installed in this workspace, where it lives, how to drive it, and what is known to be
limited in the sandbox. `AGENTS.md` is the behavioural contract; this file is the operator manual.

Verify the whole stack at any time:

```bash
bash scripts/toolkit-status.sh     # ✓ / ⚠ / ✗ for every integration
bash scripts/bootstrap.sh          # restore node_modules after a fresh clone
bash scripts/bootstrap.sh --tools  # + clone/refresh gstack, superpowers, ruflo and mirror skills
```

---

## 1. framer-motion (Motion for React)

| | |
|---|---|
| Package | `framer-motion@^13.4.0` (dependency of this app) |
| Install | `npm install framer-motion` · `yarn add framer-motion` · `bun add framer-motion` |
| Used in | `src/App.tsx`, `src/components/**` |
| Host app | Vite + React 19 + TypeScript + Tailwind v4 (`src/styles.css` uses `@import 'tailwindcss'`) |

Working reference implementation (`src/App.tsx`): staggered card entrance with `Variants`, hover
tilt via `whileHover` + `transformPerspective`, a `useMotionValue`/`useSpring`/`useTransform`
physics bar, `layout` animation on chips, and an `AnimatePresence` height-animated list.

House style:

```tsx
const container: Variants = {
  hidden: {},
  show: { transition: { staggerChildren: 0.07, delayChildren: 0.1 } },
};
const item: Variants = {
  hidden: { opacity: 0, y: 18, filter: 'blur(6px)' },
  show: { opacity: 1, y: 0, filter: 'blur(0px)',
          transition: { type: 'spring', stiffness: 220, damping: 26 } },
};
```

- Interaction springs: `stiffness 200–320`, `damping 18–30`.
- Durations: 0.15s–0.5s. Animate `transform` / `opacity` / `filter` only.
- `AnimatePresence` for anything that mounts/unmounts; `layout` for anything that moves.
- Gate non-essential motion behind `prefers-reduced-motion`.

---

## 2. gstack — 55 skills, the virtual engineering team

| | |
|---|---|
| Repo | `~/.claude/skills/gstack` (v1.87.4, commit `a6b3a57`) |
| Skills linked | `~/.claude/skills/<skill>` (55 entries; also `.agents/skills/gstack-*` inside the repo) |
| Runtime dep | `bun` (installed globally, v1.4.2) |
| Install flags used | `GSTACK_SKIP_PLAYWRIGHT=1 GSTACK_SKIP_CSO_BUILD=1 GSTACK_SKIP_FONTS=1 ./setup --no-team --no-plan-tune-hooks --no-timeline-stop-hook` |

Because of the flags above, these need a real machine: `/browse`, `/scrape`, `/setup-browser-cookies`,
`/qa` (browser), `/pair-agent`, `/make-pdf` (browser rendering), `/diagram` (render step), and `/cso`
(Docker image preload). Re-run `./setup` without the skip flags on a machine with Chromium/Docker.

The digest that governs behaviour even without loading a skill lives at
`~/.claude/skills/gstack/agents-digest/gstack-AGENTS.md`; the full index is
`~/.claude/skills/gstack/llms.txt`.

Upgrade: `cd ~/.claude/skills/gstack && git pull && ./setup`.

---

## 3. superpowers — methodology skills

| | |
|---|---|
| Repo | `tools/superpowers` (v6.3.0, commit `b36e082`) |
| Vendored source of truth | `.agents/skills/<skill>/SKILL.md` (14 skills, committed) |
| Mirrors | `.claude/skills/` (project) and `~/.claude/skills/` (global) via `scripts/sync-skills.sh` |
| Session hook | `hooks/session-start` — Claude Code harnesses inject `using-superpowers` automatically; everywhere else AGENTS.md §1 carries the rule |

Skills: `brainstorming`, `writing-plans`, `executing-plans`, `test-driven-development`,
`subagent-driven-development`, `dispatching-parallel-agents`, `systematic-debugging`,
`verification-before-completion`, `requesting-code-review`, `receiving-code-review`,
`using-git-worktrees`, `finishing-a-development-branch`, `writing-skills`, `using-superpowers`.

Update: `bash scripts/install-tools.sh` (pulls and re-syncs), then commit the vendored diff.

---

## 4. ruflo — agent meta-harness (claude-flow v3)

| | |
|---|---|
| Source | `tools/ruflo` (v3.42.3, commit `6f0ed71`) |
| CLI | `npx ruflo@latest …` (npm `ruflo@3.42.3`) |
| Project scaffolding | `.claude/` (agents, commands, skills, helpers, settings.json), `.claude-flow/`, `.agents/skills/{ruflo,memory-management,swarm-orchestration}`, `.codex/` |
| MCP server | `claude-flow` in `.mcp.json` — 353 tools, `CLAUDE_FLOW_MEMORY_BACKEND=sqlite` |
| Baseline health | `npx ruflo@latest doctor` → 17 passed / 11 warnings in this repo (warnings are optional packages / no API keys) |
| Verified | MCP `initialize` handshake returns `ruflo 3.0.0`; `tools/list` advertises 353 tools (e.g. `agent_spawn`, `agent_execute`, `swarm_*`, `memory_*`) |

```bash
npx ruflo@latest doctor
npx ruflo@latest swarm init --topology hierarchical
npx ruflo@latest memory store --key pattern --value "…"
npx ruflo@latest memory search --query "…"
npx ruflo@latest daemon start           # background workers (optional)
npx ruflo@latest mcp start              # MCP server over stdio
npx ruflo@latest metaharness score
```

**Known limitation (this sandbox).** The host has 3.9 GB RAM and no swap, and ruflo's memory
substrate allocates ~4 GB. Two consequences, both verified:

| Command | Result here |
|---|---|
| `npx ruflo@latest init --dual --minimal --no-skills-sh` | ✅ works — **this is the stable path** |
| `npx ruflo@latest doctor` | ✅ 16 passed / 12 warnings |
| `npx ruflo@latest swarm init --topology hierarchical` | ✅ works |
| `npx ruflo@latest mcp start` (353 tools) | ✅ works |
| `npx ruflo@latest init` (full) | ⛔ `memory allocation of 4158883080 bytes failed` |
| `npx ruflo@latest memory store/search` | ⛔ same abort (even without `--vector`) |

**Do not retry the full init or the memory CLI on this host** — it aborts every time with the same
allocation failure. Memory tools are a large-machine feature; here, use the MCP layer from a host
with ≥8 GB RAM, or `--full` + `--with-embeddings` there.

The native `better-sqlite3` driver *does* build here, but only when node-gyp can find Node's C++
headers locally (nodejs.org is unreachable):

```bash
export npm_config_nodedir=/usr/local/include/node   # scripts/bootstrap.sh does this automatically
```

`npm config set nodedir …` is rejected by npm 10 — it has to be the environment variable.

---

## 5. 21st.dev — component registry + MCP

| | |
|---|---|
| CLI | `npx @21st-dev/cli@latest` (package `@21st-dev/cli`) |
| MCP | `21st` → `https://21st.dev/api/mcp`, header `x-api-key: ${API_KEY_21ST}` |
| Design context | `.21st/design.json` (machine) + `.21st/DESIGN.md` (brief) — committed, edit constraints/decisions in `design.json` |
| Component target | `src/components/ui/` with `components.json` (shadcn "new-york", Tailwind v4, `cn()` helper) |

**Auth is required for registry calls and is not set up yet:**

```bash
npx @21st-dev/cli@latest login        # browser login, stores credentials
# or non-interactive:
export API_KEY_21ST=...               # from https://21st.dev/mcp  (also read as TWENTYFIRST_TOKEN)
npx @21st-dev/cli@latest whoami
```

Offline-safe commands: `init --design-context`, `init --client <name> --write`, `review`.
Authenticated + online: `search`, `get`, `generate`, `iterate`, `add`, `logo`, `publish`,
`bookmarks`, `lists`, `teams`.

**Sandbox egress (verified 2026-09-17).** `21st.dev` resolves in DNS but every TLS connection is
reset from this sandbox — `https://21st.dev/api/mcp` returns `000`/`ECONNRESET`, and even the free
no-login `logo` command fails with `fetch failed`. So in this Arena environment the 21st.dev
registry and its MCP server are **unavailable regardless of login**; what works here is the CLI's
local surface (design context, `review`, config generation). Run the registry commands from your own
machine, where egress is not blocked.

Note on naming: the request mentioned "21.dev". That domain belongs to the Bitcoin/Swift toolchain
org (`21-DOT-DEV`, e.g. the P256K Swift package) and has nothing to do with React UI or this stack —
**21st.dev** is the component registry and Magic MCP, and that is what is installed here. Say the
word if a Bitcoin/Swift toolchain was actually intended.

---

## 6. MCP servers

`.mcp.json` registers both servers; Claude Code, Codex, Cursor and VS Code all read variants of it.

```json
{
  "mcpServers": {
    "claude-flow": { "command": "npx", "args": ["-y", "ruflo@latest", "mcp", "start"] },
    "21st": { "type": "http", "url": "https://21st.dev/api/mcp",
              "headers": { "x-api-key": "${API_KEY_21ST}" } }
  }
}
```

Generate a client-specific config any time:

```bash
npx @21st-dev/cli@latest init --client claude   # or cursor | codex | vscode | devin
```

---

## 7. Repo map

```
AGENTS.md              the contract (CLAUDE.md symlinks here)
TOOLKIT.md             this file
tools.lock.json        pinned versions + commit SHAs of every integration
.mcp.json              MCP servers (ruflo + 21st)
.21st/                 design context consumed by 21st tooling
.agents/skills/        superpowers + ruflo skills (committed source of truth)
.claude/               ruflo agents/commands/skills/helpers/settings + mirrored skills
.claude-flow/          ruflo runtime config and capability docs
.swarm/                swarm memory (db gitignored, schema committed)
src/                   the React app (Vite + Tailwind + framer-motion reference implementation)
scripts/               bootstrap.sh · install-tools.sh · sync-skills.sh · toolkit-status.sh
tools/                 external checkouts (gitignored): superpowers, ruflo
```
