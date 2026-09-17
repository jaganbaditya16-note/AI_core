# AI Core

A ready-to-build workspace with the full agent stack wired in, plus a running React app that proves
it. Every request in this repo is expected to use all five integrations — that contract lives in
[`AGENTS.md`](AGENTS.md) (symlinked as `CLAUDE.md`).

| Integration | What it gives you | Where |
|---|---|---|
| [gstack](https://github.com/garrytan/gstack) | 55 engineering skills: `/office-hours`, `/autoplan`, `/review`, `/qa`, `/ship`, `/cso`, `/browse` | `~/.claude/skills/gstack` |
| [superpowers](https://github.com/obra/superpowers) | Methodology: brainstorming → plans → TDD → subagent execution → verification | `.agents/skills/` |
| [ruflo](https://github.com/ruvnet/ruflo) | Agent meta-harness: agents, swarms, hooks, persistent memory, MCP (353 tools) | `.claude/`, `.claude-flow/`, `.mcp.json` |
| [21st.dev](https://21st.dev) | React component registry + MCP + project design context | `.21st/`, `.mcp.json` |
| [framer-motion](https://motion.dev) | Springs, gestures, layout, `AnimatePresence` | `src/` |

## Quick start

```bash
bash scripts/bootstrap.sh --tools     # deps + tool checkouts + skills
npm run dev                           # http://localhost:5173
bash scripts/toolkit-status.sh        # verify every integration
```

The dev server binds `0.0.0.0` with `allowedHosts: true` so it works behind a preview proxy.

## What you get out of the box

- Vite + React 19 + TypeScript + Tailwind v4 app (`src/App.tsx`) that reads as a live status board
  and doubles as the framer-motion reference implementation: staggered entrances, spring physics,
  hover gestures, layout transitions, `AnimatePresence`.
- shadcn-compatible component target: `components.json`, `@/` path alias, `cn()` helper,
  `src/components/ui/` ready for `npx @21st-dev/cli@latest add <author>/<slug>`.
- ruflo scaffolding (agents, commands, skills, hooks, settings) and MCP registration for both
  ruflo and 21st.dev.
- `.21st/design.json` + `.21st/DESIGN.md`: the tokens, motion values, and constraints every future
  component inherits.

## One-time steps / known limits

- **21st.dev registry calls need a login:** `npx @21st-dev/cli@latest login` or `export API_KEY_21ST=…`
  (key from <https://21st.dev/mcp>). Everything else works offline.
- **No browser or Docker in this sandbox:** gstack's `/browse`, `/scrape`, `/qa` and `/cso` are
  installed but inert until Chromium/Docker exist (`GSTACK_SKIP_PLAYWRIGHT=1`, `GSTACK_SKIP_CSO_BUILD=1`).
- **3.9 GB RAM:** ruflo runs with the `sqlite` memory backend and `init --dual --minimal`; its
  agentdb/vector paths abort. See [`TOOLKIT.md`](TOOLKIT.md#4-ruflo--agent-meta-harness-claude-flow-v3).
- `node_modules` is not preserved across sandbox sessions — rerun `bash scripts/bootstrap.sh`.

Details, commands, and troubleshooting: [`TOOLKIT.md`](TOOLKIT.md).
