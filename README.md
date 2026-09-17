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

- **21st.dev is blocked from this sandbox** (TLS reset to `21st.dev`, login or not), so the registry
  and its MCP server only work from your own machine — run `npx @21st-dev/cli@latest login` or set
  `API_KEY_21ST` (see [`.env.example`](.env.example)) there. Local CLI features work here.
- **No browser or Docker:** gstack's `/browse`, `/scrape`, `/qa`, `/pair-agent` and `/cso` are
  installed (binaries built) but inert until Chromium/Docker exist.
- **3.9 GB RAM:** ruflo is pinned to `init --dual --minimal` + `sqlite`. Full init and the
  `memory store/search` CLI abort with a 4 GB allocation failure — don't retry them here.
  See [`TOOLKIT.md`](TOOLKIT.md#4-ruflo--agent-meta-harness-claude-flow-v3).
- `node_modules`, `~/.claude/skills` and `tools/` are not preserved across sandbox sessions —
  rerun `bash scripts/bootstrap.sh --tools`. See [`TOOLING-STATUS.md`](TOOLING-STATUS.md).

Details, commands, and troubleshooting: [`TOOLKIT.md`](TOOLKIT.md).
