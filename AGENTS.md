# AI Core — agent operating instructions

**This file is the contract for every request in this repository.** `CLAUDE.md` is a symlink to
it. Read it before planning, and treat the five integrations below as part of the definition of
done — not optional extras.

Installed stack and exact versions: [`tools.lock.json`](tools.lock.json), [`TOOLKIT.md`](TOOLKIT.md).
Verify everything still works: `bash scripts/toolkit-status.sh`.

---

## 0. The rule

Every build, feature, fix, or UI request runs through this pipeline:

| Phase | Owner | What it means in practice |
|---|---|---|
| 1. Understand | **superpowers** | Invoke `brainstorming`; interrogate the ask before writing anything. |
| 2. Plan | **gstack** | `/office-hours` → `/autoplan` (CEO + design + eng + DX review) or `/spec`. |
| 3. Build | **ruflo** + **21st.dev** | ruflo agents/swarms for parallel workstreams; 21st registry components instead of invented UI. |
| 4. Animate | **framer-motion** | Every interactive surface has motion: springs, staggers, layout transitions. |
| 5. Verify | **superpowers** + **gstack** | TDD, `/review`, `/qa`, `/cso` for anything touching auth, data, or money. |
| 6. Ship | **gstack** | `/ship` (or `/land-and-deploy`) — tests, changelog, PR. |

A shortcut on any row needs a recorded reason in the final report.

---

## 1. superpowers — process before code

Source of truth: [`.agents/skills/`](.agents/skills) (vendored, mirrored to `.claude/skills/` and
`~/.claude/skills/`).

**Invoke the relevant skill BEFORE any response or action** — including clarifying questions and
"quick looks" at the codebase. If a skill applies, use it; announce `Using <skill> to <purpose>`
and follow it exactly.

| Skill | Use when |
|---|---|
| `brainstorming` | Any "let's build X" — refine the idea into a spec in chunks the user can read. |
| `writing-plans` | After the spec — a plan a junior engineer could execute. |
| `test-driven-development` | Any implementation — red/green, no exceptions for "simple" code. |
| `subagent-driven-development` | Multi-task plans — dispatch subagents per task, review their work. |
| `dispatching-parallel-agents` | Independent workstreams that can run concurrently. |
| `systematic-debugging` | Any bug — root cause before fix, never symptom patching. |
| `verification-before-completion` | Before claiming anything is done. |
| `requesting-code-review` / `receiving-code-review` | Before landing, and when review feedback arrives. |
| `executing-plans` | Working through an approved plan without drifting. |
| `using-git-worktrees` | Parallel branches; one writer per worktree. |
| `finishing-a-development-branch` | Merging/cleaning up when work is done. |
| `writing-skills` / `using-superpowers` | Extending this setup; re-reading the rules. |

Priority: **process skills first** (`brainstorming`, `systematic-debugging`), then implementation
skills. `YAGNI`, `DRY`, and true red/green TDD are non-negotiable.

---

## 2. gstack — the engineering team (55 skills)

Installed at `~/.claude/skills/gstack` (skills linked into `~/.claude/skills/`). Digest of the
behavioural rules that apply even when a full skill isn't loaded:

- **Boil the Ocean** — completeness is cheap now: tests, edge cases, error paths. A shortcut needs
  an explicit, recorded decision.
- **Search Before Building** — know what exists first. Then use the reuse ladder: existing
  helper → standard library → native platform feature → already-installed dependency → new code.
- **User Sovereignty** — recommend, don't override. Cross-model agreement is signal, not permission.
- **Voice** — direct, concrete, builder-to-builder. Name files, functions, commands, and user-visible
  impact. No filler, no AI vocabulary.

Standard commands (load gstack first: *"Load gstack. Run /review"*):

| Command | Purpose |
|---|---|
| `/office-hours` | YC-style interrogation of the idea before building. |
| `/plan-ceo-review`, `/plan-eng-review`, `/plan-design-review`, `/plan-devex-review` | Single-lens plan reviews. |
| `/autoplan` | Runs CEO + design + eng + DX reviews in sequence with auto-decisions. Start here for features. |
| `/spec` | Turn vague intent into a precise executable spec. |
| `/review` | Pre-landing PR review of the diff. |
| `/qa`, `/qa-only` | Browser QA of a running app; `/qa` also fixes what it finds. |
| `/ship` | Merge base, tests, changelog, VERSION bump, commit, push, PR. |
| `/land-and-deploy`, `/canary` | Release + post-release monitoring. |
| `/cso` | Security audit (OWASP + STRIDE) — required for auth/data/money changes. |
| `/investigate` | Root-cause debugging. |
| `/design-shotgun`, `/design-html`, `/design-review`, `/design-consultation` | Generate and harden UI direction; `/design-review` hunts AI slop. |
| `/browse`, `/scrape`, `/setup-browser-cookies` | Real-browser driving. **Requires a browser** — see §7. |
| `/benchmark`, `/health`, `/retro`, `/learn`, `/diagram`, `/make-pdf`, `/document-generate`, `/document-release` | Measurement, docs, diagrams, retrospectives. |
| `/careful`, `/guard`, `/freeze`, `/unfreeze` | Safety rails for destructive or scoped work. |

Full list: `~/.claude/skills/gstack/llms.txt` (55 skills, 76 browse commands).

---

## 3. ruflo — agents, swarms, memory

Scaffolding lives in `.claude/` (agents, commands, skills, helpers, hooks), `.claude-flow/`, and
`.agents/skills/{ruflo,memory-management,swarm-orchestration}`. MCP server `claude-flow` is
registered in `.mcp.json` (353 tools).

```bash
npx ruflo@latest doctor                 # health check (14 pass / 14 warn baseline here)
npx ruflo@latest swarm init --topology hierarchical
npx ruflo@latest memory store --key <k> --value <v>
npx ruflo@latest memory search --query "<q>"
npx ruflo@latest hooks list
npx ruflo@latest metaharness score      # harness readiness scorecard
npx ruflo@latest mcp start              # MCP server (also launched by .mcp.json)
```

Operating loop (from ruflo's own agent contract):
**recall → inspect → route → plan → execute → test → validate → receipt.**
Route each task to the smallest capable topology and agent set; cheaper than a swarm for small work.

Hard rules:
- One writer per worktree; read-only research agents may share a checkout, writers may not.
- A child agent may drop capabilities, never add tools, servers, network, spend, or delegation depth.
- Only the integration agent touches shared manifests or lockfiles.
- **Never auto-commit, push, merge, release, or delete worktrees without explicit authorization.**
- Persistent memory: prefer `sqlite` backend in this sandbox (§7).

---

## 4. 21st.dev — real components, not invented ones

MCP server `21st` (`https://21st.dev/api/mcp`) + CLI `@21st-dev/cli`. Design context is committed
at [`.21st/design.json`](.21st/design.json) with the human-readable brief in `.21st/DESIGN.md`.

```bash
npx @21st-dev/cli@latest login                 # required once: browser login (or set API_KEY_21ST)
npx @21st-dev/cli@latest search "command palette" --type c
npx @21st-dev/cli@latest generate "settings panel with toggles" --variants 3
npx @21st-dev/cli@latest add <author>/<slug>   # install a published component into this project
npx @21st-dev/cli@latest review src/           # deterministic local UI rule check
npx @21st-dev/cli@latest init --design-context --check
```

Rules:
1. **Search the registry before hand-writing UI.** If a component exists, use or remix it (reuse ladder).
2. Components land in `src/components/ui/` (shadcn-style, `components.json` is configured, `cn()` helper
   in `src/lib/utils.ts`) — never in vendored or generated directories.
3. Every generated component inherits the tokens, spacing, radii, and motion values in
   `.21st/design.json`. When a design decision changes, update `design.json` **and** `DESIGN.md`.
4. Registry calls need auth. If not signed in, say so, build against the committed design context,
   and flag the component as "unverified against registry".

---

## 5. framer-motion — motion is part of "done"

Installed as a real dependency (`framer-motion@^13`, also fine via `yarn add framer-motion`).

```tsx
import { motion, AnimatePresence, useSpring, useTransform, type Variants } from 'framer-motion';
```

Required practice for any UI work:
- **Import from `framer-motion`** — that is the package this project installs and animates with.
- **Entrances**: wrap lists/grids in a variants container with `staggerChildren` (0.05–0.1s) — see
  `src/App.tsx` for the reference implementation.
- **Springs over linear easing** for anything that responds to a user: `{ type: 'spring', stiffness: 200-320, damping: 18-30 }`.
- **Gestures**: `whileHover` / `whileTap` on every button, card, and row that is clickable.
- **`AnimatePresence`** for mount/unmount (modals, drawers, toasts, list items) — never a hard cut.
- **`layout`** prop for reorder/resize instead of animating width/height manually.
- Animate only `transform`, `opacity`, and `filter` on hot paths; keep transitions between 0.15s and
  0.5s; never block input on an animation.
- Respect `prefers-reduced-motion` for non-essential motion.

Do not ship a static interactive surface, and do not substitute CSS keyframes where a motion
primitive exists.

---

## 6. Definition of done

- [ ] `npm run typecheck` and `npm run build` pass (`vite build`).
- [ ] Tests written first where logic exists (superpowers TDD); `npm test` if the project has one.
- [ ] UI: registry searched, `framer-motion` applied per §5, `npm run dev` renders without console errors.
- [ ] `/review` on the diff; `/cso` when auth, data, or money is touched; `/qa` for browser flows.
- [ ] Report: files changed, exact commands run, evidence observed, limitations/waivers.

---

## 7. Sandbox facts (this environment)

- **`node_modules` is not persisted** between sessions → `bash scripts/bootstrap.sh` restores it.
  External tool clones live in `tools/` (gitignored) and `~/.claude/skills/`; `scripts/install-tools.sh` recreates them.
- **3.9 GB RAM, no swap.** ruflo's full `init` and its `agentdb`/`hybrid` vector path abort with
  `memory allocation of 4158883080 bytes failed`. The memory backend is therefore pinned to `sqlite`
  in `.mcp.json`. `npx ruflo@latest init --dual --minimal` is the working init. `swarm init`, `doctor`,
  and the MCP server are unaffected. On a normal dev machine, `--full` and `hybrid` are fine.
- **No Chromium, no Docker.** gstack was installed with `GSTACK_SKIP_PLAYWRIGHT=1` and
  `GSTACK_SKIP_CSO_BUILD=1`: `/browse`, `/scrape`, `/qa`, `/pair-agent` and the CSO container preload
  are unavailable until a browser/Docker exists. Everything else works.
- **21st.dev is not logged in.** `search` / `generate` / `add` need `npx @21st-dev/cli@latest login`
  (or `API_KEY_21ST`). The design context works offline.
- Dev server must bind `0.0.0.0` with `allowedHosts: true` (already set in `vite.config.ts`) so the
  sandbox preview proxy can reach it.

---

## 8. Anti-patterns (reject on sight)

- Writing code before brainstorming/planning on a non-trivial request.
- Inventing a button, table, modal, or chart that the 21st registry already has.
- Shipping a static UI with no motion, or motion with linear easing and 1s+ durations.
- Symptom patches instead of root-cause fixes; tests written after the fact to match behaviour.
- Silent scope cuts, unverified "done" claims, or auto-commit/push without authorization.
- Adding a new dependency for what the reuse ladder already covers.
