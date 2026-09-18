# Phase 0 scope

> **Status:** this document is the contract Phase 0 was built against and is kept
> as the record of that phase. Phase 1 has since added what it reserved: the
> tenant root, the multi-tenancy conventions and the Alembic migrations. See
> [database.md](database.md) for the current state; authentication, RBAC and the
> remaining domain tables are still not implemented.

Phase 0 builds the **foundation** of AICore. This document is the contract for
what is and is not in the repository at this point.

## In scope — implemented and verified

| Area | What exists |
|---|---|
| Frontend | Next.js 16 App Router + TypeScript (strict), Tailwind v4 tokens, overview page, system-health page, route-level `loading.tsx` / `error.tsx` / `not-found.tsx`, security headers |
| Backend | FastAPI application factory, Pydantic settings with validation, uniform error envelope, request-id middleware, `/health` (liveness), `/health/ready` (readiness), OpenAPI document |
| Integration | Same-origin health proxy (`/api/health`) with server-only configuration; loading, ok, degraded, unreachable and misconfiguration states handled |
| Database | PostgreSQL via SQLAlchemy 2 + psycopg 3, connection pool, `SELECT 1` readiness probe, `aicore` schema namespace — **no domain tables** |
| Infrastructure | Dockerfiles for web and api (multi-stage, non-root, health checks), Docker Compose with PostgreSQL, health-gated startup |
| Tests | 25 Pytest tests (health, readiness, errors, configuration, OpenAPI contract), Playwright E2E configuration + smoke tests |
| Quality | ESLint, TypeScript strict, Ruff (incl. bandit security rules), Mypy strict, Prettier |
| CI | GitHub Actions: web (install/lint/typecheck/build), api (lint/format/types/tests/live-PostgreSQL), E2E, secret scan, Compose validation, LICENSE integrity |
| Docs | README, architecture, this scope document, development guide, decision record |

## Explicitly out of scope — not implemented

Nothing below exists in this repository, not even as a stub. Anything that
looked like a fake version of these would be worse than nothing, because it
would misrepresent the security posture of the system.

**Identity & access:** authentication, login, sessions, RBAC, organizations,
tenants, users, API keys.

**Inventory & discovery:** agent registry, model registry, tool registry, AI
inventory, dependency graph, shadow-AI detection, agent identity, AI
supply-chain security.

**Control:** permissions, policy engine, policy-as-code, action firewall,
approval workflows, kill switch, MCP firewall, model routing.

**Monitoring & response:** monitoring, audit system, anomaly detection, risk
engine, incident management, cost engine, metric dashboards.

**Intelligence:** NVIDIA Nemotron integration, Nebius Token Factory
integration, AI assistant, natural-language security queries.

**Data:** all domain tables and all migrations. Phase 0 ships a schema namespace
and a connection, nothing more.

**Demo artifacts:** no fake dashboards, no seeded agents, no sample incidents,
no placeholder metrics. The overview page states plainly what is not built.

## Boundary rules for the next phase

1. Phase 0 files are the skeleton. New features add modules; they do not reshape
   the settings, error envelope, health contract or module boundaries.
2. The first domain change brings the first migration (see `database/migrations/README.md`).
3. Authentication does not arrive as part of a feature PR — it is its own phase
   with its own review.
4. The intelligence layer never gains the ability to authorize or enforce.
   Deterministic services decide; the model advises. This is a product
   invariant, not an implementation detail.
