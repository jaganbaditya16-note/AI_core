# Architecture (Phase 0)

## The product, in one paragraph

AICore is an **enterprise AI control plane**. The intended product shape is
DISCOVER (AI inventory, agent/model/tool registry, shadow AI) → CONTROL
(identity, permissions, policy, action firewall, approvals, kill switch) →
MONITOR (behaviour, anomalies, cost, audit, incidents), with an intelligence
layer (NVIDIA Nemotron via Nebius Token Factory) providing reasoning,
explanations and recommendations.

**Core principle, decided now and reflected in the architecture:** the model
provides analysis; **deterministic AICore services make the authorization,
policy and security decisions**. The LLM is never the final security authority.
That is why Phase 0 establishes a plain, testable service boundary rather than
coupling anything to a model provider — there is no model integration in this
phase at all.

## What Phase 1 adds

The multi-tenancy foundation: one table (`aicore.organizations`) and the
conventions every future table inherits, so the tenant boundary exists before
there is anything to leak. Design and rationale live in
[database.md](database.md); the short version:

```
organizations (the tenant root)
      ▲
      │ organization_id NOT NULL, ON DELETE RESTRICT
      │
  every tenant-owned table (agents, models, tools, policies, events, … in later phases)
```

Three rules make the boundary hard to bypass accidentally: ownership is declared
by inheritance rather than listed anywhere; an engine-level guard refuses any
statement that touches a tenant-owned table without a bound tenant *or* without
an `organization_id` filter; and the repository base class fails closed when no
tenant is resolved. Phase 1 deliberately does **not** enable Row Level Security —
it prepares for it (see the design note in `database.md`) rather than adding a
policy that is not yet enforceable.

## What Phase 0 actually is

A foundation: an application skeleton, a versioned API contract, a database
connection, container infrastructure, and tests. Every box in the product
diagram above is *not implemented*. See [phase-0-scope.md](phase-0-scope.md) for
the explicit list.

## Components

```
┌──────────────────────────────┐        ┌───────────────────────────────┐
│  apps/web — Next.js 16       │        │  apps/api — FastAPI           │
│  App Router, TypeScript      │        │  Python 3.11+, Pydantic v2    │
│                              │        │                               │
│  /            overview       │        │  GET /health        liveness  │
│  /health      system health  │        │  GET /health/ready  readiness │
│  /api/health  same-origin    │ ──────▶│  /docs              OpenAPI   │
│               proxy (server) │  HTTP  │                               │
└──────────────────────────────┘        └───────────────┬───────────────┘
             ▲                                          │ SQLAlchemy 2
             │ browser (never talks to the API host)    ▼
             │                                  ┌───────────────┐
        ┌────┴─────┐                            │  PostgreSQL   │
        │ Browser  │                            │  organizations│
        └──────────┘                            │  + tenant     │
                                                │  boundary     │
                                                └───────────────┘
```

### Why the browser never calls the API directly

The browser calls `/api/health` **on the web origin**. A Next.js route handler
then calls the API server-side using `API_INTERNAL_URL`. Consequences:

- The API's address and any future API credentials stay out of the browser
  bundle (enforced by the `server-only` import in `apps/web/src/lib/env.ts` —
  the build fails if that module reaches a Client Component).
- CORS stays empty by default: there is no cross-origin request to allow.
- The same deployment works whether the API is `127.0.0.1:8000` in development
  or `http://api:8000` inside Compose.

`NEXT_PUBLIC_API_URL` exists as a documented fallback for frontend-only work,
but nothing in the default architecture requires it.

### Why the health endpoints are split

`/health` (liveness) answers while the process serves, and touches nothing.
`/health/ready` (readiness) probes PostgreSQL and returns **503** when a
dependency is down. That is what an orchestrator needs: a slow database must not
cause the API container to be killed, but it must stop receiving traffic.

### API contract

One error envelope for every non-2xx response:

```json
{ "error": { "code": "not_found", "message": "…", "details": null, "request_id": "…" } }
```

Every response carries `X-Request-ID` (validated against a strict allow-list, or
generated), so a client report maps to a server log line. The OpenAPI document
is the source of truth; `packages/types` mirrors the Phase 0 shapes in
TypeScript and a backend test asserts they have not drifted.

### Module layout (API)

```
apps/api/src/aicore_api/
  main.py         application factory: settings, middleware, handlers, router
  config.py       Pydantic settings + validation (fail-fast, no defaults for secrets)
  api/            HTTP layer only: router aggregation + route modules
  core/           cross-cutting: logging, error envelope, request id, middleware
  db/             engine/session factory + connectivity probe (no models yet)
  schemas/        Pydantic models = the published contract
```

`api/` contains no business logic, `db/` contains no domain models, and
`schemas/` contains no Phase 1+ entities. New features add modules; they do not
reshape these boundaries.

## Decisions and trade-offs

| Decision | Why | Cost |
|---|---|---|
| Next.js route handler as same-origin proxy | keeps API host and future credentials server-side; removes CORS from the default path | one extra hop |
| `packages/types` mirrors Pydantic by hand (no codegen) | zero build pipeline in Phase 0 | a test must guard drift (it exists) |
| `AICORE_DATABASE_URL` required, `SecretStr`, no default | misconfiguration fails at startup; credentials cannot leak via logs | tests must set the variable (conftest does) |
| CORS empty by default; wildcard rejected in production | secure default; explicit opt-in | a future external client needs configuration |
| Docs (`/docs`) toggleable, disabled in production | reduce exposed surface in production | one extra env var |
| PostgreSQL only (no SQLite fallback) | matches the target system; avoids behaviour drift between dev and prod | local dev needs PostgreSQL (Docker or `scripts/dev-db.sh`) |
| Redis deliberately absent | not needed in Phase 0; adding it now would be speculative | readiness has one dependency instead of two |

## Security posture in Phase 0

- No authentication or authorization exists — and none is faked. There are no
  protected routes to protect: the surface is two health endpoints and a static
  page.
- No secrets in code or in git; `scripts/check-secrets.sh` enforces this in CI.
- Database credentials are never sent to the browser or into the web image.
- Error responses never include internal details; unexpected exceptions are
  logged with a correlation id and returned as a generic 500.
- Containers run as non-root (`aicore`, `nextjs`), with health checks and no
  build toolchain in the runtime stage.

## What later phases add here

1. Identity, tenants, RBAC — first domain tables, first migrations.
2. Inventory (agents, models, tools, dependencies) + discovery.
3. Policy engine and action firewall (deterministic decisions).
4. Audit, monitoring, anomalies, incidents.
5. Intelligence layer (Nemotron / Nebius) as an *advisor* that proposes; the
   deterministic services continue to decide.
