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

## What Phase 2 adds

Identity and access control, on top of the tenant boundary: users, roles,
permissions, memberships and API tokens, plus the authorization flow that turns
"a request arrived" into "this person may do this here".

```
credential ─► identify user ─► resolve organization ─► verify membership
            ─► resolve role ─► resolve permissions ─► check required permission ─► handler
                                    ▲
                          the catalog (core/permissions.py, seeded by migration 0002)
```

Two structural decisions carry the security argument. First, a route states its
requirement in its signature (`Depends(require_permission(Permission.USER_READ))`)
rather than inside its body, so no handler can forget to authorize and the whole
surface is reviewable in one file. Second, the organization always comes from the
request path and the caller always from the credential — there is no
client-settable "current organization" to abuse, which is what makes a
cross-tenant request fail as a `404` indistinguishable from an unknown id.

Credentials are provisioned out of band (`python -m aicore_api.cli`), never over
HTTP: there is no sign-up route to attack, no password stored anywhere, and
nothing that behaves differently in development than in production. Design and
rationale: [authentication.md](authentication.md).

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

## Security posture

- **Authentication and authorization are server-side.** Bearer tokens (stored
  only as hashes) identify a user; memberships and explicit permissions authorize
  the request. The frontend is never the security boundary, and no check exists
  only in the UI.
- **No passwords exist to leak**, and no credential is issued over HTTP. The only
  path to a token is the operator CLI, and it is shown exactly once.
- **Refusals leak nothing**: an inaccessible tenant answers `404` — the same as a
  tenant that does not exist — and every authentication failure answers an
  identical `401`.
- No secrets in code or in git; `scripts/check-secrets.sh` enforces this in CI.
- Database credentials are never sent to the browser or into the web image.
- Error responses never include internal details; unexpected exceptions are
  logged with a correlation id and returned as a generic 500.
- Containers run as non-root (`aicore`, `nextjs`), with health checks and no
  build toolchain in the runtime stage.

## What later phases add here

1. ~~Identity, tenants, RBAC~~ — **tenants in Phase 1, identity and RBAC in
   Phase 2**.
2. Inventory (agents, models, tools, dependencies) + discovery — with the
   permissions that govern them, added to the same catalog.
3. Policy engine and action firewall (deterministic decisions).
4. Audit, monitoring, anomalies, incidents.
5. Intelligence layer (Nemotron / Nebius) as an *advisor* that proposes; the
   deterministic services continue to decide.
