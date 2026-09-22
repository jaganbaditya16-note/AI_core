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

## What Phase 3 adds

The inventory: one table for every AI asset the organization knows about, and the
API that manages it.

```
POST /organizations/{id}/assets ─► AssetCreate ─► owner resolution ─► AssetRepository
                                        │                                   │
                                        └─ metadata validated per type       └─ tenant-filtered statement
                                                                                (guard refuses anything else)

discovery integration ─► DiscoveredAsset ─► validate ─► active membership ─► ON CONFLICT (org, type, external id)
```

Three decisions shape it, and all three are about not repeating a mistake later:

**One table, not seven.** `agent`, `application`, `model`, `tool`, `mcp_server`,
`api` and `data_source` differ in what is interesting about them, not in how they
are stored, listed, filtered, owned or isolated. The type is a column and the
type-specific detail is validated JSONB, so the seven-way split never has to be
undone. The cost is explicit: metadata cannot be joined or indexed per type, which
is the right trade for a phase whose queries are "what do we have".

**Tenant isolation is a database property first.** `assets` inherits the
tenant-owned conventions (non-null `organization_id`, `ON DELETE RESTRICT`), and
the owner is a *composite* foreign key to a membership in the same organization —
so "an asset in A owned by a user in B" is a row PostgreSQL will not accept. The
repository cannot be constructed without an organization, and the tenancy guard
refuses any statement that does not filter on `organization_id`: a forgotten
`WHERE` is an exception, not a wider query.

**Discovery is a boundary, not a feature.** `aicore_api.discovery` is the internal
service a future integration calls: it normalizes the report, validates metadata
against the asset type, resolves an owner to an active membership, and writes
idempotently on `(organization_id, asset_type, external_identifier)`. No cloud or
network integration exists, and the API says so.

Inventory changes emit domain events (`aicore_api/core/events.py`) at the four
points worth auditing later. That is a seam for Phase 8, not an audit system, and
it is the reason the later phase has one boundary to attach to.

Design, API usage and current limitations: [inventory.md](inventory.md).

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
  core/           cross-cutting: logging, error envelope, request id, middleware,
                  the permission catalog, asset vocabularies, domain events
  db/             engine/session factory, connectivity probe, models, repositories
  discovery/      the ingestion boundary a future integration calls (no integration)
  auth/           credentials → principal → organization context → permission check
  schemas/        Pydantic models = the published contract
```

`api/` contains no business logic, `db/` contains no HTTP concerns, and
`schemas/` publishes the contract without implementing it. New features add
modules; they do not reshape these boundaries.

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
2. ~~Inventory~~ — **Phase 3**. Automatic discovery (cloud, network, endpoint
   integrations), agent identity, agent execution and the dependency graph remain.
3. Policy engine and action firewall (deterministic decisions).
4. Audit, monitoring, anomalies, incidents.
5. Intelligence layer (Nemotron / Nebius) as an *advisor* that proposes; the
   deterministic services continue to decide.
