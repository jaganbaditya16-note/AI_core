# ADR 0001 — Phase 0 foundation decisions

Status: accepted · Date: 2026-09-17 · Scope: Phase 0

## Context

AICore is an enterprise AI control plane. Phase 0 must establish a foundation
that later phases (identity, inventory, policy, firewall, audit, intelligence)
can build on without rework, while making no security claims it cannot support.
The locked stack is Next.js + TypeScript (App Router), FastAPI + Pydantic,
PostgreSQL, Docker/Compose, Pytest + Playwright, REST/OpenAPI, npm.

## Decisions

### 1. The browser never talks to the API host directly

The frontend calls a same-origin route handler (`/api/health`), which calls the
API server-side.

*Why:* the API location and any future credentials stay out of the browser
bundle; CORS is unnecessary in the default architecture; one deployment works
for local, Compose, and hosted environments.

*Consequences:* one extra hop, and server configuration must be available per
request (`export const dynamic = "force-dynamic"`). A `server-only` import
enforces the boundary at build time.

### 2. Split liveness and readiness

`/health` never touches a dependency; `/health/ready` probes PostgreSQL and
returns 503 when it fails.

*Why:* a slow database must not get the API container killed, but must stop it
receiving traffic. It also gives the frontend a meaningful degraded state to
render.

### 3. Configuration fails fast and never defaults a secret

`AICORE_DATABASE_URL` is required, typed `SecretStr`, PostgreSQL-only, with no
default. Production additionally rejects `debug` and wildcard CORS.

*Why:* a missing credential should stop a deployment at startup, not at the
first request against the wrong database. `SecretStr` keeps credentials out of
logs and tracebacks.

### 4. One error envelope, one correlation id

Every non-2xx response is `{"error": {code, message, details, request_id}}`;
every response carries `X-Request-ID` (validated against an allow-list).
Unexpected exceptions are logged with the id and returned as a generic 500.

*Why:* clients get a single shape to handle; operators can map a report to a log
line; internal details never leak.

### 5. Shared types are hand-mirrored, with a drift test

`packages/types` mirrors the Phase 0 Pydantic schemas in TypeScript; a backend
test fails if the schema and the mirror diverge.

*Why:* no codegen pipeline in Phase 0, but no silent drift either. When the
domain contract grows, this is the natural place to introduce generation.

### 6. Compose keeps credentials out of the web tier

The web service receives only `API_INTERNAL_URL` and timeouts — no `env_file`.
The API receives the database URL assembled from `POSTGRES_*`.

*Why:* a frontend container has no reason to hold database credentials. This is
a structural guarantee, not a convention.

### 7. No Redis, no SQLite fallback, no domain tables

*Why:* Redis is not needed for a health endpoint. A SQLite fallback would create
behaviour drift from the target database. Domain tables belong to the phases that
define their invariants, and each of those brings its own reviewed migration.

### 8. Intelligence is advisory by construction

No model provider is integrated in Phase 0, and the architecture states the
invariant explicitly: deterministic services authorize and enforce; the model
reasons and recommends.

*Why:* the moment an LLM can authorize an action, the control plane's security
model becomes probabilistic. Keeping the boundary structural now avoids having
to unwind it later.

## Alternatives considered

| Alternative | Rejected because |
|---|---|
| Browser calls the API directly with CORS | exposes the API surface and any future credentials to the browser; CORS config becomes a security-critical knob |
| Single `/health` that always checks the database | conflates liveness and readiness; causes restart loops during database outages |
| Code generation (OpenAPI → TypeScript) | premature build machinery for two endpoints; revisit when the contract grows |
| Shared `.env` for all services | hands database credentials to the web tier |
| SQLite for local development | different semantics from PostgreSQL; readiness would not be representative |

## Follow-ups (later phases)

- First domain model + Alembic migration (identity phase).
- AuthN/AuthZ design and threat model before any protected route exists.
- Replace the hand-mirrored types with generation once the contract grows.
- Structured (JSON) logging with the request id as a first-class field.
