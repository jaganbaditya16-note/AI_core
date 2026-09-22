# AICore

**Enterprise AI Control Plane** — currently at **Phase 3: AI asset discovery and
inventory**. Phase 0 delivered the skeleton, Phase 1 the PostgreSQL schema and
tenant boundary, Phase 2 the identity layer on top of it (bearer tokens identify a
user, memberships bind them to an organization with a role, protected routes
authorize against explicit permissions), and Phase 3 the inventory: one record per
AI asset an organization knows about, with ownership, lifecycle, environment,
discovery state and validated metadata.

AICore is intended to let an organization discover the AI running in its
environment, control what that AI is allowed to do, and monitor what it did, with
an intelligence layer (NVIDIA Nemotron via Nebius Token Factory) providing
reasoning and recommendations.

**Discovery is not automatic and control is not implemented.** Nothing in this
repository scans a network or a cloud account: assets are recorded by a person
through the API, or by a future integration through the internal service boundary
described in [`docs/inventory.md`](docs/inventory.md). There is no policy engine,
firewall, containment or monitoring, and
[`docs/phase-0-scope.md`](docs/phase-0-scope.md) lists exactly what is absent.

## Architecture direction

```
DISCOVER              CONTROL                  MONITOR
AI inventory          Identity · Permissions   Behaviour · Anomalies
Agent registry        Policy · Action firewall Security · Cost
Model/Tool inventory  Approval · Kill switch   Audit · Incidents
        └──────────────────────┬──────────────────────┘
                               ▼
                          INTELLIGENCE
                    Nemotron · Nebius Token Factory
```

**Core principle:** the model reasons, explains and recommends. **Deterministic
AICore services make the authorization, policy and security decisions.** The LLM
is never the final security authority — which is why the foundation couples
nothing to a model provider.

## Technology stack (locked)

| Layer | Choice |
|---|---|
| Frontend | Next.js 16 (App Router), TypeScript, Tailwind CSS v4, npm |
| Backend | Python 3.11+, FastAPI, Pydantic v2 |
| Database | PostgreSQL 16 (SQLAlchemy 2 + psycopg 3) |
| Infrastructure | Docker, Docker Compose |
| Testing | Pytest, Playwright |
| API | REST + OpenAPI |
| Motion | framer-motion (used minimally — one entrance transition, reduced-motion aware) |

Redis and Supabase are deliberately **not** part of this architecture.

## Repository structure

```
apps/
  web/                  Next.js frontend
    src/app/            overview, /health, /api/health proxy, error/loading/not-found
    src/lib/            server-only config + health client
    src/components/     health panel, motion wrapper
  api/                  FastAPI backend
    src/aicore_api/     main · config · cli · api · auth · core · db · discovery · schemas
    tests/              Pytest suite (unit + PostgreSQL integration)
packages/
  types/                shared API contract types (health, errors, organizations, identity, assets)
database/
  init/                 one-time bootstrap SQL (schema namespace only)
  migrations/           Alembic environment and revisions
    versions/0001_organizations.py
    versions/0002_identity_and_rbac.py
    versions/0003_assets.py
tests/e2e/              Playwright smoke tests
docs/                   architecture, scope, development guide, ADRs
infrastructure/         docker-compose.yml
scripts/                dev-db, dev-api, py, migrate, test-db, verify, check-secrets
```

## Local setup

```bash
cp .env.example .env          # then set POSTGRES_PASSWORD
npm install
bash scripts/py.sh -c pass    # creates apps/api/.venv, installs API deps
```

## Start the stack

**1 — PostgreSQL** (no Docker needed):

```bash
bash scripts/dev-db.sh        # prints the AICORE_DATABASE_URL to export
```

or with Docker:

```bash
docker compose --env-file .env -f infrastructure/docker-compose.yml up -d db
```

**2 — Backend:**

```bash
npm run dev:api               # http://127.0.0.1:8000 · docs at /docs
curl http://127.0.0.1:8000/health
# {"status":"ok","service":"aicore-api","version":"0.1.0","environment":"development"}
```

**3 — Frontend:**

```bash
npm run dev                   # http://127.0.0.1:3000
```

Whole stack in containers:

```bash
docker compose --env-file .env -f infrastructure/docker-compose.yml up --build
# web → http://localhost:3000 · api → http://localhost:8000 · db → localhost:5432
```

## Environment variables

All variables are documented in [`.env.example`](.env.example). Nothing is
hardcoded, `.env` is gitignored, and the web container never receives database
credentials.

| Variable | Purpose |
|---|---|
| `POSTGRES_USER` / `POSTGRES_PASSWORD` / `POSTGRES_DB` / `POSTGRES_PORT` | database provisioning (Compose) |
| `AICORE_DATABASE_URL` | API → PostgreSQL (**required**, PostgreSQL-only, never logged) |
| `AICORE_ENVIRONMENT` / `AICORE_DEBUG` / `AICORE_LOG_LEVEL` | runtime mode; `production` rejects debug and wildcard CORS |
| `AICORE_CORS_ALLOW_ORIGINS` | empty by default (same-origin proxy) |
| `AICORE_AUTH_PROVIDER` | credential provider; `api_token` today, external identity providers later |
| `API_INTERNAL_URL` | server-side address the web tier uses to reach the API |
| `API_REQUEST_TIMEOUT_MS` | backend request timeout (250–30000 ms) |
| `NEXT_PUBLIC_API_URL` | optional fallback; anything `NEXT_PUBLIC_*` is public |

## Tests and checks

```bash
npm run lint          npm run typecheck      npm run build
npm run test:api      npm run test:e2e       npm run verify:motion
npm run check:secrets
npm run verify                # lint, types, tests, build, secret scan, LICENSE
bash scripts/verify.sh --full # + live PostgreSQL + E2E where available
```

`bash scripts/test-db.sh` starts a real PostgreSQL, provisions the role and
database, migrates it from empty, checks the schema against the models
(`alembic check`), proves the migration reverses, and runs the whole suite against
it — readiness included.

## Health contract

| Endpoint | Meaning | Failure mode |
|---|---|---|
| `GET /health` | liveness — process is serving; no dependencies touched | never fails while running |
| `GET /health/ready` | readiness — PostgreSQL reachable (`SELECT 1`) | `503` with the failing check named |
| `GET /api/health` (web) | same-origin proxy report for the browser | `503`, structured `errors[]` |

Every non-2xx API response uses one envelope:
`{"error": {"code", "message", "details", "request_id"}}`, and every response
carries `X-Request-ID`.

## Current limitations

- **No sign-up, login or session management.** Credentials are provisioned out of
  band with the CLI (see below); there is no password anywhere in AICore, and the
  frontend is never a security boundary.
- **No user-management API.** Adding members and issuing tokens is an operator
  action. `POST /organizations` remains a development/test provisioning route
  (404 everywhere else), because this phase has no platform-administrator concept
  that could authorize tenant creation.
- **No permissions for resources that do not exist.** `audit.read` and
  `security.read` are part of the catalog and appear on `GET /me`, but there is no
  audit trail or security finding to read yet — no route pretends otherwise.
- **No domain tables beyond the tenant root, the identity tables and the asset
  inventory.** The policy, event and incident tables arrive in later phases,
  through migrations.
- **No automatic discovery.** Nothing scans a network or a cloud account, and no
  provider is integrated. Assets are registered by a person or by a future
  integration through an internal service boundary — see
  [docs/inventory.md](docs/inventory.md).
- **No AI features.** No model provider is integrated; no policy engine, action
  firewall, runtime containment, behaviour monitoring or incident handling.
- **Local verification caveats:** this sandbox has no Docker and blocks
  Playwright's browser CDN, so Compose is validated as configuration (and in CI)
  and E2E runs in CI or on a developer machine with browser access. Both are
  reported honestly by `scripts/verify.sh` rather than skipped silently.

## What Phase 3 adds

The AI **inventory**: what an organization knows it has, and what it knows about
each thing.

- **One inventory table, seven asset types** — `agent`, `application`, `model`,
  `tool`, `mcp_server`, `api`, `data_source`, all in `aicore.assets`. The type is a
  column and the type-specific detail lives in validated `metadata`, so list,
  filter, paginate, own, classify and isolate work identically for every type
  instead of being written seven times.
- **Recorded state, not runtime state** — lifecycle (`draft`, `active`,
  `suspended`, `retired`), discovery state (`managed`, `unknown`, `shadow`),
  environment (`development`, `staging`, `production`, `unknown`) and a risk
  classification (`low` … `critical`, `unassessed`) that is **stored only**: no
  scoring, no enforcement, no kill switch.
- **Real ownership** — the owner is a membership in the same organization,
  enforced by a composite foreign key, so a cross-tenant owner is unrepresentable
  in the database rather than rejected by a handler. Application code never
  invents a user.
- **Deterministic deduplication** — `(organization_id, asset_type,
  external_identifier)` is unique when the identifier is present, so re-reporting
  an asset converges on one record. Names are never identifiers.
- **Asset API** — `GET|POST /organizations/{id}/assets`,
  `GET|PATCH|DELETE /organizations/{id}/assets/{asset_id}` and
  `GET /organizations/{id}/assets/owners`: repeatable filters, bounded pagination
  (`limit` ≤ 200, opt-in `total`), and four permissions (`asset.read`,
  `asset.create`, `asset.update`, `asset.delete`) checked by the backend.
- **A discovery seam, not a discovery feature** — `aicore_api.discovery` defines
  the normalise → validate → ownership → record path a future integration calls.
  No cloud or network integration ships, and nothing claims otherwise.
- **Audit readiness** — inventory changes emit domain events
  (`asset.created`, `asset.updated`, `asset.deleted`, `asset.discovered`) through
  one boundary. No audit system is implemented; the events are hooks, not records.

Design, API usage and current limitations: [docs/inventory.md](docs/inventory.md).

## What Phase 2 adds

Identity and access control, enforced by the server:

- **Authentication** — bearer API tokens, stored only as SHA-256 hashes, read from
  the `Authorization` header only, revocable and expirable. Credentials are issued
  by `python -m aicore_api.cli`, never over HTTP, and there is no
  development-only authentication path.
- **Roles and permissions** — six roles (`owner`, `admin`, `security_admin`,
  `ai_admin`, `analyst`, `viewer`) built from explicit permissions (eight here;
  twelve after Phase 3 added the four `asset.*` permissions). Code asks for a
  permission, never for a role name, so privilege changes happen in one catalog
  rather than in route handlers.
- **Authorization** — every tenant-scoped route resolves the caller's membership
  in the organization named in the path and checks one required permission before
  the handler runs: `authenticate → identify → resolve organization → verify
  membership → resolve role → resolve permissions → authorize`.
- **Tenant isolation under authentication** — a member of one organization gets
  the same `404` for another organization as for one that does not exist, so
  access refusals leak neither data nor existence.
- **API** — `GET /me` (who am I, which organizations, which roles, which
  permissions) and the authorized organization reads (`GET /organizations/{id}`,
  `/members`, `/roles`, `/permissions`). No more than the phase needs.

Design and rationale: [docs/authentication.md](docs/authentication.md).

## What Phase 1 adds

One table and the boundary every later table inherits:

- **`aicore.organizations`** — the tenant root: UUID key, unique slug, lifecycle
  status, timestamps, all enforced by database constraints.
- **Tenant-owned conventions** — future tables inherit a UUID key, timestamps and
  a non-null `organization_id` foreign key (`ON DELETE RESTRICT`), so a table
  cannot be added without a tenant boundary.
- **An isolation guard** — every statement touching a tenant-owned table is
  refused unless a tenant is bound *and* the statement filters on
  `organization_id`. Tenant context is explicit and request-scoped; there is no
  default tenant to fall back on.
- **Alembic migrations** — a dev dependency, with `bash scripts/migrate.sh`,
  a drift check (`alembic check`) and a proven downgrade path.

Two deliberately narrow exceptions exist so the foundation can be verified: a
minimal `POST /organizations` + `GET /organizations/{id}` persistence path that
answers only in `development` and `test` (it returns 404 elsewhere, and there is
no organization-management API), and a test-only tenant-owned table.

Design and rationale: [docs/database.md](docs/database.md).

## Future phases (high level)

1. ~~Tenants~~ — **Phase 1**. ~~Users, roles, permissions, membership
   enforcement~~ — **Phase 2**.
2. ~~Discovery and inventory~~ — **Phase 3** records it. Automatic discovery
   (cloud, network, endpoint integrations), agent identity, agent execution and
   the dependency graph are later work; nothing in this build observes anything.
3. Control: policy engine, action firewall, approvals, kill switch.
4. Monitoring: behaviour, anomalies, cost, audit, incidents (making `audit.read`
   and `security.read` mean something).
5. Intelligence: Nemotron / Nebius as an advisory layer over deterministic
   decisions.

Details and rationale: [`docs/architecture.md`](docs/architecture.md) ·
[`docs/decisions/0001-phase-0-foundation.md`](docs/decisions/0001-phase-0-foundation.md).

## Development tooling

Agent tooling used while building this repository (gstack, Superpowers, ruflo,
21st.dev) is documented in [`TOOLKIT.md`](TOOLKIT.md) and is **not** part of the
AICore runtime: it is excluded from Docker images via `.dockerignore` and is not
a dependency of either application.

## License

See [`LICENSE`](LICENSE).
