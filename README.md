# AICore

**Enterprise AI Control Plane** — currently in **Phase 0: foundation only**.

AICore is intended to let an organization discover the AI running in its
environment, control what that AI is allowed to do, and monitor what it did, with
an intelligence layer (NVIDIA Nemotron via Nebius Token Factory) providing
reasoning and recommendations.

**This repository does not implement any of that yet.** It contains the
foundation those phases will be built on: an application skeleton, a versioned
API contract, a PostgreSQL connection, container infrastructure, and tests. The
overview page in the app says the same thing, and
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
is never the final security authority — which is why Phase 0 couples nothing to
a model provider.

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
    src/aicore_api/     main · config · api · core · db · schemas
    tests/              Pytest suite (25 tests)
packages/
  types/                shared API contract types (health, errors)
database/
  init/                 one-time bootstrap SQL (schema namespace only)
  migrations/           reserved for Alembic (no migrations yet)
tests/e2e/              Playwright smoke tests
docs/                   architecture, scope, development guide, ADRs
infrastructure/         docker-compose.yml
scripts/                dev-db, dev-api, py, test-db, verify, check-secrets
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
database, and asserts `GET /health/ready` returns 200.

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

- **No authentication or authorization** — by design; there are no protected
  routes to protect. Nothing is faked either.
- **No domain tables and no migrations.** The database contains a schema
  namespace and nothing else.
- **No AI features.** No model provider is integrated; no agent/model/tool
  inventory, policy engine, firewall, audit, monitoring or incidents.
- **Local verification caveats:** this sandbox has no Docker and blocks
  Playwright's browser CDN, so Compose is validated as configuration (and in CI)
  and E2E runs in CI or on a developer machine with browser access. Both are
  reported honestly by `scripts/verify.sh` rather than skipped silently.

## Future phases (high level)

1. Identity, tenants, RBAC — first domain tables and migrations.
2. Discovery and inventory: agents, models, tools, dependencies, shadow AI.
3. Control: permissions, policy engine, action firewall, approvals, kill switch.
4. Monitoring: behaviour, anomalies, cost, audit, incidents.
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
