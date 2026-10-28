# Development guide

## Prerequisites

| Tool | Version | Notes |
|---|---|---|
| Node.js | ≥ 20.9 (22 recommended) | frontend, tooling |
| npm | 10+ | the only supported package manager here |
| Python | ≥ 3.11 | backend |
| PostgreSQL | 16 (or 14+) | via Docker Compose, an existing server, or `scripts/dev-db.sh` |
| Docker | optional | required only for the container path |

## First run

```bash
cp .env.example .env          # then set POSTGRES_PASSWORD
npm install                   # workspace dependencies (web + shared types)
bash scripts/py.sh -c pass    # creates apps/api/.venv and installs API deps
```

## Running the stack

**Terminal 1 — database.** Either a local server:

```bash
bash scripts/dev-db.sh        # prints the AICORE_DATABASE_URL to export
```

or Docker:

```bash
docker compose --env-file .env -f infrastructure/docker-compose.yml up -d db
```

**Terminal 2 — API** (reads the repository `.env`):

```bash
npm run dev:api               # http://127.0.0.1:8000  (docs at /docs)
```

**Terminal 3 — frontend:**

```bash
npm run dev                   # http://127.0.0.1:3000
```

Open <http://127.0.0.1:3000/health> — it should read **Operational**. Stop the
API and it becomes **Backend unreachable**; that is the error path working, not
a bug.

## Tests and checks

```bash
npm run lint                  # ESLint (web)
npm run typecheck             # TypeScript strict (web + shared types)
npm run build                 # production build
npm run verify:motion         # framer-motion runtime check (headless)
npm run lint:api              # Ruff
npm run typecheck:api         # Mypy (strict)
npm run test:api              # Pytest (unit; integration tests skip without a database)
npm run test:e2e              # Playwright (needs: npx playwright install chromium)
npm run check:secrets         # secret scan
npm run verify                # everything above that does not need Docker/browser
bash scripts/verify.sh --full # + live PostgreSQL + E2E where available
bash scripts/test-db.sh       # real PostgreSQL: migrate from scratch, drift check,
                              # readiness probe, full test suite

# Database migrations (Alembic)
bash scripts/migrate.sh upgrade head      # apply migrations
bash scripts/migrate.sh current           # applied revision
bash scripts/migrate.sh check             # fail if models and the schema disagree
bash scripts/migrate.sh downgrade -1      # reverse one revision
bash scripts/migrate.sh revision --autogenerate -m "add x"   # author one (review it)

# Provisioning identities (authentication, Phase 2)
#   There is no sign-up route and no user-management API: credentials are created
#   out of band, by an operator with database access, and printed exactly once.
bash scripts/py.sh -m aicore_api.cli bootstrap \
  --email owner@example.com --full-name "Ada Lovelace" \
  --organization-name "Acme Corporation" --organization-slug acme
bash scripts/py.sh -m aicore_api.cli create-api-token --email owner@example.com --name laptop
bash scripts/py.sh -m aicore_api.cli add-member --organization acme --email analyst@example.com --role analyst

curl -H "Authorization: Bearer <printed token>" http://127.0.0.1:8000/me
```

## Configuration

Every variable is documented in `.env.example`. The essentials:

| Variable | Used by | Notes |
|---|---|---|
| `POSTGRES_*` | Compose `db` | credentials have no defaults in Compose |
| `AICORE_DATABASE_URL` | API | required; PostgreSQL only; never logged or returned |
| `AICORE_ENVIRONMENT` | API | `production` tightens validation (no debug, no wildcard CORS) |
| `AICORE_AUTH_PROVIDER` | API | credential provider (`api_token` today); routes never name one |
| `API_INTERNAL_URL` | web (server-side) | where the web tier reaches the API |
| `API_REQUEST_TIMEOUT_MS` | web | 250–30000, default 4000 |
| `NEXT_PUBLIC_*` | web (browser) | anything here is public — never credentials |

`.env` is gitignored and the web container deliberately does **not** receive it;
`infrastructure/docker-compose.yml` passes the web tier only `API_INTERNAL_URL`
and timeouts, so database credentials cannot reach the frontend.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| API exits at startup with a validation error | `AICORE_DATABASE_URL` missing or not a PostgreSQL URL — the fail-fast is intentional |
| `/health/ready` returns 503 | PostgreSQL down or unreachable; the response names the failing check |
| Health page shows "Frontend misconfigured" | `API_INTERNAL_URL` / `NEXT_PUBLIC_API_URL` is not a valid http(s) URL |
| `next build` complains about `jsx` | Next 16 rewrites `tsconfig.json` (adds `jsx: react-jsx`) on first build; commit that change |
| Playwright cannot download browsers | `cdn.playwright.dev` blocked. Point Playwright at an existing Chrome: `PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH=/usr/bin/chromium npx playwright test`, or run E2E in CI / on a machine with egress |
| `psql: command not found` | expected on minimal images; use `docker compose … exec db psql` |
