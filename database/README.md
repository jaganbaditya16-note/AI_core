# Database

PostgreSQL foundation for AICore.

## Phase 0 scope

This directory establishes the database only. It deliberately contains **no domain
schema**: there are no `agents`, `models`, `tools`, `permissions`, `policies`,
`events`, `incidents` or `users` tables. Those belong to later phases and will be
added through reviewed migrations, not by hand.

What exists today:

| Path | Purpose |
|---|---|
| `init/01-init.sql` | Runs once on a fresh Docker volume: creates the `aicore` schema namespace. |
| `migrations/` | Reserved for Alembic migrations (see its README). |

## Connection

The API reads `AICORE_DATABASE_URL` (a `SecretStr`, never logged, never returned
to clients). Example for local development:

```
AICORE_DATABASE_URL=postgresql+psycopg://aicore:<POSTGRES_PASSWORD>@localhost:5432/aicore
```

Docker Compose builds this URL from `POSTGRES_USER`, `POSTGRES_PASSWORD` and
`POSTGRES_DB` — see `infrastructure/docker-compose.yml`.

## Starting PostgreSQL

Docker Compose (recommended):

```bash
docker compose --env-file .env -f infrastructure/docker-compose.yml up -d db
docker compose --env-file .env -f infrastructure/docker-compose.yml exec db \
  psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "SELECT version();"
```

Without Docker, any local PostgreSQL 14+ instance works; point
`AICORE_DATABASE_URL` at it.

## Health

`GET /health/ready` runs `SELECT 1` through the API's SQLAlchemy engine and
returns `503` when the database is unreachable. It is the only database
interaction in Phase 0.

## Migrations (later phases)

Alembic is **not** installed in Phase 0: there are no domain models, so there is
nothing to migrate and no configuration to get wrong. When the first domain
table arrives it will be added to `apps/api/pyproject.toml` as a dev dependency,
with `alembic.ini` at the repository root and revisions under
`database/migrations/`. The first revision must land together with that model —
until then, running a migration tool would be meaningless.
