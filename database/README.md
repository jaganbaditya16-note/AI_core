# Database

PostgreSQL foundation for AICore.

## Scope

This directory holds the database's schema history and bootstrap. Phase 1 adds the
tenant root and the multi-tenancy conventions; it deliberately contains **no
domain schema**: there are no `agents`, `models`, `tools`, `permissions`,
`policies`, `events`, `incidents` or `users` tables yet. Those arrive in later
phases through reviewed migrations, not by hand.

What exists today:

| Path | Purpose |
|---|---|
| `init/01-init.sql` | Runs once on a fresh Docker volume: creates the `aicore` schema namespace. |
| `migrations/` | Alembic environment and revisions (see its README). |
| `migrations/versions/0001_organizations.py` | Phase 1: the `aicore` schema and `aicore.organizations`. |

Design, tenant model, isolation strategy and the RLS decision are documented in
[`../docs/database.md`](../docs/database.md).

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

## Migrations

Alembic is a **dev dependency** of the API (`apps/api/pyproject.toml`); the
runtime image installs only runtime dependencies, because schema changes are
applied from the repository rather than baked into the application container.

```bash
bash scripts/migrate.sh upgrade head    # apply migrations
bash scripts/migrate.sh check           # fail if the models and schema disagree
bash scripts/migrate.sh downgrade -1    # reverse one revision
```

Credentials come from `AICORE_DATABASE_URL` (or `.env`); they are never written
into `alembic.ini` or a revision file.
