-- AICore — database bootstrap (runs once, on an empty Docker volume).
--
-- This script creates the schema namespace only. Tables are created by Alembic
-- migrations (see ../migrations/versions/), which run afterwards and are the
-- single source of schema truth: Phase 1 adds aicore.organizations, and the
-- agent, model, tool, policy, identity, audit and incident tables arrive in
-- later phases the same way.
--
-- The database itself, its owner and its password are created by the postgres
-- image from POSTGRES_USER / POSTGRES_PASSWORD / POSTGRES_DB. No credential is
-- hardcoded here.

CREATE SCHEMA IF NOT EXISTS aicore;

COMMENT ON SCHEMA aicore IS
  'AICore application namespace. Tables are managed by Alembic migrations.';
