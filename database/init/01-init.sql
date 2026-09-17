-- AICore — database bootstrap (runs once, on an empty Docker volume).
--
-- Phase 0 creates the schema namespace only. No domain tables: the agent,
-- model, tool, policy, identity, audit and incident tables arrive in later
-- phases through reviewed migrations (see ../migrations/README.md).
--
-- The database itself, its owner and its password are created by the postgres
-- image from POSTGRES_USER / POSTGRES_PASSWORD / POSTGRES_DB. No credential is
-- hardcoded here.

CREATE SCHEMA IF NOT EXISTS aicore;

COMMENT ON SCHEMA aicore IS
  'AICore application namespace. Phase 0: empty by design.';
