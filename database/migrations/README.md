# Migrations

Reserved for Alembic revisions.

Phase 0 ships **no migrations** because it ships no domain tables. The first
migration will be added in the phase that introduces the first domain model, and
it must be reviewable: one concern per revision, with an explicit downgrade.

Planned layout (not yet active):

```
alembic.ini                  # repository root, points at database/migrations
database/migrations/
  env.py
  script.py.mako
  versions/
    0001_<first_domain_change>.py
```

Rules for that work:

- Migrations are reviewed like code; no `--autogenerate` output committed unreviewed.
- Every migration states its downgrade path, or documents why it is irreversible.
- Schema changes and model changes land in the same pull request.
- Credentials come from `AICORE_DATABASE_URL`; they are never written into
  `alembic.ini` or into a revision file.
