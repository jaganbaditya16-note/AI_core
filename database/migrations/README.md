# Migrations

Alembic revisions for the AICore schema.

Layout:

```
alembic.ini                  # repository root, no database URL in it
database/migrations/
  env.py                     # reads AICORE_DATABASE_URL via the app's settings
  script.py.mako
  versions/
    0001_organizations.py    # Phase 1: aicore schema + tenant root
```

Rules for that work:

- Migrations are reviewed like code; no `--autogenerate` output committed unreviewed.
- Run `bash scripts/migrate.sh check` after editing a model: it fails when the
  models and the migrated schema disagree (including constraint *names*).
- Every migration states its downgrade path, or documents why it is irreversible.
- Schema changes and model changes land in the same pull request.
- Credentials come from `AICORE_DATABASE_URL`; they are never written into
  `alembic.ini` or into a revision file.
