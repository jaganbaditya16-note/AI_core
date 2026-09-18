"""Alembic environment.

The migration environment is deliberately thin: it does not decide anything about
the schema, it only supplies a connection and the metadata to compare against.

Two properties are worth stating explicitly, because migrations run against
production databases:

- **Credentials come from the environment.** ``AICORE_DATABASE_URL`` (or the
  repository ``.env``) is read through the application's own settings object, so
  there is exactly one place where the database URL is defined and no secret is
  ever written into ``alembic.ini`` or into a revision file.
- **Only the AICore schema is compared.** Autogenerate never proposes dropping
  objects that belong to somebody else (see ``_include_name``).
"""

from __future__ import annotations

import logging
from logging.config import fileConfig

from alembic import context
from pydantic import ValidationError
from sqlalchemy import create_engine, pool, text
from sqlalchemy.engine import Connection

# Importing the models package registers every table on Base.metadata; importing
# only Base would make autogenerate propose dropping tables it cannot see.
from aicore_api.config import get_settings
from aicore_api.db.base import APP_SCHEMA, Base
import aicore_api.db.models  # noqa: F401  (imported for its registration side effect)

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name, disable_existing_loggers=False)

logger = logging.getLogger("alembic.env")

#: What autogenerate compares the migration history against.
target_metadata = Base.metadata


def _database_url() -> str:
    """Return the configured PostgreSQL URL, or explain precisely what is missing."""
    try:
        settings = get_settings()
    except ValidationError as exc:  # pragma: no cover - operator error path
        raise SystemExit(
            "AICORE_DATABASE_URL is not set. Export it (or copy .env.example to .env) "
            "before running migrations."
        ) from exc
    return settings.database_url.get_secret_value()


def _include_name(name: str | None, type_: str, parent_names: dict[str, str | None]) -> bool:
    """Restrict reflection to the AICore schema.

    Without this, ``include_schemas=True`` would make autogenerate compare every
    schema in the database — and propose dropping anything it does not own.
    """
    if type_ == "schema":
        return name in (APP_SCHEMA, None)
    return True


def _include_object(
    obj: object, name: str | None, type_: str, reflected: bool, compare_to: object
) -> bool:
    """Keep Alembic's own bookkeeping out of the comparison.

    Without this, ``alembic check`` and autogenerate propose dropping
    ``aicore.alembic_version`` on every run.
    """
    return not (type_ == "table" and name == "alembic_version")


def _configure(connection: Connection | None, url: str, *, offline: bool) -> None:
    context.configure(
        connection=connection,
        url=url,
        target_metadata=target_metadata,
        include_schemas=True,
        include_name=_include_name,
        include_object=_include_object,
        compare_type=True,
        compare_server_default=True,
        # The version table lives beside the application tables, so "is this
        # database migrated?" is answerable from one schema.
        version_table_schema=APP_SCHEMA,
        literal_binds=offline,
        dialect_opts={"paramstyle": "named"} if offline else {},
    )


def run_migrations_offline() -> None:
    """Emit SQL to stdout instead of executing it (``alembic upgrade head --sql``)."""
    url = _database_url()
    _configure(None, url, offline=True)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Apply migrations to the configured database."""
    url = _database_url()
    connectable = create_engine(url, poolclass=pool.NullPool)

    # The version table lives in the AICore schema, so the namespace must exist
    # before Alembic boots. It is created in its own committed transaction on
    # purpose: issuing this statement on the migration connection would open an
    # implicit transaction, and Alembic treats an existing transaction as
    # externally managed — it would then never commit, and the migration would
    # silently do nothing. `engine.begin()` commits. Idempotent, so it is safe on
    # every run and matches database/init/01-init.sql.
    with connectable.begin() as bootstrap:
        bootstrap.execute(text(f'CREATE SCHEMA IF NOT EXISTS "{APP_SCHEMA}"'))

    with connectable.connect() as connection:
        _configure(connection, url, offline=False)
        with context.begin_transaction():
            context.run_migrations()

    connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
