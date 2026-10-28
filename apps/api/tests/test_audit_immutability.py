"""Phase 8's append-only claim, asserted against the database rather than promised.

A trail that can be edited is not evidence, so the phase states the property three
times — no route writes an event, no repository method mutates one, and the table
refuses ``UPDATE``, ``DELETE`` and ``TRUNCATE`` — and this file checks all three. The
database is the one that matters most: the code that exists today is the easy case, and
the interesting question is what a data fix, a migration or a future script can do.

The checks here are deliberately raw SQL. The application is designed never to attempt
any of them, so the only way to know PostgreSQL refuses them is to ask it directly, and
every statement is written the way an operator would have to write it: with the tenant
bound, because the isolation guard applies to raw statements too.

The one exception the build admits — the named override a test fixture uses to remove a
tenant's trail before removing the tenant — is exercised as well, including its shape:
``DELETE`` only, inside one transaction, with a stated reason, and nothing afterwards.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import Engine, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from aicore_api.db.models.audit_event import AuditEvent
from aicore_api.db.repositories.audit_events import (
    AuditEventRepository,
    audit_retention_override,
)
from aicore_api.db.tenancy import bind_tenant
from assets_fixture import assets_path
from audit_fixture import AuditScene

#: A row that is valid in every respect. Each refusal test overrides exactly one column,
#: so the difference between an accepted row and a refused one is the column under test.
_VALID: dict[str, Any] = {
    "event_type": "asset.created",
    "schema_version": 1,
    "actor_type": "system",
    "actor_id": None,
    "actor_membership_id": None,
    "resource_type": "asset",
    "resource_id": None,
    "action": "asset.create",
    "decision": None,
    "outcome": "success",
    "correlation_id": "corr-immutability",
    "request_id": None,
    "source": "ingestion",
    "metadata": "{}",
}

_INSERT = text(
    "INSERT INTO aicore.audit_events "
    "(organization_id, event_type, schema_version, actor_type, actor_id, "
    " actor_membership_id, resource_type, resource_id, action, decision, outcome, "
    " correlation_id, request_id, source, metadata) "
    "VALUES (:organization_id, :event_type, :schema_version, :actor_type, "
    " CAST(:actor_id AS uuid), CAST(:actor_membership_id AS uuid), :resource_type, "
    " CAST(:resource_id AS uuid), :action, :decision, :outcome, :correlation_id, "
    " :request_id, :source, CAST(:metadata AS jsonb)) "
    "RETURNING id"
)


@contextmanager
def _attempt(
    engine: Engine, organization_id: uuid.UUID, statement: str, parameters: Mapping[str, Any]
) -> Iterator[Any]:
    """Run one statement with the tenant bound, in its own transaction.

    Each statement gets its own connection because PostgreSQL aborts a transaction after a
    constraint violation: a test that reused one would be asserting about the first
    failure only.
    """
    with bind_tenant(organization_id), engine.begin() as connection:
        yield connection.execute(text(statement), dict(parameters))


def _rejected(engine: Engine, tenant: uuid.UUID, statement: str, **values: Any) -> IntegrityError:
    """Assert the database refuses one statement, and hand back what it said.

    The tenant is positional and separate from ``values`` because the statement's own
    parameters include it: the guard requires it to be bound *and* filtered on.
    """
    with pytest.raises(IntegrityError) as captured, _attempt(engine, tenant, statement, values):
        pass
    return captured.value


def _values(organization_id: uuid.UUID, **overrides: Any) -> dict[str, Any]:
    """The parameters for one insert: a valid row, with exactly the named columns changed."""
    values: dict[str, Any] = {**_VALID, **overrides, "organization_id": str(organization_id)}
    for column in ("actor_id", "actor_membership_id", "resource_id"):
        identifier = values[column]
        values[column] = None if identifier is None else str(identifier)
    if not isinstance(values["metadata"], str):
        values["metadata"] = json.dumps(values["metadata"])
    return values


def _insert(engine: Engine, organization_id: uuid.UUID, **overrides: Any) -> uuid.UUID:
    """Write one row straight into the table, as only a maintenance path could."""
    with _attempt(
        engine, organization_id, _INSERT.text, _values(organization_id, **overrides)
    ) as result:
        return result.scalar_one()


def _refused_inside(session: Session, statement: str, **values: Any) -> IntegrityError:
    """Run one statement in an open session, roll back, and hand back the refusal.

    The rollback has to happen *inside* the caller's transaction window: the retention
    override is transaction-local, so a test that left the transaction aborted would have
    the override's own cleanup fail rather than the statement under test.
    """
    try:
        session.execute(text(statement), values)
    except IntegrityError as exc:
        session.rollback()
        return exc
    raise AssertionError("the database accepted a statement it should have refused")


def _one_row(audit: AuditScene, *, index: int = 0) -> Mapping[str, Any]:
    """Create one real event and return the stored row, so refusals have a subject."""
    response = audit.trail.as_owner().post(
        assets_path(audit.organization_id),
        json={"name": f"Immutable Asset {index}", "asset_type": "model"},
    )
    assert response.status_code == 201, response.text
    return audit.trail.stored()[-1]


# ── The database refuses to rewrite history ───────────────────────────────────


def test_an_event_cannot_be_changed(audit: AuditScene) -> None:
    """No column is mutable, and the refusal names itself."""
    stored = _one_row(audit)

    failure = _rejected(
        audit.trail.engine,
        audit.organization_id,
        "UPDATE aicore.audit_events SET outcome = 'failed' "
        "WHERE organization_id = :organization_id AND id = :id",
        organization_id=str(audit.organization_id),
        id=str(stored["id"]),
    )

    assert "append-only" in str(failure)
    assert "UPDATE" in str(failure)
    assert audit.trail.stored()[0]["outcome"] == "success"


def test_an_event_cannot_be_deleted(audit: AuditScene) -> None:
    """The row stays, and the attempt is an error rather than a silent no-op."""
    stored = _one_row(audit)

    failure = _rejected(
        audit.trail.engine,
        audit.organization_id,
        "DELETE FROM aicore.audit_events WHERE organization_id = :organization_id AND id = :id",
        organization_id=str(audit.organization_id),
        id=str(stored["id"]),
    )

    assert "append-only" in str(failure)
    assert audit.trail.count() == 1


def test_the_whole_table_cannot_be_emptied(audit: AuditScene) -> None:
    """``TRUNCATE`` bypasses row triggers, so a statement trigger refuses it too."""
    _one_row(audit)

    with (
        bind_tenant(audit.organization_id),
        audit.trail.engine.begin() as connection,
        pytest.raises(IntegrityError) as captured,
    ):
        connection.exec_driver_sql("TRUNCATE aicore.audit_events")

    assert "append-only" in str(captured.value)
    assert audit.trail.count() == 1


def test_the_model_declares_no_way_to_change_itself() -> None:
    """The schema, too: no update trigger, no second timestamp, nothing that moves."""
    columns = AuditEvent.__table__.columns

    assert not any(column.onupdate is not None for column in columns)
    assert {column.name for column in columns if column.name.endswith("_at")} == {"occurred_at"}


def test_the_repository_offers_no_mutation() -> None:
    """One write, and it is an append: everything else the read side needs reads."""
    writes = {
        name
        for name in dir(AuditEventRepository)
        if not name.startswith("_") and callable(getattr(AuditEventRepository, name))
    }

    assert "append" in writes
    assert writes.isdisjoint({"update", "delete", "remove", "save", "set", "patch", "replace"})


def test_the_public_api_declares_no_write_route() -> None:
    """The published document is the contract, and it offers ``GET`` and nothing else."""
    from fastapi.routing import APIRoute, iter_route_contexts

    from aicore_api.main import create_app

    routes = [
        context.original_route
        for context in iter_route_contexts(create_app().routes)
        if isinstance(context.original_route, APIRoute)
    ]
    audit_routes = [route for route in routes if "audit" in route.path.lower()]

    assert [route.path for route in audit_routes] == [
        "/organizations/{organization_id}/audit-events"
    ]
    assert {method for route in audit_routes for method in route.methods or set()} == {"GET"}

    # And no route anywhere accepts an event: the only write-shaped verbs the API serves
    # are the ones the earlier phases declared, on their own resources.
    for route in routes:
        for method in route.methods or set():
            if method in {"POST", "PUT", "PATCH", "DELETE"}:
                assert "audit" not in route.path.lower()


# ── The schema refuses what the application cannot produce ────────────────────


@pytest.mark.parametrize(
    ("column", "value"),
    [
        ("event_type", "asset.exploded"),
        ("event_type", "ASSET.CREATED"),
        ("actor_type", "robot"),
        ("actor_type", "agent"),
        ("resource_type", "firewall"),
        ("decision", "maybe"),
        ("outcome", "succeeded"),
        ("source", "kafka"),
        ("schema_version", 2),
        ("schema_version", 0),
    ],
)
def test_the_schema_refuses_a_value_outside_the_vocabulary(
    integration_engine: Engine,
    two_organizations: tuple[uuid.UUID, uuid.UUID],
    column: str,
    value: Any,
) -> None:
    """Every closed vocabulary is a ``CHECK``, so a data fix cannot invent history."""
    organization_id = two_organizations[0]

    failure = _rejected(
        integration_engine,
        organization_id,
        _INSERT.text,
        **_values(organization_id, **{column: value}),
    )

    assert "ck_audit_events" in str(failure)


@pytest.mark.parametrize(
    ("overrides", "note"),
    [
        (
            {"actor_type": "system", "actor_id": "actor", "actor_membership_id": "membership"},
            "system names a person",
        ),
        (
            {"actor_type": "human", "actor_id": None, "actor_membership_id": None},
            "human names nobody",
        ),
        (
            {"actor_type": "human", "actor_id": "actor", "actor_membership_id": None},
            "half attributed",
        ),
    ],
)
def test_the_schema_refuses_a_half_attributed_row(
    integration_engine: Engine,
    two_organizations: tuple[uuid.UUID, uuid.UUID],
    identity_factory: Any,
    overrides: Mapping[str, Any],
    note: str,
) -> None:
    """The tie the actor type enforces in Python, enforced again where rows live."""
    organization_id = two_organizations[0]
    identity = identity_factory(role_code="owner", organization_id=organization_id)
    resolved = {
        "actor_id": identity.user_id if overrides["actor_id"] == "actor" else None,
        "actor_membership_id": (
            identity.membership_id if overrides["actor_membership_id"] == "membership" else None
        ),
    }

    failure = _rejected(
        integration_engine,
        organization_id,
        _INSERT.text,
        **_values(organization_id, **{**overrides, **resolved}),
    )

    assert "ck_audit_events" in str(failure), note


def test_the_schema_refuses_an_undecided_event_that_is_not_a_request(
    integration_engine: Engine, two_organizations: tuple[uuid.UUID, uuid.UUID]
) -> None:
    """``pending`` belongs to exactly one event type, in both directions."""
    organization_id = two_organizations[0]

    neither = _rejected(
        integration_engine,
        organization_id,
        _INSERT.text,
        **_values(organization_id, event_type="asset.created", outcome="pending"),
    )
    assert "ck_audit_events_pending_consistent" in str(neither)

    claimed = _rejected(
        integration_engine,
        organization_id,
        _INSERT.text,
        **_values(organization_id, event_type="action.requested", outcome="success"),
    )
    assert "ck_audit_events_pending_consistent" in str(claimed)


@pytest.mark.parametrize(
    ("overrides", "constraint"),
    [
        ({"source": "api", "request_id": None}, "ck_audit_events_source_request_consistent"),
        (
            {"source": "ingestion", "request_id": "req-unrequested"},
            "ck_audit_events_source_request_consistent",
        ),
        ({"correlation_id": "has spaces"}, "ck_audit_events_correlation_id_shape"),
        ({"correlation_id": "corr/with/slash"}, "ck_audit_events_correlation_id_shape"),
        ({"request_id": "not a request id"}, "ck_audit_events_request_id_shape"),
        ({"action": "Not An Action"}, "ck_audit_events_action_shape"),
        ({"metadata": []}, "ck_audit_events_metadata_is_object"),
        # A JSON string is valid JSON and still not a document.
        ({"metadata": '"a string"'}, "ck_audit_events_metadata_is_object"),
    ],
)
def test_the_schema_refuses_a_row_that_cannot_be_true(
    integration_engine: Engine,
    two_organizations: tuple[uuid.UUID, uuid.UUID],
    overrides: Mapping[str, Any],
    constraint: str,
) -> None:
    """Shape constraints on the columns a client could otherwise try to fill in."""
    organization_id = two_organizations[0]

    failure = _rejected(
        integration_engine, organization_id, _INSERT.text, **_values(organization_id, **overrides)
    )

    assert constraint in str(failure)


def test_the_schema_bounds_the_summary(
    integration_engine: Engine, two_organizations: tuple[uuid.UUID, uuid.UUID]
) -> None:
    """A metadata document is bounded in the schema as well as at the boundary."""
    organization_id = two_organizations[0]

    failure = _rejected(
        integration_engine,
        organization_id,
        _INSERT.text,
        **_values(organization_id, metadata={"note": "x" * 9000}),
    )

    assert "ck_audit_events_metadata_bounded" in str(failure)


def test_the_schema_requires_a_tenant_and_a_moment(
    integration_engine: Engine, two_organizations: tuple[uuid.UUID, uuid.UUID]
) -> None:
    """Both are ``NOT NULL``: an event with no organization or no time is not an event."""
    organization_id = two_organizations[0]

    # Written through the driver on purpose: a row with no organization cannot be
    # expressed through the guard, which is itself part of the answer — the only way to
    # reach this ``NOT NULL`` is to bypass the layer that keeps tenants apart.
    with (
        bind_tenant(organization_id),
        integration_engine.begin() as connection,
        pytest.raises(IntegrityError) as captured,
    ):
        connection.exec_driver_sql(
            "INSERT INTO aicore.audit_events "
            "(event_type, schema_version, actor_type, resource_type, outcome, "
            " correlation_id, source, metadata) "
            "VALUES ('asset.created', 1, 'system', 'asset', 'success', 'corr', "
            " 'ingestion', '{}'::jsonb)"
        )
    assert "organization_id" in str(captured.value)

    with (
        bind_tenant(organization_id),
        integration_engine.begin() as connection,
        pytest.raises(IntegrityError) as captured,
    ):
        connection.exec_driver_sql(
            "INSERT INTO aicore.audit_events "
            "(organization_id, event_type, schema_version, actor_type, resource_type, "
            " outcome, occurred_at, correlation_id, source, metadata) "
            f"VALUES ('{organization_id}', 'asset.created', 1, 'system', 'asset', "
            " 'success', NULL, 'corr', 'ingestion', '{}'::jsonb)"
        )
    assert "occurred_at" in str(captured.value)


def test_the_identifier_and_the_moment_are_the_databases(
    integration_engine: Engine, two_organizations: tuple[uuid.UUID, uuid.UUID]
) -> None:
    """Python supplies neither: both columns default on the server."""
    for column in (AuditEvent.__table__.c.id, AuditEvent.__table__.c.occurred_at):
        assert column.server_default is not None
        assert column.default is None

    organization_id = two_organizations[0]
    row = _insert(integration_engine, organization_id)

    with bind_tenant(organization_id), integration_engine.connect() as connection:
        stored = (
            connection.execute(
                text(
                    "SELECT id, occurred_at FROM aicore.audit_events "
                    "WHERE organization_id = :organization_id AND id = :id"
                ),
                {"organization_id": str(organization_id), "id": str(row)},
            )
            .mappings()
            .one()
        )

    assert stored["id"] == row
    assert stored["occurred_at"].tzinfo is not None
    assert abs(datetime.now(UTC) - stored["occurred_at"]) < timedelta(minutes=1)


# ── The one exception, and its shape ──────────────────────────────────────────


def test_a_delete_is_possible_only_inside_the_named_override(audit: AuditScene) -> None:
    """Teardown needs it; nothing else does, and it does not stretch beyond one transaction."""
    stored = _one_row(audit)
    remaining = _one_row(audit, index=1)
    session = Session(audit.trail.engine)
    try:
        with (
            bind_tenant(audit.organization_id),
            audit_retention_override(session, "phase 8 immutability test"),
        ):
            deleted = session.execute(
                text(
                    "DELETE FROM aicore.audit_events "
                    "WHERE organization_id = :organization_id AND id = :id"
                ),
                {"organization_id": str(audit.organization_id), "id": str(stored["id"])},
            ).rowcount
            session.commit()
        assert deleted == 1

        # After the override, a delete is refused again: it was a window, not a mode.
        failure = _rejected(
            audit.trail.engine,
            audit.organization_id,
            "DELETE FROM aicore.audit_events WHERE organization_id = :organization_id AND id = :id",
            organization_id=str(audit.organization_id),
            id=str(remaining["id"]),
        )
        assert "append-only" in str(failure)
        assert [row["id"] for row in audit.trail.stored()] == [remaining["id"]]
    finally:
        session.close()


def test_the_override_permits_a_delete_and_never_a_rewrite(audit: AuditScene) -> None:
    """Retention is a decision about *removing* history, not about changing it."""
    stored = _one_row(audit)
    session = Session(audit.trail.engine)
    try:
        with (
            bind_tenant(audit.organization_id),
            audit_retention_override(session, "phase 8 immutability test"),
        ):
            failure = _refused_inside(
                session,
                "UPDATE aicore.audit_events SET outcome = 'failed' "
                "WHERE organization_id = :organization_id AND id = :id",
                organization_id=str(audit.organization_id),
                id=str(stored["id"]),
            )
        assert "append-only" in str(failure)
        assert audit.trail.stored()[0]["outcome"] == "success"
    finally:
        session.close()


def test_the_override_must_state_a_reason(audit: AuditScene) -> None:
    """It is asked for in code, by name, out loud — an empty reason is not a reason."""
    session = Session(audit.trail.engine)
    try:
        with (
            pytest.raises(ValueError, match="requires a reason"),
            audit_retention_override(session, "   "),
        ):
            pass  # pragma: no cover - the error is raised on entry
    finally:
        session.close()


def test_a_row_written_outside_the_writer_still_reads_as_a_record(audit: AuditScene) -> None:
    """Maintenance rows are readable: the trail is closed in shape, not in content."""
    row = _insert(
        audit.trail.engine,
        audit.organization_id,
        event_type="agent.registered",
        resource_type="agent",
        action="agent.create",
        metadata={"source": "migration"},
    )

    stored = audit.trail.stored()[0]

    assert stored["id"] == row
    assert stored["event_type"] == "agent.registered"
    assert stored["metadata"] == {"source": "migration"}
    assert audit.trail.page()[0]["event_type"] == "agent.registered"
