"""The audit vocabulary and the metadata boundary: pure, and asserted hard.

Phase 8's rules about what a record may say are only worth having if they hold for *every*
record, so they live in ``core.audit`` — a module with no database, no session and no I/O —
and they are tested here without one. A rule that needed a database to check would be a
rule that some write path could skip.

Three properties are the point of this file:

- **the vocabulary is closed and matches the schema.** A type, actor, decision, outcome or
  source the code can produce and the database cannot store (or the other way round) is a
  bug that shows up as a 500 in production; here it shows up as a failing test;
- **attribution cannot be partial or invented.** An actor is a person (with both
  identifiers) or the system (with neither), and there is no third shape to construct;
- **metadata is a summary, never a payload.** Secrets are redacted by key *and* by shape,
  oversized or nested values are refused, and action arguments have nowhere to go.
"""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import CheckConstraint

from aicore_api.core.actions import IDEMPOTENCY_KEY_PATTERN
from aicore_api.core.audit import (
    AUDIT_SCHEMA_VERSION,
    LIFECYCLE_ACTIONS,
    MAX_METADATA_BYTES,
    MAX_METADATA_KEYS,
    MAX_METADATA_STRING_LENGTH,
    REDACTED,
    ActorType,
    AuditActor,
    AuditDecision,
    AuditError,
    AuditEventType,
    AuditMetadataError,
    AuditOutcome,
    AuditResourceType,
    AuditSource,
    resolve_event_type,
    sanitize_metadata,
)
from aicore_api.core.firewall import FirewallOutcome
from aicore_api.core.permissions import Permission
from aicore_api.db.models.audit_event import AuditEvent

# ── The vocabulary ────────────────────────────────────────────────────────────


def test_the_event_vocabulary_is_exactly_the_events_this_build_produces() -> None:
    """A closed list, spelled out.

    Every entry is emitted by a code path that exists: the inventory, the registry, the
    policy record, the ingestion boundary and the action pipeline. A type nothing emits
    would advertise history that does not exist, and a type emitted but not declared here
    would fail to be stored — both are visible in this list.
    """
    assert {event_type.value for event_type in AuditEventType} == {
        "asset.created",
        "asset.updated",
        "asset.deleted",
        "asset.discovered",
        "agent.registered",
        "agent.updated",
        "agent.deleted",
        "policy.created",
        "policy.updated",
        "policy.version_published",
        "policy.status_changed",
        "policy.deleted",
        "action.requested",
        "action.denied",
        "action.require_approval",
        "action.executed",
        "action.replayed",
        "action.failed",
    }


def test_no_declared_event_describes_a_phase_that_does_not_exist() -> None:
    """Monitoring, incidents, approvals and the kill switch contribute nothing.

    A vocabulary is where a build overstates itself most easily — one plausible-looking
    constant is enough — so the words that belong to later phases are asserted absent.
    """
    forbidden = (
        "incident",
        "alert",
        "monitor",
        "anomaly",
        "approval.granted",
        "kill",
        "block",
        "quarantine",
        "contain",
        "suspend",
    )
    offenders = [
        event_type.value
        for event_type in AuditEventType
        if any(word in event_type.value for word in forbidden)
    ]
    assert offenders == []


def test_the_resource_vocabulary_names_only_rows_this_build_has() -> None:
    assert {value.value for value in AuditResourceType} == {"asset", "agent", "policy"}


def test_the_actor_vocabulary_is_the_two_origins_that_exist() -> None:
    """A person, or nobody. There is no agent-initiated or service-initiated request."""
    assert {value.value for value in ActorType} == {"human", "system"}
    assert {value.value for value in AuditSource} == {"api", "ingestion"}


def test_the_decision_vocabulary_is_phase_sevens_own() -> None:
    """The trail stores the words the firewall already decided in.

    Two enums, one vocabulary: the audit column is closed independently of the code that
    writes it (that is why it is declared twice), and this test is what keeps the two
    copies from drifting. A fourth firewall outcome would fail here rather than being
    silently unmappable at a call site.
    """
    assert {value.value for value in AuditDecision} == {value.value for value in FirewallOutcome}


def test_the_outcome_vocabulary_is_closed() -> None:
    assert {value.value for value in AuditOutcome} == {
        "success",
        "failed",
        "blocked",
        "not_executed",
        "replayed",
        "pending",
    }


def test_every_lifecycle_action_is_a_declared_permission() -> None:
    """The operation a lifecycle event names must be a capability that exists.

    ``LIFECYCLE_ACTIONS`` maps an event to the ``resource.action`` permission that guarded
    the route which emitted it. Those codes appear in stored rows, so a typo would live in
    the trail forever — and a code no longer in the catalog would be worse, because nothing
    would ever check it again.
    """
    declared = {permission.value for permission in Permission}
    mapped = set(LIFECYCLE_ACTIONS.values())

    assert mapped <= declared, f"not permissions: {mapped - declared}"

    # The execution events are deliberately absent: for those, ``action`` is the registered
    # action's identifier, which is not a permission.
    execution_events = {
        event_type.value for event_type in AuditEventType if event_type.value.startswith("action.")
    }
    assert not mapped & execution_events
    assert set(LIFECYCLE_ACTIONS) == {
        AuditEventType.ASSET_CREATED,
        AuditEventType.ASSET_UPDATED,
        AuditEventType.ASSET_DELETED,
        AuditEventType.ASSET_DISCOVERED,
        AuditEventType.AGENT_REGISTERED,
        AuditEventType.AGENT_UPDATED,
        AuditEventType.AGENT_DELETED,
        AuditEventType.POLICY_CREATED,
        AuditEventType.POLICY_UPDATED,
        AuditEventType.POLICY_VERSION_PUBLISHED,
        AuditEventType.POLICY_STATUS_CHANGED,
        AuditEventType.POLICY_DELETED,
    }


def test_an_undeclared_event_type_is_refused_with_the_catalogue() -> None:
    """The closed door, with a message that names what is allowed."""
    with pytest.raises(AuditError, match="not a declared audit event type"):
        resolve_event_type("incident.opened")

    assert resolve_event_type("asset.created") is AuditEventType.ASSET_CREATED
    assert resolve_event_type(AuditEventType.ACTION_DENIED) is AuditEventType.ACTION_DENIED


def test_the_schema_version_is_pinned() -> None:
    """One version, stated once: a row cannot claim a shape this build does not write."""
    assert AUDIT_SCHEMA_VERSION == 1
    assert AuditEvent.__table__.c.schema_version.server_default is not None


# ── Attribution ───────────────────────────────────────────────────────────────


def test_a_human_actor_names_the_person_and_the_membership() -> None:
    user_id, membership_id = uuid.uuid4(), uuid.uuid4()
    actor = AuditActor.human(user_id=user_id, membership_id=membership_id)

    assert actor.type is ActorType.HUMAN
    assert actor.user_id == user_id
    assert actor.membership_id == membership_id
    assert actor.is_human


def test_a_system_actor_names_nobody() -> None:
    actor = AuditActor.system()

    assert actor.type is ActorType.SYSTEM
    assert actor.user_id is None
    assert actor.membership_id is None
    assert not actor.is_human


@pytest.mark.parametrize(
    "kwargs",
    [
        {"type": ActorType.HUMAN},
        {"type": ActorType.HUMAN, "user_id": uuid.uuid4()},
        {"type": ActorType.HUMAN, "membership_id": uuid.uuid4()},
        {"type": ActorType.SYSTEM, "user_id": uuid.uuid4()},
        {"type": ActorType.SYSTEM, "membership_id": uuid.uuid4()},
    ],
)
def test_an_actor_cannot_be_partially_or_wrongly_attributed(kwargs: dict[str, object]) -> None:
    """A person without a membership, and a system with a person, are both refused.

    This is the type-level half of "the caller cannot spoof the actor": there is no shape
    that says "a person did this" without saying which membership carried the role, so no
    code path can produce one by accident.
    """
    with pytest.raises(AuditError):
        AuditActor(**kwargs)  # type: ignore[arg-type]


def test_an_actor_is_repr_safe() -> None:
    """An actor ends up in log lines, so it renders its kind and not an identifier."""
    assert repr(AuditActor.system()) == "<AuditActor system>"
    assert (
        repr(AuditActor.human(user_id=uuid.uuid4(), membership_id=uuid.uuid4()))
        == "<AuditActor human>"
    )


# ── Metadata: the boundary ────────────────────────────────────────────────────


def test_a_summary_passes_through_unchanged() -> None:
    """The ordinary case: small, flat, structured facts are stored as written."""
    sanitized = sanitize_metadata(
        {"asset_type": "agent", "fields": ["name", "status"], "count": 3, "created": True}
    )

    assert sanitized == {
        "asset_type": "agent",
        "fields": ["name", "status"],
        "count": 3,
        "created": True,
    }


def test_no_metadata_is_an_empty_object() -> None:
    assert sanitize_metadata(None) == {}
    assert sanitize_metadata({}) == {}


@pytest.mark.parametrize(
    "key",
    [
        "api_key",
        "access_token",
        "refresh_token",
        "password",
        "passwd",
        "secret",
        "client_secret",
        "authorization",
        "cookie",
        "session_id",
        "jwt",
        "private_key",
        "signing_key",
        "bearer",
        "credentials",
    ],
)
def test_a_key_that_names_a_credential_is_redacted(key: str) -> None:
    """By key name, so a caller cannot leak a secret by choosing its value well.

    Segmentation on ``_``/``-``/``.`` is what catches ``access_token`` while leaving
    ``idempotency_key`` alone: a key is an opaque request identifier, not a credential, and
    redacting it would make the trail less useful without making it safer.
    """
    assert sanitize_metadata({key: "s3cr3t-value"}) == {key: REDACTED}


@pytest.mark.parametrize(
    "value",
    [
        "Bearer abcdefghijklmnop",
        "bearer abc",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature",
        "-----BEGIN RSA PRIVATE KEY-----",
    ],
)
def test_a_value_that_looks_like_a_credential_is_redacted(value: str) -> None:
    """By shape too, because a careless key name is not the only way to leak one."""
    assert sanitize_metadata({"note": value}) == {"note": REDACTED}


def test_an_innocent_value_is_not_redacted() -> None:
    """The redaction is not a blanket: ordinary summaries survive it.

    A boundary that redacted anything token-shaped would redact the identifiers an
    investigation needs, and a trail nobody can read is a trail nobody uses.
    """
    sanitized = sanitize_metadata(
        {
            "idempotency_key": "test-0f8a1b2c3d4e",
            "correlation_id": "abc-123",
            "principal_role": "security_admin",
            "digest": "a" * 64,
            "replayed": False,
        }
    )

    assert sanitized["idempotency_key"] == "test-0f8a1b2c3d4e"
    assert sanitized["correlation_id"] == "abc-123"
    assert sanitized["principal_role"] == "security_admin"
    assert sanitized["digest"] == "a" * 64
    assert sanitized["replayed"] is False


def test_a_redaction_is_visible_rather_than_silent() -> None:
    """A record that says something sensitive was present beats one that omits it."""
    assert sanitize_metadata({"password": "hunter2"})["password"] == REDACTED
    assert REDACTED != ""


@pytest.mark.parametrize(
    ("label", "value"),
    [
        ("a nested object", {"nested": {"a": 1}}),
        ("an object in a list", {"items": [{"a": 1}]}),
        ("a set", {"items": {1, 2}}),
        ("bytes", {"blob": b"raw"}),
        ("null", {"value": None}),
        ("a float that is not a number", {"value": float("nan")}),
        ("infinity", {"value": float("inf")}),
    ],
)
def test_a_value_that_is_not_a_flat_scalar_is_refused(label: str, value: dict[str, object]) -> None:
    """Refused rather than flattened: a nested payload has no place in a summary."""
    with pytest.raises(AuditMetadataError):
        sanitize_metadata(value)


def test_action_arguments_have_nowhere_to_go() -> None:
    """Requirement 10's example, as a test: the shape a caller would try is refused.

    The execution path records *how many* arguments a request carried, never what they
    were. Storing them is not merely discouraged here; the arguments of the registered
    action are strings, and a mapping of them would still pass — so the rule is about what
    the platform writes, and this test states the boundary the platform relies on: an
    arbitrary nested body cannot be stored even if a future call site tried.
    """
    with pytest.raises(AuditMetadataError):
        sanitize_metadata({"arguments": {"report_detail": {"nested": "full"}}})

    # And the summary the platform actually writes is accepted.
    assert sanitize_metadata({"argument_count": 2}) == {"argument_count": 2}


@pytest.mark.parametrize(
    "key",
    ["Password", "SECRET", "with space", "with/slash", "", "1leading_digit", "x" * 65],
)
def test_a_key_that_is_not_a_lowercase_identifier_is_refused(key: str) -> None:
    """Keys are a closed shape so a reader can rely on them, and so ``grep`` works."""
    with pytest.raises(AuditMetadataError):
        sanitize_metadata({key: "value"})


def test_control_characters_are_refused() -> None:
    """A value with a control character is a payload or a log-injection attempt."""
    with pytest.raises(AuditMetadataError):
        sanitize_metadata({"note": "line\nbreak"})
    with pytest.raises(AuditMetadataError):
        sanitize_metadata({"note": "null\x00byte"})


def test_an_oversized_value_is_refused() -> None:
    with pytest.raises(AuditMetadataError, match="longer than"):
        sanitize_metadata({"note": "x" * (MAX_METADATA_STRING_LENGTH + 1)})


def test_too_many_keys_are_refused() -> None:
    with pytest.raises(AuditMetadataError, match="keys"):
        sanitize_metadata({f"k{index}": 1 for index in range(MAX_METADATA_KEYS + 1)})


def test_an_oversized_document_is_refused_even_when_every_value_fits() -> None:
    """The sum is bounded as well as the parts: 32 full-length strings exceed it."""
    payload = {f"key_{index:02d}": "x" * MAX_METADATA_STRING_LENGTH for index in range(32)}

    with pytest.raises(AuditMetadataError, match="bytes"):
        sanitize_metadata(payload)


def test_metadata_must_be_a_mapping() -> None:
    """A list, a string or an event object is not metadata."""
    with pytest.raises(AuditMetadataError, match="mapping"):
        sanitize_metadata(["a", "b"])  # type: ignore[arg-type]
    with pytest.raises(AuditMetadataError, match="mapping"):
        sanitize_metadata("a string")  # type: ignore[arg-type]


def test_the_document_bound_is_smaller_than_the_database_bound() -> None:
    """The application refuses what the schema would refuse, only earlier and more clearly.

    The ``CHECK`` constraint is a backstop for rows written outside the writer; if the
    application's bound were the larger of the two, a legitimate write would fail deep in
    PostgreSQL instead of at the boundary that made the mistake.
    """
    from aicore_api.db.models.audit_event import MAX_METADATA_BYTES as database_bound

    assert database_bound > MAX_METADATA_BYTES


def test_the_idempotency_key_shape_survives_the_boundary() -> None:
    """The one opaque caller-supplied value a trail row may carry is stored as-is.

    An execution records the key so a retry can be recognized. It is not a credential, and
    redacting it would remove the only link between a trail row and the ledger row that
    answers "did this run twice?".
    """
    from aicore_api.core.actions import IDEMPOTENCY_KEY_MAX_LENGTH

    key = "test-" + "a" * 20
    assert len(key) <= IDEMPOTENCY_KEY_MAX_LENGTH
    assert re.compile(IDEMPOTENCY_KEY_PATTERN).match(key)
    assert sanitize_metadata({"idempotency_key": key})["idempotency_key"] == key


# ── The model, without a database ─────────────────────────────────────────────


def test_the_model_stores_metadata_under_the_column_named_metadata() -> None:
    """The attribute is ``event_metadata`` because ``metadata`` is SQLAlchemy's registry.

    The inventory hit this first (``assets.metadata``); the same rule applies here, and the
    column name is what a raw query and the migration use.
    """
    assert AuditEvent.event_metadata.property.columns[0].name == "metadata"
    assert "metadata" in {column.name for column in AuditEvent.__table__.columns}


def test_the_model_has_no_updated_at_and_no_mutable_column() -> None:
    """There is no timestamp for a modification because there is no modification.

    Every other table in this schema carries ``updated_at`` (``TimestampMixin``); this one
    deliberately does not, and its absence is the schema's own statement that a row is
    written once.
    """
    columns = {column.name for column in AuditEvent.__table__.columns}

    assert "created_at" not in columns
    assert "updated_at" not in columns
    assert "occurred_at" in columns
    assert columns == {
        "id",
        "organization_id",
        "event_type",
        "schema_version",
        "occurred_at",
        "actor_type",
        "actor_id",
        "actor_membership_id",
        "agent_id",
        "resource_type",
        "resource_id",
        "action",
        "decision",
        "outcome",
        "correlation_id",
        "request_id",
        "source",
        "metadata",
    }


def test_the_timestamp_is_the_databases() -> None:
    """``occurred_at`` has a server default and no Python default on the model."""
    column = AuditEvent.__table__.c.occurred_at

    assert column.server_default is not None
    assert column.default is None
    assert column.nullable is False
    assert column.type.timezone is True


def test_a_stored_row_cannot_be_partially_attributed() -> None:
    """The same tie the actor type enforces, restated as a database constraint.

    The application's type keeps a half-attributed event from being *built*; the constraint
    keeps one from being *stored*, whatever wrote it.
    """
    constraints = {constraint.name for constraint in AuditEvent.__table__.constraints}
    checks = {
        constraint.name: str(constraint.sqltext)
        for constraint in AuditEvent.__table__.constraints
        if isinstance(constraint, CheckConstraint)
        and constraint.name is not None
        and constraint.name.startswith("ck_audit_events_")
    }

    assert "ck_audit_events_actor_named" in constraints
    assert "ck_audit_events_actor_membership_named" in constraints
    assert (
        "(actor_type = 'human') = (actor_id IS NOT NULL)" in checks["ck_audit_events_actor_named"]
    )
    assert (
        "(actor_type = 'human') = (actor_membership_id IS NOT NULL)"
        in checks["ck_audit_events_actor_membership_named"]
    )


def test_every_stored_vocabulary_is_constrained() -> None:
    """Closed vocabularies are enforced by the schema, not only by the code that writes.

    A data fix, a migration or a future script cannot put a value in the table that the
    application could not have written — which is what makes the vocabulary something a
    reader can rely on rather than something the writer happens to do.
    """
    checks = {
        constraint.name
        for constraint in AuditEvent.__table__.constraints
        if constraint.name is not None
    }

    assert {
        "ck_audit_events_event_type_valid",
        "ck_audit_events_actor_type_valid",
        "ck_audit_events_resource_type_valid",
        "ck_audit_events_decision_valid",
        "ck_audit_events_outcome_valid",
        "ck_audit_events_source_valid",
        "ck_audit_events_schema_version_valid",
        "ck_audit_events_pending_consistent",
        "ck_audit_events_source_request_consistent",
        "ck_audit_events_action_shape",
        "ck_audit_events_correlation_id_shape",
        "ck_audit_events_request_id_shape",
        "ck_audit_events_metadata_is_object",
        "ck_audit_events_metadata_bounded",
    } <= checks


def test_only_a_requested_action_may_be_pending() -> None:
    """The one way an event can be undecided, and the reason for it.

    An event that says "pending" for anything other than an admitted execution request would
    be a row that never gets an ending; an ``action.requested`` row that claims an outcome
    would be a record of something that had not happened yet.
    """
    checks = {
        constraint.name: str(constraint.sqltext)
        for constraint in AuditEvent.__table__.constraints
        if isinstance(constraint, CheckConstraint) and constraint.name is not None
    }

    assert (
        checks["ck_audit_events_pending_consistent"]
        == "(outcome = 'pending') = (event_type = 'action.requested')"
    )


def test_the_repr_of_a_row_does_not_render_its_metadata() -> None:
    """A row ends up in a log line; the metadata may hold anything that passed the boundary."""
    row = AuditEvent(event_type="asset.created", outcome="success", event_metadata={"a": "b"})

    assert "asset.created" in repr(row)
    assert "b" not in repr(row)


def test_a_row_can_be_constructed_by_tests_without_a_database() -> None:
    """The model is a plain declarative class: no session, no engine, no side effect."""
    row = AuditEvent(
        organization_id=uuid.uuid4(),
        event_type=AuditEventType.ASSET_CREATED.value,
        schema_version=AUDIT_SCHEMA_VERSION,
        actor_type=ActorType.SYSTEM.value,
        resource_type=AuditResourceType.ASSET.value,
        outcome=AuditOutcome.SUCCESS.value,
        correlation_id="corr-1",
        source=AuditSource.INGESTION.value,
        event_metadata={},
    )

    assert row.occurred_at is None  # the database supplies it, not Python
    assert row.organization_id is not None
    assert isinstance(datetime.now(UTC), datetime)
