"""Policies at the database level: what is stored, what is refused, what cascades.

Everything asserted here is a database property, which is why these tests run against
real PostgreSQL (``scripts/test-db.sh`` sets ``AICORE_TEST_DATABASE_URL``) rather than
against a stub: the composite foreign key that makes a cross-tenant version
unrepresentable, the check constraints that keep the statuses, effects, targets and
priorities closed, the composite key that stops two versions of one policy sharing a
number, the append-only history, and the tenant guard that refuses an unscoped
statement against a tenant-owned table.

That is not incidental coverage. If those invariants lived only in the application,
the first migration, data fix or support query to write a row directly could put an
unenforceable policy into force — and no test going through the API would notice.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Iterator
from contextlib import contextmanager

import pytest
from sqlalchemy import Engine, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from aicore_api.core.domain_errors import ConflictError
from aicore_api.core.permissions import Action, Resource
from aicore_api.core.policy import (
    MAX_CONDITIONS,
    PRIORITY_MAX,
    PRIORITY_MIN,
    PolicyDefinitionError,
    PolicyEffect,
    PolicyStatus,
)
from aicore_api.db.models.policy import Policy, PolicyVersion
from aicore_api.db.repositories.policies import PolicyRepository
from aicore_api.db.tenancy import TenantScopeError, bind_tenant
from identity_fixture import Identity, IdentityFactory
from policies_fixture import count_policies, count_versions

CONDITION = {"field": "environment", "operator": "equals", "value": "production"}


def _repository(session: Session, identity: Identity) -> PolicyRepository:
    return PolicyRepository(session, identity.organization_id)


def _raw(engine: Engine, organization_id: uuid.UUID, statement: str, **parameters: object) -> None:
    """Run one direct statement against a tenant-owned table.

    Every caller binds the tenant and filters on ``organization_id``, which is what
    the isolation guard requires of raw SQL too — the point of these tests is what
    *PostgreSQL* refuses, not what the repository would have refused first.
    """
    with bind_tenant(organization_id), engine.begin() as connection:
        connection.execute(
            text(statement),
            {"organization_id": str(organization_id), **parameters},
        )


@contextmanager
def _fresh_session(engine: Engine) -> Iterator[Session]:
    """A session with an empty identity map, standing in for a new request.

    The fixtures' session caches what it wrote, so a test that changes a row
    underneath the application has to read it back the way the next request would —
    otherwise it would assert against the copy in memory rather than the row.
    """
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    session = factory()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


def _create(
    repository: PolicyRepository, name: str = "Staging guard", **overrides: object
) -> Policy:
    """Create a policy through the repository, with valid parts by default."""
    fields: dict[str, object] = {
        "name": name,
        "description": "Because the database tests say so.",
        "resource": Resource.AGENT,
        "action": Action.UPDATE,
        "effect": PolicyEffect.DENY,
        "priority": 100,
        "conditions": [dict(CONDITION)],
        "status": PolicyStatus.DRAFT,
    }
    fields.update(overrides)
    return repository.create(**fields)  # type: ignore[arg-type]


# ── Storage ──────────────────────────────────────────────────────────────────


def test_a_policy_is_stored_with_its_first_version_and_pointer(
    integration_session: Session, identity_factory: IdentityFactory
) -> None:
    """The pair of rows is written together, and the pointer agrees with the row."""
    identity = identity_factory(role_code="owner")
    repository = _repository(integration_session, identity)

    policy = _create(repository, "  Production changes  ")

    assert policy.organization_id == identity.organization_id
    assert policy.name == "Production changes"  # normalized on the way in
    assert policy.description == "Because the database tests say so."
    assert policy.status == PolicyStatus.DRAFT.value
    assert policy.current_version == 1
    assert policy.created_at is not None and policy.updated_at is not None

    version = policy.current_version_row
    assert version is not None
    assert version.version == 1
    assert version.organization_id == identity.organization_id
    assert version.effect == PolicyEffect.DENY.value
    assert version.resource == Resource.AGENT.value
    assert version.action == Action.UPDATE.value
    assert version.priority == 100
    assert version.conditions == [CONDITION]


def test_the_stored_conditions_are_structured_json_and_nothing_else(
    integration_session: Session, identity_factory: IdentityFactory, integration_engine: Engine
) -> None:
    """JSONB holds the condition array; the row is readable without the ORM.

    Read back through raw SQL on purpose: what the schema stores is the contract, and
    a test that only ever reads through the ORM cannot tell a JSON array from a
    JSON-encoded string.
    """
    identity = identity_factory(role_code="owner")
    policy = _create(_repository(integration_session, identity))

    with bind_tenant(identity.organization_id), integration_engine.connect() as connection:
        stored = connection.execute(
            text(
                "SELECT conditions, jsonb_typeof(conditions) FROM aicore.policy_versions "
                "WHERE policy_id = :policy_id AND organization_id = :organization_id"
            ),
            {"policy_id": str(policy.id), "organization_id": str(identity.organization_id)},
        ).one()

    assert stored[0] == [CONDITION]
    assert stored[1] == "array"


def test_an_empty_condition_list_is_stored_as_an_empty_array(
    integration_session: Session, identity_factory: IdentityFactory
) -> None:
    """A blanket rule is stored as ``[]``, not as a null or a missing value."""
    identity = identity_factory(role_code="owner")

    policy = _create(_repository(integration_session, identity), conditions=[])

    assert policy.current_version_row is not None
    assert policy.current_version_row.conditions == []


# ── The vocabulary, enforced by the schema ───────────────────────────────────


@pytest.mark.parametrize(
    ("column", "value"),
    [
        ("status", "suspended"),
        ("status", "ACTIVE"),
        ("status", ""),
    ],
)
def test_the_database_refuses_an_unknown_policy_status(
    integration_session: Session,
    identity_factory: IdentityFactory,
    integration_engine: Engine,
    column: str,
    value: str,
) -> None:
    """Even a direct writer cannot store a state the application does not know."""
    identity = identity_factory(role_code="owner")
    _create(_repository(integration_session, identity))

    with pytest.raises(IntegrityError):
        _raw(
            integration_engine,
            identity.organization_id,
            f"UPDATE aicore.policies SET {column} = :value "
            "WHERE organization_id = :organization_id",
            value=value,
        )


@pytest.mark.parametrize(
    ("column", "value"),
    [
        ("effect", "permit"),
        ("effect", "DENY"),
        ("resource", "firewall"),
        ("action", "execute"),
        ("action", "block"),
        ("priority", PRIORITY_MAX + 1),
        ("priority", PRIORITY_MIN - 1),
        ("version", 0),
    ],
)
def test_the_database_refuses_a_version_outside_the_declared_vocabulary(
    integration_session: Session,
    identity_factory: IdentityFactory,
    integration_engine: Engine,
    column: str,
    value: object,
) -> None:
    """The closed sets are constraints, not conventions.

    ``resource`` and ``action`` are checked against the *union* of the declared
    values rather than the declared pairs: PostgreSQL can compare two small closed
    sets cheaply, while "this pair is a permission" is a fact about the permission
    catalogue. The application decides that, and both halves are asserted — here and
    in ``test_policy_conditions.py``.
    """
    identity = identity_factory(role_code="owner")
    policy = _create(_repository(integration_session, identity))

    with pytest.raises(IntegrityError):
        _raw(
            integration_engine,
            identity.organization_id,
            f"UPDATE aicore.policy_versions SET {column} = :value "
            "WHERE policy_id = :policy_id AND organization_id = :organization_id",
            value=value,
            policy_id=str(policy.id),
        )


def test_the_database_refuses_conditions_that_are_not_an_array(
    integration_session: Session, identity_factory: IdentityFactory, integration_engine: Engine
) -> None:
    """Structure is the schema's business: an object or a scalar is not conditions."""
    identity = identity_factory(role_code="owner")
    _create(_repository(integration_session, identity))

    for value in ('{"field": "environment"}', "42", '"production"'):
        with pytest.raises(IntegrityError):
            _raw(
                integration_engine,
                identity.organization_id,
                "UPDATE aicore.policy_versions SET conditions = CAST(:value AS jsonb) "
                "WHERE organization_id = :organization_id",
                value=value,
            )


def test_the_database_refuses_more_conditions_than_the_language_allows(
    integration_session: Session, identity_factory: IdentityFactory, integration_engine: Engine
) -> None:
    """The bound on work is in the schema, so it holds for a direct writer too."""
    identity = identity_factory(role_code="owner")
    _create(_repository(integration_session, identity))
    too_many = str([CONDITION] * (MAX_CONDITIONS + 1)).replace("'", '"')

    with pytest.raises(IntegrityError):
        _raw(
            integration_engine,
            identity.organization_id,
            "UPDATE aicore.policy_versions SET conditions = CAST(:value AS jsonb) "
            "WHERE organization_id = :organization_id",
            value=too_many,
        )


def test_the_code_vocabulary_equals_the_constraint_sets(integration_engine: Engine) -> None:
    """The ``CHECK`` lists and the code vocabulary are the same sets, checked.

    They are written twice on purpose — a migration describes the database at one
    point in time and must not import application code — so the two copies are
    compared here rather than trusted to stay in step.
    """
    statements = _constraint_statements(integration_engine, "policy_versions")
    resource_check = next(value for name, value in statements if name.endswith("resource_valid"))
    action_check = next(value for name, value in statements if name.endswith("action_valid"))
    effect_check = next(value for name, value in statements if name.endswith("effect_valid"))

    assert set(_quoted(resource_check)) == {resource.value for resource in Resource}
    assert set(_quoted(effect_check)) == {effect.value for effect in PolicyEffect}
    assert set(_quoted(action_check)) == {action.value for action in Action}, (
        "the action vocabulary is closed, and the constraint lists exactly it"
    )

    # …and the *bounds* are the same numbers on both sides. A bound that is stricter
    # in the database would refuse a policy the language accepts; a looser one would
    # let a row in that the language cannot read back.
    length_check = next(value for name, value in statements if name.endswith("conditions_length"))
    priority_check = next(value for name, value in statements if name.endswith("priority_range"))

    assert _numbers(length_check) == [MAX_CONDITIONS]
    assert _numbers(priority_check) == [PRIORITY_MIN, PRIORITY_MAX]


def _numbers(definition: str) -> list[int]:
    """Every integer in a constraint definition, in the order PostgreSQL wrote them.

    Read rather than pattern-matched: the definition is what the database enforces,
    and the two numbers in the priority check are the bound's own endpoints.
    """
    return [int(found) for found in re.findall(r"\d+", definition)]


def _constraint_statements(engine: Engine, table: str) -> list[tuple[str, str]]:
    """Every constraint on ``table``, as ``(name, definition)``.

    Read from the catalogue rather than from the migration source: what matters is
    what the database enforces, not what the file that created it said. ``pg_class``
    is not tenant-owned, so this read needs no tenant binding.
    """
    with engine.connect() as connection:
        rows = connection.execute(
            text(
                "SELECT con.conname, pg_get_constraintdef(con.oid) FROM pg_constraint con "
                "JOIN pg_class rel ON rel.oid = con.conrelid "
                "JOIN pg_namespace ns ON ns.oid = rel.relnamespace "
                "WHERE ns.nspname = 'aicore' AND rel.relname = :table"
            ),
            {"table": table},
        ).all()
    return [(row[0], row[1]) for row in rows]


def _quoted(definition: str) -> list[str]:
    """The single-quoted literals inside a constraint definition."""
    return [
        part.split("'")[1]
        for part in definition.split("'::text")[0].split("(")[-1].split(",")
        if "'" in part
    ]


# ── Identity, ownership and uniqueness ───────────────────────────────────────


def test_one_name_per_organization_and_the_same_name_in_another_tenant(
    integration_session: Session, identity_factory: IdentityFactory
) -> None:
    """Names are unique per tenant, and privilege in one tenant buys nothing in another."""
    first = identity_factory(role_code="owner")
    second = identity_factory(role_code="owner")
    _create(_repository(integration_session, first), "Shared name")

    with pytest.raises(ConflictError):
        _create(_repository(integration_session, first), "Shared name")

    # The other organization is free to use the same label: uniqueness is per tenant,
    # and knowing a name in another tenant tells a caller nothing about this one.
    other = _create(_repository(integration_session, second), "Shared name")
    assert other.organization_id == second.organization_id


def test_a_policy_of_another_organization_is_not_visible_at_all(
    integration_session: Session, identity_factory: IdentityFactory
) -> None:
    """Read, list, count and history: none of them cross the tenant boundary."""
    owner = identity_factory(role_code="owner")
    stranger = identity_factory(role_code="owner")
    policy = _create(_repository(integration_session, owner))

    other = _repository(integration_session, stranger)

    assert other.find(policy.id) is None
    assert other.page(limit=10, offset=0) == []
    assert other.count() == 0
    assert other.active_definitions(Resource.AGENT, Action.UPDATE) == []


def test_a_version_cannot_be_attached_to_another_organizations_policy(
    integration_session: Session, identity_factory: IdentityFactory, integration_engine: Engine
) -> None:
    """Cross-tenant versions are unrepresentable, not merely rejected.

    The composite foreign key ``(organization_id, policy_id)`` is what makes that
    true: a row naming one tenant and another tenant's policy violates the reference
    rather than creating a policy whose history belongs to somebody else.
    """
    owner = identity_factory(role_code="owner")
    stranger = identity_factory(role_code="owner")
    policy = _create(_repository(integration_session, owner))

    with pytest.raises(IntegrityError):
        _raw(
            integration_engine,
            stranger.organization_id,
            "INSERT INTO aicore.policy_versions "
            "(policy_id, version, organization_id, effect, resource, action, priority, conditions) "
            "VALUES (:policy_id, 99, :organization_id, 'deny', 'agent', 'update', 10, '[]')",
            policy_id=str(policy.id),
        )


def test_two_versions_of_one_policy_cannot_share_a_number(
    integration_session: Session, identity_factory: IdentityFactory, integration_engine: Engine
) -> None:
    """``(policy_id, version)`` is the primary key, so a version is one row."""
    identity = identity_factory(role_code="owner")
    policy = _create(_repository(integration_session, identity))

    with pytest.raises(IntegrityError):
        _raw(
            integration_engine,
            identity.organization_id,
            "INSERT INTO aicore.policy_versions "
            "(policy_id, version, organization_id, effect, resource, action, priority, conditions) "
            "VALUES (:policy_id, 1, :organization_id, 'allow', 'agent', 'update', 10, '[]')",
            policy_id=str(policy.id),
        )


def test_an_unscoped_statement_against_policies_is_refused(
    integration_session: Session, integration_engine: Engine, identity_factory: IdentityFactory
) -> None:
    """The tenant guard applies to raw SQL too, which is the point of it.

    Both halves of the rule: no bound tenant is refused, and a bound tenant with no
    ``organization_id`` filter is refused as well — so a query cannot look scoped
    without being scoped.
    """
    identity = identity_factory(role_code="owner")
    _create(_repository(integration_session, identity))

    with pytest.raises(TenantScopeError), integration_engine.connect() as connection:
        connection.execute(text("SELECT count(*) FROM aicore.policies"))

    with (
        pytest.raises(TenantScopeError),
        bind_tenant(identity.organization_id),
        integration_engine.connect() as connection,
    ):
        connection.execute(text("SELECT count(*) FROM aicore.policy_versions"))


# ── Versioning ───────────────────────────────────────────────────────────────


def test_publishing_appends_a_version_and_moves_the_pointer(
    integration_session: Session, identity_factory: IdentityFactory, integration_engine: Engine
) -> None:
    """Editing a definition is an append; the policy then points at the new row."""
    identity = identity_factory(role_code="owner")
    repository = _repository(integration_session, identity)
    policy = _create(repository, priority=10)

    published = repository.publish_version(
        policy,
        resource=Resource.AGENT,
        action=Action.UPDATE,
        effect=PolicyEffect.ALLOW,
        priority=5,
        conditions=[],
    )

    assert published.version == 2
    assert published.effect is PolicyEffect.ALLOW
    assert policy.current_version == 2
    assert count_versions(integration_engine, identity.organization_id) == 2


def test_a_published_version_is_never_rewritten(
    integration_session: Session, identity_factory: IdentityFactory, integration_engine: Engine
) -> None:
    """History is append-only: what a version said, it still says."""
    identity = identity_factory(role_code="owner")
    repository = _repository(integration_session, identity)
    policy = _create(repository, priority=10)
    repository.publish_version(
        policy,
        resource=Resource.AGENT,
        action=Action.UPDATE,
        effect=PolicyEffect.ALLOW,
        priority=5,
        conditions=[],
    )

    with bind_tenant(identity.organization_id), integration_engine.connect() as connection:
        first = connection.execute(
            text(
                "SELECT effect, priority, conditions FROM aicore.policy_versions "
                "WHERE policy_id = :policy_id AND version = 1 "
                "AND organization_id = :organization_id"
            ),
            {"policy_id": str(policy.id), "organization_id": str(identity.organization_id)},
        ).one()

    assert first[0] == PolicyEffect.DENY.value
    assert first[1] == 10
    assert first[2] == [CONDITION]


def test_the_repository_exposes_no_way_to_edit_or_delete_a_version() -> None:
    """Stated structurally, because "we do not do that" is a claim until something checks.

    A version that could be edited would make a recorded decision unexplainable; one
    that could be deleted individually would leave a policy with a hole in its
    history. Neither is offered, and neither is reachable through the ORM cascade —
    the only thing that removes versions is removing the whole policy.
    """
    surface = {
        name
        for name in dir(PolicyRepository)
        if not name.startswith("__") and callable(getattr(PolicyRepository, name, None))
    }

    assert not {name for name in surface if "version" in name} & {
        "delete_version",
        "update_version",
        "edit_version",
        "remove_version",
    }


def test_publishing_an_unchanged_definition_appends_nothing(
    integration_session: Session, identity_factory: IdentityFactory, integration_engine: Engine
) -> None:
    """A version number is what a decision is attributed to; it does not inflate."""
    identity = identity_factory(role_code="owner")
    repository = _repository(integration_session, identity)
    policy = _create(repository)

    published = repository.publish_version(
        policy,
        resource=Resource.AGENT,
        action=Action.UPDATE,
        effect=PolicyEffect.DENY,
        priority=100,
        conditions=[dict(CONDITION)],
    )

    assert published.version == 1
    assert policy.current_version == 1
    assert count_versions(integration_engine, identity.organization_id) == 1


def test_the_history_is_paged_and_counted(
    integration_session: Session, identity_factory: IdentityFactory
) -> None:
    """A history grows with every edit, so reading it is bounded like everything else."""
    identity = identity_factory(role_code="owner")
    repository = _repository(integration_session, identity)
    policy = _create(repository)
    for priority in (90, 80, 70):
        repository.publish_version(
            policy,
            resource=Resource.AGENT,
            action=Action.UPDATE,
            effect=PolicyEffect.DENY,
            priority=priority,
            conditions=[dict(CONDITION)],
        )

    first_page = repository.versions_of(policy, limit=2, offset=0)
    second_page = repository.versions_of(policy, limit=2, offset=2)

    assert [row.version for row in first_page] == [1, 2]
    assert [row.version for row in second_page] == [3, 4]
    assert repository.version_count(policy) == 4


# ── Lifecycle ────────────────────────────────────────────────────────────────


def test_only_active_policies_are_loaded_for_evaluation(
    integration_session: Session, identity_factory: IdentityFactory
) -> None:
    """The evaluation query is the only thing that decides what is in force."""
    identity = identity_factory(role_code="owner")
    repository = _repository(integration_session, identity)
    draft = _create(repository, "Draft", status=PolicyStatus.DRAFT)
    active = _create(repository, "Active", status=PolicyStatus.ACTIVE)
    disabled = _create(repository, "Disabled", status=PolicyStatus.ACTIVE)

    assert repository.set_status(disabled, PolicyStatus.DISABLED) is True

    loaded = repository.active_definitions(Resource.AGENT, Action.UPDATE)

    assert [definition.policy_id for definition in loaded] == [active.id]
    assert draft.id not in {definition.policy_id for definition in loaded}


def test_the_evaluation_query_filters_by_target(
    integration_session: Session, identity_factory: IdentityFactory
) -> None:
    """Only policies about this ``resource.action`` are candidates."""
    identity = identity_factory(role_code="owner")
    repository = _repository(integration_session, identity)
    agent_update = _create(repository, "Agent update", status=PolicyStatus.ACTIVE)
    _create(
        repository,
        "Asset delete",
        resource=Resource.ASSET,
        action=Action.DELETE,
        status=PolicyStatus.ACTIVE,
    )
    _create(
        repository,
        "Agent delete",
        action=Action.DELETE,
        status=PolicyStatus.ACTIVE,
    )

    loaded = repository.active_definitions(Resource.AGENT, Action.UPDATE)

    assert [definition.policy_id for definition in loaded] == [agent_update.id]


def test_a_retired_policy_leaves_evaluation_permanently(
    integration_session: Session, identity_factory: IdentityFactory
) -> None:
    """Retiring is the non-destructive alternative to deleting, and it is final."""
    identity = identity_factory(role_code="owner")
    repository = _repository(integration_session, identity)
    policy = _create(repository, status=PolicyStatus.ACTIVE)
    assert repository.active_definitions(Resource.AGENT, Action.UPDATE)

    repository.set_status(policy, PolicyStatus.RETIRED)

    assert repository.active_definitions(Resource.AGENT, Action.UPDATE) == []
    with pytest.raises(ConflictError):
        repository.set_status(policy, PolicyStatus.ACTIVE)


def test_activating_validates_the_stored_definition_not_the_request(
    integration_session: Session, identity_factory: IdentityFactory, integration_engine: Engine
) -> None:
    """A row this build cannot evaluate cannot be put into force.

    Simulated the only way it can happen: by writing a row the application refuses to
    write. Activation then re-reads what is stored rather than trusting the request,
    and the policy stays out of force.
    """
    identity = identity_factory(role_code="owner")
    repository = _repository(integration_session, identity)
    policy = _create(repository)

    _raw(
        integration_engine,
        identity.organization_id,
        "UPDATE aicore.policy_versions SET conditions = CAST(:value AS jsonb) "
        "WHERE policy_id = :policy_id AND organization_id = :organization_id",
        value='[{"field": "environment", "operator": "equals", "value": "prod"}]',
        policy_id=str(policy.id),
    )

    # Read through a *fresh* session, the way a request would: the point is what the
    # stored row says, not what the fixture's session still remembers writing.
    with _fresh_session(integration_engine) as session:
        reading = _repository(session, identity)
        reloaded = reading.find(policy.id)
        assert reloaded is not None
        with pytest.raises(ConflictError, match="cannot be activated"):
            reading.set_status(reloaded, PolicyStatus.ACTIVE)

    with _fresh_session(integration_engine) as session:
        still_draft = _repository(session, identity).find(policy.id)
        assert still_draft is not None
        assert still_draft.status == PolicyStatus.DRAFT.value


def test_reading_a_row_this_build_cannot_interpret_raises(
    integration_session: Session, identity_factory: IdentityFactory, integration_engine: Engine
) -> None:
    """A stored definition that does not parse is a deployment defect, not a skip.

    Skipping it would silently change what the organization's policy says — and
    skipping a *denial* is permitting the action.
    """
    identity = identity_factory(role_code="owner")
    repository = _repository(integration_session, identity)
    policy = _create(repository)

    _raw(
        integration_engine,
        identity.organization_id,
        "UPDATE aicore.policy_versions SET conditions = CAST(:value AS jsonb) "
        "WHERE policy_id = :policy_id AND organization_id = :organization_id",
        value='["not a condition"]',
        policy_id=str(policy.id),
    )

    with _fresh_session(integration_engine) as session:
        reading = _repository(session, identity)
        reloaded = reading.find(policy.id)
        assert reloaded is not None
        with pytest.raises(PolicyDefinitionError, match=policy.name):
            reading.definition_of(reloaded)


# ── Deleting, and the tenant boundary on the write that cannot be undone ─────


def test_deleting_a_policy_removes_its_versions_by_cascade(
    integration_session: Session, identity_factory: IdentityFactory, integration_engine: Engine
) -> None:
    """An orphaned version is unreachable, so it goes with the policy."""
    identity = identity_factory(role_code="owner")
    repository = _repository(integration_session, identity)
    policy = _create(repository)
    repository.publish_version(
        policy,
        resource=Resource.AGENT,
        action=Action.UPDATE,
        effect=PolicyEffect.ALLOW,
        priority=5,
        conditions=[],
    )
    assert count_versions(integration_engine, identity.organization_id) == 2

    repository.delete(policy)

    assert repository.find(policy.id) is None
    assert count_policies(integration_engine, identity.organization_id) == 0
    assert count_versions(integration_engine, identity.organization_id) == 0


def test_deleting_through_another_tenants_repository_removes_nothing(
    integration_session: Session, identity_factory: IdentityFactory
) -> None:
    """The delete statement carries the tenant boundary, like every other query."""
    owner = identity_factory(role_code="owner")
    stranger = identity_factory(role_code="owner")
    policy = _create(_repository(integration_session, owner))

    _repository(integration_session, stranger).delete(policy)

    assert _repository(integration_session, owner).find(policy.id) is not None


def test_an_organization_with_policies_cannot_be_deleted(
    integration_session: Session, identity_factory: IdentityFactory, integration_engine: Engine
) -> None:
    """Removing a tenant is an explicit procedure, never a side effect of a delete."""
    identity = identity_factory(role_code="owner")
    _create(_repository(integration_session, identity))

    with pytest.raises(IntegrityError), integration_engine.begin() as connection:
        connection.execute(
            text("DELETE FROM aicore.organizations WHERE id = :id"),
            {"id": str(identity.organization_id)},
        )


# ── The evaluation load ──────────────────────────────────────────────────────


def test_the_evaluation_load_returns_every_active_policy_for_the_target(
    integration_session: Session, identity_factory: IdentityFactory
) -> None:
    """All of them, not the first: precedence is decided by the engine, not the query.

    The statement is ordered for the database's benefit, and the engine sorts its own
    candidates — so this asserts the *set*, and
    ``test_policy_engine.py`` asserts that the order rows arrive in cannot change the
    decision.
    """
    identity = identity_factory(role_code="owner")
    repository = _repository(integration_session, identity)
    created = {
        _create(repository, f"Policy {index}", priority=index, status=PolicyStatus.ACTIVE).id
        for index in range(5)
    }

    loaded = repository.active_definitions(Resource.AGENT, Action.UPDATE)

    assert {definition.policy_id for definition in loaded} == created
    assert len(loaded) == 5


def test_the_evaluation_load_refuses_a_target_no_policy_may_use(
    integration_session: Session, identity_factory: IdentityFactory
) -> None:
    """The query itself is closed over the vocabulary, not merely the write paths."""
    identity = identity_factory(role_code="owner")
    repository = _repository(integration_session, identity)

    for resource, action in (("firewall", "block"), ("agent", "execute"), ("policy", "execute")):
        with pytest.raises(PolicyDefinitionError):
            repository.active_definitions(resource, action)


def test_a_definition_carries_the_policy_and_the_version_together(
    integration_session: Session, identity_factory: IdentityFactory
) -> None:
    """What the engine receives is a value, and it names the row it came from."""
    identity = identity_factory(role_code="owner")
    repository = _repository(integration_session, identity)
    policy = _create(repository, "Attributable", priority=7, status=PolicyStatus.ACTIVE)

    definition = repository.active_definitions(Resource.AGENT, Action.UPDATE)[0]

    assert definition.policy_id == policy.id
    assert definition.version == 1
    assert definition.name == "Attributable"
    assert definition.priority == 7
    assert definition.effect is PolicyEffect.DENY
    assert definition.conditions[0].as_payload() == CONDITION


def test_policies_of_one_tenant_never_appear_in_another_tenants_evaluation(
    integration_session: Session, identity_factory: IdentityFactory
) -> None:
    """The load is tenant-scoped, so evaluation cannot see a foreign policy."""
    owner = identity_factory(role_code="owner")
    stranger = identity_factory(role_code="owner")
    _create(_repository(integration_session, owner), status=PolicyStatus.ACTIVE)

    assert (
        _repository(integration_session, stranger).active_definitions(Resource.AGENT, Action.UPDATE)
        == []
    )


def test_a_policy_row_is_never_read_without_a_tenant(
    integration_session: Session, identity_factory: IdentityFactory
) -> None:
    """Constructing the repository without a tenant is refused before any query."""
    with pytest.raises(TenantScopeError):
        PolicyRepository(integration_session)


def test_the_orm_models_declare_the_same_constraint_names_as_the_database(
    integration_engine: Engine,
) -> None:
    """``alembic check`` covers the columns; this covers the names a caller sees.

    A translated constraint violation (:class:`ConflictError`) is matched by name, so
    a rename in the model or the migration without the other would turn a 409 into a
    500 — quietly, and only under a race.
    """
    live = {
        name for name, _definition in _constraint_statements(integration_engine, "policy_versions")
    }
    live |= {name for name, _definition in _constraint_statements(integration_engine, "policies")}
    declared = {
        constraint.name
        for table in (Policy.__table__, PolicyVersion.__table__)
        for constraint in table.constraints
        if constraint.name
    }

    assert declared <= live, f"declared but not enforced: {declared - live}"


def test_every_policy_table_is_tenant_owned() -> None:
    """The isolation guard reads columns, so the columns have to be there."""
    assert "organization_id" in Policy.__table__.columns
    assert "organization_id" in PolicyVersion.__table__.columns
