"""The action vocabulary: a closed catalogue, and a request that cannot widen it.

Phase 7's claim is that the build can be asked to do exactly one thing, that the thing
is written in source rather than stored in a row or named by a caller, and that the
arguments of a request are validated before anything decides whether it may run. These
tests are the pure half of that: no database, no HTTP, no clock.

What they assert, in order:

- the catalogue is one entry, and every entry is internally consistent — an identifier,
  a target resource from the permission vocabulary, a sensitivity, an adapter something
  registered, and an input schema that refuses keys it does not declare;
- building a registry refuses the mistakes that would make a catalogue unreviewable
  (a duplicate, a bare name, an adapter that does not exist);
- a request is assembled by the *server*: the identity fields are not client fields,
  and a request that exists carries arguments its action's schema already accepted;
- the idempotency key and the correlation id are bounded and opaque, and the
  fingerprint that identifies "the same request" covers what was asked for and nothing
  about who asked.
"""

from __future__ import annotations

import dataclasses
import uuid

import pytest
from pydantic import BaseModel, ConfigDict, Field

from aicore_api.core.actions import (
    ACTION_ID_PATTERN,
    AGENT_POSTURE_CHECK,
    DEFAULT_ACTIONS,
    IDEMPOTENCY_KEY_PATTERN,
    MAX_ACTION_ARGUMENTS,
    MAX_ARGUMENT_KEY_LENGTH,
    MAX_ARGUMENT_LIST_LENGTH,
    MAX_ARGUMENT_STRING_LENGTH,
    ActionArgumentError,
    ActionDefinition,
    ActionDefinitionError,
    ActionError,
    ActionRegistry,
    ActionRequest,
    ActionSensitivity,
    ActionTarget,
    AgentPostureArguments,
    UnknownActionError,
    default_action_registry,
)
from aicore_api.core.assets import Environment
from aicore_api.core.executors import DEFAULT_EXECUTORS
from aicore_api.core.permissions import Action, Permission, Resource
from aicore_api.core.policy import ConditionField


def _request(**overrides: object) -> ActionRequest:
    """A valid request, built the way the route builds one."""
    fields: dict[str, object] = {
        "definition": AGENT_POSTURE_CHECK,
        "organization_id": uuid.uuid4(),
        "principal_id": uuid.uuid4(),
        "membership_id": uuid.uuid4(),
        "target_id": uuid.uuid4(),
        "environment": Environment.PRODUCTION,
        "arguments": {},
        "correlation_id": "request-id-0001",
        "idempotency_key": "key-0001",
    }
    fields.update(overrides)
    return ActionRequest.build(**fields)  # type: ignore[arg-type]


# ── The catalogue ────────────────────────────────────────────────────────────


def test_the_catalogue_is_one_action_and_the_registry_serves_it() -> None:
    """One action, and the registry is the same object however it is reached.

    Stated as three assertions because they answer three different questions: which
    actions exist, whether the process-wide registry serves them, and whether the
    registry can be reached by identifier at all.
    """
    assert DEFAULT_ACTIONS.action_ids() == ("agent.posture_check",)
    assert len(DEFAULT_ACTIONS) == 1
    assert default_action_registry() is DEFAULT_ACTIONS
    assert AGENT_POSTURE_CHECK in default_action_registry().definitions()


def test_every_registered_action_is_internally_consistent() -> None:
    """A catalogue entry names what it does, where it acts, and who runs it.

    The assertions read the definitions rather than restating them, so this test
    cannot agree with a broken entry: it would fail on the field that is wrong.
    """
    for definition in DEFAULT_ACTIONS.definitions():
        assert definition.action_id == definition.action_id.lower()
        assert "." in definition.action_id
        assert 0 < len(definition.description) <= 200
        assert isinstance(definition.target_resource, Resource)
        assert definition.permission is Permission.ACTION_EXECUTE
        assert definition.policy_target == (Resource.ACTION, Action.EXECUTE)
        assert definition.requires_existing_target is True
        assert definition.argument_model.model_config.get("extra") == "forbid"

    # The adapter each definition names exists, and the whole set of adapters the
    # catalogue reaches is the one this build registered.
    assert DEFAULT_ACTIONS.executor_ids() == frozenset(
        definition.executor_id for definition in DEFAULT_ACTIONS.definitions()
    )
    for executor_id in DEFAULT_ACTIONS.executor_ids():
        assert executor_id in DEFAULT_EXECUTORS
        assert DEFAULT_EXECUTORS.get(executor_id) is not None


def test_the_catalogue_touches_nothing_this_phase_cannot_undo() -> None:
    """Everything registered is ``routine``: it reads and reports, and changes nothing.

    A ``controlled`` or ``sensitive`` action would mean this phase ships something with
    side effects, which is exactly what it does not do. Asserted over the whole
    catalogue so registering one later is a decision a reviewer sees.
    """
    assert {definition.sensitivity for definition in DEFAULT_ACTIONS.definitions()} == {
        ActionSensitivity.ROUTINE
    }


def test_the_reference_action_addresses_agent_rows() -> None:
    """The one action addresses the registry, and its adapter is the registry adapter."""
    assert AGENT_POSTURE_CHECK.target_resource is Resource.AGENT
    assert AGENT_POSTURE_CHECK.executor_id == "agent_registry"
    assert AGENT_POSTURE_CHECK.argument_model is AgentPostureArguments


def test_an_unknown_identifier_is_refused_and_the_catalogue_is_named() -> None:
    """A request cannot invent an action, and the refusal says what does exist.

    The catalogue is not a secret — it is the list of things a client may ask for — so
    the message names it. What matters is that resolution *ends* here: nothing is
    imported, loaded or guessed to satisfy the identifier.
    """
    for candidate in (
        "agent.posture_check_v2",
        "agent.execute",
        "shell.run",
        "os.system",
        "importlib.import_module",
        "agent.posture_check.extra",
        "",
    ):
        with pytest.raises(UnknownActionError) as refusal:
            DEFAULT_ACTIONS.resolve(candidate)
        assert "agent.posture_check" in str(refusal.value)
    assert DEFAULT_ACTIONS.get("agent.execute") is None
    assert "agent.execute" not in DEFAULT_ACTIONS


# ── Building a catalogue: the mistakes that must be impossible ───────────────


class _Arguments(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    detail: bool = Field(default=False)


class _Permissive(BaseModel):
    """An input schema that would silently ignore a key it does not declare."""

    detail: bool = Field(default=False)


def _definition(**overrides: object) -> ActionDefinition:
    fields: dict[str, object] = {
        "action_id": "agent.example",
        "description": "An example action, for the tests that build catalogues.",
        "target_resource": Resource.AGENT,
        "sensitivity": ActionSensitivity.ROUTINE,
        "argument_model": _Arguments,
        "executor_id": "agent_registry",
    }
    fields.update(overrides)
    return ActionDefinition(**fields)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "action_id",
    [
        "example",  # a bare name: not a name for something
        "Agent.Example",  # upper case
        "agent-example",  # not dotted
        ".example",
        "agent.",
        "agent..example",
        "agent.example!",
        1,
        None,
    ],
)
def test_an_identifier_that_is_not_an_action_identifier_cannot_be_registered(
    action_id: object,
) -> None:
    """Registration is where a catalogue mistake must be loud.

    The same pattern the permission vocabulary uses, asserted through the definition
    so the registry cannot hold an identifier no client could ever name.
    """
    with pytest.raises(ActionDefinitionError):
        _definition(action_id=action_id)


def test_an_identifier_cannot_be_longer_than_the_column_that_stores_it() -> None:
    """The bound is the column's: an identifier the database cannot hold is not one."""
    with pytest.raises(ActionDefinitionError):
        _definition(action_id=f"agent.{'x' * 64}")


def test_a_definition_must_state_what_it_does_and_who_runs_it() -> None:
    """No description, a foreign target, an unknown adapter: all refused at build time."""
    with pytest.raises(ActionDefinitionError):
        _definition(description="")
    with pytest.raises(ActionDefinitionError):
        _definition(description="x" * 201)
    with pytest.raises(ActionDefinitionError):
        _definition(target_resource="agent")
    with pytest.raises(ActionDefinitionError):
        _definition(sensitivity="routine")
    with pytest.raises(ActionDefinitionError):
        _definition(executor_id="not a dotted path")
    with pytest.raises(ActionDefinitionError):
        _definition(executor_id="")
    with pytest.raises(ActionDefinitionError):
        _definition(argument_model=dict)


def test_an_input_schema_that_would_ignore_unknown_keys_cannot_be_registered() -> None:
    """``extra="forbid"`` is required, not recommended.

    A schema that dropped an undeclared key would turn a typo into a silent default —
    and, worse, would make "the arguments a request carries" and "the arguments the
    adapter sees" two different things.
    """
    with pytest.raises(ActionDefinitionError) as refusal:
        _definition(argument_model=_Permissive)
    assert "unknown keys" in str(refusal.value)


def test_a_registry_refuses_two_actions_with_one_identifier() -> None:
    """One identifier names exactly one action: a duplicate is a build failure."""
    with pytest.raises(ActionDefinitionError):
        ActionRegistry((_definition(), _definition()))


def test_a_registry_refuses_a_definition_whose_adapter_is_missing() -> None:
    """An action whose adapter does not exist could be authorized and never run."""
    with pytest.raises(ActionDefinitionError) as refusal:
        ActionRegistry(
            (_definition(executor_id="nothing_registered"),),
            executor_ids=("agent_registry",),
        )
    assert "nothing_registered" in str(refusal.value)


def test_a_registry_refuses_values_that_are_not_definitions() -> None:
    """The catalogue holds definitions, not dictionaries that resemble them."""
    with pytest.raises(ActionDefinitionError):
        ActionRegistry(({"action_id": "agent.example"},))  # type: ignore[arg-type]


# ── Arguments ────────────────────────────────────────────────────────────────


def test_the_schema_decides_which_keys_an_action_has() -> None:
    """An unknown key, a wrong type and a value outside the closed set are all refused."""
    parsed = AGENT_POSTURE_CHECK.parse_arguments({"report_detail": "full"})
    assert isinstance(parsed, AgentPostureArguments)
    assert parsed.report_detail == "full"
    # The default is applied by the schema, so an empty body is a valid request.
    assert AGENT_POSTURE_CHECK.parse_arguments({}).report_detail == "summary"

    for arguments in (
        {"report_detail": "everything"},  # outside the literals
        {"report_detail": True},  # strict: a boolean is not a string
        {"report_detail": 1},
        {"report_detail": None},
        {"detail": "full"},  # a key the action does not have
        {"report_detail": "full", "extra": "x"},
        {"report_detail": {"nested": "object"}},
    ):
        with pytest.raises(ActionArgumentError):
            AGENT_POSTURE_CHECK.parse_arguments(arguments)


def test_arguments_are_bounded_before_any_schema_sees_them() -> None:
    """Bounds on *work*, applied to every action: keys, strings, lists, nesting."""
    schema = AGENT_POSTURE_CHECK

    with pytest.raises(ActionArgumentError):
        schema.parse_arguments({f"key{index}": index for index in range(MAX_ACTION_ARGUMENTS + 1)})
    with pytest.raises(ActionArgumentError):
        schema.parse_arguments({"k" * (MAX_ARGUMENT_KEY_LENGTH + 1): "x"})
    with pytest.raises(ActionArgumentError):
        schema.parse_arguments({"report_detail": "x" * (MAX_ARGUMENT_STRING_LENGTH + 1)})
    with pytest.raises(ActionArgumentError):
        schema.parse_arguments({"detail": ["x"] * (MAX_ARGUMENT_LIST_LENGTH + 1)})
    with pytest.raises(ActionArgumentError):
        schema.parse_arguments({"detail": {"nested": {"deep": "object"}}})
    with pytest.raises(ActionArgumentError):
        schema.parse_arguments({"detail": None})  # type: ignore[dict-item]
    with pytest.raises(ActionArgumentError):
        schema.parse_arguments(["not", "a", "mapping"])  # type: ignore[arg-type]


def test_a_refusal_never_repeats_what_the_caller_sent() -> None:
    """The message names the location and the schema's rule, never the value.

    A request body is attacker-chosen input. A refusal that quotes it is how a secret
    ends up in a log file, so the wording is built from the schema — asserted here,
    because the property is easy to lose in a later edit.
    """
    with pytest.raises(ActionArgumentError) as refusal:
        AGENT_POSTURE_CHECK.parse_arguments({"report_detail": "hunter2-secret-value"})

    message = str(refusal.value)
    assert "report_detail" in message
    assert "hunter2" not in message


# ── The request the server assembles ─────────────────────────────────────────


def test_a_request_carries_the_identity_the_server_resolved() -> None:
    """Organization, principal, membership and correlation id come from the server."""
    organization_id = uuid.uuid4()
    request = _request(organization_id=organization_id, idempotency_key="key-0001")

    assert request.organization_id == organization_id
    assert request.action_id == AGENT_POSTURE_CHECK.action_id
    assert request.environment is Environment.PRODUCTION
    assert isinstance(request.arguments, AgentPostureArguments)
    # The repr names the request; it never renders the arguments it carries.
    assert "arguments" not in repr(request)


def test_a_request_cannot_be_built_from_values_a_client_controls() -> None:
    """The constructor refuses anything that is not a validated value.

    ``build`` is the only door the route uses, and it validates the arguments against
    the action's schema. The checks below are the ones that would matter if a future
    caller tried to assemble a request out of raw body fields.
    """
    with pytest.raises(ActionArgumentError):
        _request(arguments={"report_detail": "everything"})
    with pytest.raises(ActionError):
        _request(organization_id="not-a-uuid")
    with pytest.raises(ActionError):
        _request(target_id=str(uuid.uuid4()))
    with pytest.raises(ActionError):
        _request(environment="production")
    # ``build`` validates a raw mapping (that is the point of ``build``); the
    # constructor itself accepts only the model it produced, so a caller cannot
    # assemble a request out of unvalidated body fields.
    with pytest.raises(ActionError):
        ActionRequest(
            organization_id=uuid.uuid4(),
            principal_id=uuid.uuid4(),
            membership_id=uuid.uuid4(),
            action_id="agent.posture_check",
            target_id=uuid.uuid4(),
            environment=Environment.PRODUCTION,
            arguments={"report_detail": "summary"},  # type: ignore[arg-type]
            correlation_id="request-id-0001",
            idempotency_key="key-0001",
        )
    with pytest.raises(ActionError):
        _request(idempotency_key="not a key")
    with pytest.raises(ActionError):
        _request(idempotency_key="")
    with pytest.raises(ActionError):
        _request(correlation_id="bad\nvalue")


@pytest.mark.parametrize(
    "candidate",
    ["short", "with-dash", "with_underscore", "with.dot", "with:colon", "A" * 128],
)
def test_an_idempotency_key_is_an_opaque_bounded_token(candidate: str) -> None:
    """The key is stored, compared and echoed — never interpreted, never a path."""
    assert _request(idempotency_key=candidate).idempotency_key == candidate


@pytest.mark.parametrize(
    "candidate",
    ["", "with space", "with/slash", "with'quote", "with%percent", "A" * 129, "unicode-é"],
)
def test_an_idempotency_key_that_is_not_a_token_is_refused(candidate: str) -> None:
    """A key that could mean something to a query, a path or a shell is not a key."""
    with pytest.raises(ActionError):
        _request(idempotency_key=candidate)


def test_the_fingerprint_describes_the_request_and_not_the_caller() -> None:
    """Same request, same fingerprint; different request, different fingerprint.

    This is what makes an idempotency replay safe: a key reused for a *different*
    request must not be answered with the first request's result, and a retry that
    happens to carry a new correlation id is still the same retry.
    """
    target_id = uuid.uuid4()
    base = _request(target_id=target_id)
    same = _request(
        target_id=target_id,
        organization_id=base.organization_id,
        principal_id=base.principal_id,
        membership_id=base.membership_id,
        correlation_id="a-different-request-id",
        idempotency_key="a-different-key",
    )

    assert base.fingerprint == same.fingerprint
    assert len(base.fingerprint) == 64

    assert _request(target_id=uuid.uuid4()).fingerprint != base.fingerprint
    assert (
        _request(target_id=target_id, environment=Environment.STAGING).fingerprint
        != base.fingerprint
    )
    assert (
        _request(target_id=target_id, arguments={"report_detail": "full"}).fingerprint
        != base.fingerprint
    )
    assert _request(target_id=target_id, agent_id=uuid.uuid4()).fingerprint != base.fingerprint


def test_the_identifiers_have_one_shape_wherever_they_are_written() -> None:
    """The patterns the model, the schema and the migration all state are one pattern."""
    assert ACTION_ID_PATTERN == r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$"
    assert IDEMPOTENCY_KEY_PATTERN == r"^[A-Za-z0-9._:-]{1,128}$"


# ── Targets ──────────────────────────────────────────────────────────────────


def test_a_target_carries_facts_the_server_could_attest() -> None:
    """Facts are the policy vocabulary, and an unknown field is refused."""
    identifier = uuid.uuid4()
    target = ActionTarget(
        resource=Resource.AGENT,
        identifier=identifier,
        facts={ConditionField.ENVIRONMENT: "production"},
    )

    assert target.environment is Environment.PRODUCTION
    assert target.identifier == identifier

    with pytest.raises(ActionError):
        ActionTarget(
            resource=Resource.AGENT,
            identifier=identifier,
            facts={"nonsense": "x"},  # type: ignore[dict-item]
        )
    with pytest.raises(ActionError):
        ActionTarget(resource="agent", identifier=identifier)  # type: ignore[arg-type]
    with pytest.raises(ActionError):
        ActionTarget(resource=Resource.AGENT, identifier="not-a-uuid")  # type: ignore[arg-type]


def test_a_target_without_a_usable_environment_says_so() -> None:
    """``None`` is "cannot confirm", which the firewall treats as a refusal."""
    identifier = uuid.uuid4()
    assert ActionTarget(resource=Resource.AGENT, identifier=identifier).environment is None
    assert (
        ActionTarget(
            resource=Resource.AGENT,
            identifier=identifier,
            facts={ConditionField.ENVIRONMENT: "atlantis"},
        ).environment
        is None
    )


def test_a_definition_can_be_replaced_without_mutating_the_catalogue() -> None:
    """Definitions are frozen values: a test (or a later phase) builds a new one.

    Asserted because the alternative — a mutable catalogue — is how a test suite ends
    up proving things about a registry the application does not use.
    """
    replacement = dataclasses.replace(AGENT_POSTURE_CHECK, executor_id="agent_registry")
    assert replacement == AGENT_POSTURE_CHECK
    with pytest.raises(dataclasses.FrozenInstanceError):
        AGENT_POSTURE_CHECK.action_id = "agent.something_else"  # type: ignore[misc]
