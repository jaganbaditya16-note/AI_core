"""The condition language: a closed vocabulary, typed values, no expressions.

A policy engine's security comes from what it *cannot* express. This language has no
arbitrary expressions, no user-supplied Python, no ``eval()``, no SQL a policy author
composes, no OR, no nesting and no free-form strings: a condition is one field, one
operator from a closed set, and a value that is validated against the field's own type
and closed set (or numeric bounds) *before* it is stored.

These tests are about the language itself — what it accepts, what it refuses, and the
fact that the vocabulary is derived from the entities it describes rather than
written out twice. Evaluation semantics (which conditions match, what several
matching policies mean) are in ``test_policy_engine.py``; the API's use of the same
validators is in ``test_policies_api.py``.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping

import pytest
from pydantic import ValidationError

from aicore_api.core.agents import AgentCategory
from aicore_api.core.assets import AssetStatus, AssetType, Environment, RiskClassification
from aicore_api.core.permissions import RESOURCE_ACTIONS, Action, Permission, Resource, RoleCode
from aicore_api.core.policy import (
    CONDITION_FIELDS,
    DEFAULT_PRIORITY,
    EFFECT_PRECEDENCE,
    MAX_CONDITIONS,
    MAX_SET_VALUES,
    ORDERED_OPERATORS,
    POLICY_INITIAL_STATES,
    POLICY_TARGETS,
    POLICY_TRANSITIONS,
    PRIORITY_MAX,
    PRIORITY_MIN,
    SET_OPERATORS,
    ConditionField,
    ConditionOperator,
    ContextValueType,
    PolicyCondition,
    PolicyDefinition,
    PolicyDefinitionError,
    PolicyEffect,
    PolicyError,
    PolicyStatus,
    UnknownPolicyTargetError,
    conditions_from_stored,
    normalize_description,
    normalize_name,
    target_permission,
    validate_condition,
    validate_conditions,
    validate_definition,
    validate_field_value,
    validate_initial_status,
    validate_priority,
    validate_target,
    validate_transition,
)

#: A condition that is valid in every part, for the tests that change one part.
VALID_CONDITION: dict[str, object] = {
    "field": "environment",
    "operator": "equals",
    "value": "production",
}


# ── The vocabulary ───────────────────────────────────────────────────────────


def test_the_operator_set_is_closed_and_exactly_the_documented_eight() -> None:
    """No expression language, no negation of a whole policy, no ``matches``."""
    assert {operator.value for operator in ConditionOperator} == {
        "equals",
        "not_equals",
        "in",
        "not_in",
        "less_than",
        "less_than_or_equal",
        "greater_than",
        "greater_than_or_equal",
    }
    assert set(ConditionOperator) >= SET_OPERATORS | ORDERED_OPERATORS
    assert not SET_OPERATORS & ORDERED_OPERATORS


def test_the_field_vocabulary_is_closed_and_small() -> None:
    """Eight fields, each one answerable from genuinely available context.

    Deliberately absent: request source, tool or model identifiers, IP addresses,
    user ids, agent ids, free-form metadata, and anything a caller could claim. A
    field nobody can supply would be a condition that never matches, and a field a
    caller could claim would be a condition that can be spoofed.
    """
    assert {field.value for field in ConditionField} == {
        "environment",
        "asset_type",
        "resource_status",
        "risk_classification",
        "agent_category",
        "user_role",
        "is_resource_owner",
        "agent_age_days",
        "asset_age_days",
    }
    for forbidden in ("request_source", "tool", "model", "ip", "user_id", "agent_id", "metadata"):
        assert forbidden not in {field.value for field in ConditionField}


def test_each_field_declares_a_type_and_the_strings_are_closed_sets() -> None:
    """The shape of the table itself: type, and a closed set exactly where it applies."""
    for field, spec in CONDITION_FIELDS.items():
        assert spec.description, f"{field} has no description"
        if spec.value_type is ContextValueType.STRING:
            assert spec.allowed_values, f"{field} is a string field with no closed set"
            assert spec.minimum is None and spec.maximum is None
        elif spec.value_type is ContextValueType.BOOLEAN:
            assert spec.allowed_values is None
        else:
            assert spec.value_type is ContextValueType.NUMBER
            assert spec.allowed_values is None
            assert spec.minimum is not None and spec.maximum is not None


def test_the_field_vocabulary_is_derived_from_the_entities_it_describes() -> None:
    """A new environment, category or role becomes usable by existing, not by editing.

    The alternative — a second, hand-written list of allowed values — is how a policy
    language drifts away from the objects policies are written about, and how an
    author ends up unable to write a condition about something the inventory stores.
    """
    expected = {
        ConditionField.ENVIRONMENT: {member.value for member in Environment},
        ConditionField.ASSET_TYPE: {member.value for member in AssetType},
        # Only the inventory carries a lifecycle state. An agent record deliberately
        # has none of its own (its identity's status belongs to the asset it is
        # registered as), so there is no second set to include here — and a policy
        # that asks about ``resource_status`` for a target whose context has none
        # simply does not match rather than being guessed at.
        ConditionField.RESOURCE_STATUS: {member.value for member in AssetStatus},
        ConditionField.RISK_CLASSIFICATION: {member.value for member in RiskClassification},
        ConditionField.AGENT_CATEGORY: {member.value for member in AgentCategory},
        ConditionField.USER_ROLE: {member.value for member in RoleCode},
    }

    for field, values in expected.items():
        assert CONDITION_FIELDS[field].allowed_values == values, field
        # …and every one of them is accepted where it is declared.
        for value in values:
            assert validate_field_value(field, value) == value


def test_the_targets_are_exactly_the_declared_permissions() -> None:
    """A policy targets a capability this build has, or it is refused."""
    declared = {
        (resource, action) for resource, actions in RESOURCE_ACTIONS.items() for action in actions
    }

    reachable = {
        (resource, action) for resource, actions in POLICY_TARGETS.items() for action in actions
    }
    assert reachable == declared
    for resource, action in sorted(reachable, key=lambda pair: (pair[0].value, pair[1].value)):
        resolved_resource, resolved_action = validate_target(resource.value, action.value)
        assert (resolved_resource, resolved_action) == (resource, action)
        assert target_permission(resource, action) is Permission.parse(
            f"{resource.value}.{action.value}"
        )


@pytest.mark.parametrize(
    ("resource", "action"),
    [
        ("firewall", "block"),
        ("incident", "create"),
        ("kill", "execute"),
        ("tool", "invoke"),
        ("agent", "execute"),
        ("agent", "manage"),
        ("model", "read"),
        ("policy", "execute"),
        ("policy", "evaluate"),
        ("policy", "approve"),
    ],
)
def test_a_target_this_build_does_not_declare_is_refused(resource: str, action: str) -> None:
    """Runtime control, incidents, tools and approval are other phases' vocabulary.

    ``policy.execute`` is singled out: policies are evaluated, and nothing in this
    build lets a policy *do* anything. A target naming execution would be a claim
    the application cannot honour.
    """
    with pytest.raises(UnknownPolicyTargetError):
        validate_target(resource, action)


def test_an_undeclared_target_is_a_definition_error() -> None:
    """Callers catch the definition error; the target error is a narrower one."""
    assert issubclass(UnknownPolicyTargetError, PolicyDefinitionError)
    assert issubclass(PolicyDefinitionError, PolicyError)
    assert issubclass(PolicyError, ValueError)


# ── Valid conditions ─────────────────────────────────────────────────────────


def test_a_condition_round_trips_through_the_shape_it_is_stored_in() -> None:
    """The wire format, the stored JSON and the validated model are one thing."""
    condition = PolicyCondition.model_validate(VALID_CONDITION)

    assert condition.as_payload() == VALID_CONDITION
    assert validate_conditions([condition]) == (condition,)
    assert validate_conditions([VALID_CONDITION]) == (condition,)
    assert validate_conditions(conditions_from_stored([VALID_CONDITION], source="x")) == (
        condition,
    )


def test_a_condition_is_immutable() -> None:
    """A validated condition cannot be changed after it was checked."""
    condition = PolicyCondition.model_validate(VALID_CONDITION)

    with pytest.raises(ValidationError):
        condition.value = "staging"  # type: ignore[misc]


@pytest.mark.parametrize(
    "condition",
    [
        {"field": "environment", "operator": "not_equals", "value": "production"},
        {"field": "environment", "operator": "in", "value": ["production", "staging"]},
        {"field": "environment", "operator": "not_in", "value": ["production"]},
        {"field": "is_resource_owner", "operator": "equals", "value": True},
        {"field": "is_resource_owner", "operator": "not_equals", "value": False},
        {"field": "agent_age_days", "operator": "less_than", "value": 30},
        {"field": "asset_age_days", "operator": "less_than_or_equal", "value": 7.5},
        {"field": "asset_age_days", "operator": "greater_than", "value": 0},
        {"field": "asset_age_days", "operator": "greater_than_or_equal", "value": 36500},
        {"field": "agent_category", "operator": "in", "value": ["coding", "autonomous"]},
        {"field": "user_role", "operator": "not_in", "value": ["owner", "admin"]},
        {"field": "risk_classification", "operator": "equals", "value": "critical"},
    ],
)
def test_every_operator_is_accepted_where_it_is_meaningful(
    condition: dict[str, object],
) -> None:
    """The positive half of the table: each operator has a field it belongs with."""
    field, operator, value = validate_condition(
        condition["field"],
        condition["operator"],
        condition["value"],  # type: ignore[arg-type]
    )

    assert field.value == condition["field"]
    assert operator.value == condition["operator"]
    assert value == condition["value"]


# ── Refusals: shape, type, membership, bounds ────────────────────────────────


@pytest.mark.parametrize(
    "condition",
    [
        {"field": "request_source", "operator": "equals", "value": "cli"},
        {"field": "environment", "operator": "sql_like", "value": "%prod%"},
        {"field": "environment", "operator": "equals", "value": "production", "extra": 1},
        {"field": "environment", "operator": "equals"},
        {"field": "environment", "value": "production"},
        {"operator": "equals", "value": "production"},
        {},
    ],
)
def test_a_condition_that_is_not_the_declared_shape_is_refused(
    condition: Mapping[str, object],
) -> None:
    """No unknown field, no unknown operator, no extra keys, no missing parts.

    An extra key is the interesting one: a policy author who writes
    ``{"field": ..., "operator": ..., "value": ..., "note": ...}`` should be told,
    not silently ignored — a condition whose meaning came from a key the engine does
    not read would be a policy that does not do what it says.
    """
    with pytest.raises(PolicyDefinitionError):
        validate_conditions([dict(condition)])


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("environment", 1),
        ("environment", True),
        ("environment", ["production"]),
        ("environment", None),
        ("environment", {"value": "production"}),
        ("is_resource_owner", 1),
        ("is_resource_owner", "true"),
        ("is_resource_owner", None),
        ("agent_age_days", "seven"),
        ("agent_age_days", True),
        ("agent_age_days", None),
        ("agent_age_days", [7]),
    ],
)
def test_a_value_of_the_wrong_type_is_refused(field: str, value: object) -> None:
    """Typed comparison, and ``None`` is not a value this language has.

    ``None`` is refused rather than treated as "any": a condition cannot ask "is this
    field absent?", because absence means the context did not carry the fact and the
    answer to every operator is then "does not match".
    """
    with pytest.raises(PolicyDefinitionError):
        validate_condition(field, "equals", value)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("environment", "Production"),
        ("environment", "prod"),
        ("environment", " production"),
        ("asset_type", "llm"),
        ("risk_classification", "severe"),
        ("agent_category", "chatbot"),
        ("user_role", "root"),
        ("resource_status", "archived"),
        ("asset_age_days", -1),
        ("asset_age_days", 36501),
        ("agent_age_days", 10**9),
    ],
)
def test_a_value_outside_the_closed_set_or_the_bounds_is_refused(field: str, value: object) -> None:
    """Case-sensitive, exact, and bounded: no near-miss becomes a policy."""
    with pytest.raises(PolicyDefinitionError):
        validate_condition(field, "equals", value)


def test_a_numeric_comparison_is_refused_on_a_field_without_an_order() -> None:
    """``less_than`` on an environment would compare strings by accident."""
    for field in ("environment", "asset_type", "is_resource_owner"):
        with pytest.raises(PolicyDefinitionError, match="orders numbers"):
            validate_condition(field, "less_than", 1)


def test_a_set_comparison_is_refused_on_a_boolean_field() -> None:
    """A set of booleans is an ``equals`` in disguise, and misleading as written."""
    for operator in ("in", "not_in"):
        with pytest.raises(PolicyDefinitionError, match="boolean field"):
            validate_condition("is_resource_owner", operator, [True, False])


@pytest.mark.parametrize("value", [[], (), "", 1, None, {"a": 1}])
def test_a_set_operator_requires_a_non_empty_list(value: object) -> None:
    """An empty set matches nothing or everything by accident; both are mistakes."""
    for operator in ("in", "not_in"):
        with pytest.raises(PolicyDefinitionError):
            validate_condition("environment", operator, value)


def test_a_set_operator_is_bounded_and_typed_element_by_element() -> None:
    """The bound on work, and no list whose members are not values of the field."""
    too_many = ["production"] * (MAX_SET_VALUES + 1)
    mixed = ["production", 1]
    nested = [["production"]]

    for value in (too_many, mixed, nested):
        with pytest.raises(PolicyDefinitionError):
            validate_condition("environment", "in", value)


def test_the_same_rule_validates_a_condition_value_and_a_context_fact() -> None:
    """One function, two callers: a condition can never be written about a value the
    context cannot carry, and a context can never carry a value no condition may
    compare against."""
    assert validate_field_value("environment", "production") == "production"
    assert validate_condition("environment", "equals", "production")[2] == "production"

    refused = (("environment", "Production"), ("agent_age_days", -1), ("is_resource_owner", 1))
    for field, value in refused:
        assert _both_refuse(field, value)


def _both_refuse(field: str, value: object) -> bool:
    for call in (
        lambda: validate_field_value(field, value),
        lambda: validate_condition(field, "equals", value),
    ):
        with pytest.raises(PolicyDefinitionError):
            call()
    return True


def test_a_list_of_conditions_is_bounded_and_ordered_as_written() -> None:
    """AND semantics, a bounded list, and an order that is preserved for review."""
    many = [dict(VALID_CONDITION) for _ in range(MAX_CONDITIONS)]
    validated = validate_conditions(many)
    assert isinstance(validated, tuple)
    assert len(validated) == MAX_CONDITIONS

    with pytest.raises(PolicyDefinitionError, match="at most"):
        validate_conditions([*many, dict(VALID_CONDITION)])


def test_conditions_are_allowed_to_be_empty_and_an_empty_rule_is_a_blanket_rule() -> None:
    """``[]`` is not "invalid": it means "no conditions", which matches on the target."""
    assert validate_conditions([]) == ()


@pytest.mark.parametrize("raw", ["environment=production", 1, None, {"field": "environment"}])
def test_conditions_that_are_not_a_list_are_refused(raw: object) -> None:
    """The stored shape is an array; anything else is a defect, not a policy."""
    with pytest.raises(PolicyDefinitionError):
        validate_conditions(raw)  # type: ignore[arg-type]


def test_a_stored_row_that_cannot_be_read_names_itself() -> None:
    """A deployment defect is reported with an address, and never skipped.

    Skipping an unreadable policy would silently change what the organization's
    policy says — and skipping a *denial* is permitting the action.
    """
    with pytest.raises(PolicyDefinitionError, match="policy 'x' version 3"):
        conditions_from_stored(
            [{"field": "environment", "operator": "equals", "value": "prod"}],
            source="policy 'x' version 3",
        )

    with pytest.raises(PolicyDefinitionError, match="not a list"):
        conditions_from_stored({"field": "environment"}, source="policy 'x' version 3")

    assert conditions_from_stored([], source="policy 'x' version 3") == ()


# ── Lifecycle, effects, priority and targets: the closed tables ──────────────


def test_the_lifecycle_table_is_exactly_the_documented_one() -> None:
    """Who may move a policy where, written out as data a test can enumerate."""
    assert {
        status: {target.value for target in targets}
        for status, targets in POLICY_TRANSITIONS.items()
    } == {
        PolicyStatus.DRAFT: {"active", "retired"},
        PolicyStatus.ACTIVE: {"disabled", "retired"},
        PolicyStatus.DISABLED: {"active", "retired"},
        PolicyStatus.RETIRED: set(),
    }


def test_only_draft_and_active_are_initial_states() -> None:
    """A policy cannot be born disabled or retired; those are states it moves to."""
    assert {PolicyStatus.DRAFT, PolicyStatus.ACTIVE} == POLICY_INITIAL_STATES
    assert validate_initial_status("draft") is PolicyStatus.DRAFT
    assert validate_initial_status(PolicyStatus.ACTIVE) is PolicyStatus.ACTIVE
    for status in ("disabled", "retired"):
        with pytest.raises(PolicyDefinitionError):
            validate_initial_status(status)


def test_the_transition_table_refuses_every_move_it_does_not_list() -> None:
    """Every pair is checked, so the allowed set is the table and nothing else."""
    for current in PolicyStatus:
        for target in PolicyStatus:
            allowed = current == target or target in POLICY_TRANSITIONS[current]
            if allowed:
                validate_transition(current, target)
            else:
                with pytest.raises(PolicyDefinitionError):
                    validate_transition(current, target)


def test_a_retired_policy_is_terminal_and_the_refusal_says_so() -> None:
    """Retiring is the non-destructive alternative to deleting; it is not reversible."""
    with pytest.raises(PolicyDefinitionError, match="terminal"):
        validate_transition("retired", "active")


def test_effect_precedence_orders_deny_over_approval_over_allow() -> None:
    """The rule that makes precedence deterministic rather than merely documented."""
    assert EFFECT_PRECEDENCE[PolicyEffect.DENY] > EFFECT_PRECEDENCE[PolicyEffect.REQUIRE_APPROVAL]
    assert EFFECT_PRECEDENCE[PolicyEffect.REQUIRE_APPROVAL] > EFFECT_PRECEDENCE[PolicyEffect.ALLOW]
    assert {effect.value for effect in PolicyEffect} == {"allow", "deny", "require_approval"}


def test_a_priority_is_bounded_and_low_is_more_important() -> None:
    """Bounded so it can be compared; the direction is stated in one place."""
    assert validate_priority(PRIORITY_MIN) == PRIORITY_MIN
    assert validate_priority(PRIORITY_MAX) == PRIORITY_MAX
    assert validate_priority(DEFAULT_PRIORITY) == DEFAULT_PRIORITY
    for refused in (PRIORITY_MIN - 1, PRIORITY_MAX + 1, True, 1.0, "10"):
        with pytest.raises(PolicyDefinitionError):
            validate_priority(refused)  # type: ignore[arg-type]


def test_a_name_and_a_description_are_trimmed_and_bounded() -> None:
    """Required, trimmed and bounded: a rule an operator reads in one screen."""
    assert normalize_name("  Staging guard  ") == "Staging guard"
    assert normalize_description("  Because.  ") == "Because."

    for refused in ("", "   ", "x" * 97, 1, None):
        with pytest.raises(PolicyDefinitionError):
            normalize_name(refused)  # type: ignore[arg-type]

    for refused in ("", "   ", "x" * 501):
        with pytest.raises(PolicyDefinitionError):
            normalize_description(refused)


# ── Definitions ──────────────────────────────────────────────────────────────


def _definition(**overrides: object) -> PolicyDefinition:
    fields: dict[str, object] = {
        "policy_id": uuid.uuid4(),
        "version": 1,
        "name": "Example",
        "priority": 10,
        "effect": PolicyEffect.DENY,
        "resource": Resource.AGENT,
        "action": Action.UPDATE,
        "conditions": (PolicyCondition.model_validate(VALID_CONDITION),),
    }
    fields.update(overrides)
    return PolicyDefinition(**fields)  # type: ignore[arg-type]


def test_a_definition_carries_the_version_it_was_published_as() -> None:
    """A definition is identified by (policy, version) — that is what attribution
    means, and it is why neither can be defaulted or inferred."""
    definition = _definition()

    assert definition.version == 1
    assert definition.effect is PolicyEffect.DENY
    assert definition.resource is Resource.AGENT
    assert definition.action is Action.UPDATE
    assert [condition.as_payload() for condition in definition.conditions] == [VALID_CONDITION]


def test_a_definition_validates_its_own_parts() -> None:
    """An invalid effect, priority or condition cannot be constructed at all."""
    with pytest.raises(PolicyDefinitionError):
        validate_definition(
            resource="agent",
            action="update",
            effect="permit",
            priority=10,
            conditions=[],
        )
    with pytest.raises(PolicyDefinitionError):
        validate_definition(
            resource="firewall",
            action="block",
            effect="deny",
            priority=10,
            conditions=[],
        )
    with pytest.raises(PolicyDefinitionError):
        validate_definition(
            resource="agent",
            action="update",
            effect="deny",
            priority=-1,
            conditions=[],
        )
    with pytest.raises(PolicyDefinitionError):
        validate_definition(
            resource="agent",
            action="update",
            effect="deny",
            priority=10,
            conditions=[{"field": "environment", "operator": "equals", "value": "prod"}],
        )


def test_a_valid_definition_passes_the_activation_gate() -> None:
    """The gate is the same validator the write paths call, so activation cannot
    put something in force that creation would have refused."""
    validate_definition(
        resource="agent",
        action="update",
        effect="deny",
        priority=10,
        conditions=[dict(VALID_CONDITION)],
        status="active",
    )
