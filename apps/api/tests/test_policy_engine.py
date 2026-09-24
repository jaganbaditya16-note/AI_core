"""The engine: every operator, and a decision that cannot depend on input order.

Evaluation is the part of this phase a security review reads most closely, because
it is where a policy stops being a record and starts being an answer. What follows
from that is a specific set of tests:

- **Every operator, on every kind of field.** The eight operators are the whole
  language; each one is checked where it is meaningful and refused where it is not
  (the refusals are in ``test_policy_conditions.py``).
- **Missing context never matches**, for every operator including the negated ones.
  This is the rule that keeps ``not_equals`` from being satisfied by ignorance — and
  it is why an unevaluatable condition cannot *widen* an authorization decision.
- **AND, and only AND.** One condition failing means the policy does not apply.
- **Precedence by effect, then priority, then name and id** — and, crucially, no
  dependence on the order the definitions arrived in. The same policies in a
  different order produce the same decision, byte for byte.
- **The engine is a pure function.** No clock, no database, no network: it is handed
  values and returns a value, which is what makes a decision reproducible and a
  policy unable to act.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest

from aicore_api.core.permissions import Action, Resource
from aicore_api.core.policy import (
    ConditionField,
    ConditionOperator,
    PolicyCondition,
    PolicyContextError,
    PolicyDefinition,
    PolicyDefinitionError,
    PolicyEffect,
    validate_conditions,
)
from aicore_api.core.policy_engine import (
    MAX_REPORTED_MATCHES,
    MatchedCondition,
    MatchedPolicy,
    PolicyContext,
    PolicyDecision,
    PolicyDecisionKind,
    PolicyReason,
    evaluate_condition,
    evaluate_policies,
    evaluate_policy,
)
from aicore_api.core.policy_engine import (
    ConditionField as _ReExportedField,  # noqa: F401  (imported to assert the export list)
)

ORGANIZATION_ID = uuid.UUID("11111111-1111-1111-1111-111111111111")
EVALUATED_AT = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)


def _condition(field: str, operator: str, value: object) -> PolicyCondition:
    """Validate a raw condition, so a test cannot construct an invalid one."""
    return validate_conditions([{"field": field, "operator": operator, "value": value}])[0]


def _definition(
    *,
    name: str = "Example",
    priority: int = 100,
    effect: PolicyEffect | str = PolicyEffect.DENY,
    resource: Resource | str = Resource.AGENT,
    action: Action | str = Action.UPDATE,
    conditions: object = (),
    version: int = 1,
    policy_id: uuid.UUID | None = None,
) -> PolicyDefinition:
    """A definition, with the parts the evaluator reads spelled out.

    The defaults describe a blanket deny of ``agent.update``: the simplest policy
    that does something, so a test about matching has to say what it is changing.
    """
    validated = validate_conditions(conditions) if conditions else ()
    return PolicyDefinition(
        policy_id=policy_id or uuid.uuid4(),
        version=version,
        name=name,
        priority=priority,
        effect=PolicyEffect(effect),
        resource=Resource(resource),
        action=Action(action),
        conditions=validated,
    )


def _context(
    *,
    resource: Resource | str = Resource.AGENT,
    action: Action | str = Action.UPDATE,
    **facts: object,
) -> PolicyContext:
    """A context for one target, with the facts named as keyword arguments."""
    return PolicyContext(
        organization_id=ORGANIZATION_ID,
        resource=Resource(resource),
        action=Action(action),
        facts=facts,  # type: ignore[arg-type]
    )


def _decide(definitions: object, context: PolicyContext) -> PolicyDecision:
    """Evaluate, with the timestamp the engine never invents for itself."""
    return evaluate_policies(definitions, context, evaluated_at=EVALUATED_AT)  # type: ignore[arg-type]


# ── The context ──────────────────────────────────────────────────────────────


def test_a_context_carries_only_declared_fields_with_typed_values() -> None:
    """The context is validated like the language: one vocabulary, one type rule."""
    context = _context(environment="production", is_resource_owner=True, agent_age_days=3)

    assert context.has(ConditionField.ENVIRONMENT)
    assert context.value_of(ConditionField.ENVIRONMENT) == "production"
    assert context.value_of(ConditionField.AGENT_AGE_DAYS) == 3
    assert not context.has(ConditionField.RISK_CLASSIFICATION)


@pytest.mark.parametrize(
    ("facts", "match"),
    [
        ({"request_source": "cli"}, "unknown context field"),
        ({"environment": "Production"}, "environment"),
        ({"environment": ["production"]}, "single"),
        ({"is_resource_owner": 1}, "is_resource_owner"),
        ({"agent_age_days": "seven"}, "agent_age_days"),
        ({"agent_age_days": -1}, "at least"),
    ],
)
def test_a_context_fact_outside_the_vocabulary_is_refused(
    facts: dict[str, object], match: str
) -> None:
    """A caller cannot invent a fact, mistype one, or smuggle a list in as one."""
    with pytest.raises(PolicyContextError, match=match):
        _context(**facts)


def test_a_context_refuses_a_target_no_policy_may_use() -> None:
    """The context's target is the same closed vocabulary a policy's is.

    Constructed with raw strings on purpose: the check has to live in the context
    itself, so that a caller who never went through a request model still cannot
    evaluate a target this build does not declare.
    """
    for resource, action in (("firewall", "block"), ("agent", "execute"), ("incident", "create")):
        with pytest.raises(PolicyDefinitionError):
            PolicyContext(
                organization_id=ORGANIZATION_ID,
                resource=resource,  # type: ignore[arg-type]
                action=action,  # type: ignore[arg-type]
            )


def test_a_context_is_immutable_and_frozen() -> None:
    """Determinism guard: a context cannot change between decision and record."""
    context = _context(environment="production")

    with pytest.raises(TypeError):
        context.facts[ConditionField.ENVIRONMENT] = "staging"  # type: ignore[index]

    with pytest.raises((AttributeError, TypeError)):
        context.resource = Resource.ASSET  # type: ignore[misc]


def test_an_absent_fact_is_not_the_value_unknown() -> None:
    """``unknown`` is a value of ``environment``; absence is not a value at all."""
    absent = _context()
    stated = _context(environment="unknown")

    assert not absent.has(ConditionField.ENVIRONMENT)
    assert stated.value_of(ConditionField.ENVIRONMENT) == "unknown"


# ── Every operator, where it is meaningful ───────────────────────────────────


@pytest.mark.parametrize(
    ("condition", "facts", "expected"),
    [
        # equals / not_equals on a closed-set string field
        (("environment", "equals", "production"), {"environment": "production"}, True),
        (("environment", "equals", "production"), {"environment": "staging"}, False),
        (("environment", "not_equals", "production"), {"environment": "staging"}, True),
        (("environment", "not_equals", "production"), {"environment": "production"}, False),
        # in / not_in against a list the policy states
        (("environment", "in", ["production", "staging"]), {"environment": "staging"}, True),
        (("environment", "in", ["production", "staging"]), {"environment": "development"}, False),
        (("environment", "not_in", ["production"]), {"environment": "development"}, True),
        (("environment", "not_in", ["production"]), {"environment": "production"}, False),
        # the boolean field, both operators
        (("is_resource_owner", "equals", True), {"is_resource_owner": True}, True),
        (("is_resource_owner", "equals", True), {"is_resource_owner": False}, False),
        (("is_resource_owner", "not_equals", True), {"is_resource_owner": False}, True),
        # the four ordered operators on a numeric field
        (("agent_age_days", "less_than", 30), {"agent_age_days": 3}, True),
        (("agent_age_days", "less_than", 3), {"agent_age_days": 3}, False),
        (("agent_age_days", "less_than_or_equal", 3), {"agent_age_days": 3}, True),
        (("agent_age_days", "less_than_or_equal", 3), {"agent_age_days": 4}, False),
        (("agent_age_days", "greater_than", 3), {"agent_age_days": 4}, True),
        (("agent_age_days", "greater_than", 3), {"agent_age_days": 3}, False),
        (("agent_age_days", "greater_than_or_equal", 3), {"agent_age_days": 3}, True),
        (("agent_age_days", "greater_than_or_equal", 3), {"agent_age_days": 2}, False),
        # a numeric fact against a float threshold, and vice versa
        (("asset_age_days", "less_than", 0.5), {"asset_age_days": 0}, True),
        (("asset_age_days", "greater_than", 0), {"asset_age_days": 0.25}, True),
    ],
)
def test_every_operator_has_a_field_it_belongs_with(
    condition: tuple[str, str, object], facts: dict[str, object], expected: bool
) -> None:
    """The truth table of the language, one row per operator and kind of field."""
    matches = evaluate_condition(_condition(*condition), _context(**facts))

    assert (matches is not None) is expected
    if expected:
        assert matches is not None
        assert matches.field.value == condition[0]
        assert matches.operator.value == condition[1]
        assert matches.value == condition[2]


@pytest.mark.parametrize(
    ("field", "operator", "value"),
    [
        ("environment", "equals", "production"),
        ("environment", "not_equals", "production"),
        ("environment", "in", ["production"]),
        ("environment", "not_in", ["production"]),
        ("is_resource_owner", "equals", True),
        ("is_resource_owner", "not_equals", True),
        ("agent_age_days", "less_than", 30),
        ("agent_age_days", "less_than_or_equal", 30),
        ("agent_age_days", "greater_than", 30),
        ("agent_age_days", "greater_than_or_equal", 30),
    ],
)
def test_missing_context_never_matches_for_any_operator(
    field: str, operator: str, value: object
) -> None:
    """Ignorance is not a match — and it is not a match for a negation either.

    This is the rule that stops a deny from being routed around by leaving a fact
    out: ``not_equals`` against a fact nobody supplied is not ``True``, it is
    "this policy does not apply", which leaves the authorization decision exactly
    where Phase 5 put it.
    """
    assert evaluate_condition(_condition(field, operator, value), _context()) is None


def test_an_absent_fact_on_one_condition_stops_the_whole_policy() -> None:
    """AND semantics: a policy applies only when every condition holds."""
    policy = _definition(
        conditions=[
            {"field": "environment", "operator": "equals", "value": "production"},
            {"field": "agent_age_days", "operator": "less_than", "value": 30},
        ]
    )

    assert evaluate_policy(policy, _context(environment="production", agent_age_days=3)) is not None
    assert evaluate_policy(policy, _context(environment="production")) is None
    assert evaluate_policy(policy, _context(agent_age_days=3)) is None


def test_the_matched_conditions_are_reported_with_the_facts_that_satisfied_them() -> None:
    """A decision explains itself: field, operator, stated value and actual value."""
    policy = _definition(
        conditions=[
            {"field": "environment", "operator": "in", "value": ["production", "staging"]},
            {"field": "risk_classification", "operator": "equals", "value": "high"},
        ]
    )

    matched = evaluate_policy(policy, _context(environment="staging", risk_classification="high"))

    assert matched == (
        MatchedCondition(
            field=ConditionField.ENVIRONMENT,
            operator=ConditionOperator.IN,
            value=["production", "staging"],
            actual="staging",
        ),
        MatchedCondition(
            field=ConditionField.RISK_CLASSIFICATION,
            operator=ConditionOperator.EQUALS,
            value="high",
            actual="high",
        ),
    )


def test_a_policy_with_no_conditions_applies_to_its_whole_target() -> None:
    """A blanket rule is a rule: "deny this action here" needs no conditions."""
    matched = evaluate_policy(_definition(conditions=[]), _context())

    assert matched == ()


# ── The decision ─────────────────────────────────────────────────────────────


def test_no_candidate_policy_is_a_decision_not_an_absence() -> None:
    """``not_applicable`` says "no policy addressed this" — and grants nothing."""
    decision = _decide([], _context())

    assert decision.decision is PolicyDecisionKind.NOT_APPLICABLE
    assert decision.reason is PolicyReason.NO_MATCHING_POLICY
    assert decision.applicable is False
    assert decision.allowed is False
    assert decision.denied is False
    assert decision.requires_approval is False
    assert decision.policy_id is None
    assert decision.evaluated_policies == 0


def test_a_policy_about_another_target_is_not_a_candidate() -> None:
    """The engine filters by target itself, not only because the query did."""
    other = _definition(resource=Resource.ASSET, action=Action.UPDATE)

    decision = _decide([other], _context())

    assert decision.decision is PolicyDecisionKind.NOT_APPLICABLE
    assert decision.evaluated_policies == 0


def test_a_policy_whose_conditions_do_not_match_is_counted_but_does_not_decide() -> None:
    """``evaluated_policies`` vs ``matched_policy_count``: considered, then applied."""
    policy = _definition(
        conditions=[{"field": "environment", "operator": "equals", "value": "production"}]
    )

    decision = _decide([policy], _context(environment="staging"))

    assert decision.decision is PolicyDecisionKind.NOT_APPLICABLE
    assert decision.evaluated_policies == 1
    assert decision.matched_policy_count == 0


def test_a_matching_allow_is_reported_as_the_policy_layers_own_answer() -> None:
    """``allow`` here means "no policy objects" — never "the caller may act"."""
    policy = _definition(name="Permit", effect=PolicyEffect.ALLOW, priority=5)

    decision = _decide([policy], _context())

    assert decision.decision is PolicyDecisionKind.ALLOW
    assert decision.reason is PolicyReason.MATCHING_ALLOW
    assert decision.allowed is True
    assert decision.policy_id == policy.policy_id
    assert decision.policy_version == policy.version
    assert decision.policy_name == "Permit"
    assert decision.priority == 5


def test_a_matching_deny_is_reported_with_the_version_that_produced_it() -> None:
    """A decision names the exact version, which is what makes it checkable later."""
    policy = _definition(name="Block", effect=PolicyEffect.DENY, version=7)

    decision = _decide([policy], _context())

    assert decision.denied is True
    assert decision.reason is PolicyReason.MATCHING_DENY
    assert decision.policy_version == 7


def test_require_approval_is_a_decision_value_and_not_a_permission() -> None:
    """``require_approval`` is reported; nothing here approves anything."""
    policy = _definition(effect=PolicyEffect.REQUIRE_APPROVAL)

    decision = _decide([policy], _context())

    assert decision.decision is PolicyDecisionKind.REQUIRE_APPROVAL
    assert decision.requires_approval is True
    # Not permitted outright, and not denied either: a value a later phase acts on.
    assert decision.allowed is False
    assert decision.denied is False
    assert decision.applicable is True


# ── Precedence ───────────────────────────────────────────────────────────────


def test_deny_overrides_allow_whatever_the_priorities_say() -> None:
    """The central precedence rule: a priority cannot argue a denial away."""
    allow = _definition(name="Allow", effect=PolicyEffect.ALLOW, priority=0)
    deny = _definition(name="Deny", effect=PolicyEffect.DENY, priority=1000)

    decision = _decide([allow, deny], _context())

    assert decision.decision is PolicyDecisionKind.DENY
    assert decision.policy_name == "Deny"
    assert decision.priority == 1000
    assert decision.matched_policy_count == 2


def test_deny_overrides_require_approval() -> None:
    """Adding an approval requirement cannot downgrade a denial."""
    approval = _definition(effect=PolicyEffect.REQUIRE_APPROVAL, priority=0)
    deny = _definition(effect=PolicyEffect.DENY, priority=1000)

    decision = _decide([approval, deny], _context())

    assert decision.decision is PolicyDecisionKind.DENY


def test_require_approval_overrides_allow() -> None:
    """Approval is more restrictive than a permit, and less than a denial."""
    allow = _definition(effect=PolicyEffect.ALLOW, priority=0)
    approval = _definition(effect=PolicyEffect.REQUIRE_APPROVAL, priority=1000)

    decision = _decide([allow, approval], _context())

    assert decision.decision is PolicyDecisionKind.REQUIRE_APPROVAL


def test_among_equal_effects_the_lowest_priority_decides() -> None:
    """Priority orders the *report*: which of several denies is named."""
    low = _definition(name="Low number wins", effect=PolicyEffect.DENY, priority=1)
    high = _definition(name="High number loses", effect=PolicyEffect.DENY, priority=999)
    allow = _definition(name="Also matches", effect=PolicyEffect.ALLOW, priority=0)

    decision = _decide([high, allow, low], _context())

    assert decision.policy_name == "Low number wins"
    assert decision.priority == 1
    assert decision.matched_policy_count == 3
    assert {match.name for match in decision.matched_policies} == {
        "Low number wins",
        "High number loses",
        "Also matches",
    }


def test_the_decision_does_not_depend_on_the_order_the_definitions_arrive_in() -> None:
    """Reproducibility, asserted by shuffling every permutation of a real list.

    A decision that depended on the order would be a decision that depended on how a
    query happened to return rows — which is exactly what "never rely on database row
    order" forbids, and the failure mode is silent.
    """
    definitions = [
        _definition(name="Alpha", effect=PolicyEffect.ALLOW, priority=5),
        _definition(name="Bravo", effect=PolicyEffect.DENY, priority=5),
        _definition(name="Charlie", effect=PolicyEffect.DENY, priority=5),
        _definition(name="Delta", effect=PolicyEffect.REQUIRE_APPROVAL, priority=0),
    ]
    context = _context()

    expected = _decide(definitions, context)
    assert expected.policy_name == "Bravo"  # equal effect and priority: name breaks the tie

    for rotation in range(len(definitions)):
        rotated = definitions[rotation:] + definitions[:rotation]
        assert _decide(rotated, context) == expected
    assert _decide(list(reversed(definitions)), context) == expected


def test_a_policy_that_does_not_apply_cannot_decide() -> None:
    """A deny for another environment is not a deny for this one."""
    deny = _definition(
        effect=PolicyEffect.DENY,
        conditions=[{"field": "environment", "operator": "equals", "value": "production"}],
    )
    allow = _definition(effect=PolicyEffect.ALLOW)

    decision = _decide([deny, allow], _context(environment="development"))

    assert decision.decision is PolicyDecisionKind.ALLOW
    assert decision.evaluated_policies == 2
    assert decision.matched_policy_count == 1


def test_the_report_is_bounded_but_the_count_is_exact() -> None:
    """One decision stays small however many policies an organization writes."""
    definitions = [
        _definition(name=f"Policy {index:02d}", policy_id=uuid.UUID(int=index))
        for index in range(1, MAX_REPORTED_MATCHES + 6)
    ]

    decision = _decide(definitions, _context())

    assert decision.matched_policy_count == MAX_REPORTED_MATCHES + 5
    assert len(decision.matched_policies) == MAX_REPORTED_MATCHES


def test_every_matched_policy_is_reported_with_its_effect_and_version() -> None:
    """Precedence is visible: a reader can see what a denial overrode.

    The order is the evaluation order — priority, then name — not the order of
    strength, so that a list of matches reads the way it was evaluated. Which one
    *decided* is a separate field (``policy_name``/``policy_id``), so nothing here
    has to be inferred from position.
    """
    deny = _definition(name="Deny", effect=PolicyEffect.DENY, version=3)
    allow = _definition(name="Allow", effect=PolicyEffect.ALLOW, version=9)

    decision = _decide([deny, allow], _context())

    assert decision.matched_policies == (
        MatchedPolicy(
            policy_id=allow.policy_id,
            name="Allow",
            version=9,
            effect=PolicyEffect.ALLOW,
            priority=allow.priority,
        ),
        MatchedPolicy(
            policy_id=deny.policy_id,
            name="Deny",
            version=3,
            effect=PolicyEffect.DENY,
            priority=deny.priority,
        ),
    )
    # …and the decider is named explicitly, not taken to be either end of the list.
    assert decision.policy_id == deny.policy_id
    assert decision.decision is PolicyDecisionKind.DENY


# ── Purity ───────────────────────────────────────────────────────────────────


def test_evaluating_twice_produces_the_same_value() -> None:
    """Including ``evaluated_at``: the engine never reads a clock of its own."""
    definitions = [_definition(name="Deny")]
    context = _context(environment="production")

    first = _decide(definitions, context)
    second = _decide(definitions, context)

    assert first == second
    assert first.evaluated_at == EVALUATED_AT


def test_the_engine_returns_a_value_and_changes_nothing_it_was_given() -> None:
    """Side-effect free: the definitions and the context are the same afterwards."""
    definition = _definition(name="Unchanged", conditions=[])
    context = _context(environment="production")
    before = (definition, context.facts)

    decision = _decide([definition], context)

    assert isinstance(decision, PolicyDecision)
    assert (definition, context.facts) == before
    assert context.value_of(ConditionField.ENVIRONMENT) == "production"
