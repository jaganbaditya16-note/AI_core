"""The policy engine: evaluate policies against a context, deterministically.

    identity → permission → **policy** → policy decision → effective authorization

This module is the evaluator. It answers exactly one question:

    given these policies, this target and this context, what does the
    organization's policy say?

and it answers it with a value — :class:`PolicyDecision` — for the same reason
Phase 5 answers authorization with ``AuthorizationDecision``: a decision that is a
value can be tested, recorded, compared and explained, while a decision that is a
branch inside a handler can only be trusted.

Six properties are deliberate, and each one is asserted by tests:

1. **Deterministic.** The same policies, target and context always produce the same
   decision. There is no clock read (``evaluated_at`` is an argument), no random
   number, no network client, no model call, no database access, and no dependence
   on the order the definitions arrived in: the engine sorts its own candidates.
2. **Side-effect free.** Evaluation reads nothing and writes nothing. It cannot
   suspend an agent, change a permission, create an incident or send an HTTP
   request, because it has no access to any of that — it receives value objects and
   returns a value.
3. **A policy can only restrict.** The engine never grants a permission: the
   effective decision (:mod:`aicore_api.auth.policy`) starts from the
   *authorization* decision and can only lower it. A matching ``allow`` means "no
   policy objects", not "access is granted".
4. **Precedence is by effect, then priority.** ``deny`` beats ``require_approval``
   beats ``allow``, regardless of priority, so no policy can argue its way around a
   denial. Priority decides *which* matching policy is reported, and the order the
   matches are reported in.
5. **Missing context never matches.** A condition whose field the context does not
   carry does not match — for every operator, including the negated ones, because
   ``not_equals`` against a fact nobody supplied is not a fact. What follows is
   that an unevaluatable condition leaves the authorization decision where Phase 5
   put it, which is safe precisely because a policy can only lower it.
6. **Nothing arbitrary is interpreted.** Conditions are structured data validated
   against a closed vocabulary by :mod:`aicore_api.core.policy`. The evaluator
   compares a field, using an operator, against a value; there is no expression
   tree, no ``eval``, no SQL, and nothing here reaches outside its arguments.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from types import MappingProxyType

from aicore_api.core.permissions import Action, Resource
from aicore_api.core.policy import (
    CONDITION_FIELDS,
    EFFECT_PRECEDENCE,
    SET_OPERATORS,
    ConditionField,
    ConditionOperator,
    ConditionValue,
    ContextValue,
    PolicyCondition,
    PolicyContextError,
    PolicyDefinition,
    PolicyDefinitionError,
    PolicyEffect,
    validate_field_value,
    validate_target,
)

__all__ = [
    "MAX_REPORTED_MATCHES",
    "MatchedCondition",
    "MatchedPolicy",
    "PolicyContext",
    "PolicyDecision",
    "PolicyDecisionKind",
    "PolicyReason",
    "evaluate_condition",
    "evaluate_policies",
    "evaluate_policy",
]

#: How many matching policies a decision names. The *count* is always exact; the
#: list is bounded so one decision stays small enough to read (and to log) however
#: many policies an organization writes.
MAX_REPORTED_MATCHES = 10


class PolicyReason(StrEnum):
    """Why a policy decision came out the way it did.

    Stable identifiers, like every other code in this system: a later phase records
    them without parsing prose.
    """

    #: No active policy targets this resource/action in this organization, or none
    #: of the ones that do had every condition match. The policy layer abstains.
    NO_MATCHING_POLICY = "no_matching_policy"
    #: A policy matched and permits the action; the authorization decision is
    #: unchanged by it.
    MATCHING_ALLOW = "matching_allow"
    #: A policy matched and forbids the action. It prevails over any matching allow.
    MATCHING_DENY = "matching_deny"
    #: A policy matched and requires approval. A decision value only: nothing in this
    #: build performs an approval.
    MATCHING_REQUIRE_APPROVAL = "matching_require_approval"


class PolicyDecisionKind(StrEnum):
    """What the policy layer says.

    Four values, not three. ``NOT_APPLICABLE`` is honest about the case the phase's
    table does not name: *no policy addressed this request at all*. Recording that as
    ``allow`` would make a request nothing decided indistinguishable from one a
    policy permitted — in an audit trail, exactly the distinction that matters.
    ``NOT_APPLICABLE`` never grants anything; it leaves the authorization decision as
    it was.

    ``REQUIRE_APPROVAL`` is a decision value consumed by a later phase. This build
    performs no approval: no queue, no request, no approver, no notification.
    """

    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"
    NOT_APPLICABLE = "not_applicable"

    @property
    def permits(self) -> bool:
        """Whether this decision leaves the action permitted.

        ``NOT_APPLICABLE`` permits in the only sense that matters here — it changes
        nothing — while ``REQUIRE_APPROVAL`` does not permit outright, which is why
        it is not folded into ``ALLOW``.
        """
        return self in {PolicyDecisionKind.ALLOW, PolicyDecisionKind.NOT_APPLICABLE}


@dataclass(frozen=True, slots=True)
class PolicyContext:
    """The facts a policy is evaluated against, supplied by the caller.

    Deliberately explicit and complete: the engine *receives* its context rather
    than gathering one, so an evaluation is reproducible from its arguments, and a
    condition can never query a table, call a service or read a clock to invent a
    fact. Whoever builds the context owns the facts in it — today that is a caller
    asking a dry-run question, and in the phase that enforces policies it is the
    enforcement point, reading rows it has already loaded.

    ``facts`` is keyed by the closed field vocabulary, and a fact is a single
    scalar: ``in``/``not_in`` compare a fact against a *list of values the policy
    states*, so nothing here is a set. A field that is **absent** is not the same as
    a field carrying the value ``unknown``: the first means "nothing is known", the
    second means "known to be unknown", and a policy may distinguish them.
    """

    organization_id: uuid.UUID
    resource: Resource
    action: Action
    facts: Mapping[ConditionField, ContextValue] = field(
        default_factory=lambda: MappingProxyType({})
    )

    def __post_init__(self) -> None:
        """Validate the target and the facts, and freeze the mapping.

        Validation here rather than in a factory means a context is valid however it
        was built, including by a test that constructs one directly. Freezing the
        mapping is the determinism guard: a context cannot be mutated between the
        moment a decision is computed and the moment it is recorded.
        """
        validate_target(self.resource, self.action)
        validated: dict[ConditionField, ContextValue] = {}
        for raw_field, value in self.facts.items():
            try:
                resolved = ConditionField(raw_field)
            except ValueError as exc:
                raise PolicyContextError(
                    f"unknown context field {raw_field!r}; the field vocabulary is: "
                    f"{', '.join(candidate.value for candidate in ConditionField)}"
                ) from exc
            spec = CONDITION_FIELDS[resolved]
            if isinstance(value, (list, Mapping)):
                raise PolicyContextError(
                    f"context field {resolved.value} takes a single "
                    f"{spec.value_type.value} value; a list belongs in the condition it "
                    "is compared with"
                )
            try:
                validated[resolved] = validate_field_value(resolved, value)
            except PolicyDefinitionError as exc:
                raise PolicyContextError(f"context field {resolved.value}: {exc}") from exc
        object.__setattr__(self, "facts", MappingProxyType(validated))

    def has(self, field: ConditionField) -> bool:
        """Whether this context carries ``field`` at all."""
        return field in self.facts

    def value_of(self, field: ConditionField) -> ContextValue:
        """The fact carried for ``field``. Raises ``KeyError`` when it is absent."""
        return self.facts[field]

    def __repr__(self) -> str:
        rendered = ", ".join(
            f"{field.value}={self.facts[field]!r}" for field in sorted(self.facts, key=str)
        )
        return (
            f"<PolicyContext {self.resource.value}.{self.action.value} "
            f"organization_id={self.organization_id} facts=[{rendered}]>"
        )


@dataclass(frozen=True, slots=True)
class MatchedCondition:
    """One condition that held, with the fact that satisfied it.

    Reported so a decision explains itself: the operator, the value the policy
    stated, and the value the context carried. All three are already visible to
    whoever may read the policy, so a match leaks nothing they cannot read.
    """

    field: ConditionField
    operator: ConditionOperator
    value: ConditionValue
    actual: ContextValue


@dataclass(frozen=True, slots=True)
class MatchedPolicy:
    """A policy that applied, reported without its conditions.

    The deciding policy's conditions travel with the decision
    (``matched_conditions``); the others are named so that precedence is visible —
    a denial that overrode an allow should show both, rather than leaving a reader
    to wonder what the result would have been without it.
    """

    policy_id: uuid.UUID
    name: str
    version: int
    effect: PolicyEffect
    priority: int


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    """The result of one policy evaluation, as a value.

    Fields:

    - ``decision`` — what the policy layer says (``allow``, ``deny``,
      ``require_approval``, ``not_applicable``);
    - ``reason`` — why, as a :class:`PolicyReason`;
    - ``organization_id``, ``resource``, ``action`` — the question that was asked;
    - ``evaluated_at`` — when the caller says the evaluation happened (an argument,
      never a clock read inside the engine);
    - ``policy_id``, ``policy_version``, ``policy_name``, ``priority`` — the policy
      that decided it, when one did. A recorded decision therefore names the *exact
      version* it was made from, which is what makes an old decision explainable;
    - ``matched_conditions`` — the decider's conditions, with the facts that
      satisfied them;
    - ``matched_policies`` / ``matched_policy_count`` — how many policies applied,
      and (bounded) which ones, so a denial that overrode an allow is visible;
    - ``evaluated_policies`` — how many active policies targeted this request.

    The decision is expressed in the *policy* layer's terms. It is not the effective
    answer: :func:`aicore_api.auth.policy.combine` produces that from this and the
    authorization decision, and it can only ever be at least as restrictive.
    """

    decision: PolicyDecisionKind
    reason: PolicyReason
    organization_id: uuid.UUID
    resource: Resource
    action: Action
    evaluated_at: datetime
    policy_id: uuid.UUID | None = None
    policy_version: int | None = None
    policy_name: str | None = None
    priority: int | None = None
    matched_conditions: tuple[MatchedCondition, ...] = ()
    matched_policies: tuple[MatchedPolicy, ...] = ()
    matched_policy_count: int = 0
    evaluated_policies: int = 0

    @property
    def allowed(self) -> bool:
        """Whether the policy layer permits the action outright.

        ``False`` for ``require_approval``: a request that needs approval is not
        permitted yet, and saying otherwise would be the one claim this build must
        never make.
        """
        return self.decision is PolicyDecisionKind.ALLOW

    @property
    def denied(self) -> bool:
        """Whether the policy layer forbids the action."""
        return self.decision is PolicyDecisionKind.DENY

    @property
    def requires_approval(self) -> bool:
        """Whether the policy layer says approval is needed.

        Reported so a later phase can act on it. Nothing here acts on it.
        """
        return self.decision is PolicyDecisionKind.REQUIRE_APPROVAL

    @property
    def applicable(self) -> bool:
        """Whether any policy applied at all."""
        return self.decision is not PolicyDecisionKind.NOT_APPLICABLE

    def __repr__(self) -> str:
        decided = (
            "no policy"
            if self.policy_name is None
            else f"{self.policy_name!r} v{self.policy_version}"
        )
        return (
            f"<PolicyDecision {self.decision.value} "
            f"{self.resource.value}.{self.action.value} by {decided} "
            f"reason={self.reason.value}>"
        )


#: The reason each effect produces when it wins. A mapping rather than a chain of
#: conditionals, so the effect vocabulary and the reason vocabulary cannot drift
#: apart without a test noticing.
_REASONS: Mapping[PolicyEffect, PolicyReason] = MappingProxyType(
    {
        PolicyEffect.ALLOW: PolicyReason.MATCHING_ALLOW,
        PolicyEffect.DENY: PolicyReason.MATCHING_DENY,
        PolicyEffect.REQUIRE_APPROVAL: PolicyReason.MATCHING_REQUIRE_APPROVAL,
    }
)


def _as_number(value: ContextValue) -> float:
    """A numeric view of a value the vocabulary already proved is a number."""
    if isinstance(value, int | float):
        return float(value)
    # Unreachable: ordered operators are only accepted on numeric fields, and both
    # the policy's value and the context's fact are validated against that field.
    raise PolicyContextError(f"expected a number, got {type(value).__name__}")


def _compare(condition: PolicyCondition, actual: ContextValue) -> bool:
    """Apply ``condition``'s operator to ``actual``.

    Both sides were validated against the same field specification, so the
    comparison is between values of the same kind. The comparisons that follow are
    the entire semantics of the language: eight operators, all of them total
    functions of two values, none of them able to reach outside its arguments.
    """
    operator = condition.operator
    expected: ConditionValue = condition.value

    if operator is ConditionOperator.EQUALS:
        return bool(actual == expected)
    if operator is ConditionOperator.NOT_EQUALS:
        return bool(actual != expected)

    if operator in SET_OPERATORS:
        if not isinstance(expected, list):  # pragma: no cover - excluded by validation
            return False
        present = any(actual == candidate for candidate in expected)
        return present if operator is ConditionOperator.IN else not present

    if not isinstance(expected, int | float) or isinstance(expected, bool):
        return False  # pragma: no cover - excluded by validation
    left, right = _as_number(actual), _as_number(expected)
    if operator is ConditionOperator.LESS_THAN:
        return left < right
    if operator is ConditionOperator.LESS_THAN_OR_EQUAL:
        return left <= right
    if operator is ConditionOperator.GREATER_THAN:
        return left > right
    if operator is ConditionOperator.GREATER_THAN_OR_EQUAL:
        return left >= right
    return False  # pragma: no cover - the operator vocabulary is closed


def evaluate_condition(
    condition: PolicyCondition, context: PolicyContext
) -> MatchedCondition | None:
    """Evaluate one condition; ``None`` when it does not hold.

    A condition whose field the context does not carry does not hold — the rule is
    the same for every operator, so ``not_equals`` cannot be satisfied by the
    absence of the fact it is about. There is no "unknown" that counts as a match.
    """
    if not context.has(condition.field):
        return None
    actual = context.value_of(condition.field)
    if not _compare(condition, actual):
        return None
    return MatchedCondition(
        field=condition.field,
        operator=condition.operator,
        value=condition.value,
        actual=actual,
    )


def evaluate_policy(
    definition: PolicyDefinition, context: PolicyContext
) -> tuple[MatchedCondition, ...] | None:
    """Evaluate one policy against ``context``.

    Returns the conditions that held when *every* condition held, or ``None`` when
    the policy does not apply. Conditions compose with **AND** and nothing else:
    this is the whole composition rule, and it is why "does this policy apply?" is a
    question a reviewer answers by reading one row. There is deliberately no ``OR``,
    no negation of a condition list and no nesting — a disjunction is the first step
    of an expression language, and the second step is a policy nobody can review.

    A policy with no conditions applies to every request for its target: a blanket
    rule is a legitimate rule ("deny ``agent.delete`` in this organization"), and
    saying it with zero conditions is clearer than inventing a condition that is
    always true.
    """
    matched: list[MatchedCondition] = []
    for condition in definition.conditions:
        result = evaluate_condition(condition, context)
        if result is None:
            return None
        matched.append(result)
    return tuple(matched)


def _evaluation_order(definition: PolicyDefinition) -> tuple[int, str, str]:
    """The key candidates are evaluated and reported in.

    Lowest priority first, then by name, then by identifier. Computed, never
    inherited from the caller or from database row order: two policies that differ
    in none of these are the same policy as far as ordering is concerned, so the
    result does not depend on how the list was assembled — which is what makes a
    decision reproducible rather than merely repeatable.
    """
    return (definition.priority, definition.name, str(definition.policy_id))


def evaluate_policies(
    definitions: Sequence[PolicyDefinition],
    context: PolicyContext,
    *,
    evaluated_at: datetime,
) -> PolicyDecision:
    """Evaluate every applicable policy and reduce them to one decision.

    The reduction is total and order-independent:

    1. only policies whose target matches the context's ``resource.action`` are
       considered (the repository filters too; here it is a property of the engine);
    2. a policy applies when every one of its conditions holds;
    3. among the policies that apply, the most restrictive effect wins
       (``deny`` > ``require_approval`` > ``allow``);
    4. among the policies with that effect, the lowest priority is the one named as
       the decider — and name and id are the tiebreaks, never the order the rows
       arrived in.

    No policy applying is a *decision*, not an absence of one:
    ``not_applicable`` / ``no_matching_policy``.
    """
    candidates = [
        definition
        for definition in definitions
        if definition.target == (context.resource, context.action)
    ]

    matches: list[tuple[PolicyDefinition, tuple[MatchedCondition, ...]]] = []
    for definition in sorted(candidates, key=_evaluation_order):
        conditions = evaluate_policy(definition, context)
        if conditions is not None:
            matches.append((definition, conditions))

    if not matches:
        return PolicyDecision(
            decision=PolicyDecisionKind.NOT_APPLICABLE,
            reason=PolicyReason.NO_MATCHING_POLICY,
            organization_id=context.organization_id,
            resource=context.resource,
            action=context.action,
            evaluated_at=evaluated_at,
            evaluated_policies=len(candidates),
        )

    strongest = max(EFFECT_PRECEDENCE[definition.effect] for definition, _ in matches)
    decisive, matched_conditions = next(
        (definition, conditions)
        for definition, conditions in matches
        if EFFECT_PRECEDENCE[definition.effect] == strongest
    )

    return PolicyDecision(
        decision=PolicyDecisionKind(decisive.effect.value),
        reason=_REASONS[decisive.effect],
        organization_id=context.organization_id,
        resource=context.resource,
        action=context.action,
        evaluated_at=evaluated_at,
        policy_id=decisive.policy_id,
        policy_version=decisive.version,
        policy_name=decisive.name,
        priority=decisive.priority,
        matched_conditions=matched_conditions,
        matched_policies=tuple(
            MatchedPolicy(
                policy_id=definition.policy_id,
                name=definition.name,
                version=definition.version,
                effect=definition.effect,
                priority=definition.priority,
            )
            for definition, _ in matches[:MAX_REPORTED_MATCHES]
        ),
        matched_policy_count=len(matches),
        evaluated_policies=len(candidates),
    )
