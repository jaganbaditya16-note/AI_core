"""The policy language: a closed vocabulary, and the validator that enforces it.

A policy says one thing — *for this resource and action, when every one of these
conditions holds, the effect is this* — and this module is the only place that
sentence is defined. It holds no database, no HTTP and no authorization: it is a
vocabulary plus a validator, so the same rules apply to a request body, a stored
row, an evaluation and a test.

**Everything a policy can say is enumerated here.** Fields come from
:class:`ConditionField`, operators from :class:`ConditionOperator`, effects from
:class:`PolicyEffect`, states from :class:`PolicyStatus`. A policy is therefore not
a program: there is no expression tree, no nesting, no arithmetic, no user-supplied
Python, no ``eval`` and no SQL, because there is nothing in the model to put any of
them in. The stored form is JSON data — an array of ``{field, operator, value}``
objects — and the vocabulary is validated on the way in.

**Conditions are more restrictive than they look, on purpose.** Four rules are
worth stating plainly, because each one is a place a policy language usually goes
wrong:

1. *All* conditions must match — there is no ``or``. A policy applies exactly when
   every condition it states holds, which is why one row is enough to review a rule.
   A policy with no conditions is a blanket rule for its target, and saying it that
   way is clearer than a condition that is always true.
2. A condition whose field is **absent** from the evaluation context does not match,
   whatever the operator is — including ``not_equals`` and ``not_in``. "Not equal to
   production" is not a fact about a request whose environment nobody supplied, and
   letting a negated operator match on missing data is how fail-open behaviour gets
   written by accident.
3. Every field is either a **closed set of values** or a bounded number. There is no
   free-form string field in this build, so a condition cannot carry a payload, and
   an author can enumerate every value a policy can be written about.
4. A policy is refused as a **whole** if any part of it is invalid —
   :func:`validate_definition` is the gate a policy passes through before it may
   become ``active``, and there is no partial validity.

**What is deliberately absent**, and why it matters more than what is present:

- **No expression language** — no ``and``/``or``/``not`` nodes, no parentheses, no
  arithmetic. Each addition to a condition syntax is a step towards a language
  nobody can review, and a policy reviewer has to be able to answer "does this rule
  apply to this request?" by reading one row.
- **No request source.** The phase's list of context fields names it, and this build
  cannot attest it: the only request source it can observe is an authenticated HTTP
  call, and a value the caller states about itself is exactly the kind of
  self-asserted security context a policy must never key on. Every field here is a
  fact the server derives from rows or from the authorization decision. The phase
  that owns the enforcement point can add it, with a value it can vouch for.
- **No principal or membership identifiers.** Nothing evaluates them, and a context
  is a thing that gets recorded: an evaluation record should not carry identity data
  nothing reads.
- **No time.** There is no clock in this language: a time-based condition would make
  a stored decision unreproducible, and "was this policy in force at 03:00?" is a
  question about the record, not about the rule.
- **No target that is not a declared permission.** :func:`validate_target` accepts
  only ``resource.action`` pairs that exist in the permission catalogue, so
  ``firewall.block`` or ``incident.create`` cannot be written into a policy that
  nothing enforces. The same rule the catalogue itself follows.

The vocabulary's values are the *domain's own enums* — :class:`Environment`,
:class:`AssetStatus`, :class:`AgentCategory`, the role codes — rather than copies,
so a value a policy can name is a value the rest of the system already stores, and
adding a category to the registry makes it usable in a condition with no change
here.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from aicore_api.core.agents import AgentCategory
from aicore_api.core.assets import AssetStatus, AssetType, Environment, RiskClassification
from aicore_api.core.permissions import (
    RESOURCE_ACTIONS,
    Action,
    Permission,
    Resource,
    RoleCode,
)

__all__ = [
    "CONDITION_FIELDS",
    "DEFAULT_PRIORITY",
    "EFFECT_PRECEDENCE",
    "MAX_CONDITIONS",
    "MAX_SET_VALUES",
    "ORDERED_OPERATORS",
    "POLICY_DESCRIPTION_MAX_LENGTH",
    "POLICY_INITIAL_STATES",
    "POLICY_NAME_MAX_LENGTH",
    "POLICY_TARGETS",
    "POLICY_TRANSITIONS",
    "PRIORITY_MAX",
    "PRIORITY_MIN",
    "SET_OPERATORS",
    "ConditionField",
    "ConditionFieldSpec",
    "ConditionOperator",
    "ConditionValue",
    "ContextValue",
    "ContextValueType",
    "PolicyCondition",
    "PolicyDefinition",
    "PolicyDefinitionError",
    "PolicyEffect",
    "PolicyError",
    "PolicyStatus",
    "UnknownPolicyTargetError",
    "conditions_from_stored",
    "normalize_description",
    "normalize_name",
    "target_permission",
    "validate_condition",
    "validate_conditions",
    "validate_definition",
    "validate_field_value",
    "validate_priority",
    "validate_target",
    "validate_transition",
]

#: A policy's name is a label an operator reads in a list, and its description is
#: the reason it exists. Both are bounded, like every other free-text field in this
#: system: a policy is a rule, not a document store, and a row that cannot be read
#: in one screen cannot be reviewed.
POLICY_NAME_MAX_LENGTH = 96
POLICY_DESCRIPTION_MAX_LENGTH = 500

#: How many conditions one policy may state, and how many values one set-valued
#: condition may list. Both are bounds on *work*: evaluating a policy is a loop over
#: at most this many conditions, each comparing against at most this many values,
#: and the bound is a number in the schema rather than a hope.
MAX_CONDITIONS = 8
MAX_SET_VALUES = 16

#: Priority orders policies; it never decides *whether* one applies. Lower is more
#: important — priority 0 outranks priority 10 — and the range is bounded so a
#: priority can be compared, sorted and displayed. What it can never do is outrank
#: an effect: see :data:`EFFECT_PRECEDENCE`.
PRIORITY_MIN = 0
PRIORITY_MAX = 1000
DEFAULT_PRIORITY = 100

#: Age fields measure days since a record was created. The bound is a sanity limit
#: on what a policy may compare against (a century of days), so an author cannot
#: write a threshold that is really a typo.
MAX_AGE_DAYS = 36_500


class PolicyError(ValueError):
    """Base class for a policy this build refuses.

    A :class:`ValueError` because that is what the rest of the domain layer raises
    for "the value you gave me is not one I can use" (see ``core/agents.py``,
    ``core/assets.py``), and because every caller already knows how to answer that:
    a request body earns a 422, a stored row earns a loud failure.
    """


class PolicyDefinitionError(PolicyError):
    """A policy definition is not something this build can evaluate.

    Raised for two very different situations that share one answer — *refuse it*:

    - a **request** that names an unknown target, an operator that does not suit its
      field, or a value outside a closed set (an HTTP 422);
    - a **stored row** this build cannot interpret, which is a deployment defect: a
      migration that removed a vocabulary, or a hand-edited database. That one must
      be loud — silently skipping a policy that cannot be read would change what the
      organization's policy says, and skipping a ``deny`` is permitting the action.
    """


class UnknownPolicyTargetError(PolicyDefinitionError):
    """``resource.action`` is not a permission this build declares.

    Distinct from :class:`PolicyDefinitionError` because the two are answered
    differently at the boundary: a caller naming ``firewall.block`` has made a
    request that cannot be satisfied (422), while a *stored* policy this build
    cannot read is a deployment defect.
    """


class PolicyContextError(PolicyError):
    """An evaluation context does not describe a request this engine can evaluate.

    Raised by :class:`aicore_api.core.policy_engine.PolicyContext` for an unknown
    field, a value that does not match its field's type, or a ``null`` — a context
    field is either present with a value of its declared type or absent, never null.
    A caller who builds a context wrongly has a bug, not a denial: this is not a
    decision, and it is never silently treated as one.
    """


class PolicyEffect(StrEnum):
    """What a policy says when it applies.

    Three values, and the third is deliberately not a workflow: a policy can require
    approval, and nothing in this build collects, routes or performs one. There is
    no ``log``, no ``notify``, no ``escalate`` and no ``block``: those are actions,
    and Phase 6 evaluates rather than acts.
    """

    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


#: How strong each effect is, and therefore which one wins when several policies
#: match: a greater number is more restrictive, and the comparison is by *effect*
#: before it is by priority. A ``deny`` at priority 1000 outranks an ``allow`` at
#: priority 0, so no policy can argue its way around a denial — the property that
#: makes precedence deterministic instead of merely documented.
EFFECT_PRECEDENCE: Mapping[PolicyEffect, int] = MappingProxyType(
    {
        PolicyEffect.ALLOW: 0,
        PolicyEffect.REQUIRE_APPROVAL: 1,
        PolicyEffect.DENY: 2,
    }
)


class PolicyStatus(StrEnum):
    """Where a policy is in its life.

    Only :attr:`ACTIVE` participates in evaluation. ``draft`` is editable and never
    evaluated, ``disabled`` is retained but silent, and ``retired`` is history: the
    record of a policy that will not be evaluated again. None of these is a runtime
    control — disabling a policy changes what the *engine* says, and nothing in this
    build acts on that.
    """

    DRAFT = "draft"
    ACTIVE = "active"
    DISABLED = "disabled"
    RETIRED = "retired"


#: The policy lifecycle, as a table of allowed moves — the same technique the agent
#: registry uses, for the same reason: the rule is data a test can enumerate, not a
#: chain of ``if`` statements spread over the write paths.
#:
#: - ``draft`` may be activated (the gate is :func:`validate_definition`) or retired
#:   (abandoned before it ever applied);
#: - ``active`` may be disabled or retired. Asking for the state a policy is already
#:   in is not in the table because it is not a move: :func:`validate_transition`
#:   answers it before consulting this, so a client can retry an activation
#:   idempotently without the table carrying an edge that changes nothing;
#: - ``disabled`` may be activated again or retired: disabling is reversible,
#:   retiring is not;
#: - ``retired`` has no outgoing edge. A retired policy is history.
POLICY_TRANSITIONS: Mapping[PolicyStatus, frozenset[PolicyStatus]] = MappingProxyType(
    {
        PolicyStatus.DRAFT: frozenset({PolicyStatus.ACTIVE, PolicyStatus.RETIRED}),
        PolicyStatus.ACTIVE: frozenset({PolicyStatus.DISABLED, PolicyStatus.RETIRED}),
        PolicyStatus.DISABLED: frozenset({PolicyStatus.ACTIVE, PolicyStatus.RETIRED}),
        PolicyStatus.RETIRED: frozenset(),
    }
)

#: The states a policy may be **created** in. A policy cannot be born disabled or
#: retired: those are states a policy moves to, and creating one there would be a
#: quiet way to write a record that never applies.
POLICY_INITIAL_STATES: frozenset[PolicyStatus] = frozenset(
    {PolicyStatus.DRAFT, PolicyStatus.ACTIVE}
)


class ContextValueType(StrEnum):
    """What kind of value a context field carries, and therefore which operators fit.

    ``STRING`` means a value from a closed set (an enum's members) — never free text.
    """

    STRING = "string"
    BOOLEAN = "boolean"
    NUMBER = "number"


class ConditionField(StrEnum):
    """The facts a policy may be about. Every one is derived by the server.

    Each field names something the system already knows: a stored lifecycle state,
    a category, the caller's role in this organization, whether the caller owns the
    row, or how old a record is. None of them is asserted by the client, and none of
    them is a guess — see the module docstring for why a request source is not here.
    """

    #: The environment the addressed record lives in (``assets.environment``).
    ENVIRONMENT = "environment"
    #: What kind of asset the addressed record is (``assets.asset_type``).
    ASSET_TYPE = "asset_type"
    #: The lifecycle state of the addressed record (``assets.status``). For an agent
    #: that is the state of the asset that backs it, which is why one field covers
    #: "asset status" and "agent status" rather than two names for one column.
    RESOURCE_STATUS = "resource_status"
    #: The organization's risk classification of the addressed record.
    RISK_CLASSIFICATION = "risk_classification"
    #: An agent's category (``agents.category``). Only meaningful for agent targets,
    #: and simply absent from a context that describes anything else.
    AGENT_CATEGORY = "agent_category"
    #: The caller's role code in this organization (``roles.code``) — the role Phase 5
    #: already resolved to answer its own question.
    USER_ROLE = "user_role"
    #: Whether the caller owns the addressed record. Comes from the Phase 5 decision
    #: (``AuthorizationDecision.principal_is_owner``), which reports ownership and
    #: never widens on it — a policy may narrow on it, which is a different thing.
    IS_RESOURCE_OWNER = "is_resource_owner"
    #: Days since the addressed agent was registered (``agents.created_at``).
    AGENT_AGE_DAYS = "agent_age_days"
    #: Days since the addressed asset was recorded (``assets.created_at``).
    ASSET_AGE_DAYS = "asset_age_days"


@dataclass(frozen=True, slots=True)
class ConditionFieldSpec:
    """What a field accepts: its type, and the values or bounds that come with it.

    ``allowed_values`` is set only for ``STRING`` fields, and it is never ``None``:
    every string field in this vocabulary is a closed set, so a condition cannot
    carry free text. ``minimum``/``maximum`` bound a ``NUMBER`` field.
    """

    value_type: ContextValueType
    description: str
    allowed_values: frozenset[str] | None = None
    minimum: float | None = None
    maximum: float | None = None

    def __post_init__(self) -> None:
        if self.value_type is ContextValueType.STRING and not self.allowed_values:
            raise PolicyDefinitionError(
                "a string context field must declare the values it accepts; free text "
                "is not part of this language"
            )
        if self.value_type is ContextValueType.NUMBER and (
            self.minimum is None or self.maximum is None
        ):
            raise PolicyDefinitionError(
                "a numeric context field must declare its bounds, so a threshold cannot "
                "be a typo nobody can check"
            )


#: The field vocabulary, with what each field accepts. The closed sets are the
#: domain's own enums — the objects the inventory, the registry and the role
#: catalogue store — so a policy cannot name a value the database would refuse, and
#: a new category, environment or role code becomes usable in a condition by
#: existing. ``tests/test_policy_conditions.py`` asserts that equality.
CONDITION_FIELDS: Mapping[ConditionField, ConditionFieldSpec] = MappingProxyType(
    {
        ConditionField.ENVIRONMENT: ConditionFieldSpec(
            ContextValueType.STRING,
            "The environment the addressed record lives in.",
            allowed_values=frozenset(member.value for member in Environment),
        ),
        ConditionField.ASSET_TYPE: ConditionFieldSpec(
            ContextValueType.STRING,
            "What kind of AI asset the addressed record is.",
            allowed_values=frozenset(member.value for member in AssetType),
        ),
        ConditionField.RESOURCE_STATUS: ConditionFieldSpec(
            ContextValueType.STRING,
            "The lifecycle state of the addressed record. A record; not a runtime control.",
            allowed_values=frozenset(member.value for member in AssetStatus),
        ),
        ConditionField.RISK_CLASSIFICATION: ConditionFieldSpec(
            ContextValueType.STRING,
            "The organization's risk classification of the addressed record.",
            allowed_values=frozenset(member.value for member in RiskClassification),
        ),
        ConditionField.AGENT_CATEGORY: ConditionFieldSpec(
            ContextValueType.STRING,
            "The category a registered agent was registered as.",
            allowed_values=frozenset(member.value for member in AgentCategory),
        ),
        ConditionField.USER_ROLE: ConditionFieldSpec(
            ContextValueType.STRING,
            "The role the caller holds in this organization.",
            allowed_values=frozenset(member.value for member in RoleCode),
        ),
        ConditionField.IS_RESOURCE_OWNER: ConditionFieldSpec(
            ContextValueType.BOOLEAN,
            "Whether the caller owns the addressed record.",
        ),
        ConditionField.AGENT_AGE_DAYS: ConditionFieldSpec(
            ContextValueType.NUMBER,
            "Days since the addressed agent was registered.",
            minimum=0,
            maximum=MAX_AGE_DAYS,
        ),
        ConditionField.ASSET_AGE_DAYS: ConditionFieldSpec(
            ContextValueType.NUMBER,
            "Days since the addressed asset was recorded.",
            minimum=0,
            maximum=MAX_AGE_DAYS,
        ),
    }
)


class ConditionOperator(StrEnum):
    """The operators a condition may use. A closed set of eight.

    Each operator is meaningful only for some field types, and the pairing is
    validated: comparing ``environment`` with ``less_than`` is refused because
    "is ``production`` less than ``staging``?" has no answer, and an operator that
    cannot be evaluated is a policy that cannot do what it says.
    """

    EQUALS = "equals"
    NOT_EQUALS = "not_equals"
    IN = "in"
    NOT_IN = "not_in"
    LESS_THAN = "less_than"
    LESS_THAN_OR_EQUAL = "less_than_or_equal"
    GREATER_THAN = "greater_than"
    GREATER_THAN_OR_EQUAL = "greater_than_or_equal"


#: Operators that compare a field against a **list** of values.
SET_OPERATORS: frozenset[ConditionOperator] = frozenset(
    {ConditionOperator.IN, ConditionOperator.NOT_IN}
)

#: Operators that compare **numbers**. They are refused on a field that is not a
#: number, because an ordering has to exist for the comparison to mean anything.
ORDERED_OPERATORS: frozenset[ConditionOperator] = frozenset(
    {
        ConditionOperator.LESS_THAN,
        ConditionOperator.LESS_THAN_OR_EQUAL,
        ConditionOperator.GREATER_THAN,
        ConditionOperator.GREATER_THAN_OR_EQUAL,
    }
)

#: What a policy may be about: exactly the ``resource.action`` pairs the permission
#: catalogue declares. The same object as
#: :data:`~aicore_api.core.permissions.RESOURCE_ACTIONS`, under the name the policy
#: layer reads it by — a policy target *is* a permission, or it is not a target.
POLICY_TARGETS: Mapping[Resource, frozenset[Action]] = MappingProxyType(
    {resource: RESOURCE_ACTIONS.get(resource, frozenset()) for resource in Resource}
)

#: A value a condition can compare against, and the value a context can carry: a
#: string from a closed set, a boolean, or a number. Not ``None`` — a condition
#: cannot ask "is this null?", because "the context does not carry this field" is the
#: only absence this language knows, and it never matches.
ContextValue = str | bool | int | float
ConditionValue = ContextValue | list[ContextValue]

#: What a raw condition payload may contain, before validation narrows it.
_RAW_TYPES = (str, bool, int, float)


def _value_type_name(value: object) -> str:
    """A readable name for a value's type, for error messages."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "list"
    if isinstance(value, Mapping):
        return "object"
    return type(value).__name__


def _check_scalar(field: ConditionField, spec: ConditionFieldSpec, value: object) -> None:
    """Check one scalar against its field's type, raising if it does not fit."""
    if spec.value_type is ContextValueType.STRING:
        # ``isinstance(value, str)`` before the member test: a bool is not a string,
        # and ``True in {"true"}`` would otherwise be a confusing near-miss.
        if isinstance(value, bool) or not isinstance(value, str):
            raise PolicyDefinitionError(
                f"{field.value} is a string field; its value must be one of: "
                f"{', '.join(sorted(spec.allowed_values or ()))} — got "
                f"{_value_type_name(value)}"
            )
        if value not in (spec.allowed_values or frozenset()):
            raise PolicyDefinitionError(
                f"{value!r} is not a value of {field.value}; allowed values are: "
                f"{', '.join(sorted(spec.allowed_values or ()))}"
            )
        return

    if spec.value_type is ContextValueType.BOOLEAN:
        if not isinstance(value, bool):
            raise PolicyDefinitionError(
                f"{field.value} is a boolean field; its value must be true or false, "
                f"got {_value_type_name(value)}"
            )
        return

    # NUMBER. ``bool`` is refused explicitly: ``True`` is an ``int`` in Python, and a
    # threshold that came from a boolean is a mistake that must be visible.
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise PolicyDefinitionError(
            f"{field.value} is a numeric field; its value must be a number, got "
            f"{_value_type_name(value)}"
        )
    minimum, maximum = spec.minimum, spec.maximum
    if minimum is not None and value < minimum:
        raise PolicyDefinitionError(f"{field.value} must be at least {minimum:g}, got {value:g}")
    if maximum is not None and value > maximum:
        raise PolicyDefinitionError(f"{field.value} must be at most {maximum:g}, got {value:g}")


def _check_operator(field: ConditionField, spec: ConditionFieldSpec, operator: object) -> None:
    """Check that an operator suits a field's type."""
    if not isinstance(operator, ConditionOperator):
        raise PolicyDefinitionError(
            f"unknown operator {operator!r}; allowed operators are: "
            f"{', '.join(member.value for member in ConditionOperator)}"
        )
    if operator in ORDERED_OPERATORS and spec.value_type is not ContextValueType.NUMBER:
        raise PolicyDefinitionError(
            f"{operator.value} orders numbers, and {field.value} is a {spec.value_type.value} field"
        )
    if operator in SET_OPERATORS and spec.value_type is ContextValueType.BOOLEAN:
        # Refused rather than allowed: a set of booleans is either both values (the
        # condition is always true) or one of them (it is an ``equals`` in disguise).
        # Both are mistakes an author should see, not policies that quietly do
        # something other than what they appear to.
        raise PolicyDefinitionError(
            f"{operator.value} compares against a set of values, and {field.value} is a "
            "boolean field; use equals or not_equals"
        )


def validate_field_value(field: ConditionField | str, value: object) -> ContextValue:
    """Check that ``value`` is a legal value for ``field``, and return it.

    The field-side half of the language, shared by the two things that carry a
    value: a condition's ``value`` and a context *fact*. Both must apply exactly the
    same rules — a policy that compares against a value the context can never carry
    is a policy that can never apply — so both call this.
    """
    try:
        resolved = ConditionField(field)
    except ValueError as exc:
        allowed = ", ".join(member.value for member in ConditionField)
        raise PolicyDefinitionError(
            f"unknown condition field {field!r}; the field vocabulary is: {allowed}"
        ) from exc
    _check_scalar(resolved, CONDITION_FIELDS[resolved], value)
    return value  # type: ignore[return-value]


def validate_condition(
    field: ConditionField | str,
    operator: ConditionOperator | str,
    value: object,
) -> tuple[ConditionField, ConditionOperator, ConditionValue]:
    """Validate one condition, or refuse it with the reason it is unusable.

    The single validator for the whole language: it resolves the field, checks that
    the operator suits it, and checks that the value is of the field's type and
    inside its closed set or bounds. Returns the resolved triple so a caller that
    needs the normalised form does not have to resolve anything twice.
    """
    try:
        resolved_field = ConditionField(field)
    except ValueError as exc:
        allowed = ", ".join(member.value for member in ConditionField)
        raise PolicyDefinitionError(
            f"unknown condition field {field!r}; the field vocabulary is: {allowed}"
        ) from exc
    spec = CONDITION_FIELDS[resolved_field]

    try:
        resolved_operator = ConditionOperator(operator)
    except ValueError as exc:
        allowed = ", ".join(member.value for member in ConditionOperator)
        raise PolicyDefinitionError(
            f"unknown operator {operator!r}; allowed operators are: {allowed}"
        ) from exc
    _check_operator(resolved_field, spec, resolved_operator)

    if resolved_operator in SET_OPERATORS:
        if isinstance(value, str | bytes) or not isinstance(value, list):
            raise PolicyDefinitionError(
                f"{resolved_operator.value} compares against a list of values; got "
                f"{_value_type_name(value)}"
            )
        if not value:
            raise PolicyDefinitionError(
                f"{resolved_operator.value} needs at least one value; an empty set "
                "would match everything or nothing by accident"
            )
        if len(value) > MAX_SET_VALUES:
            raise PolicyDefinitionError(
                f"a set-valued condition may list at most {MAX_SET_VALUES} values, got {len(value)}"
            )
        for member in value:
            validate_field_value(resolved_field, member)
        return resolved_field, resolved_operator, list(value)

    if isinstance(value, list | dict):
        raise PolicyDefinitionError(
            f"{resolved_operator.value} compares against a single value; got "
            f"{_value_type_name(value)}"
        )
    validate_field_value(resolved_field, value)
    return resolved_field, resolved_operator, value  # type: ignore[return-value]


class PolicyCondition(BaseModel):
    """One condition: a field, an operator, and the value it is compared against.

    The stored form is exactly the JSON shape a policy author writes::

        {"field": "environment", "operator": "equals", "value": "production"}

    ``extra="forbid"`` and ``frozen=True``: a condition with an unexpected key is
    refused rather than silently ignored, and an instance cannot be mutated after it
    was validated, so a decision made against it stays reproducible. Validation
    happens in the model, so *every* construction path — a request body, a stored
    row, a test — passes through the same rules.
    """

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        json_schema_extra={
            "examples": [
                {"field": "environment", "operator": "equals", "value": "production"},
                {"field": "resource_status", "operator": "equals", "value": "suspended"},
                {"field": "agent_category", "operator": "in", "value": ["autonomous"]},
                {"field": "agent_age_days", "operator": "less_than", "value": 7},
                {"field": "is_resource_owner", "operator": "equals", "value": False},
            ]
        },
    )

    field: ConditionField = Field(
        description="The context field this condition is about.",
        examples=[ConditionField.ENVIRONMENT.value],
    )
    operator: ConditionOperator = Field(
        description=(
            "How the field is compared. The operator must suit the field's type: "
            "ordering operators are refused on a field that is not a number."
        ),
        examples=[ConditionOperator.EQUALS.value],
    )
    value: ConditionValue = Field(
        description=(
            "What the field is compared against: one value for the comparing "
            "operators, a list of values for in/not_in. Values must match the "
            "field's type and come from its closed set, or fall inside its bounds."
        ),
        examples=["production"],
    )

    @model_validator(mode="after")
    def _validate_language(self) -> Self:
        """Validate field, operator and value together — the whole condition."""
        validate_condition(self.field, self.operator, self.value)
        return self

    def as_payload(self) -> dict[str, Any]:
        """The stored JSON form: ``{"field", "operator", "value"}`` and nothing else."""
        return {
            "field": self.field.value,
            "operator": self.operator.value,
            "value": self.value,
        }

    def __repr__(self) -> str:
        return f"<PolicyCondition {self.field.value} {self.operator.value} {self.value!r}>"


def validate_conditions(
    raw: Sequence[Mapping[str, Any]] | Sequence[PolicyCondition],
) -> tuple[PolicyCondition, ...]:
    """Validate a list of raw conditions, or refuse the list.

    Returns a tuple so the result is immutable, and preserves the order the author
    wrote: conditions are all required to hold, so order carries no meaning in
    evaluation — keeping it means a stored policy reads back exactly as it was
    written, which is what a reviewer needs.
    """
    if isinstance(raw, str | bytes) or not isinstance(raw, Sequence):
        raise PolicyDefinitionError(f"conditions must be a list, got {_value_type_name(raw)}")
    if len(raw) > MAX_CONDITIONS:
        raise PolicyDefinitionError(
            f"a policy may state at most {MAX_CONDITIONS} conditions, got {len(raw)}"
        )

    validated: list[PolicyCondition] = []
    for index, item in enumerate(raw):
        if isinstance(item, PolicyCondition):
            validated.append(item)
            continue
        if not isinstance(item, Mapping):
            raise PolicyDefinitionError(
                f"condition {index} must be an object with field, operator and value; "
                f"got {_value_type_name(item)}"
            )
        try:
            validated.append(PolicyCondition.model_validate(dict(item)))
        except ValueError as exc:
            raise PolicyDefinitionError(f"condition {index}: {_first_error(exc)}") from exc
    return tuple(validated)


def conditions_from_stored(stored: object, *, source: str) -> tuple[PolicyCondition, ...]:
    """Read a stored ``conditions`` column back into validated conditions.

    ``source`` names where the JSON came from — a policy and a version — because the
    one thing this function exists for is the case where the row cannot be read: a
    database changed outside the application, or a build that no longer knows a
    vocabulary the row uses. That is a deployment defect, and it is reported as one
    with an address, rather than being skipped. Skipping it would silently change
    what the organization's policy says, and skipping a denial is permitting the
    action.
    """
    if stored is None:
        return ()
    if not isinstance(stored, list):
        raise PolicyDefinitionError(
            f"{source}: stored conditions are not a list ({_value_type_name(stored)})"
        )
    try:
        return validate_conditions(stored)
    except PolicyDefinitionError as exc:
        raise PolicyDefinitionError(f"{source}: {exc}") from exc


def _first_error(exc: Exception) -> str:
    """A readable one-line summary of a validation failure, without its URL."""
    errors = getattr(exc, "errors", None)
    if callable(errors):
        details = errors()
        if details:
            message = details[0].get("msg", str(exc))
            return str(message)
    return str(exc).splitlines()[0]


def normalize_name(name: str) -> str:
    """Normalize a policy name: trimmed, non-empty, bounded."""
    if not isinstance(name, str):
        raise PolicyDefinitionError(f"name must be a string, got {_value_type_name(name)}")
    normalized = name.strip()
    if not normalized:
        raise PolicyDefinitionError("name must not be empty or only whitespace")
    if len(normalized) > POLICY_NAME_MAX_LENGTH:
        raise PolicyDefinitionError(
            f"name must be at most {POLICY_NAME_MAX_LENGTH} characters, got {len(normalized)}"
        )
    return normalized


def normalize_description(description: str) -> str:
    """Normalize a policy description: trimmed, non-empty, bounded.

    Required rather than optional: a policy without a stated purpose is one nobody
    can review, and the reason a rule exists belongs with the rule.
    """
    if not isinstance(description, str):
        raise PolicyDefinitionError(
            f"description must be a string, got {_value_type_name(description)}"
        )
    normalized = description.strip()
    if not normalized:
        raise PolicyDefinitionError("description must not be empty or only whitespace")
    if len(normalized) > POLICY_DESCRIPTION_MAX_LENGTH:
        raise PolicyDefinitionError(
            f"description must be at most {POLICY_DESCRIPTION_MAX_LENGTH} characters, "
            f"got {len(normalized)}"
        )
    return normalized


def validate_effect(effect: PolicyEffect | str) -> PolicyEffect:
    """Resolve an effect, refusing anything the vocabulary does not declare."""
    try:
        return PolicyEffect(effect)
    except ValueError as exc:
        allowed = ", ".join(member.value for member in PolicyEffect)
        raise PolicyDefinitionError(
            f"unknown effect {effect!r}; allowed effects are: {allowed}"
        ) from exc


def validate_status(status: PolicyStatus | str) -> PolicyStatus:
    """Resolve a lifecycle state, refusing anything the vocabulary does not declare."""
    try:
        return PolicyStatus(status)
    except ValueError as exc:
        allowed = ", ".join(member.value for member in PolicyStatus)
        raise PolicyDefinitionError(
            f"unknown policy status {status!r}; allowed statuses are: {allowed}"
        ) from exc


def validate_initial_status(status: PolicyStatus | str) -> PolicyStatus:
    """Resolve the state a policy is *created* in, refusing the states it cannot be."""
    resolved = validate_status(status)
    if resolved not in POLICY_INITIAL_STATES:
        allowed = ", ".join(sorted(state.value for state in POLICY_INITIAL_STATES))
        raise PolicyDefinitionError(
            f"a policy may be created as: {allowed} — {resolved.value} is a state a "
            "policy moves to, not one it is born in"
        )
    return resolved


def validate_transition(from_status: PolicyStatus | str, to_status: PolicyStatus | str) -> None:
    """Refuse a lifecycle move that is not in :data:`POLICY_TRANSITIONS`.

    A no-op is allowed: asking for the state a policy is already in is not a
    lifecycle change, and refusing it would make an idempotent PATCH fail.
    """
    current = validate_status(from_status)
    requested = validate_status(to_status)
    if current == requested:
        return
    allowed = POLICY_TRANSITIONS[current]
    if requested not in allowed:
        if not allowed:
            raise PolicyDefinitionError(
                f"{current.value} is a terminal state: a retired policy cannot move to "
                f"{requested.value}"
            )
        rendered = ", ".join(sorted(state.value for state in allowed))
        raise PolicyDefinitionError(
            f"cannot move a policy from {current.value} to {requested.value}; "
            f"allowed from {current.value}: {rendered}"
        )


def validate_priority(priority: int) -> int:
    """Bounds-check a priority. Lower is more important; the range is closed."""
    if isinstance(priority, bool) or not isinstance(priority, int):
        raise PolicyDefinitionError(
            f"priority must be an integer, got {_value_type_name(priority)}"
        )
    if not PRIORITY_MIN <= priority <= PRIORITY_MAX:
        raise PolicyDefinitionError(
            f"priority must be between {PRIORITY_MIN} and {PRIORITY_MAX}, got {priority}"
        )
    return priority


def validate_target(resource: Resource | str, action: Action | str) -> tuple[Resource, Action]:
    """Resolve the ``resource.action`` pair a policy targets, or refuse it.

    The targets are exactly the declared permissions: a policy about
    ``firewall.block`` or ``incident.create`` is refused, not because the syntax is
    wrong but because this build declares no such capability — and a policy about
    something nothing enforces is a claim, not a control.
    """
    try:
        resolved_resource = Resource(resource)
    except ValueError as exc:
        allowed = ", ".join(member.value for member in Resource)
        raise UnknownPolicyTargetError(
            f"unknown resource {resource!r}; the resource vocabulary is: {allowed}"
        ) from exc
    try:
        resolved_action = Action(action)
    except ValueError as exc:
        allowed = ", ".join(member.value for member in Action)
        raise UnknownPolicyTargetError(
            f"unknown action {action!r}; the action vocabulary is: {allowed}"
        ) from exc
    if resolved_action not in POLICY_TARGETS[resolved_resource]:
        raise UnknownPolicyTargetError(
            f"{resolved_resource.value}.{resolved_action.value} is not a permission this "
            "build declares, so no policy may target it"
        )
    return resolved_resource, resolved_action


def target_permission(resource: Resource | str, action: Action | str) -> Permission:
    """The declared permission a target names — the question it refines."""
    resolved_resource, resolved_action = validate_target(resource, action)
    return Permission.parse(f"{resolved_resource.value}.{resolved_action.value}")


def validate_definition(
    *,
    resource: Resource | str,
    action: Action | str,
    effect: PolicyEffect | str,
    priority: int,
    conditions: Sequence[Mapping[str, Any]] | Sequence[PolicyCondition],
    status: PolicyStatus | str | None = None,
) -> None:
    """Validate a whole definition, or refuse it.

    This is the gate activation passes: a policy becomes ``active`` only if it is a
    policy this build can evaluate. Every part is checked — the target is a declared
    permission, the effect is known, the priority is in range, every condition is
    valid and there are not too many, and (when a status is supplied) the state is
    one a policy may hold. A definition is valid as a unit or it is not valid at all.
    """
    validate_target(resource, action)
    validate_effect(effect)
    validate_priority(priority)
    validate_conditions(conditions)
    if status is not None:
        validate_status(status)


@dataclass(frozen=True, slots=True)
class PolicyDefinition:
    """One version of one policy, as the engine reads it: a value, not a row.

    Every evaluation input a version contributes is here — the identity
    (``policy_id``, ``version``, ``name``), the ordering (``priority``), what it says
    (``effect``) and what it is about (``resource``, ``action``, ``conditions``) —
    and nothing else. The repository maps rows into this, the engine reads it, and
    tests construct it directly, which is what makes the engine testable without a
    database and the mapping testable without an engine.

    It validates itself, so an invalid definition cannot exist to be evaluated: the
    only way a *stored* policy can be uninterpretable is if the store was changed
    outside this application, and that surfaces when the row is mapped here (see
    :meth:`aicore_api.db.repositories.policies.PolicyRepository.current_definition`).
    """

    policy_id: uuid.UUID
    version: int
    name: str
    priority: int
    effect: PolicyEffect
    resource: Resource
    action: Action
    conditions: tuple[PolicyCondition, ...]

    def __post_init__(self) -> None:
        if isinstance(self.version, bool) or not isinstance(self.version, int):
            raise PolicyDefinitionError(
                f"a policy version must be an integer, got {_value_type_name(self.version)}"
            )
        if self.version < 1:
            raise PolicyDefinitionError(f"a policy version is numbered from 1, got {self.version}")
        normalize_name(self.name)
        validate_definition(
            resource=self.resource,
            action=self.action,
            effect=self.effect,
            priority=self.priority,
            conditions=self.conditions,
        )
        if not isinstance(self.conditions, tuple):
            object.__setattr__(self, "conditions", tuple(self.conditions))

    @property
    def condition_payload(self) -> list[dict[str, Any]]:
        """The stored JSON form of this version's conditions."""
        return [condition.as_payload() for condition in self.conditions]

    @property
    def target(self) -> tuple[Resource, Action]:
        """``(resource, action)``: the permission this policy refines."""
        return self.resource, self.action

    def __repr__(self) -> str:
        return (
            f"<PolicyDefinition {self.name!r} v{self.version} {self.effect.value} "
            f"{self.resource.value}.{self.action.value} priority={self.priority} "
            f"conditions={len(self.conditions)}>"
        )
