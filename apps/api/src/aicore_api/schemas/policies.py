"""Policy contract: what a client may send, and what it gets back.

Three rules shape these models.

**The condition language is the core module's, not a second copy of it.** A
condition in a request body and a condition in a response are the same
:class:`~aicore_api.core.policy.PolicyCondition` the repository stores and the
engine evaluates: one model, with ``extra="forbid"``, typed fields, a closed
operator set and values compared strictly (``"7"`` is a string, ``true`` is a
boolean). An invented field, an operator that does not suit a field, or a value
outside a closed set is therefore a 422 from the boundary — and it is refused again
by the repository and again at activation, because the boundary is not the only way
into the table.

**Identity and lifecycle are not free-form fields.** ``organization_id`` comes from
the path and the caller's membership; ``status`` may only be created in a state a
policy may be born in (``draft`` or ``active``) and is moved through the lifecycle
table by the repository, which answers an impossible move with a 409; ``version`` is
never sent by a client — an edit appends the next version, and nothing can name or
overwrite one.

**Nothing here decides anything.** The evaluation request is explicitly a *dry run*:
it reports what the organization's active policies would say, and the response says
so. No field in this module starts, stops, blocks, approves or contains anything.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from aicore_api.core.permissions import Action, Resource
from aicore_api.core.policy import (
    DEFAULT_PRIORITY,
    MAX_CONDITIONS,
    POLICY_DESCRIPTION_MAX_LENGTH,
    POLICY_INITIAL_STATES,
    POLICY_NAME_MAX_LENGTH,
    PRIORITY_MAX,
    PRIORITY_MIN,
    ConditionField,
    ConditionOperator,
    ConditionValue,
    ContextValue,
    PolicyCondition,
    PolicyEffect,
    PolicyStatus,
)

__all__ = [
    "AuthorizationDecisionRead",
    "EffectiveDecisionRead",
    "MatchedConditionRead",
    "PolicyCreate",
    "PolicyDecisionRead",
    "PolicyEvaluateRequest",
    "PolicyEvaluateResponse",
    "PolicyListResponse",
    "PolicyRead",
    "PolicyUpdateRequest",
    "PolicyVersionListResponse",
    "PolicyVersionRead",
]

#: The five fields that make up a *definition*. Changing any of them appends a
#: version; changing the label or the rationale does not, because neither changes
#: what the policy does.
_DEFINITION_FIELDS = ("resource", "action", "effect", "priority", "conditions")

#: Fields that must carry a value when they appear at all. An explicit ``null`` for
#: any of them is a mistake rather than a request — "clear the effect" is not an
#: operation that should silently succeed — so it is refused by name.
_REQUIRED_WHEN_PRESENT = (
    "name",
    "description",
    "status",
    "resource",
    "action",
    "effect",
    "priority",
    "conditions",
)

#: The facts a caller may **not** assert about itself in a dry-run evaluation.
#: ``user_role`` is read from the caller's membership and ``is_resource_owner``
#: depends on a row the request does not name; accepting either from a body would be
#: letting a client write its own security context. Refused loudly rather than
#: overridden silently, because a silently ignored field is a policy author's
#: invisible bug.
_DERIVED_FIELDS = (ConditionField.USER_ROLE, ConditionField.IS_RESOURCE_OWNER)

_CONDITION_EXAMPLES = [
    {"field": "environment", "operator": "equals", "value": "production"},
    {"field": "resource_age_days", "operator": "greater_than", "value": 30},
    {"field": "agent_category", "operator": "in", "value": ["autonomous"]},
]


class PolicyCreate(BaseModel):
    """Request body for ``POST /organizations/{organization_id}/policies``."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(
        min_length=1,
        max_length=POLICY_NAME_MAX_LENGTH,
        description="Human label, unique within the organization. Not an identifier.",
        examples=["No agent changes in production"],
    )
    description: str = Field(
        min_length=1,
        max_length=POLICY_DESCRIPTION_MAX_LENGTH,
        description=(
            "Why this policy exists. Required: a rule nobody can explain cannot be reviewed."
        ),
        examples=["Production agent changes require the security team's approval."],
    )
    resource: Resource = Field(
        description="What the policy is about, from the permission catalogue.",
        examples=[Resource.AGENT.value],
    )
    action: Action = Field(description="Which action on it.", examples=[Action.UPDATE.value])
    effect: PolicyEffect = Field(
        description=(
            "What the policy says when it applies. Required rather than defaulted: "
            "the effect is the decision, and a client that omitted it would be "
            "choosing a semantics by accident."
        ),
        examples=[PolicyEffect.DENY.value],
    )
    priority: int = Field(
        default=DEFAULT_PRIORITY,
        ge=PRIORITY_MIN,
        le=PRIORITY_MAX,
        description=(
            "Ordering hint, lower first. It decides which matching policy is "
            "reported, never which effect wins: deny always beats allow."
        ),
    )
    conditions: list[PolicyCondition] = Field(
        default_factory=list,
        max_length=MAX_CONDITIONS,
        description=(
            "Every condition must hold for the policy to apply (AND). An empty list "
            "is a blanket rule for the target. A condition whose field the "
            "evaluation context does not carry never matches."
        ),
        examples=[[_CONDITION_EXAMPLES[0]]],
    )
    status: PolicyStatus = Field(
        default=PolicyStatus.DRAFT,
        description=(
            "A policy may be created as a draft (editable, never evaluated) or "
            "active (in force). It cannot be created disabled or retired: those are "
            "states a policy moves to."
        ),
    )

    @field_validator("status")
    @classmethod
    def _only_initial_states(cls, value: PolicyStatus) -> PolicyStatus:
        if value not in POLICY_INITIAL_STATES:
            allowed = ", ".join(sorted(state.value for state in POLICY_INITIAL_STATES))
            raise ValueError(f"a policy may be created as: {allowed} — not {value.value!r}")
        return value


class PolicyUpdateRequest(BaseModel):
    """Request body for ``PATCH /organizations/{organization_id}/policies/{policy_id}``.

    One body for the whole record, with three independent effects:

    - ``name`` / ``description`` change the label and the rationale;
    - ``status`` moves the policy through its lifecycle;
    - ``resource`` / ``action`` / ``effect`` / ``priority`` / ``conditions`` change
      the *definition*.

    A definition edit is a partial update of a **whole**: the fields the request
    omits carry over from the current version, and the merged definition is then
    validated as a unit. A client may therefore change one condition without
    restating the target, and a merge that produced something invalid is refused
    (422) rather than published. Publishing the same definition again is not a
    change: no version is appended.
    """

    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, min_length=1, max_length=POLICY_NAME_MAX_LENGTH)
    description: str | None = Field(
        default=None, min_length=1, max_length=POLICY_DESCRIPTION_MAX_LENGTH
    )
    status: PolicyStatus | None = Field(
        default=None,
        description=(
            "draft → active | retired; active → disabled | retired (or active, a "
            "no-op); disabled → active | retired; retired is final. An impossible "
            "move is a 409: the request was well-formed and the record says no."
        ),
    )
    resource: Resource | None = Field(default=None)
    action: Action | None = Field(default=None)
    effect: PolicyEffect | None = Field(default=None)
    priority: int | None = Field(default=None, ge=PRIORITY_MIN, le=PRIORITY_MAX)
    conditions: list[PolicyCondition] | None = Field(
        default=None, max_length=MAX_CONDITIONS, examples=[[*_CONDITION_EXAMPLES[:2]]]
    )

    @model_validator(mode="after")
    def _check_shape(self) -> Self:
        """Refuse an empty request, and refuse ``null`` where null means nothing."""
        if not self.model_fields_set:
            raise ValueError("at least one field must be provided")
        for field_name in _REQUIRED_WHEN_PRESENT:
            if field_name in self.model_fields_set and getattr(self, field_name) is None:
                raise ValueError(f"{field_name} must not be null; omit it to leave it unchanged")
        return self

    @property
    def definition_fields(self) -> tuple[str, ...]:
        """Which definition fields this request actually states.

        Read from ``model_fields_set`` rather than from ``None``: ``conditions: []``
        is a request to *remove every condition*, which is not the same as omitting
        the field. The distinction is the reason this is a property here and not an
        ``is not None`` check in the handler.
        """
        return tuple(name for name in _DEFINITION_FIELDS if name in self.model_fields_set)


class PolicyRead(BaseModel):
    """One policy, with the definition of its current version."""

    policy_id: uuid.UUID
    organization_id: uuid.UUID
    name: str
    description: str
    resource: Resource
    action: Action
    effect: PolicyEffect
    priority: int
    status: PolicyStatus
    version: int = Field(
        description=(
            "The current version number. Advanced only by editing the definition: a "
            "version is never rewritten, so a recorded decision that names one can "
            "always be read back."
        )
    )
    conditions: list[PolicyCondition] = Field(examples=[_CONDITION_EXAMPLES])
    created_at: datetime
    updated_at: datetime


class PolicyVersionRead(BaseModel):
    """One version of a policy's definition. Immutable once published."""

    version: int
    resource: Resource
    action: Action
    effect: PolicyEffect
    priority: int
    conditions: list[PolicyCondition]
    created_at: datetime


class PolicyVersionListResponse(BaseModel):
    """``GET /organizations/{organization_id}/policies/{policy_id}/versions``.

    The append-only history of one policy, oldest first. It is a wrapper rather than
    a bare list because the page size and the total matter here: a policy's history
    grows with every definition edit, so "did I see all of it?" has to be answerable
    from the response.
    """

    organization_id: uuid.UUID
    policy_id: uuid.UUID
    current_version: int = Field(
        description="Which version is in force now — not necessarily the last item."
    )
    items: list[PolicyVersionRead]
    limit: int
    offset: int
    count: int
    total: int = Field(description="How many versions exist in total, across all pages.")


class PolicyListResponse(BaseModel):
    """A page of policies. Mirrors the inventory's and the registry's list shape."""

    organization_id: uuid.UUID
    items: list[PolicyRead]
    limit: int
    offset: int
    count: int
    total: int | None = Field(
        default=None,
        description="Included only when ``?total=true``; costs a second query.",
    )


class PolicyEvaluateRequest(BaseModel):
    """Request body for the dry run: evaluate policies and report what they say.

    Nothing is enforced, nothing is written and no action is taken. The request
    names a target and supplies the context its conditions are evaluated against —
    the caller's role is the only security fact taken from the server, and the
    security fields are refused from the body (see :data:`_DERIVED_FIELDS`).
    """

    model_config = ConfigDict(extra="forbid")

    resource: Resource = Field(
        description="The resource an action would be taken on.",
        examples=[Resource.AGENT.value],
    )
    action: Action = Field(
        description="The action that would be taken.", examples=[Action.UPDATE.value]
    )
    facts: dict[ConditionField, ContextValue] = Field(
        default_factory=dict,
        description=(
            "The context the conditions are evaluated against, keyed by condition "
            "field. A field that is absent from this mapping is *unknown*, which is "
            "not the same as unknown-but-known: a condition about a missing field "
            "does not match, for every operator."
        ),
        examples=[{"environment": "production", "resource_age_days": 3}],
    )

    @field_validator("facts")
    @classmethod
    def _no_derived_facts(
        cls, value: dict[ConditionField, ContextValue]
    ) -> dict[ConditionField, ContextValue]:
        derived = sorted(field.value for field in _DERIVED_FIELDS if field in value)
        if derived:
            raise ValueError(
                "these facts are derived from the caller and cannot be supplied: "
                f"{', '.join(derived)}"
            )
        return value


class MatchedConditionRead(BaseModel):
    """One condition that held, with the fact that satisfied it."""

    field: ConditionField
    operator: ConditionOperator
    value: ConditionValue = Field(description="The value the policy states.")
    actual: ContextValue = Field(
        description="The fact the context carried. Already visible to whoever may read the policy."
    )


class PolicyDecisionRead(BaseModel):
    """What the policy layer says about one target and context.

    The policy layer's answer alone — not the effective one. ``allow`` here means
    "no active policy objects", never "the caller may act": the effective answer is
    the authorization decision combined with this, and a policy can only make it
    more restrictive (see :mod:`aicore_api.auth.policy`).
    """

    decision: str = Field(
        description="allow | deny | require_approval | not_applicable", examples=["deny"]
    )
    reason: str = Field(
        description="Stable code: why this decision came out the way it did.",
        examples=["matching_deny_policy"],
    )
    allowed: bool = Field(description="True only for ``allow``.")
    denied: bool = Field(description="True only for ``deny``.")
    requires_approval: bool = Field(
        description="True for ``require_approval`` — a value, with no workflow behind it."
    )
    applicable: bool = Field(
        description=(
            "Whether any active policy applied at all. ``not_applicable`` is a "
            'decision — "no policy addressed this" — not an absence of one.'
        )
    )
    policy_id: uuid.UUID | None = Field(
        default=None, description="The policy that decided it, when one did."
    )
    policy_version: int | None = Field(
        default=None, description="The exact version the decision was made from."
    )
    policy_name: str | None = None
    priority: int | None = None
    matched_conditions: list[MatchedConditionRead] = Field(
        default_factory=list,
        description="The decider's conditions, with the facts that satisfied them.",
    )
    matched_policy_count: int = Field(
        default=0, description="How many active policies applied (the count is always exact)."
    )
    evaluated_policies: int = Field(
        default=0, description="How many active policies targeted this request at all."
    )


class AuthorizationDecisionRead(BaseModel):
    """Phase 5's answer for the target permission, as the dry run reports it.

    Reported so the two layers are visible side by side: a client can see whether it
    was the permission or the policy that produced the effective answer. Only the
    outcome is reported — not the membership, the role id or anything else about how
    it was computed.
    """

    allowed: bool
    reason: str = Field(
        description="A Phase 5 decision reason, e.g. ``role_permission_grant``.",
        examples=["role_permission_grant"],
    )
    permission: str = Field(
        description="The permission the target names.", examples=["agent.update"]
    )


class EffectiveDecisionRead(BaseModel):
    """The combination of the two layers.

    ``deny`` unless both layers permit: a policy can further restrict an
    authorization decision and can never widen one. ``require_approval`` means "not
    permitted outright" — and nothing in this build approves anything.
    """

    decision: str = Field(description="allow | deny | require_approval", examples=["deny"])
    reason: str = Field(
        description=(
            "Which layer produced the outcome: ``authorization_denied``, "
            "``policy_denied``, ``policy_requires_approval``, ``policy_allowed`` or "
            "``authorization_grant``."
        ),
        examples=["policy_denied"],
    )
    allowed: bool
    denied: bool
    requires_approval: bool


class PolicyEvaluateResponse(BaseModel):
    """The result of a dry-run evaluation: what would happen, and nothing else."""

    dry_run: bool = Field(
        default=True,
        description=(
            "Always true. This endpoint evaluates and reports; it never enforces, "
            "records, approves or acts. Enforcement belongs to the action firewall."
        ),
    )
    organization_id: uuid.UUID
    resource: Resource
    action: Action
    permission_required: str = Field(
        description="The permission the target names — the question Phase 5 answered."
    )
    principal_role: str = Field(
        description="The caller's role here, used as the ``user_role`` fact."
    )
    authorization: AuthorizationDecisionRead
    policy: PolicyDecisionRead
    effective: EffectiveDecisionRead
    evaluated_at: datetime = Field(
        description=(
            "When the evaluation happened. The engine takes this as an argument; it "
            "never reads a clock."
        )
    )
