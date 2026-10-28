"""Action contract: what a client may ask for, and what it gets back.

Three rules shape these models.

**A client asks for an action; it never describes how one runs.** The request names a
registered action identifier, the row it addresses, the arguments, the environment it
believes it is acting in and an idempotency key. It has no field for a module, a
function, a script, a command, a URL, an executor, a permission, a role, an
organization, a principal or a correlation id — ``extra="forbid"`` refuses a body that
tries to state any of them, so the request the firewall decides on cannot be talked
into naming a different caller or a different tenant than the credential proves.

**The identity fields of the request are assembled by the server.** The typed
:class:`~aicore_api.core.actions.ActionRequest` the firewall sees carries the
organization from the path, the principal and membership from the credential, the
correlation id from the request context and the validated argument model from the
action's own input schema. None of them is a field here, and none of them can be.

**Every refusal has a shape.** A decision that is not ``ALLOW`` is answered with the
error envelope and a code that names the reason — ``action_denied``,
``approval_required``, ``unknown_action`` — so a client does not have to parse prose to
tell "no" from "not yet". The response models here describe the *executed* case, which
is the only case that returns a result: there is no field anywhere in this module that
means "ran", because a response that carries a result is the only thing that does.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from aicore_api.core.actions import (
    ACTION_ID_PATTERN,
    IDEMPOTENCY_KEY_MAX_LENGTH,
    IDEMPOTENCY_KEY_PATTERN,
    ActionSensitivity,
)
from aicore_api.core.assets import Environment
from aicore_api.core.firewall import FirewallOutcome, FirewallReason
from aicore_api.core.permissions import Permission, Resource
from aicore_api.schemas.policies import (
    AuthorizationDecisionRead,
    EffectiveDecisionRead,
    PolicyDecisionRead,
)

__all__ = [
    "ActionExecuteRequest",
    "ActionExecutionResponse",
    "ActionOutcomeRead",
    "ActionTargetRead",
    "FirewallDecisionRead",
]

_EXAMPLES = {
    "action": "agent.posture_check",
    "target_id": "3f1c1d8e-0b7b-4a3a-9f6d-2f2b6d8e5a11",
    "idempotency_key": "01J8Z0Q2P9H4V6S8T2N4K6M8R1",
}


class ActionExecuteRequest(BaseModel):
    """Request body for ``POST /organizations/{organization_id}/actions/execute``.

    The whole client-side surface of the action firewall, and deliberately opaque about
    *how* anything runs: there is no executor field, no module field, no URL field, no
    shell field and no permission field — and ``extra="forbid"`` means a body that
    tries to add one is a 422 rather than a silently ignored typo.
    """

    model_config = ConfigDict(extra="forbid")

    action: str = Field(
        min_length=1,
        max_length=64,
        pattern=ACTION_ID_PATTERN,
        description=(
            "The identifier of a registered action. An identifier that is not in this "
            "build's catalogue is refused with a 422 that names the catalogue; it is never "
            "resolved, imported or interpreted."
        ),
        examples=[_EXAMPLES["action"]],
    )
    target_id: uuid.UUID = Field(
        description=(
            "The row the action addresses, within this organization. A target that is not "
            "in this organization is answered exactly like one that does not exist."
        ),
        examples=[_EXAMPLES["target_id"]],
    )
    environment: Environment = Field(
        description=(
            "The environment the caller believes it is acting in. Not evidence: it is "
            "checked against the environment the target row is recorded in, a mismatch is "
            "refused, and the policy layer is evaluated against the *recorded* value."
        ),
        examples=[Environment.PRODUCTION.value],
    )
    arguments: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Arguments for the action, validated against the action's own input schema. "
            "Unknown keys, wrong types, nested objects and oversized values are refused "
            "before anything is authorized or executed."
        ),
        examples=[{"report_detail": "summary"}],
    )
    idempotency_key: str = Field(
        min_length=1,
        max_length=IDEMPOTENCY_KEY_MAX_LENGTH,
        pattern=IDEMPOTENCY_KEY_PATTERN,
        description=(
            "An opaque token that makes the request replayable. Required: a retry after a "
            "lost answer must not run the action twice, and an optional key is one most "
            "clients omit. A key reused for a *different* request is a 409."
        ),
        examples=[_EXAMPLES["idempotency_key"]],
    )
    agent_id: uuid.UUID | None = Field(
        default=None,
        description=(
            "The agent this execution is attributed to, when an agent rather than a person "
            "requested it. Must belong to this organization; the server never takes it from "
            "anywhere else."
        ),
    )


class ActionTargetRead(BaseModel):
    """The row an action addressed."""

    resource: Resource = Field(description="The target's resource type, from the vocabulary.")
    id: uuid.UUID


class FirewallDecisionRead(BaseModel):
    """What the firewall decided, and why.

    Only ``allow`` reaches this shape: a refusal is answered as an error, so a response
    carrying a decision is a response that ran something. The field is kept explicit
    because "which decision permitted this?" is the question a reader of the response
    should not have to infer.
    """

    outcome: FirewallOutcome = Field(
        description="The firewall's outcome. Only ``allow`` reaches an adapter.",
        examples=[FirewallOutcome.ALLOW.value],
    )
    reason: FirewallReason = Field(
        description="Stable code: why the decision came out the way it did.",
        examples=[FirewallReason.ALLOWED.value],
    )


class ActionOutcomeRead(BaseModel):
    """What the adapter reported, as an execution's result.

    The shape every adapter must produce: a sentence, closed finding codes and
    structured detail. The reference adapter's detail carries an ``assessment``
    (``standard`` | ``elevated`` | ``attention``) and, for ``full`` detail, the facts it
    assessed.
    """

    summary: str
    findings: list[str] = Field(
        default_factory=list,
        description="Stable finding codes, in the order the adapter reports them.",
    )
    details: dict[str, Any] = Field(default_factory=dict)
    adapter: str = Field(
        description=(
            "Which adapter ran. One adapter ships in this phase; the field exists so a "
            "response never leaves a reader guessing what produced it."
        ),
        examples=["agent_registry"],
    )
    digest: str = Field(
        description=(
            "A SHA-256 digest of the action, the target and the reported outcome, so two "
            "executions can be compared without comparing prose. Identifies what was done, "
            "not who asked."
        )
    )


class ActionExecutionResponse(BaseModel):
    """The result of an executed action. Returned only when the firewall said ``ALLOW``.

    Every field is either an identifier the client already has, the decision that
    permitted the execution, or the adapter's own report. Nothing about the caller is
    echoed beyond the identifiers the request was authorized with, and the arguments are
    never echoed back.
    """

    organization_id: uuid.UUID
    action_id: str
    action_sensitivity: ActionSensitivity = Field(
        description="The registered action's classification, published so it is reviewable."
    )
    target: ActionTargetRead
    agent_id: uuid.UUID | None = None
    permission_required: str = Field(
        description="The permission the execution was authorized with — ``action.execute``.",
        examples=[Permission.ACTION_EXECUTE.value],
    )
    principal_role: str = Field(
        description="The caller's role here. Reported, never used to widen anything."
    )
    environment: Environment
    firewall: FirewallDecisionRead
    authorization: AuthorizationDecisionRead
    policy: PolicyDecisionRead
    effective: EffectiveDecisionRead
    executed: bool = Field(
        default=True,
        description=(
            "Always true. A decision that did not permit execution is answered as an error, "
            "so this response is only ever produced by an execution."
        ),
    )
    replayed: bool = Field(
        description=(
            "True when this is the recorded answer to a request whose idempotency key had "
            "already been used by the same request. No adapter ran again."
        )
    )
    execution_id: uuid.UUID = Field(description="The ledger row that records this execution.")
    idempotency_key: str
    correlation_id: str = Field(
        description="The request id this decision and execution are attributable to."
    )
    executed_at: datetime
    result: ActionOutcomeRead
