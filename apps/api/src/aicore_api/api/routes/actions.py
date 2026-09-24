"""Action routes: the one endpoint in this build that can execute something.

The pipeline is the phase, so it is worth reading in the handler in order. The
credential, the tenant and the ``action.execute`` permission are resolved by the
dependency *before* the body is interpreted — an unauthorized caller learns nothing
about the action catalogue, not even whether the action they named exists. Then, in
the handler:

1. **the action is resolved** from the process-wide allowlist. An identifier that is
   not registered is a 422 that names the catalogue; nothing is imported, loaded or
   interpreted to find out;
2. **the target is resolved inside this organization** — a row belonging to another
   tenant is answered exactly like one that does not exist;
3. **the attributed agent is resolved** the same way, when the request names one;
4. **the request is assembled and validated** against the action's own input schema,
   with the identity fields taken from the credential and the path;
5. **Phase 5 answers for the target**: the existing authorization service, asked about
   ``action.execute`` with the concrete row in scope, which is also where the
   ownership fact comes from;
6. **the Phase 6 context is built from server data** — the target's recorded
   environment, lifecycle state, classification, category and ages, plus the caller's
   role and the ownership fact. The one thing a request may state about the world is
   the environment it believes it is acting in, and that is *checked* against the
   recorded value rather than believed;
7. **Phase 6 evaluates** through the existing engine, against the organization's
   active policies for the ``action.execute`` target;
8. **the firewall decides** — one typed outcome, from both layers;
9. **and only an ``ALLOW`` reaches an adapter**, through
   :class:`~aicore_api.core.execution.ActionExecutionService`, which re-checks that
   outcome rather than trusting this handler;
10. **the trail records what happened**, at three points that are deliberately not four:
   the request once it has resolved a registered action, the *decision* once — a refusal
   is one event naming the layer that refused, not one event per layer that could have —
   and the ending (executed, replayed or failed).

A decision that is not ``ALLOW`` is answered with the error envelope and a code that
names the reason, and nothing is executed — no adapter call, no ledger row. An executed
request answers 200 with the adapter's report, the decisions that produced it, and the
identifiers a retry needs.

The audit writes are ordered by what they claim. The one that says "this request was
admitted" is written *before* anything can run, and a failure to record it fails the
request: an execution nobody can account for is worse than an execution that did not
happen. The ones written afterwards describe something that has already occurred, so they
cannot be allowed to change what the caller is told — they are attempted, and a failure
is logged loudly rather than converted into a false report about what the system did. The
firewall is unaffected either way: it has already decided, and no audit path can turn a
refusal into an execution.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status

from aicore_api.api.deps import ActionExecutorRegistryDep, ActionRegistryDep, AuditWriterDep
from aicore_api.api.routes.policies import _decision_read, _effective_read
from aicore_api.audit.writer import AuditWriter
from aicore_api.auth.authorization import (
    AuthorizationDecision,
    OrganizationContext,
    ResourceScope,
    authorize_instance,
)
from aicore_api.auth.dependencies import PrincipalDep, SessionDep, require_permission
from aicore_api.auth.policy import EffectiveDecision, combine
from aicore_api.core.actions import (
    ActionDefinition,
    ActionError,
    ActionRequest,
    ActionTarget,
    UnknownActionError,
)
from aicore_api.core.audit import (
    AuditDecision,
    AuditEventType,
    AuditOutcome,
    AuditResourceType,
)
from aicore_api.core.errors import ApiError
from aicore_api.core.execution import (
    ActionExecutionResult,
    ActionExecutionService,
    ExecutionFailedError,
    IdempotencyConflictError,
)
from aicore_api.core.firewall import (
    FirewallConfigurationError,
    FirewallDecision,
    FirewallOutcome,
    FirewallReason,
    decide,
)
from aicore_api.core.permissions import Permission
from aicore_api.core.policy import MAX_AGE_DAYS, ConditionField, ContextValue
from aicore_api.core.policy_engine import PolicyContext, PolicyDecision, evaluate_policies
from aicore_api.core.request_context import get_current_request_id, sanitize_request_id
from aicore_api.db.models.agent import Agent
from aicore_api.db.repositories.action_executions import ActionExecutionRepository
from aicore_api.db.repositories.agents import AgentRepository
from aicore_api.db.repositories.policies import PolicyRepository
from aicore_api.schemas.actions import (
    ActionExecuteRequest,
    ActionExecutionResponse,
    ActionOutcomeRead,
    ActionTargetRead,
    FirewallDecisionRead,
)
from aicore_api.schemas.policies import AuthorizationDecisionRead

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/organizations", tags=["actions"])

#: The route's requirement, declared as a permission: the credential, the tenant and
#: ``action.execute`` are all resolved before the handler body runs, and the
#: dependency is what makes that readable from the route rather than buried in it.
ExecuteActions = Annotated[
    OrganizationContext, Depends(require_permission(Permission.ACTION_EXECUTE))
]

#: One message for "no such agent" and "not your agent", matching the registry's own
#: wording: the two cases must be indistinguishable, and two different strings for one
#: situation would make them distinguishable.
_AGENT_NOT_FOUND = "Agent not found"

_RESPONSES: dict[int | str, dict[str, Any]] = {
    401: {"description": "Missing or invalid credentials"},
    403: {
        "description": (
            "The caller lacks the action.execute permission, the caller's membership is "
            "not active, an active policy denies the action, the action requires an "
            "approval this build cannot grant, or the target's recorded environment is "
            "not the one the request declares. The error code names which."
        )
    },
    404: {
        "description": (
            "No such organization, no such target in this organization, or no such "
            "attributed agent. Deliberately identical for a row that does not exist and "
            "for one that belongs to another organization."
        )
    },
    409: {
        "description": (
            "The idempotency key was already used for a different request, or a request "
            "carrying it is still in progress or failed. Nothing was executed."
        )
    },
    422: {
        "description": (
            "An action identifier that is not registered, arguments the action's input "
            "schema does not accept, or a body naming a field the server owns."
        )
    },
    500: {
        "description": (
            "The action was admitted and could not be completed. The failure is recorded "
            "against the idempotency key, so retrying it does not run the action again."
        )
    },
}


def _age_days(created_at: datetime, evaluated_at: datetime) -> int:
    """How old a record is, in whole days, clamped to the vocabulary's range.

    Clamped rather than omitted: a policy that restricts something *older* than a bound
    keeps matching if a clock is wrong, and an age outside the vocabulary's range would
    otherwise make the context invalid — a 500 for a request that did nothing wrong.
    """
    return min(MAX_AGE_DAYS, max(0, (evaluated_at - created_at).days))


def _agent_facts(
    agent: Agent,
    *,
    evaluated_at: datetime,
    role_code: str,
    authorization: AuthorizationDecision,
) -> dict[ConditionField, ContextValue]:
    """The Phase 6 facts an agent target attests, derived from the stored row.

    Every value comes from the registry record, its backing inventory record, the
    membership Phase 5 resolved, or the ownership the instance decision reported. None
    of them comes from the request: a caller that could state its own role, the target's
    risk classification or its environment could argue its way past the policy it is
    supposed to be subject to.
    """
    asset = agent.asset
    facts: dict[ConditionField, ContextValue] = {
        ConditionField.ENVIRONMENT: asset.environment,
        ConditionField.ASSET_TYPE: asset.asset_type,
        ConditionField.RESOURCE_STATUS: asset.status,
        ConditionField.RISK_CLASSIFICATION: asset.risk_classification,
        ConditionField.AGENT_CATEGORY: agent.category,
        ConditionField.USER_ROLE: role_code,
        ConditionField.AGENT_AGE_DAYS: _age_days(agent.created_at, evaluated_at),
        ConditionField.ASSET_AGE_DAYS: _age_days(asset.created_at, evaluated_at),
    }
    # Absent rather than guessed when the row has no owner: a condition on an absent
    # field never matches, which is the honest answer to "nobody owns this".
    if isinstance(authorization.principal_is_owner, bool):
        facts[ConditionField.IS_RESOURCE_OWNER] = authorization.principal_is_owner
    return facts


def _authorization_for(
    context: OrganizationContext, *, agent: Agent | None
) -> AuthorizationDecision:
    """Phase 5's answer for ``action.execute``, scoped to the row when there is one.

    Two sources, deliberately: with a resolved row this is
    :func:`~aicore_api.auth.authorization.authorize_instance`, which adds the instance
    dimension (the row's tenant, and whether the caller owns it) and is what supplies
    the ``is_resource_owner`` fact; without one there is nothing to scope, so the
    decision the dependency already made — the same permission, the same organization —
    is the answer. Both are the existing service: this phase adds no second way to
    decide who may do what.
    """
    if agent is None:
        decision = context.decision
        if decision is None:  # pragma: no cover - the dependency always resolves one
            raise FirewallConfigurationError(
                "the request reached the action pipeline without an authorization decision"
            )
        if decision.permission is not Permission.ACTION_EXECUTE:
            raise FirewallConfigurationError(
                f"the authorization decision is about {decision.permission}, not "
                f"{Permission.ACTION_EXECUTE}"
            )
        return decision
    return authorize_instance(
        context,
        ResourceScope.of(agent.asset),
        permission=Permission.ACTION_EXECUTE,
    )


def _refusal(decision: FirewallDecision) -> ApiError:
    """Translate a firewall refusal into the HTTP failure its reason names.

    A refusal is never a success: every case below is an error, with a code a client can
    switch on. The 404 deliberately carries no firewall detail — the whole point of
    answering "no such target" and "not your target" identically is that the caller
    learns nothing about rows outside their tenant.
    """
    details: dict[str, Any] = {
        "action_id": decision.action_id,
        "decision": decision.outcome.value,
        "reason": decision.reason.value,
        "correlation_id": decision.correlation_id,
        "executed": False,
    }
    if decision.reason is FirewallReason.AUTHORIZATION_DENIED:
        # Unreachable through this route — the dependency refuses first — and kept so a
        # future caller of the firewall answers the same way rather than executing.
        return ApiError(
            status.HTTP_403_FORBIDDEN,
            "forbidden",
            f"this operation requires the {Permission.ACTION_EXECUTE} permission",
            details=details,
        )
    if decision.reason is FirewallReason.POLICY_DENIED:
        return ApiError(
            status.HTTP_403_FORBIDDEN,
            "policy_denied",
            "an active policy of this organization denies this action; it was not executed",
            details=details,
        )
    if decision.reason is FirewallReason.POLICY_REQUIRES_APPROVAL:
        return ApiError(
            status.HTTP_403_FORBIDDEN,
            "approval_required",
            (
                "this action requires approval, and this build has no approval workflow: "
                "nothing was executed and no approval was recorded"
            ),
            details=details,
        )
    if decision.reason is FirewallReason.ENVIRONMENT_MISMATCH:
        return ApiError(
            status.HTTP_403_FORBIDDEN,
            "environment_mismatch",
            (
                "the target is not recorded in the environment this request declares, so "
                "the request was refused"
            ),
            details=details,
        )
    return ApiError(
        status.HTTP_404_NOT_FOUND,
        "not_found",
        _AGENT_NOT_FOUND,
        details=None,
    )


def _decision_metadata(decision: FirewallDecision) -> dict[str, Any]:
    """The facts a decision event carries: which layer decided, and why.

    Deliberately not the caller's arguments, the target's contents or the policies that
    matched: an event names the decision, and the row it is written against already names
    the request. A trail that quoted what a caller sent would be a payload store with a
    security-sounding name.
    """
    return {
        "reason": decision.reason.value,
        "firewall_outcome": decision.outcome.value,
        "effective_reason": decision.effective_reason,
        "policy_decision": decision.policy_decision,
        "permission_required": decision.permission_required,
        "principal_role": decision.principal_role or "unknown",
    }


def _record_decision(
    trail: AuditWriter,
    context: OrganizationContext,
    request: ActionRequest,
    decision: FirewallDecision,
    *,
    resource_type: AuditResourceType,
) -> None:
    """Record a refusal — once.

    One event per refused request, whichever layer refused it: the firewall's reason names
    the layer (``authorization_denied``, ``policy_denied``, ``target_not_found``,
    ``environment_mismatch``, ``policy_requires_approval``), so an investigation reads *why*
    from one row instead of correlating four. Emitting an event per layer that *could* have
    refused is the duplication this phase explicitly rules out.

    The write happens after the decision and cannot change it: the refusal is raised by the
    caller regardless of what happens here, and a failure to record is logged rather than
    converted into a different answer.
    """
    event_type = (
        AuditEventType.ACTION_REQUIRE_APPROVAL
        if decision.requires_approval
        else AuditEventType.ACTION_DENIED
    )
    outcome = AuditOutcome.NOT_EXECUTED if decision.requires_approval else AuditOutcome.BLOCKED
    metadata = _decision_metadata(decision)
    metadata["idempotency_key"] = request.idempotency_key
    _record_safely(
        trail,
        event_type,
        context=context,
        request=request,
        resource_type=resource_type,
        # The firewall's outcome vocabulary and the decision column's are the same three
        # words (``allow`` / ``deny`` / ``require_approval``); ``test_audit.py`` asserts
        # that they are, so a fourth firewall outcome cannot slip past this conversion
        # without a test noticing.
        decision=AuditDecision(decision.outcome.value),
        outcome=outcome,
        metadata=metadata,
    )


def _record_outcome(
    trail: AuditWriter,
    context: OrganizationContext,
    request: ActionRequest,
    decision: FirewallDecision,
    *,
    resource_type: AuditResourceType,
    event_type: AuditEventType,
    outcome: AuditOutcome,
    metadata: dict[str, Any],
) -> None:
    """Record how an admitted action ended: executed, replayed or failed.

    Only reached when the firewall said ``ALLOW``, so the decision column is ``allow``:
    the row says both that it was permitted and what came of it, which is the pair a
    security review asks about.
    """
    _record_safely(
        trail,
        event_type,
        context=context,
        request=request,
        resource_type=resource_type,
        decision=AuditDecision.ALLOW,
        outcome=outcome,
        metadata=metadata,
    )


def _record_safely(
    trail: AuditWriter,
    event_type: AuditEventType,
    *,
    context: OrganizationContext,
    request: ActionRequest,
    resource_type: AuditResourceType,
    decision: AuditDecision,
    outcome: AuditOutcome,
    metadata: dict[str, Any],
) -> None:
    """Write one post-decision event, and never let the write change the answer.

    By the time these run the decision is made and, for the outcome events, the adapter has
    already acted. Raising here could only turn a completed execution into a reported
    failure — which would be a lie about what happened, and an invitation to retry an
    action that already ran. So the failure is logged at ERROR, where an operator will see
    it, and the caller still gets the true answer. The trail is never *silently* short: a
    missing row that nobody was told about is the failure mode this guards against.
    """
    try:
        trail.record(
            event_type,
            context=context,
            resource_type=resource_type,
            resource_id=request.target_id,
            agent_id=request.agent_id,
            action=request.action_id,
            decision=decision,
            outcome=outcome,
            correlation_id=request.correlation_id,
            metadata=metadata,
        )
    except Exception:
        logger.exception(
            "the audit trail could not record %s for action %s in organization %s",
            event_type.value,
            request.action_id,
            context.organization_id,
        )


def _read(
    *,
    context: OrganizationContext,
    definition: ActionDefinition,
    request: ActionRequest,
    decision: FirewallDecision,
    authorization: AuthorizationDecision,
    policy_decision: PolicyDecision,
    effective: EffectiveDecision,
    result: ActionExecutionResult,
) -> ActionExecutionResponse:
    """Serialize an executed action: the decisions, the identifiers and the report.

    The policy read-models are Phase 6's own serializers, imported rather than
    re-implemented: an execution reports the same policy decision a dry run does, and
    two implementations of one report would eventually disagree.
    """
    return ActionExecutionResponse(
        organization_id=context.organization_id,
        action_id=definition.action_id,
        action_sensitivity=definition.sensitivity,
        target=ActionTargetRead(resource=definition.target_resource, id=request.target_id),
        agent_id=request.agent_id,
        permission_required=str(decision.permission_required),
        principal_role=context.role_code,
        environment=request.environment,
        firewall=FirewallDecisionRead(outcome=decision.outcome, reason=decision.reason),
        authorization=AuthorizationDecisionRead(
            allowed=authorization.allowed,
            reason=authorization.reason.value,
            permission=str(Permission.ACTION_EXECUTE),
        ),
        policy=_decision_read(policy_decision),
        effective=_effective_read(effective),
        executed=True,
        replayed=result.replayed,
        execution_id=result.execution_id,
        idempotency_key=request.idempotency_key,
        correlation_id=decision.correlation_id,
        executed_at=result.executed_at,
        result=ActionOutcomeRead(
            summary=result.outcome.summary,
            findings=list(result.outcome.findings),
            details=dict(result.outcome.details),
            adapter=result.adapter,
            digest=result.digest,
        ),
    )


@router.post(
    "/{organization_id}/actions/execute",
    response_model=ActionExecutionResponse,
    summary="Execute one registered action through the action firewall",
    responses=_RESPONSES,
)
def execute_action(
    context: ExecuteActions,
    principal: PrincipalDep,
    session: SessionDep,
    registry: ActionRegistryDep,
    executors: ActionExecutorRegistryDep,
    trail: AuditWriterDep,
    payload: ActionExecuteRequest,
) -> ActionExecutionResponse:
    """Run one action from the registered catalogue, if — and only if — the firewall allows it.

    Never executes before every check has passed, and never turns a refusal into a
    success: a decision that is not ``ALLOW`` is answered as an error whose code names
    the reason. This handler resolves, decides and reports; the adapter is reached only
    through the execution service, which refuses anything that is not an ``ALLOW`` on
    its own account.
    """
    # 1. The action, from the process-wide allowlist. Nothing is imported to resolve it.
    try:
        definition = registry.resolve(payload.action)
    except UnknownActionError as exc:
        raise ApiError(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "unknown_action",
            str(exc),
            details={"registered_actions": list(registry.action_ids())},
        ) from exc

    evaluated_at = datetime.now(UTC)
    repository = AgentRepository(session, context.organization_id)

    # 2. The target, inside this organization. A foreign row answers exactly like a
    #    missing one, and the row is what the policy context is built from.
    agent = repository.find(payload.target_id)

    # 3. The attributed agent, resolved the same way. An agent from another tenant is
    #    not "an agent you may not use": as far as this organization is concerned, it is
    #    not an agent.
    if payload.agent_id is not None and repository.find(payload.agent_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=_AGENT_NOT_FOUND)

    # 4. The request, assembled from the credential, the path and the body, and
    #    validated against the action's own input schema.
    try:
        request = ActionRequest.build(
            definition=definition,
            organization_id=context.organization_id,
            principal_id=principal.user_id,
            membership_id=context.membership_id,
            target_id=payload.target_id,
            environment=payload.environment,
            arguments=payload.arguments,
            correlation_id=sanitize_request_id(get_current_request_id()),
            idempotency_key=payload.idempotency_key,
            agent_id=payload.agent_id,
        )
    except ActionError as exc:
        raise ApiError(status.HTTP_422_UNPROCESSABLE_ENTITY, "invalid_arguments", str(exc)) from exc

    # What the trail calls the row this action addresses, taken from the definition rather
    # than written here. A future action that addresses something the trail cannot name
    # fails loudly at this line, which is the right place to find out.
    trail_resource = AuditResourceType(definition.target_resource.value)

    # 4b. The trail records that this request was admitted, *before* anything can run and
    #     before any decision exists. It is the one audit write that fails the request if it
    #     fails: an execution nobody can account for is worse than an execution that did not
    #     happen, and refusing here executes nothing.
    trail.record(
        AuditEventType.ACTION_REQUESTED,
        context=context,
        resource_type=trail_resource,
        resource_id=payload.target_id,
        agent_id=payload.agent_id,
        action=definition.action_id,
        outcome=AuditOutcome.PENDING,
        correlation_id=request.correlation_id,
        metadata={
            "sensitivity": definition.sensitivity.value,
            "argument_count": len(payload.arguments or {}),
            "environment": request.environment,
            "attributed": payload.agent_id is not None,
        },
    )

    # 5. Phase 5, for this row: the existing service, asked about the permission this
    #    route enforces, with the instance dimension that reports ownership.
    authorization = _authorization_for(context, agent=agent)

    # 6. Phase 6's context, from server data. When the target is not in this
    #    organization there is nothing to describe, so the context carries only the
    #    security facts — and the firewall refuses the request before the policy answer
    #    is even considered, because "your policy says no" is not a true statement about
    #    a row this organization does not have.
    facts: dict[ConditionField, ContextValue] = {}
    target: ActionTarget | None = None
    if agent is not None:
        facts = _agent_facts(
            agent,
            evaluated_at=evaluated_at,
            role_code=context.role_code,
            authorization=authorization,
        )
        target = ActionTarget(
            resource=definition.target_resource,
            identifier=payload.target_id,
            facts=facts,
        )

    # The facts are this build's own, so an invalid context is a defect rather than a
    # bad request: it is deliberately *not* translated into a 4xx.
    policy_context = PolicyContext(
        organization_id=context.organization_id,
        resource=definition.policy_target[0],
        action=definition.policy_target[1],
        facts=facts,
    )

    # 7. Phase 6, through the existing engine and the existing repository query.
    policy_decision: PolicyDecision = evaluate_policies(
        PolicyRepository(session, context.organization_id).active_definitions(
            definition.policy_target[0], definition.policy_target[1]
        ),
        policy_context,
        evaluated_at=evaluated_at,
    )
    effective: EffectiveDecision = combine(authorization, policy_decision)

    # 8. The firewall. One typed outcome; nothing has been executed at this point.
    decision = decide(
        request=request,
        definition=definition,
        target=target,
        authorization=authorization,
        policy=effective,
    )
    if decision.outcome is not FirewallOutcome.ALLOW:
        _record_decision(trail, context, request, decision, resource_type=trail_resource)
        raise _refusal(decision)

    # 9. Execution, through the service that re-checks the decision it is handed.
    if target is None:  # pragma: no cover - ALLOW is impossible without a target
        raise FirewallConfigurationError(
            "the firewall allowed an action whose target this organization does not have"
        )
    service = ActionExecutionService(
        registry=registry,
        executors=executors,
        ledger=ActionExecutionRepository(session, context.organization_id),
    )
    try:
        result = service.execute(
            decision=decision,
            request=request,
            definition=definition,
            target=target,
            invoked_at=datetime.now(UTC),
        )
    except ExecutionFailedError as exc:
        _record_outcome(
            trail,
            context,
            request,
            decision,
            resource_type=trail_resource,
            event_type=AuditEventType.ACTION_FAILED,
            outcome=AuditOutcome.FAILED,
            metadata={"error_code": "execution_failed", "idempotency_key": request.idempotency_key},
        )
        raise ApiError(status.HTTP_500_INTERNAL_SERVER_ERROR, "execution_failed", str(exc)) from exc
    except IdempotencyConflictError as exc:
        # A key reused for a different request, or a request still in progress: nothing ran.
        # The refusal names itself in the response, and the trail records the ending — the
        # request was admitted and did not run, which is exactly what ``failed`` means. An
        # admission row with no ending would be a record that stops mid-sentence, and a
        # reader could not tell it from a process that died.
        _record_outcome(
            trail,
            context,
            request,
            decision,
            resource_type=trail_resource,
            event_type=AuditEventType.ACTION_FAILED,
            outcome=AuditOutcome.FAILED,
            metadata={
                "error_code": "idempotency_conflict",
                "idempotency_key": request.idempotency_key,
            },
        )
        raise ApiError(status.HTTP_409_CONFLICT, "idempotency_conflict", str(exc)) from exc

    _record_outcome(
        trail,
        context,
        request,
        decision,
        resource_type=trail_resource,
        event_type=(
            AuditEventType.ACTION_REPLAYED if result.replayed else AuditEventType.ACTION_EXECUTED
        ),
        outcome=AuditOutcome.REPLAYED if result.replayed else AuditOutcome.SUCCESS,
        metadata={
            "adapter": result.adapter,
            "digest": result.digest,
            "finding_count": len(result.outcome.findings),
            "idempotency_key": request.idempotency_key,
            "replayed": result.replayed,
        },
    )

    return _read(
        context=context,
        definition=definition,
        request=request,
        decision=decision,
        authorization=authorization,
        policy_decision=policy_decision,
        effective=effective,
        result=result,
    )
