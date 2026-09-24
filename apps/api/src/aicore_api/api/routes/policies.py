"""Policy routes: the organization's policy record, authorized and tenant-scoped.

The engine lives in :mod:`aicore_api.core.policy_engine`; this module is the
boundary around it. Four rules shape it.

- **The route declares a permission, not a role.** ``policy.read`` / ``policy.create``
  / ``policy.update`` / ``policy.delete`` are the whole authorization surface of the
  policy record, enforced by ``require_permission`` before the handler body runs.
  There is deliberately no ``policy.execute`` and no ``policy.approve``: nothing here
  enforces a policy, and nothing here approves anything.
- **A foreign policy is indistinguishable from a missing one.** Every item route
  answers 404 for a policy that does not exist and for another organization's
  policy, with the same message, and the version history of a foreign policy is
  answered the same way.
- **Nothing is validated only at the boundary.** The request models refuse a
  malformed condition (422); the repository validates the whole definition again
  before it stages a row; and activation re-validates the *stored* version. A policy
  that cannot be evaluated therefore cannot reach ``active``, whatever route it
  arrived by.
- **Evaluation is a dry run and says so.** ``POST .../policies/evaluate`` reports
  what the organization's active policies would say about a target and a context. It
  writes nothing, enforces nothing, and takes no action: the response says
  ``dry_run: true``, and there is no endpoint in this application that executes,
  blocks, suspends or approves anything.

One route is declared before the item routes on purpose: ``/evaluate`` is a static
path under the same prefix as ``/{policy_id}``, and FastAPI matches in declaration
order — the same ordering rule the agent registry follows for its identity lookup.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Annotated, Any, TypeVar

from fastapi import APIRouter, Depends, HTTPException, Query, status

from aicore_api.api.scope import require_instance_scope
from aicore_api.auth.authorization import OrganizationContext, authorize
from aicore_api.auth.dependencies import PrincipalDep, SessionDep, require_permission
from aicore_api.auth.policy import EffectiveDecision, combine
from aicore_api.core.domain_errors import ConflictError
from aicore_api.core.events import (
    POLICY_CREATED,
    POLICY_DELETED,
    POLICY_STATUS_CHANGED,
    POLICY_UPDATED,
    POLICY_VERSION_PUBLISHED,
    DomainEvent,
    emit_event,
)
from aicore_api.core.permissions import Action, Permission, Resource
from aicore_api.core.policy import (
    ConditionField,
    PolicyContextError,
    PolicyDefinitionError,
    PolicyEffect,
    PolicyStatus,
    target_permission,
    validate_effect,
    validate_priority,
    validate_target,
)
from aicore_api.core.policy_engine import (
    PolicyContext,
    PolicyDecision,
    PolicyDefinition,
    evaluate_policies,
)
from aicore_api.db.models.policy import Policy
from aicore_api.db.repositories.policies import PolicyRepository
from aicore_api.schemas.policies import (
    AuthorizationDecisionRead,
    EffectiveDecisionRead,
    MatchedConditionRead,
    PolicyCreate,
    PolicyDecisionRead,
    PolicyEvaluateRequest,
    PolicyEvaluateResponse,
    PolicyListResponse,
    PolicyRead,
    PolicyUpdateRequest,
    PolicyVersionListResponse,
    PolicyVersionRead,
)

router = APIRouter(prefix="/organizations", tags=["policies"])

#: Each route's requirement, declared once so the policy record's authorization
#: surface is reviewable at a glance: four permissions guard seven operations.
ReadPolicies = Annotated[OrganizationContext, Depends(require_permission(Permission.POLICY_READ))]
CreatePolicies = Annotated[
    OrganizationContext, Depends(require_permission(Permission.POLICY_CREATE))
]
UpdatePolicies = Annotated[
    OrganizationContext, Depends(require_permission(Permission.POLICY_UPDATE))
]
DeletePolicies = Annotated[
    OrganizationContext, Depends(require_permission(Permission.POLICY_DELETE))
]

#: One message for "no such policy" and "not your policy". The two cases must be
#: indistinguishable, so they share a constant rather than two similar strings.
_POLICY_NOT_FOUND = "Policy not found"

#: Bounds so that one request cannot ask the database for an unbounded amount of work.
_MAX_OFFSET = 100_000

_NOT_FOUND_RESPONSES: dict[int | str, dict[str, Any]] = {
    401: {"description": "Missing or invalid credentials"},
    403: {"description": "The caller lacks the required policy permission"},
    404: {
        "description": (
            "No such policy in this organization. Identical for a policy that does "
            "not exist and one that belongs to another organization."
        )
    },
}

_T = TypeVar("_T")


def _run(operation: Callable[[], _T]) -> _T:
    """Run a repository operation, translating its domain errors for HTTP.

    Kept in one place so every policy route answers the same way: an impossible
    lifecycle move or a duplicate name is a 409, a malformed definition — an unknown
    target, an invalid condition, a filter that names a capability no policy may
    target — is a 422, and a constraint the caller could have satisfied is never a
    500 with a PostgreSQL message in it.

    A :class:`PolicyDefinitionError` raised while *reading* a stored row is
    deliberately not caught anywhere: that is a deployment defect — a row this build
    cannot interpret — and it must be loud. Turning it into a 4xx would disguise it
    as the caller's mistake, so read paths that materialize a definition call the
    repository directly rather than through here.
    """
    try:
        return operation()
    except ConflictError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except (PolicyDefinitionError, PolicyContextError) as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc


def _policy_read(repository: PolicyRepository, policy: Policy) -> PolicyRead:
    """Serialize a policy: the record's fields, and its current version's definition.

    Built explicitly rather than from ORM attributes so the response contract is
    readable in one place — and so it is obvious that nothing outside the policy
    record (other tenants' rows, internals of the authorization that admitted the
    caller) can reach a policy response.
    """
    definition = repository.definition_of(policy)
    return PolicyRead(
        policy_id=policy.id,
        organization_id=policy.organization_id,
        name=policy.name,
        description=policy.description,
        resource=definition.resource,
        action=definition.action,
        effect=definition.effect,
        priority=definition.priority,
        status=PolicyStatus(policy.status),
        version=definition.version,
        conditions=list(definition.conditions),
        created_at=policy.created_at,
        updated_at=policy.updated_at,
    )


def _decision_read(decision: PolicyDecision) -> PolicyDecisionRead:
    """Serialize the policy layer's answer, including the conditions that produced it."""
    return PolicyDecisionRead(
        decision=decision.decision.value,
        reason=decision.reason.value,
        allowed=decision.allowed,
        denied=decision.denied,
        requires_approval=decision.requires_approval,
        applicable=decision.applicable,
        policy_id=decision.policy_id,
        policy_version=decision.policy_version,
        policy_name=decision.policy_name,
        priority=decision.priority,
        matched_conditions=[
            MatchedConditionRead(
                field=match.field,
                operator=match.operator,
                value=match.value,
                actual=match.actual,
            )
            for match in decision.matched_conditions
        ],
        matched_policy_count=decision.matched_policy_count,
        evaluated_policies=decision.evaluated_policies,
    )


def _effective_read(effective: EffectiveDecision) -> EffectiveDecisionRead:
    """Serialize the combined answer.

    Only the outcome and its reason: which layer decided, and how restrictive the
    result is. The machinery behind it — the membership, the role's other
    permissions — is not reported, because a policy evaluation is not a place to
    publish the caller's authorization internals.
    """
    return EffectiveDecisionRead(
        decision=effective.decision.value,
        reason=effective.reason.value,
        allowed=effective.allowed,
        denied=effective.denied,
        requires_approval=effective.requires_approval,
    )


@router.get(
    "/{organization_id}/policies",
    response_model=PolicyListResponse,
    summary="List the organization's policies",
    responses={
        401: {"description": "Missing or invalid credentials"},
        403: {"description": "The caller lacks the policy.read permission"},
        404: {"description": "The organization does not exist or the caller is not a member"},
    },
)
def list_policies(
    context: ReadPolicies,
    session: SessionDep,
    status_filter: Annotated[
        list[PolicyStatus] | None,
        Query(alias="status", description="Repeatable; values are ORed"),
    ] = None,
    effect: Annotated[list[PolicyEffect] | None, Query()] = None,
    resource: Annotated[list[Resource] | None, Query()] = None,
    action: Annotated[list[Action] | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0, le=_MAX_OFFSET)] = 0,
    total: Annotated[
        bool, Query(description="Include the filtered total; costs a second query")
    ] = False,
) -> PolicyListResponse:
    """A page of policies, newest first.

    Every filter is optional and repeatable, and all of them are about the policy's
    *current* version: values within one filter are ORed, different filters are
    ANDed. ``limit`` is capped at 200, which is what makes "no unbounded list query"
    a property of the endpoint rather than a hope about its callers.
    """
    repository = PolicyRepository(session, context.organization_id)

    def _page() -> list[Policy]:
        return repository.page(
            limit=limit,
            offset=offset,
            statuses=status_filter,
            effects=effect,
            resources=resource,
            actions=action,
        )

    items = _run(_page)
    count = None
    if total:
        count = _run(
            lambda: repository.count(
                statuses=status_filter, effects=effect, resources=resource, actions=action
            )
        )
    return PolicyListResponse(
        organization_id=context.organization_id,
        items=[_policy_read(repository, policy) for policy in items],
        limit=limit,
        offset=offset,
        count=len(items),
        total=count,
    )


@router.post(
    "/{organization_id}/policies",
    response_model=PolicyRead,
    status_code=status.HTTP_201_CREATED,
    summary="Define a policy for the organization",
    responses={
        401: {"description": "Missing or invalid credentials"},
        403: {"description": "The caller lacks the policy.create permission"},
        404: {"description": "The organization does not exist or the caller is not a member"},
        409: {"description": "A policy with this name already exists in this organization"},
        422: {
            "description": (
                "Invalid definition: unknown target, invalid condition, or a status a "
                "policy may not be created in"
            )
        },
    },
)
def create_policy(
    context: CreatePolicies,
    session: SessionDep,
    payload: PolicyCreate,
) -> PolicyRead:
    """Create a policy and its first version.

    A policy created as ``draft`` is stored and never evaluated until it is
    activated; a policy created as ``active`` is in force from now on. Either way it
    starts at version 1, and the version is never rewritten afterwards — an edit
    appends the next one.
    """
    repository = PolicyRepository(session, context.organization_id)
    policy = _run(
        lambda: repository.create(
            name=payload.name,
            description=payload.description,
            resource=payload.resource,
            action=payload.action,
            effect=payload.effect,
            priority=payload.priority,
            conditions=payload.conditions,
            status=payload.status,
        )
    )
    read = _policy_read(repository, policy)
    emit_event(
        DomainEvent(
            name=POLICY_CREATED,
            organization_id=context.organization_id,
            resource_type="policy",
            resource_id=policy.id,
            actor_membership_id=context.membership_id,
            data={
                "resource": read.resource.value,
                "action": read.action.value,
                "effect": read.effect.value,
                "priority": read.priority,
                "condition_count": len(read.conditions),
                "status": read.status.value,
                "version": read.version,
            },
        )
    )
    return read


@router.post(
    "/{organization_id}/policies/evaluate",
    response_model=PolicyEvaluateResponse,
    summary="Evaluate policies for a target and context (dry run)",
    responses={
        401: {"description": "Missing or invalid credentials"},
        403: {"description": "The caller lacks the policy.read permission"},
        404: {"description": "The organization does not exist or the caller is not a member"},
        422: {"description": "Unknown target, or a fact that is invalid for its field"},
    },
)
def evaluate_policies_dry_run(
    context: ReadPolicies,
    principal: PrincipalDep,
    session: SessionDep,
    payload: PolicyEvaluateRequest,
) -> PolicyEvaluateResponse:
    """Report what the organization's active policies say, and change nothing.

    This is the engine at an HTTP boundary and nothing more. It reads the active
    policies that target ``resource.action``, evaluates them against the context
    built from the caller's role and the supplied facts, and reports the result
    alongside the Phase 5 authorization decision for the same permission and the
    combination of the two.

    What it deliberately does **not** do: enforce the decision, record it, write
    anything, suspend or block anything, notify anyone or approve anything. The
    ``user_role`` fact comes from the caller's membership and the security facts are
    refused from the request body, so a caller cannot talk the engine into a context
    it does not have — and even if it could, a policy can only ever make the
    effective decision more restrictive.
    """
    repository = PolicyRepository(session, context.organization_id)
    resource, action = _run(lambda: validate_target(payload.resource, payload.action))
    facts: dict[ConditionField, Any] = {
        **payload.facts,
        ConditionField.USER_ROLE: context.role_code,
    }
    policy_context = _run(
        lambda: PolicyContext(
            organization_id=context.organization_id,
            resource=resource,
            action=action,
            facts=facts,
        )
    )
    # Deliberately *not* through ``_run``: the target was validated above, so
    # anything this raises is a stored policy this build cannot read — a deployment
    # defect that must stay a 500 rather than being answered as a bad request.
    definitions = repository.active_definitions(resource, action)
    evaluated_at = datetime.now(UTC)
    decision = evaluate_policies(definitions, policy_context, evaluated_at=evaluated_at)

    # Phase 5's answer for the same permission, as a value rather than an exception:
    # the caller may hold ``policy.read`` and not the permission under evaluation,
    # and that is a legitimate thing to ask about.
    permission = target_permission(resource, action)
    authorization = authorize(session, principal, context.organization_id, permission)
    effective = combine(authorization, decision)

    return PolicyEvaluateResponse(
        organization_id=context.organization_id,
        resource=resource,
        action=action,
        permission_required=permission.value,
        principal_role=context.role_code,
        authorization=AuthorizationDecisionRead(
            allowed=authorization.allowed,
            reason=authorization.reason.value,
            permission=permission.value,
        ),
        policy=_decision_read(decision),
        effective=_effective_read(effective),
        evaluated_at=evaluated_at,
    )


@router.get(
    "/{organization_id}/policies/{policy_id}",
    response_model=PolicyRead,
    summary="Read one policy",
    responses=_NOT_FOUND_RESPONSES,
)
def read_policy(policy_id: uuid.UUID, context: ReadPolicies, session: SessionDep) -> PolicyRead:
    """One policy, with the definition of the version currently in force."""
    repository = PolicyRepository(session, context.organization_id)
    policy = repository.find(policy_id)
    if policy is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=_POLICY_NOT_FOUND)
    require_instance_scope(
        context, policy, permission=Permission.POLICY_READ, detail=_POLICY_NOT_FOUND
    )
    return _policy_read(repository, policy)


@router.get(
    "/{organization_id}/policies/{policy_id}/versions",
    response_model=PolicyVersionListResponse,
    summary="Read a policy's version history",
    responses=_NOT_FOUND_RESPONSES,
)
def list_policy_versions(
    policy_id: uuid.UUID,
    context: ReadPolicies,
    session: SessionDep,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0, le=_MAX_OFFSET)] = 0,
) -> PolicyVersionListResponse:
    """A page of the policy's versions, oldest first.

    The history is append-only, so this is what makes a recorded decision
    checkable: a decision names a policy and a version, and the row that version
    names still says exactly what it said. A version is never edited and never
    deleted — the only thing an organization can do to a policy's history is add to
    it, or remove the whole policy with it.
    """
    repository = PolicyRepository(session, context.organization_id)
    policy = repository.find(policy_id)
    if policy is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=_POLICY_NOT_FOUND)
    require_instance_scope(
        context, policy, permission=Permission.POLICY_READ, detail=_POLICY_NOT_FOUND
    )
    rows = _run(lambda: repository.versions_of(policy, limit=limit, offset=offset))
    versions: list[PolicyVersionRead] = []
    for row in rows:
        resolved_resource, resolved_action = validate_target(row.resource, row.action)
        versions.append(
            PolicyVersionRead(
                version=row.version,
                resource=resolved_resource,
                action=resolved_action,
                effect=validate_effect(row.effect),
                priority=validate_priority(row.priority),
                conditions=list(repository.conditions_of(policy, row)),
                created_at=row.created_at,
            )
        )
    return PolicyVersionListResponse(
        organization_id=context.organization_id,
        policy_id=policy.id,
        current_version=policy.current_version,
        items=versions,
        limit=limit,
        offset=offset,
        count=len(versions),
        total=_run(lambda: repository.version_count(policy)),
    )


@router.patch(
    "/{organization_id}/policies/{policy_id}",
    response_model=PolicyRead,
    summary="Change a policy's label, rationale, definition or lifecycle state",
    responses={
        **_NOT_FOUND_RESPONSES,
        409: {
            "description": (
                "The name is already used in this organization, or the lifecycle move "
                "is not allowed from the current state"
            )
        },
        422: {
            "description": (
                "An invalid definition — a partial edit is merged with the current "
                "version and validated as a whole — or a state a policy may not hold"
            )
        },
    },
)
def update_policy(
    policy_id: uuid.UUID,
    context: UpdatePolicies,
    session: SessionDep,
    payload: PolicyUpdateRequest,
) -> PolicyRead:
    """Apply a change to a policy.

    Three independent effects, applied in the order that keeps the record valid at
    every step: the label and rationale first, then the definition (which appends a
    version and never rewrites one), then the lifecycle move — so a request that
    changes a definition *and* activates validates the new definition before the
    policy becomes active.

    An edit to an active policy takes effect immediately: the policy is in force,
    the new version becomes its current one, and the previous version stays readable
    and permanently attributable. Nothing is silently rewritten, and nothing here is
    enforced — a policy evaluation is still a report, not an action.
    """
    repository = PolicyRepository(session, context.organization_id)
    policy = repository.find(policy_id)
    if policy is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=_POLICY_NOT_FOUND)
    require_instance_scope(
        context, policy, permission=Permission.POLICY_UPDATE, detail=_POLICY_NOT_FOUND
    )

    changed: list[str] = []
    metadata_fields = payload.model_fields_set & {"name", "description"}
    if metadata_fields:
        metadata_changed = _run(
            lambda: repository.update_metadata(
                policy,
                name=payload.name if "name" in metadata_fields else None,
                description=(payload.description if "description" in metadata_fields else None),
            )
        )
        changed.extend(metadata_changed)
        if metadata_changed:
            emit_event(
                DomainEvent(
                    name=POLICY_UPDATED,
                    organization_id=context.organization_id,
                    resource_type="policy",
                    resource_id=policy.id,
                    actor_membership_id=context.membership_id,
                    data={"fields": sorted(changed)},
                )
            )

    definition_fields = payload.definition_fields
    if definition_fields:
        current = _run(lambda: repository.definition_of(policy))
        merged = _merge_definition(payload, current)
        published = _run(lambda: repository.publish_version(policy, **merged))
        if published.version != current.version:
            changed.append("definition")
            emit_event(
                DomainEvent(
                    name=POLICY_VERSION_PUBLISHED,
                    organization_id=context.organization_id,
                    resource_type="policy",
                    resource_id=policy.id,
                    actor_membership_id=context.membership_id,
                    data={
                        "version": published.version,
                        "previous_version": current.version,
                        "resource": published.resource.value,
                        "action": published.action.value,
                        "effect": published.effect.value,
                        "priority": published.priority,
                        "condition_count": len(published.conditions),
                    },
                )
            )

    if "status" in payload.model_fields_set and payload.status is not None:
        # The request model already refuses an explicit ``null`` here (see
        # ``_REQUIRED_WHEN_PRESENT``), so the narrowing is for the type checker
        # rather than a case a client can reach.
        target_status = payload.status
        moved = _run(lambda: repository.set_status(policy, target_status))
        if moved:
            changed.append("status")
            emit_event(
                DomainEvent(
                    name=POLICY_STATUS_CHANGED,
                    organization_id=context.organization_id,
                    resource_type="policy",
                    resource_id=policy.id,
                    actor_membership_id=context.membership_id,
                    data={"status": policy.status},
                )
            )

    return _policy_read(repository, policy)


@router.delete(
    "/{organization_id}/policies/{policy_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Remove a policy and its version history",
    responses=_NOT_FOUND_RESPONSES,
)
def delete_policy(policy_id: uuid.UUID, context: DeletePolicies, session: SessionDep) -> None:
    """Remove the policy.

    A hard delete: the row *is* the record, and version history belongs to the policy
    it describes — an orphaned version is unreachable, so it goes too. The event is
    emitted first, so the removal stays observable after the rows are gone.

    Retiring is the non-destructive alternative, and the reason ``policy.update`` and
    ``policy.delete`` are separate permissions: a security administrator may write
    and revise a policy without being able to erase the record of it.
    """
    repository = PolicyRepository(session, context.organization_id)
    policy = repository.find(policy_id)
    if policy is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=_POLICY_NOT_FOUND)
    require_instance_scope(
        context, policy, permission=Permission.POLICY_DELETE, detail=_POLICY_NOT_FOUND
    )
    definition = _run(lambda: repository.definition_of(policy))
    emit_event(
        DomainEvent(
            name=POLICY_DELETED,
            organization_id=context.organization_id,
            resource_type="policy",
            resource_id=policy.id,
            actor_membership_id=context.membership_id,
            data={
                "resource": definition.resource.value,
                "action": definition.action.value,
                "effect": definition.effect.value,
                "status": policy.status,
                "version": definition.version,
            },
        )
    )
    repository.delete(policy)


def _merge_definition(payload: PolicyUpdateRequest, current: PolicyDefinition) -> dict[str, Any]:
    """Merge a partial definition edit with the version it edits.

    The fields the request omits carry over from the current version, so a client may
    change one condition without restating the target. The merged definition is then
    validated as a whole by the repository — a merge that produced something invalid
    is refused (422) rather than published, which is what keeps "a policy is valid as
    a unit or it is not valid at all" true for partial edits too.
    """
    fields = payload.definition_fields
    return {
        "resource": payload.resource if "resource" in fields else current.resource,
        "action": payload.action if "action" in fields else current.action,
        "effect": payload.effect if "effect" in fields else current.effect,
        "priority": payload.priority if "priority" in fields else current.priority,
        "conditions": (
            list(payload.conditions)
            if "conditions" in fields and payload.conditions is not None
            else list(current.conditions)
        ),
    }
