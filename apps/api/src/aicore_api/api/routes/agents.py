"""Agent routes: the organization's agent registry, authorized and tenant-scoped.

The registry answers one question the inventory cannot: *who is this agent?* The
inventory records that an organization knows about an agent, what it is called and
who owns it. The registry gives that record a stable identifier that survives
renames and version changes, and records the category and version it was registered
at. Both are served from the same object here, because to a caller an agent is one
thing — the split is a storage decision, not a contract.

Four rules shape this module.

- **The route declares a permission, not a role.** ``agent.read`` / ``agent.create``
  / ``agent.update`` / ``agent.delete`` are the whole authorization surface of the
  registry, and each is enforced by ``require_permission`` before the handler body
  runs. There is no ``agent.execute``: registering an agent is not a capability to
  run one.
- **Identity is generated, never supplied.** No request model has an
  ``identity_id`` field, and the column has a database default, so a client cannot
  choose, change or spoof who an agent is — it can only name it.
- **A foreign agent is indistinguishable from a missing one.** ``GET``, ``PATCH``
  and ``DELETE`` answer 404 for both, with the same message, and so does the
  identity lookup: an identifier from another tenant resolves to nothing.
- **Lifecycle moves are checked against the transition table** in
  ``core/agents.py``. An impossible move is a 409 — the request was well-formed and
  the record says no — and ``suspended``/``retired`` remain records. Nothing in this
  phase starts, stops, blocks or contains anything.

One route is ordered deliberately: ``/identity/{identity_id}`` is declared before
``/{agent_id}``, because FastAPI matches in declaration order and a uuid-typed path
parameter would otherwise shadow the identity lookup.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from typing import Annotated, Any, TypeVar

from fastapi import APIRouter, Depends, HTTPException, Query, status

from aicore_api.api.ownership import resolve_owner_membership
from aicore_api.api.scope import require_instance_scope
from aicore_api.auth.authorization import OrganizationContext
from aicore_api.auth.dependencies import SessionDep, require_permission
from aicore_api.core.agents import (
    AgentCategory,
    validate_identity_metadata,
)
from aicore_api.core.assets import AssetStatus, Environment, normalize_external_identifier
from aicore_api.core.domain_errors import ConflictError, InvalidReferenceError
from aicore_api.core.events import (
    AGENT_DELETED,
    AGENT_REGISTERED,
    AGENT_UPDATED,
    ASSET_CREATED,
    ASSET_DELETED,
    DomainEvent,
    emit_event,
)
from aicore_api.core.permissions import Permission
from aicore_api.db.models.agent import Agent
from aicore_api.db.repositories.agents import AgentRepository, AgentUpdate, RegistrationResult
from aicore_api.db.repositories.assets import AssetUpdate
from aicore_api.schemas.agents import (
    AgentCreate,
    AgentListResponse,
    AgentOwnerRead,
    AgentRead,
    AgentUpdateRequest,
)
from aicore_api.schemas.assets import AssetOwnerRead

router = APIRouter(prefix="/organizations", tags=["agents"])

#: Each route's requirement, declared once so the registry's authorization surface
#: is reviewable at a glance: four permissions guard six operations.
ReadAgents = Annotated[OrganizationContext, Depends(require_permission(Permission.AGENT_READ))]
CreateAgents = Annotated[OrganizationContext, Depends(require_permission(Permission.AGENT_CREATE))]
UpdateAgents = Annotated[OrganizationContext, Depends(require_permission(Permission.AGENT_UPDATE))]
DeleteAgents = Annotated[OrganizationContext, Depends(require_permission(Permission.AGENT_DELETE))]

#: One message for "no such agent" and "not your agent". The two cases must be
#: indistinguishable, so they share a constant rather than two similar strings.
_AGENT_NOT_FOUND = "Agent not found"

#: The same message for the identity lookup, for the same reason.
_IDENTITY_NOT_FOUND = "Agent identity not found"

#: Bounds so that one request cannot ask the database for an unbounded amount of work.
_MAX_OFFSET = 100_000

_NOT_FOUND_RESPONSES: dict[int | str, dict[str, Any]] = {
    401: {"description": "Missing or invalid credentials"},
    403: {"description": "The caller lacks the required agent permission"},
    404: {
        "description": (
            "No such agent in this organization. Identical for an agent that does "
            "not exist and one that belongs to another organization."
        )
    },
}

_T = TypeVar("_T")


def _agent_read(agent: Agent) -> AgentRead:
    """Serialize a registered agent: registry fields, inventory fields, one record.

    Built explicitly rather than from ORM attributes so the response contract is
    readable in one place — and so it is obvious that nothing outside the registry
    and its record (credentials, membership internals, other tenants' rows) can
    reach an agent response.
    """
    owner: AgentOwnerRead | None = None
    membership = agent.asset.owner_membership
    if membership is not None:
        owner = AssetOwnerRead(
            membership_id=membership.id,
            user_id=membership.user.id,
            email=membership.user.email,
            full_name=membership.user.full_name,
        )
    return AgentRead(
        id=agent.id,
        organization_id=agent.organization_id,
        identity_id=agent.identity_id,
        asset_id=agent.asset_id,
        display_name=agent.asset.name,
        description=agent.asset.description,
        category=AgentCategory(agent.category),
        version=agent.version,
        framework=agent.framework,
        build_revision=agent.build_revision,
        status=AssetStatus(agent.asset.status),
        environment=Environment(agent.asset.environment),
        identity_metadata=agent.identity_metadata,
        owner=owner,
        created_at=agent.created_at,
        updated_at=agent.updated_at,
    )


def _validated_identity_metadata(payload: dict[str, Any] | None) -> dict[str, Any] | None:
    """Validate runtime identity metadata, or refuse the request with a 422.

    A 422 rather than a 400, like the inventory's metadata contract: the body is
    well-formed JSON whose field violates a documented model. The message names the
    offending key, because "an identity record is not the place for a credential" is
    only actionable if the caller is told which key looked like one.
    """
    try:
        return validate_identity_metadata(payload)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"invalid identity_metadata: {exc}",
        ) from exc


def _external_identifier(value: str | None) -> str | None:
    """Normalize the reported identifier, or refuse it if it is unusable."""
    try:
        return normalize_external_identifier(value)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"invalid external_identifier: {exc}",
        ) from exc


def _run(operation: Callable[[], _T]) -> _T:
    """Run a repository write, translating its domain errors for HTTP.

    Kept in one place so every registry write answers the same way: a duplicate or
    an unreachable lifecycle move is a 409, a reference that does not resolve is a
    422, an assertion about the request that the schema cannot express (a
    registration that asks to start an agent suspended) is a 422, and a constraint
    the caller could have satisfied is never a 500 with a PostgreSQL message in it.
    """
    try:
        return operation()
    except ConflictError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except InvalidReferenceError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc
    except ValueError as exc:
        # An assertion about the request itself that the schema cannot express —
        # a registration that asks to start an agent suspended or retired, or a
        # version label that is only whitespace. The request is malformed, so 422,
        # the same answer the inventory gives for metadata that breaks its contract.
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc


def _registered_events(context: OrganizationContext, result: RegistrationResult) -> None:
    """Emit what a registration actually did.

    Two events, not one, when the registration also created the inventory record: an
    agent acquired an identity *and* an asset came into existence, and a later audit
    view will want to read either without reconstructing the other.
    """
    agent = result.agent
    if result.asset_created:
        emit_event(
            DomainEvent(
                name=ASSET_CREATED,
                organization_id=context.organization_id,
                resource_type="asset",
                resource_id=agent.asset_id,
                actor_membership_id=context.membership.id,
                data={"asset_type": "agent", "discovery_state": agent.asset.discovery_state},
            )
        )
    emit_event(
        DomainEvent(
            name=AGENT_REGISTERED,
            organization_id=context.organization_id,
            resource_type="agent",
            resource_id=agent.id,
            actor_membership_id=context.membership.id,
            data={
                "category": agent.category,
                "version": agent.version,
                "asset_id": str(agent.asset_id),
            },
        )
    )


@router.get(
    "/{organization_id}/agents",
    response_model=AgentListResponse,
    summary="List the organization's registered agents",
    responses={
        401: {"description": "Missing or invalid credentials"},
        403: {"description": "The caller lacks the agent.read permission"},
        404: {"description": "The organization does not exist or the caller is not a member"},
    },
)
def list_agents(
    context: ReadAgents,
    session: SessionDep,
    category: Annotated[
        list[AgentCategory] | None, Query(description="Repeatable; values are ORed")
    ] = None,
    status_filter: Annotated[list[AssetStatus] | None, Query(alias="status")] = None,
    environment: Annotated[list[Environment] | None, Query()] = None,
    owner_membership_id: Annotated[uuid.UUID | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0, le=_MAX_OFFSET)] = 0,
    total: Annotated[
        bool, Query(description="Include the filtered total; costs a second query")
    ] = False,
) -> AgentListResponse:
    """A page of registered agents, newest registration first.

    Every filter is optional and repeatable: values within one filter are ORed,
    different filters are ANDed. ``status``, ``environment`` and
    ``owner_membership_id`` filter the agent's inventory record — the registry does
    not keep a second copy of them. ``limit`` is capped at 200, which is what makes
    "no unbounded list query" a property of the endpoint rather than a hope about
    its callers.
    """
    repository = AgentRepository(session, context.organization_id)
    items = repository.page(
        limit=limit,
        offset=offset,
        categories=category,
        statuses=status_filter,
        environments=[value.value for value in environment] if environment else None,
        owner_membership_id=owner_membership_id,
    )
    count = None
    if total:
        count = repository.count(
            categories=category,
            statuses=status_filter,
            environments=[value.value for value in environment] if environment else None,
            owner_membership_id=owner_membership_id,
        )
    return AgentListResponse(
        organization_id=context.organization_id,
        items=[_agent_read(agent) for agent in items],
        limit=limit,
        offset=offset,
        count=len(items),
        total=count,
    )


@router.post(
    "/{organization_id}/agents",
    response_model=AgentRead,
    status_code=status.HTTP_201_CREATED,
    summary="Register an agent and give it a stable identity",
    responses={
        401: {"description": "Missing or invalid credentials"},
        403: {"description": "The caller lacks the agent.create permission"},
        404: {"description": "The organization does not exist or the caller is not a member"},
        409: {
            "description": (
                "The agent is already registered, or an existing agent asset it would "
                "adopt contradicts the request"
            )
        },
        422: {"description": "Invalid category, version, identity metadata, owner or status"},
    },
)
def register_agent(
    context: CreateAgents,
    session: SessionDep,
    payload: AgentCreate,
) -> AgentRead:
    """Register an agent: create (or adopt) its inventory record, then its identity.

    The server generates ``identity_id``. Two registrations of the same
    ``external_identifier`` are the same agent — the second one is refused rather
    than given a second identity — and a request that contradicts what the existing
    record says is refused rather than applied, so a registration can never quietly
    reassign an owner or a lifecycle state that somebody else decided.
    """
    repository = AgentRepository(session, context.organization_id)
    identity_metadata = _validated_identity_metadata(payload.identity_metadata)
    external_identifier = _external_identifier(payload.external_identifier)
    owner_membership_id = resolve_owner_membership(
        session, context.organization_id, payload.owner_user_id
    )

    result = _run(
        lambda: repository.register(
            category=payload.category,
            version=payload.version,
            owner_membership_id=owner_membership_id,
            display_name=payload.display_name,
            description=payload.description,
            status=payload.status,
            environment=payload.environment.value,
            external_identifier=external_identifier,
            framework=payload.framework,
            build_revision=payload.build_revision,
            identity_metadata=identity_metadata,
        )
    )
    _registered_events(context, result)
    return _agent_read(result.agent)


@router.get(
    "/{organization_id}/agents/identity/{identity_id}",
    response_model=AgentRead,
    summary="Look up an agent by its stable identity",
    responses={
        **_NOT_FOUND_RESPONSES,
        404: {
            "description": (
                "No agent in this organization holds that identity. Identical for an "
                "identity that does not exist and one that belongs to another organization."
            )
        },
    },
)
def read_agent_by_identity(
    identity_id: uuid.UUID, context: ReadAgents, session: SessionDep
) -> AgentRead:
    """Resolve a stable identity to the agent that holds it.

    The lookup a later phase performs when it has to attribute something to an
    agent and must not trust a display name. It is scoped to the caller's
    organization like every other read here, so an identity from another tenant is
    indistinguishable from one that was never issued.

    ``agent.read`` guards it: the identity is not a secret, and an agent record is
    not more sensitive than the inventory record it belongs to.
    """
    agent = AgentRepository(session, context.organization_id).find_by_identity(identity_id)
    if agent is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=_IDENTITY_NOT_FOUND)
    require_instance_scope(
        context, agent, permission=Permission.AGENT_READ, detail=_IDENTITY_NOT_FOUND
    )
    return _agent_read(agent)


@router.get(
    "/{organization_id}/agents/{agent_id}",
    response_model=AgentRead,
    summary="Read one registered agent",
    responses=_NOT_FOUND_RESPONSES,
)
def read_agent(agent_id: uuid.UUID, context: ReadAgents, session: SessionDep) -> AgentRead:
    """One agent by its registry id, or 404 — never a hint that a foreign agent exists."""
    agent = AgentRepository(session, context.organization_id).find(agent_id)
    if agent is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=_AGENT_NOT_FOUND)
    require_instance_scope(
        context, agent, permission=Permission.AGENT_READ, detail=_AGENT_NOT_FOUND
    )
    return _agent_read(agent)


@router.patch(
    "/{organization_id}/agents/{agent_id}",
    response_model=AgentRead,
    summary="Update one registered agent",
    responses={
        **_NOT_FOUND_RESPONSES,
        409: {"description": "The requested lifecycle transition is not allowed"},
        422: {
            "description": (
                "No fields to update, a null where null means nothing, invalid "
                "identity metadata, or an owner who is not an active member"
            )
        },
    },
)
def update_agent(
    agent_id: uuid.UUID,
    context: UpdateAgents,
    session: SessionDep,
    payload: AgentUpdateRequest,
) -> AgentRead:
    """Change the parts of a registered agent the caller sent, and nothing else.

    The registry fields (category, version, build revision, framework, identity
    metadata) and the record's fields (display name, description, environment,
    owner, lifecycle status) are one operation, because they are one decision: a
    version bump and a status change described separately would eventually be
    applied separately.

    ``identity_id`` is not in the request model and cannot be changed by any route —
    a rename or a version change leaves identity exactly where it was. A status
    change is validated against the transition table: ``active → suspended`` is a
    recorded decision, ``retired → active`` is refused, and nothing is started,
    stopped or blocked by either.
    """
    repository = AgentRepository(session, context.organization_id)
    agent = repository.find(agent_id)
    if agent is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=_AGENT_NOT_FOUND)
    require_instance_scope(
        context, agent, permission=Permission.AGENT_UPDATE, detail=_AGENT_NOT_FOUND
    )

    identity_metadata = _validated_identity_metadata(payload.identity_metadata)
    owner_membership_id = (
        resolve_owner_membership(session, context.organization_id, payload.owner_user_id)
        if payload.owner_user_id is not None
        else None
    )

    change = AgentUpdate(
        asset=AssetUpdate(
            name=payload.display_name,
            description=payload.description,
            status=None if payload.status is None else payload.status.value,
            environment=None if payload.environment is None else payload.environment.value,
            owner_membership_id=owner_membership_id,
            clear_owner=payload.clears("owner_user_id"),
            clear_description=payload.clears("description"),
        ),
        category=payload.category,
        version=payload.version,
        framework=payload.framework,
        build_revision=payload.build_revision,
        identity_metadata=identity_metadata,
        clear_framework=payload.clears("framework"),
        clear_build_revision=payload.clears("build_revision"),
        clear_identity_metadata=payload.clears("identity_metadata"),
    )

    changed = _run(lambda: repository.update(agent, change))
    if changed:
        emit_event(
            DomainEvent(
                name=AGENT_UPDATED,
                organization_id=context.organization_id,
                resource_type="agent",
                resource_id=agent.id,
                actor_membership_id=context.membership.id,
                data={"fields": sorted(changed)},
            )
        )
    return _agent_read(agent)


@router.delete(
    "/{organization_id}/agents/{agent_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Remove one agent, its identity and its inventory record",
    responses=_NOT_FOUND_RESPONSES,
)
def delete_agent(agent_id: uuid.UUID, context: DeleteAgents, session: SessionDep) -> None:
    """Remove the agent identity together with the record it belongs to.

    One operation rather than two, because an identity whose agent no longer exists
    is an orphan: the registry's composite foreign key cascades from the inventory
    record, so this cannot leave one behind even if a caller tried. The events are
    emitted first, so the removal stays observable after the rows are gone.

    ``agent.update`` and ``agent.delete`` are separate permissions on purpose: an
    operator may register an agent or move it through its lifecycle without being
    able to erase the identity a later phase will have attributed actions to.
    """
    repository = AgentRepository(session, context.organization_id)
    agent = repository.find(agent_id)
    if agent is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=_AGENT_NOT_FOUND)
    require_instance_scope(
        context, agent, permission=Permission.AGENT_DELETE, detail=_AGENT_NOT_FOUND
    )
    emit_event(
        DomainEvent(
            name=AGENT_DELETED,
            organization_id=context.organization_id,
            resource_type="agent",
            resource_id=agent.id,
            actor_membership_id=context.membership.id,
            data={
                "category": agent.category,
                "version": agent.version,
                "identity_id": str(agent.identity_id),
            },
        )
    )
    emit_event(
        DomainEvent(
            name=ASSET_DELETED,
            organization_id=context.organization_id,
            resource_type="asset",
            resource_id=agent.asset_id,
            actor_membership_id=context.membership.id,
            data={"asset_type": "agent", "removed_with": "agent"},
        )
    )
    repository.delete(agent)
