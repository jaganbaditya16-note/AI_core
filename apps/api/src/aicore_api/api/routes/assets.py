"""Asset routes: the organization's AI inventory, authorized and tenant-scoped.

The paths are nested under ``/organizations/{organization_id}`` for the same
reason the membership and role routes are: the organization is resolved from the
path against the caller's memberships, so a request cannot name a tenant it does
not belong to, and no separate "which organization am I acting in?" mechanism has
to exist. A flat ``/assets`` would have needed one — a header or a query parameter
carrying the tenant — and that would be a new place for a caller to try to assert
an organization. There is exactly one such place in this application, and it is
the URL of a resource that has already been authorized.

Everything a handler does follows from the context it was handed:

- **The route declares a permission, not a role.** ``asset.read`` / ``asset.create``
  / ``asset.update`` / ``asset.delete`` are the entire authorization surface of
  this phase, and each is enforced by ``require_permission`` before the handler
  body runs.
- **A foreign asset is indistinguishable from a missing one.** ``GET``, ``PATCH``
  and ``DELETE`` answer 404 for both, with the same message. A caller can learn
  what its own inventory contains and nothing about anyone else's.
- **Errors are translated here.** Metadata that does not match its asset type and
  an owner who is not an active member are both 422s — the request is malformed,
  the server is fine. A database constraint is never surfaced as a driver message.

One route is ordered deliberately: ``/owners`` is declared before ``/{asset_id}``,
because FastAPI matches in declaration order and a uuid-typed path parameter would
otherwise answer 422 for a request whose intent was a listing.
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from aicore_api.api.ownership import resolve_owner_membership
from aicore_api.api.scope import require_instance_scope
from aicore_api.auth.authorization import OrganizationContext
from aicore_api.auth.dependencies import SessionDep, require_permission
from aicore_api.core.assets import (
    AssetStatus,
    AssetType,
    DiscoveryState,
    Environment,
    RiskClassification,
    normalize_external_identifier,
    validate_metadata,
)
from aicore_api.core.domain_errors import ConflictError, InvalidReferenceError
from aicore_api.core.events import (
    ASSET_CREATED,
    ASSET_DELETED,
    ASSET_UPDATED,
    DomainEvent,
    emit_event,
)
from aicore_api.core.permissions import Permission
from aicore_api.db.models.asset import Asset
from aicore_api.db.models.membership import Membership
from aicore_api.db.models.user import User
from aicore_api.db.repositories.assets import AssetRepository, AssetUpdate
from aicore_api.schemas.assets import (
    AssetCreate,
    AssetListResponse,
    AssetOwnerListResponse,
    AssetOwnerRead,
    AssetRead,
    AssetUpdateRequest,
)

router = APIRouter(prefix="/organizations", tags=["assets"])

#: Each route's requirement, declared once so the phase's authorization surface is
#: reviewable at a glance: four permissions guard six operations.
ReadAssets = Annotated[OrganizationContext, Depends(require_permission(Permission.ASSET_READ))]
CreateAssets = Annotated[OrganizationContext, Depends(require_permission(Permission.ASSET_CREATE))]
UpdateAssets = Annotated[OrganizationContext, Depends(require_permission(Permission.ASSET_UPDATE))]
DeleteAssets = Annotated[OrganizationContext, Depends(require_permission(Permission.ASSET_DELETE))]

#: One message for "no such asset" and "not your asset". The two cases must be
#: indistinguishable, so they share a constant rather than two similar strings.
_ASSET_NOT_FOUND = "Asset not found"

#: Bounds so that one request cannot ask the database for an unbounded amount of
#: work. The owner directory is capped because it is a directory, not a paged API;
#: deep paging is what ``limit``/``offset`` on the inventory itself are for.
_OWNER_PAGE_LIMIT = 500
_MAX_OFFSET = 100_000

_NOT_FOUND_RESPONSES: dict[int | str, dict[str, Any]] = {
    401: {"description": "Missing or invalid credentials"},
    403: {"description": "The caller lacks the required asset permission"},
    404: {
        "description": (
            "No such asset in this organization. Identical for an asset that does "
            "not exist and one that belongs to another organization."
        )
    },
}


def _asset_read(asset: Asset) -> AssetRead:
    """Serialize an asset, including its owner when one is recorded.

    Built explicitly rather than from ORM attributes: the owner is a membership
    that carries a user, and spelling the shape out here keeps the response
    contract readable in one place — and makes it obvious that nothing outside the
    inventory (credentials, membership internals) can leak into an asset response.
    """
    owner: AssetOwnerRead | None = None
    membership = asset.owner_membership
    if membership is not None:
        owner = _owner_read(membership, membership.user)
    return AssetRead(
        id=asset.id,
        organization_id=asset.organization_id,
        name=asset.name,
        description=asset.description,
        asset_type=AssetType(asset.asset_type),
        status=AssetStatus(asset.status),
        environment=Environment(asset.environment),
        discovery_state=DiscoveryState(asset.discovery_state),
        risk_classification=RiskClassification(asset.risk_classification),
        external_identifier=asset.external_identifier,
        discovery_source=asset.discovery_source,
        last_seen_at=asset.last_seen_at,
        metadata=asset.asset_metadata,
        owner=owner,
        created_at=asset.created_at,
        updated_at=asset.updated_at,
    )


def _owner_read(membership: Membership, user: User) -> AssetOwnerRead:
    """An owner, as a client needs to render one: who, in which membership."""
    return AssetOwnerRead(
        membership_id=membership.id,
        user_id=user.id,
        email=user.email,
        full_name=user.full_name,
    )


def _validated_metadata(
    asset_type: AssetType, payload: dict[str, Any] | None
) -> dict[str, Any] | None:
    """Validate a metadata object against its asset type, or refuse the request.

    A 422 rather than a 400: the request is well-formed JSON with a field that
    violates the contract for the asset type it names. The message names the
    problem, because an integration author needs to know which key was wrong — and
    because silently dropping an unknown key is how a collector looks like it is
    working while recording nothing.
    """
    try:
        return validate_metadata(asset_type, payload)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"invalid metadata for a {asset_type} asset: {exc}",
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


def _resolve_owner(
    session: Session, context: OrganizationContext, user_id: uuid.UUID | None
) -> uuid.UUID | None:
    """Resolve ``user_id`` to an owner membership of the context's organization.

    The rule itself lives in :mod:`aicore_api.api.ownership`, shared with the agent
    registry: it is a tenant-integrity rule, and a second copy of it would be a
    second place for it to drift.
    """
    return resolve_owner_membership(session, context.organization_id, user_id)


def _write(repository: AssetRepository, operation: Any) -> Any:
    """Run a repository write, translating its domain errors for HTTP.

    Kept in one place so every asset write answers the same way: a duplicate is a
    409, a reference that does not resolve is a 422, and a constraint the caller
    could have satisfied is never a 500 with a PostgreSQL message in it.
    """
    try:
        return operation()
    except ConflictError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except InvalidReferenceError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc


@router.get(
    "/{organization_id}/assets",
    response_model=AssetListResponse,
    summary="List the organization's AI assets",
    responses={
        401: {"description": "Missing or invalid credentials"},
        403: {"description": "The caller lacks the asset.read permission"},
        404: {"description": "The organization does not exist or the caller is not a member"},
    },
)
def list_assets(
    context: ReadAssets,
    session: SessionDep,
    asset_type: Annotated[
        list[AssetType] | None, Query(description="Repeatable; values are ORed")
    ] = None,
    status_filter: Annotated[list[AssetStatus] | None, Query(alias="status")] = None,
    environment: Annotated[list[Environment] | None, Query()] = None,
    discovery_state: Annotated[list[DiscoveryState] | None, Query()] = None,
    risk_classification: Annotated[list[RiskClassification] | None, Query()] = None,
    owner_membership_id: Annotated[uuid.UUID | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0, le=_MAX_OFFSET)] = 0,
    total: Annotated[
        bool, Query(description="Include the filtered total; costs a second query")
    ] = False,
) -> AssetListResponse:
    """A page of the inventory, newest first.

    Every filter is optional and repeatable: values within one filter are ORed,
    different filters are ANDed. ``limit`` is capped at 200, which is what makes
    "no unbounded list query" a property of the endpoint rather than a hope about
    its callers.
    """
    repository = AssetRepository(session, context.organization_id)
    items = repository.page(
        limit=limit,
        offset=offset,
        asset_types=asset_type,
        statuses=status_filter,
        environments=environment,
        discovery_states=discovery_state,
        risk_classifications=risk_classification,
        owner_membership_id=owner_membership_id,
    )
    count = None
    if total:
        count = repository.count(
            asset_types=asset_type,
            statuses=status_filter,
            environments=environment,
            discovery_states=discovery_state,
            risk_classifications=risk_classification,
            owner_membership_id=owner_membership_id,
        )
    return AssetListResponse(
        organization_id=context.organization_id,
        items=[_asset_read(asset) for asset in items],
        limit=limit,
        offset=offset,
        count=len(items),
        total=count,
    )


@router.post(
    "/{organization_id}/assets",
    response_model=AssetRead,
    status_code=status.HTTP_201_CREATED,
    summary="Register an AI asset in the organization's inventory",
    responses={
        401: {"description": "Missing or invalid credentials"},
        403: {"description": "The caller lacks the asset.create permission"},
        404: {"description": "The organization does not exist or the caller is not a member"},
        409: {"description": "An asset of this type already uses this external identifier"},
        422: {"description": "Invalid asset type, state, owner or metadata"},
    },
)
def create_asset(
    context: CreateAssets,
    session: SessionDep,
    payload: AssetCreate,
) -> AssetRead:
    """Create one inventory record.

    This is *registration*, not discovery: the caller states what the asset is.
    Nothing here observes any infrastructure, and the record it produces says so —
    ``discovery_source`` is ``manual`` and ``last_seen_at`` stays null. A record
    that an integration reported is written by
    :func:`aicore_api.discovery.registry.register_discovered_asset` instead, and is
    labelled with its source.
    """
    repository = AssetRepository(session, context.organization_id)
    metadata = _validated_metadata(payload.asset_type, payload.metadata)
    external_identifier = _external_identifier(payload.external_identifier)
    owner_membership_id = _resolve_owner(session, context, payload.owner_user_id)

    if external_identifier is not None and repository.find_by_external_identifier(
        asset_type=payload.asset_type.value, external_identifier=external_identifier
    ):
        # Checked before the insert so the common case gets a clear message; the
        # partial unique index is what actually guarantees it under concurrency,
        # and _write turns that violation into the same 409.
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"this organization already has a {payload.asset_type} asset with that "
                "external identifier"
            ),
        )

    asset = _write(
        repository,
        lambda: repository.add(
            name=payload.name,
            asset_type=payload.asset_type.value,
            description=payload.description,
            status=payload.status.value,
            environment=payload.environment.value,
            discovery_state=payload.discovery_state.value,
            risk_classification=payload.risk_classification.value,
            owner_membership_id=owner_membership_id,
            external_identifier=external_identifier,
            asset_metadata=metadata,
        ),
    )
    emit_event(
        DomainEvent(
            name=ASSET_CREATED,
            organization_id=context.organization_id,
            resource_type="asset",
            resource_id=asset.id,
            actor_membership_id=context.membership.id,
            actor_id=context.user_id,
            data={"asset_type": asset.asset_type, "discovery_state": asset.discovery_state},
        ),
        session=session,
    )
    return _asset_read(asset)


@router.get(
    "/{organization_id}/assets/owners",
    response_model=AssetOwnerListResponse,
    summary="List the members who can own an asset",
    responses={
        401: {"description": "Missing or invalid credentials"},
        403: {"description": "The caller lacks the asset.read permission"},
        404: {"description": "The organization does not exist or the caller is not a member"},
    },
)
def list_asset_owners(context: ReadAssets, session: SessionDep) -> AssetOwnerListResponse:
    """The organization's members, as candidate owners.

    So a client can offer a real choice instead of asking an operator to paste a
    UUID — and so the API never has to accept an owner identifier that was not
    resolved against this organization's memberships. Bounded, because it is a
    directory: an organization with tens of thousands of members needs the paged
    membership API, not this.
    """
    repository = AssetRepository(session, context.organization_id)
    owners = [
        _owner_read(membership, user)
        for membership, user in repository.list_owners(limit=_OWNER_PAGE_LIMIT)
    ]
    return AssetOwnerListResponse(organization_id=context.organization_id, owners=owners)


@router.get(
    "/{organization_id}/assets/{asset_id}",
    response_model=AssetRead,
    summary="Read one asset",
    responses=_NOT_FOUND_RESPONSES,
)
def read_asset(asset_id: uuid.UUID, context: ReadAssets, session: SessionDep) -> AssetRead:
    """One asset, or 404 — never a hint that a foreign asset exists."""
    asset = AssetRepository(session, context.organization_id).find(asset_id)
    if asset is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=_ASSET_NOT_FOUND)
    # The row is authorized as well as loaded: `asset.read` *for this row*, in this
    # organization. See aicore_api.api.scope.
    require_instance_scope(
        context, asset, permission=Permission.ASSET_READ, detail=_ASSET_NOT_FOUND
    )
    return _asset_read(asset)


@router.patch(
    "/{organization_id}/assets/{asset_id}",
    response_model=AssetRead,
    summary="Update one asset",
    responses={
        **_NOT_FOUND_RESPONSES,
        409: {"description": "Another asset already uses this external identifier"},
        422: {"description": "No fields to update, a null state, or invalid metadata"},
    },
)
def update_asset(
    asset_id: uuid.UUID,
    context: UpdateAssets,
    session: SessionDep,
    payload: AssetUpdateRequest,
) -> AssetRead:
    """Change the parts of a record the caller sent, and nothing else.

    The lifecycle, discovery and risk fields are the organization's judgement about
    the asset, which is why this is the operation that records those decisions —
    including ``status: suspended``, which is a statement about the inventory and
    **not** a runtime control. Nothing is stopped by setting it.
    """
    repository = AssetRepository(session, context.organization_id)
    asset = repository.find(asset_id)
    if asset is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=_ASSET_NOT_FOUND)
    require_instance_scope(
        context, asset, permission=Permission.ASSET_UPDATE, detail=_ASSET_NOT_FOUND
    )

    fields = payload.model_fields_set
    metadata = (
        _validated_metadata(AssetType(asset.asset_type), payload.metadata)
        if "metadata" in fields
        else None
    )
    external_identifier = (
        _external_identifier(payload.external_identifier)
        if "external_identifier" in fields
        else None
    )
    owner_membership_id = (
        _resolve_owner(session, context, payload.owner_user_id)
        if payload.owner_user_id is not None
        else None
    )

    change = AssetUpdate(
        name=payload.name,
        description=payload.description,
        status=None if payload.status is None else payload.status.value,
        environment=None if payload.environment is None else payload.environment.value,
        discovery_state=(
            None if payload.discovery_state is None else payload.discovery_state.value
        ),
        risk_classification=(
            None if payload.risk_classification is None else payload.risk_classification.value
        ),
        owner_membership_id=owner_membership_id,
        external_identifier=external_identifier,
        asset_metadata=metadata,
        clear_owner=payload.clears("owner_user_id"),
        clear_metadata=payload.clears("metadata"),
        clear_description=payload.clears("description"),
        clear_external_identifier=payload.clears("external_identifier"),
    )
    changed = _write(repository, lambda: repository.update(asset, change))
    if changed:
        emit_event(
            DomainEvent(
                name=ASSET_UPDATED,
                organization_id=context.organization_id,
                resource_type="asset",
                resource_id=asset.id,
                actor_membership_id=context.membership.id,
                actor_id=context.user_id,
                data={"fields": sorted(changed)},
            ),
            session=session,
        )
    return _asset_read(asset)


@router.delete(
    "/{organization_id}/assets/{asset_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Remove one asset from the inventory",
    responses=_NOT_FOUND_RESPONSES,
)
def delete_asset(asset_id: uuid.UUID, context: DeleteAssets, session: SessionDep) -> None:
    """Delete the record.

    The asset is removed rather than flagged: this table *is* the inventory, and a
    retained "deleted" row would have to be filtered out by every reader. The event
    is emitted first, so the removal stays observable after the row is gone — and a
    future audit trail is where the history this table does not keep will live.

    ``asset.update`` and ``asset.delete`` are separate permissions on purpose: a
    security administrator may record that an asset is suspect without being able
    to erase the record of it.
    """
    repository = AssetRepository(session, context.organization_id)
    asset = repository.find(asset_id)
    if asset is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=_ASSET_NOT_FOUND)
    require_instance_scope(
        context, asset, permission=Permission.ASSET_DELETE, detail=_ASSET_NOT_FOUND
    )
    # The identifiers are read before the row goes, and the event is written *after* the
    # delete commits. That order matters for the audit trail in a way it did not for a log
    # line: an event is a claim that something happened, and writing it first would leave a
    # record of a deletion that might then fail. The asset is already captured here, so the
    # trail still names what was removed.
    asset_type = asset.asset_type
    repository.delete(asset)
    emit_event(
        DomainEvent(
            name=ASSET_DELETED,
            organization_id=context.organization_id,
            resource_type="asset",
            resource_id=asset_id,
            actor_membership_id=context.membership.id,
            actor_id=context.user_id,
            data={"asset_type": asset_type},
        ),
        session=session,
    )
