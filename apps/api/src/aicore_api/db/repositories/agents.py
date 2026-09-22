"""Agent repository — registration, lookup and lifecycle, tenant-scoped by construction.

The class is an :class:`~aicore_api.db.repositories.organizations.OrganizationScopedRepository`,
so it cannot be constructed without an organization and every statement it builds
is filtered to that organization. Cross-organization reads are impossible by
construction rather than avoided by discipline, exactly as in the inventory
repository.

Three behaviours are worth reading before the code.

**The registry does not duplicate the inventory.** An agent's display name,
description, lifecycle state, environment and owner live on the asset — Phase 3
models them, constrains them, and enforces that an owner is a member of the same
organization. This repository *drives* that record (it composes
:class:`AssetRepository` rather than re-querying the table), which is why the
registry has no second copy of anything to keep in sync.

**Registration is atomic.** Staging the asset and staging the identity happen in
one unit of work: either the organization has an agent with an identity, or it has
nothing. A half-registration — an inventory record with no identity, or an
identity with no record — is not a state this code can produce, and the database
would refuse the second shape anyway (the composite foreign key).

**Registering an asset that already exists adopts it.** A caller that supplies an
``external_identifier`` may be pointing at an ``agent`` asset the inventory
already holds (an organization could record agents before it had a registry). That
asset is adopted rather than duplicated, and adoption never overwrites the
organization's decisions: a request that contradicts what is recorded — a
different owner, lifecycle state, environment or name — is refused with a conflict
instead of quietly winning.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from sqlalchemy import Select, delete
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, contains_eager

from aicore_api.core.agents import (
    BUILD_REVISION_MAX_LENGTH,
    FRAMEWORK_MAX_LENGTH,
    AgentCategory,
    normalize_optional_text,
    normalize_version,
    validate_identity_metadata,
    validate_initial_status,
    validate_transition,
)
from aicore_api.core.assets import (
    AssetStatus,
    AssetType,
    DiscoveryState,
    Environment,
    RiskClassification,
)
from aicore_api.core.domain_errors import ConflictError
from aicore_api.db.models.agent import Agent
from aicore_api.db.models.asset import Asset
from aicore_api.db.repositories.assets import (
    AssetRepository,
    AssetUpdate,
    _translate_integrity_error,
)
from aicore_api.db.repositories.organizations import OrganizationScopedRepository

__all__ = ["AgentRepository", "AgentUpdate", "RegistrationResult"]


def _translate_agent_integrity_error(exc: IntegrityError) -> Exception:
    """Turn a registry constraint violation into the domain error it means.

    The inventory's mappings apply first — a registration writes an asset too, and a
    duplicate external identifier or an owner who is not a member must be reported
    the same way here as it is there. Only then the registry's own: the unique
    constraint on ``asset_id`` is the race where two registrations for one asset
    arrive at once and the second loses.
    """
    constraint = getattr(getattr(exc.orig, "diag", None), "constraint_name", None)
    if constraint == "uq_agents_asset_id":
        return ConflictError(
            "this agent is already registered; read it instead of registering it again"
        )
    if constraint == "fk_agents_organization_id_assets":
        # Reachable only if the asset was deleted between the lookup and the flush.
        return ConflictError("the agent's asset no longer exists")
    return _translate_integrity_error(exc)


@dataclass(frozen=True, slots=True)
class RegistrationResult:
    """What a registration did: the identity, and how its asset was obtained."""

    agent: Agent
    #: ``True`` when this call created the inventory record, ``False`` when it
    #: adopted an ``agent`` asset the inventory already held.
    asset_created: bool


class AgentUpdate:
    """The registry fields an update may change, plus the inventory changes it implies.

    Split deliberately: ``asset`` carries the changes that belong to the inventory
    record (display name, description, lifecycle state, environment, owner) and the
    fields here are the registry's own (category, version, build revision,
    framework, identity metadata). One object so that "what can an update touch?"
    is a single readable list, and so applying them is one unit of work.

    ``identity_id`` is absent on purpose: identity is what survives a change, so
    there is no path that writes it.
    """

    __slots__ = (
        "_clear_build_revision",
        "_clear_framework",
        "_clear_identity_metadata",
        "asset",
        "build_revision",
        "category",
        "framework",
        "identity_metadata",
        "version",
    )

    def __init__(
        self,
        *,
        asset: AssetUpdate | None = None,
        category: AgentCategory | str | None = None,
        version: str | None = None,
        build_revision: str | None = None,
        framework: str | None = None,
        identity_metadata: dict[str, Any] | None = None,
        clear_build_revision: bool = False,
        clear_framework: bool = False,
        clear_identity_metadata: bool = False,
    ) -> None:
        self.asset = asset
        self.category = AgentCategory(category).value if category is not None else None
        self.version = version
        self.build_revision = build_revision
        self.framework = framework
        self.identity_metadata = identity_metadata
        self._clear_build_revision = clear_build_revision
        self._clear_framework = clear_framework
        self._clear_identity_metadata = clear_identity_metadata

    def is_empty(self) -> bool:
        """Whether the request asked for no registry- or inventory-level change."""
        return not any(
            (
                self.category,
                self.version,
                self.build_revision,
                self.framework,
                self.identity_metadata,
                self._clear_build_revision,
                self._clear_framework,
                self._clear_identity_metadata,
                self.asset is not None,
            )
        )

    def apply_to(self, agent: Agent) -> list[str]:
        """Apply the registry fields to ``agent``; returns the names that changed.

        Same contract as :class:`~aicore_api.db.repositories.assets.AssetUpdate`: a
        field left as ``None`` was not stated and is skipped, and the ``clear_``
        flags are how a caller says "remove this" rather than "leave it alone".
        """
        changed: list[str] = []
        assignments: list[tuple[str, Any]] = [
            ("category", self.category),
            ("version", normalize_version(self.version) if self.version is not None else None),
            (
                "build_revision",
                normalize_optional_text(
                    self.build_revision,
                    field_name="build_revision",
                    max_length=BUILD_REVISION_MAX_LENGTH,
                )
                if self.build_revision is not None
                else None,
            ),
            (
                "framework",
                normalize_optional_text(
                    self.framework, field_name="framework", max_length=FRAMEWORK_MAX_LENGTH
                )
                if self.framework is not None
                else None,
            ),
            ("identity_metadata", self.identity_metadata),
        ]
        for field_name, value in assignments:
            if value is None:
                continue
            if getattr(agent, field_name) != value:
                setattr(agent, field_name, value)
                changed.append(field_name)

        clears: list[tuple[bool, str]] = [
            (self._clear_build_revision, "build_revision"),
            (self._clear_framework, "framework"),
            (self._clear_identity_metadata, "identity_metadata"),
        ]
        for requested, field_name in clears:
            if requested and getattr(agent, field_name) is not None:
                setattr(agent, field_name, None)
                changed.append(field_name)
        return changed


class AgentRepository(OrganizationScopedRepository):
    """Registered agents of exactly one organization."""

    def __init__(self, session: Session, organization_id: uuid.UUID | None = None) -> None:
        super().__init__(session, organization_id)
        # Composition, not inheritance: the registry drives inventory records
        # through the repository that already knows how to write them (including
        # the integrity-error translation), so there is one implementation of
        # "insert an asset" and one of "update an asset" in this codebase.
        self._assets = AssetRepository(session, self.organization_id)

    # ── Reads ────────────────────────────────────────────────────────────────

    def find(self, agent_id: uuid.UUID) -> Agent | None:
        """One agent by registry id, or ``None`` for a missing *or* foreign one.

        The tenant filter comes from :meth:`_scoped`, so an id belonging to another
        organization is indistinguishable from an id that does not exist — which is
        what lets the API answer without leaking existence.
        """
        statement = self._with_asset().where(Agent.id == agent_id)
        return self.execute(statement).unique().scalars().one_or_none()

    def find_by_identity(self, identity_id: uuid.UUID) -> Agent | None:
        """One agent by its stable identity — the lookup a runtime check would make.

        Scoped to this organization like every other read: an identity belonging to
        another tenant answers ``None``, which the API renders as the same 404 a
        made-up identifier gets.
        """
        statement = self._with_asset().where(Agent.identity_id == identity_id)
        return self.execute(statement).unique().scalars().one_or_none()

    def find_by_asset(self, asset_id: uuid.UUID) -> Agent | None:
        """The registry record for an asset, if this organization has one."""
        statement = self._with_asset().where(Agent.asset_id == asset_id)
        return self.execute(statement).unique().scalars().one_or_none()

    def page(
        self,
        *,
        limit: int,
        offset: int,
        categories: Sequence[AgentCategory | str] | None = None,
        statuses: Sequence[AssetStatus | str] | None = None,
        environments: Sequence[str] | None = None,
        owner_membership_id: uuid.UUID | None = None,
    ) -> list[Agent]:
        """A page of registered agents, newest registration first.

        ``limit`` is required and has no default: callers choose the page size (the
        API caps it), but nothing in this layer can be asked for "all agents", so an
        unbounded query cannot be written by accident. The id breaks timestamp ties
        so paging cannot skip or repeat a row.
        """
        # ``_filtered`` adds the join to the inventory record; the loader option
        # tells the ORM to reuse that join instead of issuing a second query.
        statement = self._filtered(
            self._scoped(Agent).options(contains_eager(Agent.asset)),
            categories=categories,
            statuses=statuses,
            environments=environments,
            owner_membership_id=owner_membership_id,
        )
        statement = (
            statement.order_by(Agent.created_at.desc(), Agent.id).limit(limit).offset(offset)
        )
        return list(self.execute(statement).unique().scalars())

    def count(
        self,
        *,
        categories: Sequence[AgentCategory | str] | None = None,
        statuses: Sequence[AssetStatus | str] | None = None,
        environments: Sequence[str] | None = None,
        owner_membership_id: uuid.UUID | None = None,
    ) -> int:
        """How many agents match the same filters, for an opt-in ``?total=true``.

        Optional for the caller because it is a second pass over the same predicate:
        worth it when a client renders a page count, wasted when it is paging
        through a feed.
        """
        statement = self._filtered(
            self._scoped_count(Agent),
            categories=categories,
            statuses=statuses,
            environments=environments,
            owner_membership_id=owner_membership_id,
        )
        return int(self.execute(statement).scalar_one())

    def _with_asset(self) -> Select[Any]:
        """A tenant-scoped select that loads the inventory record in the same query.

        ``contains_eager`` rather than a second query per agent: a page of agents
        needs each one's name, status and owner to answer with, and the join is
        many-to-one, so it can neither multiply rows nor interact badly with
        ``LIMIT``.
        """
        return (
            self._scoped(Agent)
            .join(Asset, Asset.id == Agent.asset_id)
            .options(contains_eager(Agent.asset))
        )

    def _filtered(
        self,
        statement: Select[Any],
        *,
        categories: Sequence[AgentCategory | str] | None,
        statuses: Sequence[AssetStatus | str] | None,
        environments: Sequence[str] | None,
        owner_membership_id: uuid.UUID | None,
    ) -> Select[Any]:
        """Add the registry's filters: OR within a dimension, AND across dimensions.

        Category is a registry column; status, environment and owner are inventory
        columns reached through a join, because the registry does not keep a second
        copy of them (see the module docstring).
        """
        if categories:
            statement = statement.where(
                Agent.category.in_([AgentCategory(category).value for category in categories])
            )
        statement = statement.join(Asset, Asset.id == Agent.asset_id)
        if statuses:
            statement = statement.where(Asset.status.in_([str(status) for status in statuses]))
        if environments:
            statement = statement.where(
                Asset.environment.in_([str(environment) for environment in environments])
            )
        if owner_membership_id is not None:
            statement = statement.where(Asset.owner_membership_id == owner_membership_id)
        return statement

    # ── Writes ───────────────────────────────────────────────────────────────

    def register(
        self,
        *,
        category: AgentCategory | str,
        version: str,
        owner_membership_id: uuid.UUID | None,
        display_name: str,
        description: str | None = None,
        status: AssetStatus | str | None = None,
        environment: str | None = None,
        external_identifier: str | None = None,
        framework: str | None = None,
        build_revision: str | None = None,
        identity_metadata: Mapping[str, Any] | None = None,
    ) -> RegistrationResult:
        """Register an agent, creating or adopting the ``agent`` asset behind it.

        The optional parameters mean "what the caller asserted": a value left as
        ``None`` was not stated, so it neither sets anything on a new asset (the
        database defaults apply) nor contradicts anything on an adopted one. That is
        the distinction ``PATCH`` makes, and it is what makes adoption safe — the
        request decides what it claims and never overwrites a decision it did not
        make.

        Raises :class:`ConflictError` when the external identifier already belongs to
        a registered agent, when the request contradicts an existing asset it is
        trying to adopt, or when the requested lifecycle state cannot start a record
        (``suspended`` and ``retired`` are states an agent moves to, not states it
        starts in).
        """
        category_value = AgentCategory(category).value
        version_value = normalize_version(version)
        framework_value = normalize_optional_text(
            framework, field_name="framework", max_length=FRAMEWORK_MAX_LENGTH
        )
        revision_value = normalize_optional_text(
            build_revision, field_name="build_revision", max_length=BUILD_REVISION_MAX_LENGTH
        )
        metadata_value = validate_identity_metadata(identity_metadata)
        initial_status = (
            validate_initial_status(status) if status is not None else AssetStatus.DRAFT
        )

        existing_asset: Asset | None = None
        if external_identifier is not None:
            # The inventory's notion of identity for an external system: the same
            # identifier and type must be the same agent, or registration could
            # create a second identity for one thing.
            existing_asset = self._assets.find_by_external_identifier(
                asset_type=AssetType.AGENT.value, external_identifier=external_identifier
            )

        if existing_asset is None:
            return self._register_new_asset(
                category=category_value,
                version=version_value,
                owner_membership_id=owner_membership_id,
                display_name=display_name,
                description=description,
                status=initial_status.value,
                environment=environment,
                external_identifier=external_identifier,
                framework=framework_value,
                build_revision=revision_value,
                identity_metadata=metadata_value,
            )

        return self._adopt_existing_asset(
            asset=existing_asset,
            category=category_value,
            version=version_value,
            owner_membership_id=owner_membership_id,
            display_name=display_name,
            description=description,
            status=status,
            environment=environment,
            framework=framework_value,
            build_revision=revision_value,
            identity_metadata=metadata_value,
        )

    def update(self, agent: Agent, change: AgentUpdate) -> list[str]:
        """Apply ``change`` to ``agent`` and its record; returns what changed.

        The lifecycle rule is enforced here rather than in the route, so every write
        path — this API today, an ingestion or administrative path later — obeys the
        same transitions. A move that is not allowed is a :class:`ConflictError`
        (what the request asked for is not reachable from the current state), not a
        validation error: the request was well-formed and the record says no.
        """
        changed: list[str] = []
        with self.writing():
            if change.asset is not None and change.asset.status is not None:
                try:
                    validate_transition(agent.asset.status, change.asset.status)
                except ValueError as exc:
                    raise ConflictError(str(exc)) from exc
            changed.extend(change.apply_to(agent))
            if change.asset is not None:
                changed.extend(self._assets.apply(agent.asset, change.asset))
            if changed:
                self._flush()
                self.session.commit()
                # Two refreshes, because an update here spans two tables: the agent
                # and the inventory record it belongs to. Sessions do not expire on
                # commit, so each is reloaded explicitly rather than relying on a
                # later read to notice.
                self.session.refresh(agent)
                self.session.refresh(agent.asset)
        return changed

    def delete(self, agent: Agent) -> None:
        """Remove the identity *and* its inventory record, in one transaction.

        Deleting the record is what removes the identity — the registry's composite
        foreign key cascades — so no orphan can be left behind and no caller has to
        remember to delete two rows in the right order. The caller emits the domain
        event before this runs.
        """
        asset_id = agent.asset_id
        with self.writing():
            # Explicit and tenant-filtered, as in the inventory repository: the row
            # is removed only if it belongs to this repository's tenant.
            self.session.execute(
                delete(Asset)
                .where(Asset.id == asset_id)
                .where(Asset.organization_id == self.organization_id)
            )
            self.session.commit()

    # ── Internals ────────────────────────────────────────────────────────────

    def _register_new_asset(
        self,
        *,
        category: str,
        version: str,
        owner_membership_id: uuid.UUID | None,
        display_name: str,
        description: str | None,
        status: str,
        environment: str | None,
        external_identifier: str | None,
        framework: str | None,
        build_revision: str | None,
        identity_metadata: dict[str, Any] | None,
    ) -> RegistrationResult:
        """Stage the inventory record and the identity in one unit of work."""
        with self.writing():
            asset = self._assets.insert(
                name=display_name,
                asset_type=AssetType.AGENT.value,
                description=description,
                status=status,
                environment=environment or Environment.UNKNOWN.value,
                discovery_state=DiscoveryState.MANAGED.value,
                risk_classification=RiskClassification.UNASSESSED.value,
                owner_membership_id=owner_membership_id,
                external_identifier=external_identifier,
            )
            agent = self._stage(
                asset_id=asset.id,
                category=category,
                version=version,
                framework=framework,
                build_revision=build_revision,
                identity_metadata=identity_metadata,
            )
            self.session.commit()
            agent = self._reload(agent)
        return RegistrationResult(agent=agent, asset_created=True)

    def _adopt_existing_asset(
        self,
        *,
        asset: Asset,
        category: str,
        version: str,
        owner_membership_id: uuid.UUID | None,
        display_name: str,
        description: str | None,
        status: AssetStatus | str | None,
        environment: str | None,
        framework: str | None,
        build_revision: str | None,
        identity_metadata: dict[str, Any] | None,
    ) -> RegistrationResult:
        """Attach an identity to an ``agent`` asset the inventory already holds.

        Every claim in the request has to agree with what is recorded. A request that
        disagrees is refused rather than applied, because the alternative is a
        registration silently rewriting an inventory record — including its owner or
        its lifecycle state — that somebody else decided.
        """
        if self.find_by_asset(asset.id) is not None:
            raise ConflictError(
                "this agent is already registered; read it instead of registering it again"
            )

        conflicts: list[str] = []
        if display_name.strip() != asset.name:
            conflicts.append(f"display_name (recorded as {asset.name!r})")
        if description is not None and description != asset.description:
            conflicts.append("description")
        if environment is not None and environment != asset.environment:
            conflicts.append(f"environment (recorded as {asset.environment!r})")
        if status is not None and AssetStatus(status).value != asset.status:
            conflicts.append(f"status (recorded as {asset.status!r})")
        if (
            owner_membership_id is not None
            and asset.owner_membership_id is not None
            and owner_membership_id != asset.owner_membership_id
        ):
            conflicts.append("owner_user_id (the record already has a different owner)")
        if conflicts:
            raise ConflictError(
                "an agent asset with this external identifier already exists and the "
                f"request contradicts it: {', '.join(conflicts)}. Update the agent "
                "through the agents API instead of registering it again."
            )

        with self.writing():
            # Only a gap is filled, never a decision replaced: an unowned inventory
            # record gains the owner this registration names.
            if owner_membership_id is not None and asset.owner_membership_id is None:
                self._assets.apply(asset, AssetUpdate(owner_membership_id=owner_membership_id))
                # Refreshed explicitly because sessions here do not expire on commit
                # (`db/session.py`), so the relationship loaded above — "no owner" —
                # would otherwise outlive the change and be echoed back as the answer.
                self.session.refresh(asset)
            agent = self._stage(
                asset_id=asset.id,
                category=category,
                version=version,
                framework=framework,
                build_revision=build_revision,
                identity_metadata=identity_metadata,
            )
            self.session.commit()
            agent = self._reload(agent)
        return RegistrationResult(agent=agent, asset_created=False)

    def _stage(
        self,
        *,
        asset_id: uuid.UUID,
        category: str,
        version: str,
        framework: str | None,
        build_revision: str | None,
        identity_metadata: dict[str, Any] | None,
    ) -> Agent:
        """Insert the registry row. ``identity_id`` is deliberately not set here.

        The database generates it, so no code path — and no request — can choose an
        agent's identity.
        """
        agent = Agent(
            organization_id=self.organization_id,
            asset_id=asset_id,
            category=category,
            version=version,
            framework=framework,
            build_revision=build_revision,
            identity_metadata=identity_metadata,
        )
        self.session.add(agent)
        self._flush()
        return agent

    def _reload(self, agent: Agent) -> Agent:
        """Reload a just-committed agent together with the record it belongs to.

        The identity, ``created_at`` and the asset's server-written columns only
        exist after the commit, so the object that gets returned is re-read rather
        than assumed.
        """
        registered = self.find(agent.id)
        if registered is None:  # impossible: the row was committed in this tenant
            raise RuntimeError("the committed agent could not be re-read")
        return registered

    def _flush(self) -> None:
        """Flush, translating a constraint violation into the domain error it means."""
        try:
            self.session.flush()
        except IntegrityError as exc:
            self.session.rollback()
            raise _translate_agent_integrity_error(exc) from exc
