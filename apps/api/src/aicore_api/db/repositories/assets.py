"""Asset repository — every query the inventory API needs, tenant-scoped by construction.

The class is an :class:`~aicore_api.db.repositories.organizations.OrganizationScopedRepository`,
so it cannot be constructed without an organization and every statement it builds
is filtered to that organization by the base class. That is not a convenience: it
is the reason "list the assets" cannot accidentally mean "list every asset in the
installation". Cross-organization reads here are impossible by construction rather
than avoided by discipline.

Two behaviours are worth reading before the code:

- **Lookups return ``None`` for a missing *and* a foreign asset.** Not because the
  distinction is unimportant — it is the whole point of tenant isolation — but
  because the API must not expose it. A 404 that says "this exists, but not for
  you" is an enumeration oracle; see ``api/routes/assets.py``.
- **Registering a discovered asset is an idempotent write, not an insert.** An
  integration re-reports what it saw, so the same external identifier must converge
  on one row. The decision is made in PostgreSQL (``ON CONFLICT``) rather than by a
  read-then-write in Python, which would race against a concurrent collector.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any, cast

from sqlalchemy import Select, Table, delete, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import IntegrityError

from aicore_api.core.assets import (
    MANUAL_DISCOVERY_SOURCE,
    AssetStatus,
    DiscoveryState,
    Environment,
    RiskClassification,
    normalize_name,
)
from aicore_api.core.domain_errors import ConflictError, InvalidReferenceError
from aicore_api.db.models.asset import Asset
from aicore_api.db.models.membership import Membership
from aicore_api.db.models.user import User
from aicore_api.db.repositories.organizations import OrganizationScopedRepository

__all__ = ["AssetRepository", "AssetUpdate"]

#: What a report from an integration may refresh on an existing asset. Lifecycle
#: status, owner and risk classification are *not* here: those are the
#: organization's judgement about the asset, and observing something again is not
#: a reason to overwrite a decision a person made.
#:
#: Mapped from the *column* names used by the INSERT to the *attribute* names the
#: ORM update needs. They differ for one field: the column is ``metadata`` and the
#: attribute is ``asset_metadata``, because ``metadata`` on a declarative class is
#: SQLAlchemy's ``MetaData`` registry. Getting that wrong is silent on one path and
#: an ``AttributeError`` on the other, so the mapping is written out rather than
#: derived.
_OBSERVED_COLUMNS = ("name", "description", "metadata", "last_seen_at", "discovery_source")
_OBSERVED_ATTRIBUTES = {
    "name": "name",
    "description": "description",
    "metadata": "asset_metadata",
    "last_seen_at": "last_seen_at",
    "discovery_source": "discovery_source",
}


class AssetUpdate:
    """The fields an update may change, and nothing else.

    A tiny carrier rather than a dict so that "what is updatable?" is one readable
    list, and so that a column added to the model cannot silently become updatable
    because somebody passed a dictionary through.

    The ``clear_*`` flags exist because PATCH must distinguish *leave it alone*
    from *remove it*: with one nullable column, "no value in the body" and "set it
    to null" are otherwise the same request.
    """

    __slots__ = (
        "_clear_description",
        "_clear_external_identifier",
        "_clear_metadata",
        "_clear_owner",
        "asset_metadata",
        "description",
        "discovery_state",
        "environment",
        "external_identifier",
        "name",
        "owner_membership_id",
        "risk_classification",
        "status",
    )

    def __init__(
        self,
        *,
        name: str | None = None,
        description: str | None = None,
        status: str | None = None,
        environment: str | None = None,
        discovery_state: str | None = None,
        risk_classification: str | None = None,
        owner_membership_id: uuid.UUID | None = None,
        external_identifier: str | None = None,
        asset_metadata: dict[str, Any] | None = None,
        clear_owner: bool = False,
        clear_metadata: bool = False,
        clear_description: bool = False,
        clear_external_identifier: bool = False,
    ) -> None:
        self.name = name
        self.description = description
        self.status = status
        self.environment = environment
        self.discovery_state = discovery_state
        self.risk_classification = risk_classification
        self.owner_membership_id = owner_membership_id
        self.external_identifier = external_identifier
        self.asset_metadata = asset_metadata
        self._clear_owner = clear_owner
        self._clear_metadata = clear_metadata
        self._clear_description = clear_description
        self._clear_external_identifier = clear_external_identifier

    def is_empty(self) -> bool:
        """Whether the request asked for no change at all."""
        return not any(
            (
                self.name,
                self.description,
                self.status,
                self.environment,
                self.discovery_state,
                self.risk_classification,
                self.owner_membership_id,
                self.external_identifier,
                self.asset_metadata,
                self._clear_owner,
                self._clear_metadata,
                self._clear_description,
                self._clear_external_identifier,
            )
        )

    def apply_to(self, asset: Asset) -> list[str]:
        """Apply the change to ``asset`` and return the names of the changed fields.

        Returned names are what the domain event reports: "asset.updated, fields
        [status]" is a useful audit line; a copy of the row is not.
        """
        changed: list[str] = []
        assignments: list[tuple[str, Any]] = [
            ("name", normalize_name(self.name) if self.name is not None else None),
            ("description", self.description),
            ("status", self.status),
            ("environment", self.environment),
            ("discovery_state", self.discovery_state),
            ("risk_classification", self.risk_classification),
            ("owner_membership_id", self.owner_membership_id),
            ("external_identifier", self.external_identifier),
            # The *attribute* name, not the column name. The column is called
            # `metadata` and the attribute is called `asset_metadata`, because
            # `metadata` on a declarative class is SQLAlchemy's ``MetaData``
            # registry — `setattr(asset, "metadata", ...)` would set an unmapped
            # instance attribute and the update would silently do nothing.
            ("asset_metadata", self.asset_metadata),
        ]
        for field_name, value in assignments:
            if value is None:
                continue
            if getattr(asset, field_name) != value:
                setattr(asset, field_name, value)
                changed.append(field_name)

        clears: list[tuple[bool, str]] = [
            (self._clear_owner, "owner_membership_id"),
            (self._clear_metadata, "asset_metadata"),
            (self._clear_description, "description"),
            (self._clear_external_identifier, "external_identifier"),
        ]
        for requested, field_name in clears:
            if requested and getattr(asset, field_name) is not None:
                setattr(asset, field_name, None)
                changed.append(field_name)
        return changed


def _translate_integrity_error(exc: IntegrityError) -> Exception:
    """Turn a constraint violation into the domain error it means, or return ``exc``.

    The two cases worth translating are races that a caller can actually cause: a
    duplicate external identifier (someone else registered it first) and an owner
    who is not a member. The database decides both — a pre-flight check in Python
    would be a race, and the constraint is not — so the mapping is by constraint
    name.

    Anything else is returned unchanged. A check constraint the application itself
    is supposed to respect being violated means this build wrote something it
    should not have been able to write, and answering 409 would turn a defect into
    a plausible-looking client error.
    """
    constraint = getattr(getattr(exc.orig, "diag", None), "constraint_name", None)
    if constraint == "uq_assets_organization_id_asset_type_external_identifier":
        return ConflictError("an asset of this type already uses that external identifier")
    if constraint == "fk_assets_organization_id_memberships":
        return InvalidReferenceError("owner must be a member of this organization")
    if constraint == "fk_assets_organization_id_organizations":
        return InvalidReferenceError("no such organization")
    return exc


class AssetRepository(OrganizationScopedRepository):
    """Assets of exactly one organization."""

    # ── Reads ────────────────────────────────────────────────────────────────

    def find(self, asset_id: uuid.UUID) -> Asset | None:
        """One asset of this organization, or ``None``.

        The organization filter comes from :meth:`_scoped`, so an id belonging to
        another tenant is *indistinguishable from an id that does not exist* —
        exactly what the API needs in order to answer without leaking existence.
        """
        statement = self._scoped(Asset).where(Asset.id == asset_id)
        return self.execute(statement).scalars().unique().one_or_none()

    def page(
        self,
        *,
        limit: int,
        offset: int,
        asset_types: Sequence[str] | None = None,
        statuses: Sequence[str] | None = None,
        environments: Sequence[str] | None = None,
        discovery_states: Sequence[str] | None = None,
        risk_classifications: Sequence[str] | None = None,
        owner_membership_id: uuid.UUID | None = None,
    ) -> list[Asset]:
        """A page of this organization's assets, newest first.

        ``limit`` is required and has no default: the caller chooses the page size
        (the API caps it), but nothing in this layer can be asked for "all assets",
        so an unbounded query cannot be written by accident. Ordering is
        ``(created_at DESC, id DESC)`` — the id breaks ties, so paging cannot skip
        or repeat a row when two assets share a timestamp.
        """
        statement = self._filtered(
            self._scoped(Asset),
            asset_types=asset_types,
            statuses=statuses,
            environments=environments,
            discovery_states=discovery_states,
            risk_classifications=risk_classifications,
            owner_membership_id=owner_membership_id,
        )
        statement = (
            statement.order_by(Asset.created_at.desc(), Asset.id.desc()).limit(limit).offset(offset)
        )
        return list(self.execute(statement).scalars().unique().all())

    def count(
        self,
        *,
        asset_types: Sequence[str] | None = None,
        statuses: Sequence[str] | None = None,
        environments: Sequence[str] | None = None,
        discovery_states: Sequence[str] | None = None,
        risk_classifications: Sequence[str] | None = None,
        owner_membership_id: uuid.UUID | None = None,
    ) -> int:
        """How many assets match the same filters.

        Optional for the caller (``GET /assets?total=true``) because it is a second
        pass over the same predicate: worth it when a client renders a page count,
        wasted when it is paging through a feed.
        """
        statement = self._filtered(
            self._scoped_count(Asset),
            asset_types=asset_types,
            statuses=statuses,
            environments=environments,
            discovery_states=discovery_states,
            risk_classifications=risk_classifications,
            owner_membership_id=owner_membership_id,
        )
        return int(self.execute(statement).scalar_one())

    def _filtered(
        self,
        statement: Select[Any],
        *,
        asset_types: Sequence[str] | None,
        statuses: Sequence[str] | None,
        environments: Sequence[str] | None,
        discovery_states: Sequence[str] | None,
        risk_classifications: Sequence[str] | None,
        owner_membership_id: uuid.UUID | None,
    ) -> Select[Any]:
        """Add the inventory's filters: OR within a dimension, AND across dimensions.

        That is the usual reading of a filter set, and the one a query string such
        as ``?asset_type=model&asset_type=tool&environment=production`` implies.
        """
        dimensions: list[tuple[Any, Sequence[str] | None]] = [
            (Asset.asset_type, asset_types),
            (Asset.status, statuses),
            (Asset.environment, environments),
            (Asset.discovery_state, discovery_states),
            (Asset.risk_classification, risk_classifications),
        ]
        for column, values in dimensions:
            if values:
                statement = statement.where(column.in_(list(values)))
        if owner_membership_id is not None:
            statement = statement.where(Asset.owner_membership_id == owner_membership_id)
        return statement

    def list_owners(self, *, limit: int) -> list[tuple[Membership, User]]:
        """Members of this organization who could own an asset, with their user row.

        The only source of owner identifiers the API offers. A client cannot pass a
        user id, and a membership id it guessed is resolved against this
        organization — so inventing an owner is impossible through the API and
        impossible in the database, thanks to the composite foreign key on
        ``assets``.
        """
        statement = (
            select(Membership, User)
            .join(User, User.id == Membership.user_id)
            .where(Membership.organization_id == self.organization_id)
            .order_by(User.full_name, User.id)
            .limit(limit)
        )
        return [(membership, user) for membership, user in self.execute(statement).all()]

    def member(self, membership_id: uuid.UUID) -> Membership | None:
        """The membership ``membership_id``, if it belongs to this organization.

        Resolving rather than trusting is the point: an id from another tenant
        resolves to nothing, and the caller then refuses the request with the same
        error it uses for an id that does not exist at all.
        """
        statement = self._scoped(Membership).where(Membership.id == membership_id)
        return self.execute(statement).scalars().unique().one_or_none()

    def find_by_external_identifier(
        self, *, asset_type: str, external_identifier: str
    ) -> Asset | None:
        """The asset a producing system's identifier refers to, if it is recorded."""
        statement = self._scoped(Asset).where(
            Asset.asset_type == asset_type,
            Asset.external_identifier == external_identifier,
        )
        return self.execute(statement).scalars().unique().one_or_none()

    # ── Writes ───────────────────────────────────────────────────────────────

    def add(
        self,
        *,
        name: str,
        asset_type: str,
        description: str | None = None,
        status: str = AssetStatus.DRAFT.value,
        environment: str = Environment.UNKNOWN.value,
        discovery_state: str = DiscoveryState.MANAGED.value,
        risk_classification: str = RiskClassification.UNASSESSED.value,
        owner_membership_id: uuid.UUID | None = None,
        external_identifier: str | None = None,
        discovery_source: str = MANUAL_DISCOVERY_SOURCE,
        last_seen_at: datetime | None = None,
        asset_metadata: Mapping[str, Any] | None = None,
    ) -> Asset:
        """Insert one asset. Its identity columns are set here, never by the caller.

        ``organization_id`` comes from the repository (the tenant is not a request
        field), ``status``/``discovery_state``/``risk_classification`` have
        database defaults and are only overridden when the caller states them, and
        ``discovery_source`` defaults to ``manual`` — an API caller cannot claim a
        record came from an integration.
        """
        asset = Asset(
            organization_id=self.organization_id,
            name=normalize_name(name),
            description=description,
            asset_type=asset_type,
            status=status,
            environment=environment,
            discovery_state=discovery_state,
            risk_classification=risk_classification,
            owner_membership_id=owner_membership_id,
            external_identifier=external_identifier,
            discovery_source=discovery_source,
            last_seen_at=last_seen_at,
            asset_metadata=dict(asset_metadata) if asset_metadata is not None else None,
        )
        with self.writing():
            self.session.add(asset)
            try:
                self.session.flush()
            except IntegrityError as exc:
                self.session.rollback()
                raise _translate_integrity_error(exc) from exc
            self.session.commit()
            # After commit, not before: the primary key and the timestamps are
            # written by the database, and a caller echoing the new asset back
            # should echo the row that exists.
            self.session.refresh(asset)
        return asset

    def update(self, asset: Asset, change: AssetUpdate) -> list[str]:
        """Apply ``change`` to ``asset``; returns the names of what changed."""
        with self.writing():
            changed = change.apply_to(asset)
            if changed:
                try:
                    self.session.flush()
                except IntegrityError as exc:
                    self.session.rollback()
                    raise _translate_integrity_error(exc) from exc
                self.session.commit()
                self.session.refresh(asset)
        return changed

    def delete(self, asset: Asset) -> None:
        """Remove one asset from the inventory.

        A hard delete of a row whose only dependants are future audit records: the
        record *is* the inventory, and keeping a "deleted" asset in the table would
        mean every reader has to remember to filter it out. The caller emits the
        domain event before this runs, so the removal stays observable — and if a
        later phase introduces the event store as a table with a foreign key here,
        this method is where the retention decision gets made, in one place.
        """
        with self.writing():
            # An explicit, tenant-filtered DELETE rather than ``session.delete``:
            # the statement itself carries the organization boundary, so the row is
            # removed only if it belongs to this repository's tenant — the same
            # rule every read here obeys, applied to the write that cannot be undone.
            self.session.execute(
                delete(Asset)
                .where(Asset.id == asset.id)
                .where(Asset.organization_id == self.organization_id)
            )
            self.session.commit()

    def register_discovered(
        self,
        *,
        name: str,
        asset_type: str,
        external_identifier: str,
        discovery_source: str,
        description: str | None = None,
        status: str = AssetStatus.ACTIVE.value,
        environment: str = Environment.UNKNOWN.value,
        discovery_state: str = DiscoveryState.UNKNOWN.value,
        risk_classification: str = RiskClassification.UNASSESSED.value,
        owner_membership_id: uuid.UUID | None = None,
        asset_metadata: Mapping[str, Any] | None = None,
        observed_at: datetime | None = None,
    ) -> tuple[Asset, bool]:
        """Record an asset reported by an integration; returns ``(asset, created)``.

        Idempotent by construction. The write is
        ``ON CONFLICT (organization_id, asset_type, external_identifier) DO NOTHING``,
        so a collector that reports the same asset every five minutes updates one
        row instead of filling the inventory with duplicates and two concurrent
        reports cannot both insert. ``created`` then states a fact rather than a
        guess: it is true only for the caller whose insert actually won.

        What a repeat report does **not** touch matters as much as what it does.
        Lifecycle ``status``, ``owner_membership_id`` and ``risk_classification``
        are the organization's judgement about the asset; observing the asset again
        is not a reason to overwrite a decision a person made. What it refreshes is
        what the integration is authoritative about: ``last_seen_at``, and the name,
        description and metadata it just read.

        A consequence worth stating: an asset first found by a collector arrives as
        ``discovery_state='unknown'`` and ``status='active'``. The integration
        reports that the asset exists, not who owns it — promoting it to
        ``managed`` is a decision a member of the organization makes through
        ``PATCH``.
        """
        now = datetime.now(UTC)
        # SQLAlchemy's stubs type ``__table__`` as ``FromClause``; the declarative
        # mapping guarantees a ``Table``, which is what these Core operations and
        # their ``index_elements`` need.
        table = cast(Table, Asset.__table__)
        values = {
            "organization_id": self.organization_id,
            "name": normalize_name(name),
            "description": description,
            "asset_type": asset_type,
            "status": status,
            "environment": environment,
            "discovery_state": discovery_state,
            "risk_classification": risk_classification,
            "owner_membership_id": owner_membership_id,
            "external_identifier": external_identifier,
            "discovery_source": discovery_source,
            "last_seen_at": observed_at or now,
            "metadata": dict(asset_metadata) if asset_metadata is not None else None,
        }
        insert_statement = (
            pg_insert(table)
            .values(**values)
            .on_conflict_do_nothing(
                index_elements=[
                    table.c.organization_id,
                    table.c.asset_type,
                    table.c.external_identifier,
                ],
                index_where=table.c.external_identifier.is_not(None),
            )
            .returning(table.c.id)
        )

        with self.writing():
            try:
                inserted_id = self.session.execute(insert_statement).scalar_one_or_none()
            except IntegrityError as exc:
                self.session.rollback()
                raise _translate_integrity_error(exc) from exc
            created = inserted_id is not None
            if inserted_id is None:
                # The row already exists: refresh only the observed fields, and
                # leave the organization's own decisions (status, owner, risk) as
                # they were.
                # An *ORM-enabled* update, not a Core one: SQLAlchemy synchronizes
                # the session's objects for ORM statements, so the row returned
                # below is the row that was just written. A Core update would leave
                # the identity map holding the previous values, and the caller
                # would be handed a stale asset — the sort of bug that only shows
                # up when something is reported twice.
                self.session.execute(
                    update(Asset)
                    .where(
                        Asset.organization_id == self.organization_id,
                        Asset.asset_type == asset_type,
                        Asset.external_identifier == external_identifier,
                    )
                    .values(
                        **{
                            _OBSERVED_ATTRIBUTES[column]: values[column]
                            for column in _OBSERVED_COLUMNS
                        },
                        updated_at=now,
                    )
                )
            self.session.commit()

        asset = self.find_by_external_identifier(
            asset_type=asset_type, external_identifier=external_identifier
        )
        if asset is None:  # pragma: no cover - the write above just committed this row
            raise RuntimeError("discovered asset vanished after write")
        return asset, created
