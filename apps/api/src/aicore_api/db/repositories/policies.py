"""Policy repository — the policy record, tenant-scoped by construction.

The class is an :class:`~aicore_api.db.repositories.organizations.OrganizationScopedRepository`,
so it cannot be built without an organization and every statement it issues is
filtered to that organization. A policy belonging to another tenant is therefore
indistinguishable from one that does not exist, which is what lets the API answer
without leaking existence.

Four behaviours are worth reading before the code.

**A policy is written as a pair of rows.** Creating one inserts the policy and its
first version in one unit of work; editing its definition appends the next version
and moves the pointer in one unit of work. There is no state in which a policy
points at a version that does not exist, and no state in which a version belongs to
nobody.

**Versions are append-only.** Nothing here updates or deletes a
:class:`~aicore_api.db.models.policy.PolicyVersion` row. That is what makes a
recorded decision reproducible: a decision names a policy *and a version*, and the
row those name still says exactly what it said when the decision was made.
``tests/test_policies.py`` asserts the absence of an update path both behaviourally
and structurally, because "we do not do that" is a claim until something checks it.

**Nothing invalid is ever written.** Every write path calls the language's
validators (:mod:`aicore_api.core.policy`) *before* it stages a row, and activation
re-validates the stored version rather than trusting that it was validated on the
way in. A policy that cannot be evaluated therefore cannot reach ``active``.

**A stored row this build cannot read fails loudly.**
:meth:`PolicyRepository.definition_of` raises
:class:`~aicore_api.core.policy.PolicyDefinitionError` for a version whose
conditions, target, effect or priority do not parse — a database edited outside the
application, or a downgrade that removed a vocabulary. Silently skipping such a
policy would quietly change what the organization's policy says, which is the one
thing this layer must never do.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from typing import Any

from sqlalchemy import ColumnElement, Select, delete, func, select
from sqlalchemy.exc import IntegrityError

from aicore_api.core.domain_errors import ConflictError
from aicore_api.core.permissions import Action, Resource
from aicore_api.core.policy import (
    POLICY_TARGETS,
    PolicyCondition,
    PolicyDefinition,
    PolicyDefinitionError,
    PolicyEffect,
    PolicyStatus,
    conditions_from_stored,
    normalize_description,
    normalize_name,
    validate_conditions,
    validate_definition,
    validate_effect,
    validate_initial_status,
    validate_priority,
    validate_status,
    validate_target,
    validate_transition,
)
from aicore_api.db.models.policy import Policy, PolicyVersion
from aicore_api.db.repositories.organizations import OrganizationScopedRepository

__all__ = ["PolicyRepository"]


def _current_version_join() -> ColumnElement[bool]:
    """The join that pairs a policy with the version it currently points at.

    The same condition :attr:`aicore_api.db.models.policy.Policy.current_version_row`
    is defined with, written once as a value because three queries need it as an
    explicit ``JOIN``: the evaluation load, the listing (whose filters are about the
    definition) and the count. A wrong condition here would silently evaluate the
    wrong version — the kind of bug that looks like a policy that does not work.
    """
    return (Policy.id == PolicyVersion.policy_id) & (
        Policy.current_version == PolicyVersion.version
    )


def _translate_integrity_error(exc: IntegrityError) -> Exception:
    """Turn a constraint violation into the domain error it means, or return ``exc``.

    The cases worth translating are races a caller can actually cause: two policies
    with one name in one organization (the second loses), two writers publishing the
    same version number, and a version whose policy was removed underneath it.
    Anything else is returned unchanged: a check constraint the application is
    supposed to respect being violated means this build wrote something it should
    not have been able to write, and answering 409 would turn a defect into a
    plausible-looking client error.
    """
    constraint = getattr(getattr(exc.orig, "diag", None), "constraint_name", None)
    if constraint == "uq_policies_organization_id_name":
        return ConflictError("a policy with this name already exists in this organization")
    if constraint == "pk_policy_versions":
        return ConflictError(
            "the policy was modified concurrently; read it again and reapply the change"
        )
    if constraint == "fk_policy_versions_organization_id_policies":
        return ConflictError("the policy this version belongs to no longer exists")
    return exc


#: The actions any policy may target, derived from the permission catalog: the
#: union of the actions declared for the policy targets. Derived, never written out,
#: so adding a permission is enough to make it filterable.
_TARGET_ACTIONS: frozenset[Action] = frozenset(
    action for targets in POLICY_TARGETS.values() for action in targets
)


def resolve_resource(value: Resource | str) -> Resource:
    """Resolve a ``resource`` filter to the vocabulary, refusing anything else.

    Stricter than ``Resource(value)`` alone: a resource is usable as a policy filter
    only if some policy may target it, so ``security`` — a real permission with no
    policy target in this build — is refused here exactly as it is refused when it
    appears in a policy's own target.
    """
    try:
        resource = Resource(value)
    except ValueError as exc:
        allowed = ", ".join(item.value for item in Resource)
        raise PolicyDefinitionError(
            f"unknown resource {value!r}; policy resources are: {allowed}"
        ) from exc
    if not POLICY_TARGETS.get(resource):
        raise PolicyDefinitionError(
            f"{resource.value} is not a resource any policy may target in this build"
        )
    return resource


def resolve_action(value: Action | str) -> Action:
    """Resolve an ``action`` filter to the vocabulary, refusing anything else."""
    try:
        action = Action(value)
    except ValueError as exc:
        allowed = ", ".join(item.value for item in Action)
        raise PolicyDefinitionError(
            f"unknown action {value!r}; policy actions are: {allowed}"
        ) from exc
    if action not in _TARGET_ACTIONS:
        raise PolicyDefinitionError(
            f"{action.value} is not an action any policy may target in this build"
        )
    return action


class PolicyRepository(OrganizationScopedRepository):
    """Policies of exactly one organization."""

    # ── Reads ────────────────────────────────────────────────────────────────

    def find(self, policy_id: uuid.UUID) -> Policy | None:
        """One policy of this organization, or ``None``.

        ``None`` covers both "no such policy" and "another organization's policy",
        deliberately: the API must not be able to tell them apart.
        """
        statement = self._scoped(Policy).where(Policy.id == policy_id)
        return self.execute(statement).unique().scalars().one_or_none()

    def page(
        self,
        *,
        limit: int,
        offset: int,
        statuses: Sequence[PolicyStatus | str] | None = None,
        effects: Sequence[PolicyEffect | str] | None = None,
        resources: Sequence[Resource | str] | None = None,
        actions: Sequence[Action | str] | None = None,
    ) -> list[Policy]:
        """A page of policies, newest first.

        ``limit`` is required and has no default: callers choose the page size (the
        API caps it), but nothing in this layer can be asked for "all policies", so
        an unbounded query cannot be written by accident. The id breaks timestamp
        ties so paging cannot skip or repeat a row.

        Every filter is about the policy's *current* version, which is why the join
        lives here rather than at the call site: "effect is deny" must not be able
        to mean "was a deny two versions ago".
        """
        statement = self._filtered(
            self._scoped(Policy),
            statuses=statuses,
            effects=effects,
            resources=resources,
            actions=actions,
        )
        statement = (
            statement.order_by(Policy.created_at.desc(), Policy.id).limit(limit).offset(offset)
        )
        return list(self.execute(statement).unique().scalars())

    def count(
        self,
        *,
        statuses: Sequence[PolicyStatus | str] | None = None,
        effects: Sequence[PolicyEffect | str] | None = None,
        resources: Sequence[Resource | str] | None = None,
        actions: Sequence[Action | str] | None = None,
    ) -> int:
        """How many policies match the same filters, for an opt-in ``?total=true``.

        The count is over the same joined statement as the page — a count built from
        a different predicate than the page it belongs to is a classic way to report
        a total that never matches the rows.
        """
        statement = self._filtered(
            self._scoped_count(Policy),
            statuses=statuses,
            effects=effects,
            resources=resources,
            actions=actions,
        )
        return int(self.execute(statement).scalar_one())

    def definition_of(self, policy: Policy) -> PolicyDefinition:
        """The current version of ``policy``, as the evaluator sees it.

        The single place a stored row becomes a value the engine can use — and so
        the single place where a row this build cannot interpret becomes visible: a
        corrupt definition raises here rather than being skipped.
        """
        return self._definition(policy)

    def active_definitions(
        self, resource: Resource | str, action: Action | str
    ) -> list[PolicyDefinition]:
        """Every ``active`` policy of this organization that targets ``resource.action``.

        The engine's input, and the only query in this codebase that decides what a
        policy evaluation considers: the tenant comes from the repository, the
        lifecycle filter is ``active`` alone (a draft, a disabled or a retired policy
        does not participate — that is the whole meaning of those states), and the
        definition comes from the *current* version.

        Ordered for the database's benefit; the engine sorts its own candidates, so
        the decision never depends on this order.
        """
        resolved_resource, resolved_action = validate_target(resource, action)
        statement = (
            self._scoped(Policy)
            .join(PolicyVersion, _current_version_join())
            .where(Policy.status == PolicyStatus.ACTIVE.value)
            .where(PolicyVersion.resource == resolved_resource.value)
            .where(PolicyVersion.action == resolved_action.value)
            .order_by(PolicyVersion.priority, Policy.name, Policy.id)
        )
        rows = self.execute(statement).unique().scalars().all()
        return [self._definition(policy) for policy in rows]

    def versions_of(self, policy: Policy, *, limit: int, offset: int) -> list[PolicyVersion]:
        """A page of ``policy``'s version history, oldest first.

        ``limit`` is required and has no default, for the same reason
        :meth:`page`'s is: no query in this layer can be asked for every row of a
        table, and a history that grows with every edit is a table. Read through the
        same tenant filter as everything else here, so a caller cannot reach another
        organization's history even with a policy id — and ordered by the version
        number rather than by ``created_at``, because the version number *is* the
        identity of a version.
        """
        statement = (
            select(PolicyVersion)
            .where(PolicyVersion.policy_id == policy.id)
            .where(PolicyVersion.organization_id == self.organization_id)
            .order_by(PolicyVersion.version)
            .limit(limit)
            .offset(offset)
        )
        return list(self.execute(statement).scalars())

    def version_count(self, policy: Policy) -> int:
        """How many versions ``policy`` has, for the count beside a history page."""
        statement = (
            select(func.count())
            .select_from(PolicyVersion)
            .where(PolicyVersion.policy_id == policy.id)
            .where(PolicyVersion.organization_id == self.organization_id)
        )
        return int(self.execute(statement).scalar_one())

    def conditions_of(self, policy: Policy, version: PolicyVersion) -> tuple[PolicyCondition, ...]:
        """One stored version's conditions, validated back into the language.

        A row this build cannot interpret raises here, naming the policy and the
        version — the same contract as :meth:`definition_of`, because a history
        entry that cannot be read is exactly as much of a deployment defect as a
        current version that cannot be read.
        """
        return conditions_from_stored(
            version.conditions,
            source=f"policy {policy.name!r} version {version.version}",
        )

    # ── Writes ───────────────────────────────────────────────────────────────

    def create(
        self,
        *,
        name: str,
        description: str,
        resource: Resource | str,
        action: Action | str,
        effect: PolicyEffect | str,
        priority: int,
        conditions: Sequence[PolicyCondition] | Sequence[dict[str, Any]],
        status: PolicyStatus | str,
    ) -> Policy:
        """Create a policy and its first version, in one unit of work.

        Both rows or neither: a policy with no version is a policy nobody can
        evaluate, and a version with no policy is unreachable. The whole definition
        is validated before anything is staged, so an invalid policy is refused
        rather than stored in a broken state.

        The two rows are written in dependency order inside one transaction — the
        policy first, so the database can give it the identifier its version will
        carry — and the caller never sees the intermediate state.
        """
        resolved_status = validate_initial_status(status)
        validated = validate_conditions(conditions)
        validate_definition(
            resource=resource,
            action=action,
            effect=effect,
            priority=priority,
            conditions=validated,
            status=resolved_status,
        )
        resolved_resource, resolved_action = validate_target(resource, action)

        with self.writing():
            policy = Policy(
                organization_id=self.organization_id,
                name=normalize_name(name),
                description=normalize_description(description),
                status=resolved_status.value,
                current_version=1,
            )
            self.session.add(policy)
            self._flush()
            self.session.add(
                PolicyVersion(
                    policy_id=policy.id,
                    organization_id=self.organization_id,
                    version=1,
                    effect=validate_effect(effect).value,
                    resource=resolved_resource.value,
                    action=resolved_action.value,
                    priority=validate_priority(priority),
                    conditions=[condition.as_payload() for condition in validated],
                )
            )
            self._flush()
            self.session.commit()
            # After the commit, not before: the primary key and the timestamps are
            # written by the database, and the caller should get back the row that
            # exists — with the version it points at.
            self.session.refresh(policy)
        return policy

    def update_metadata(
        self,
        policy: Policy,
        *,
        name: str | None = None,
        description: str | None = None,
    ) -> list[str]:
        """Change the label and the rationale. Returns the fields that changed.

        Neither is part of a version: a name is what a person calls the policy, and
        a description is why they wrote it. Renaming a policy does not change what
        it does, so it does not create a version — while editing its *definition*
        always does, because that is what a recorded decision was made from.
        """
        changed: list[str] = []
        if name is not None:
            normalized_name = normalize_name(name)
            if normalized_name != policy.name:
                policy.name = normalized_name
                changed.append("name")
        if description is not None:
            normalized_description = normalize_description(description)
            if normalized_description != policy.description:
                policy.description = normalized_description
                changed.append("description")
        if not changed:
            return []
        with self.writing():
            self._flush()
            self.session.commit()
            self.session.refresh(policy)
        return changed

    def publish_version(
        self,
        policy: Policy,
        *,
        resource: Resource | str,
        action: Action | str,
        effect: PolicyEffect | str,
        priority: int,
        conditions: Sequence[PolicyCondition] | Sequence[dict[str, Any]],
    ) -> PolicyDefinition:
        """Append the next version of ``policy``'s definition and point the policy at it.

        Append-only: the previous version stays exactly as it was, so a decision
        recorded against it can still be read back. The new definition is validated
        first, so publishing cannot be the step that lets something malformed into
        the record.

        An edit that changes nothing appends nothing. A client that sends the
        definition it already has is not making a change, and a version number is
        what a decision is attributed to — so inflation here would make the history
        harder to read and the attribution harder to check, for no gain. The current
        definition is returned either way, which is what lets the caller tell the two
        cases apart (:meth:`set_status` does the same for a repeated activation).
        """
        validated = validate_conditions(conditions)
        validate_definition(
            resource=resource,
            action=action,
            effect=effect,
            priority=priority,
            conditions=validated,
        )
        resolved_resource, resolved_action = validate_target(resource, action)
        resolved_effect = validate_effect(effect)
        resolved_priority = validate_priority(priority)

        current = self.definition_of(policy)
        if (
            resolved_resource,
            resolved_action,
            resolved_effect,
            resolved_priority,
            validated,
        ) == (
            current.resource,
            current.action,
            current.effect,
            current.priority,
            current.conditions,
        ):
            return current

        with self.writing():
            self.session.add(
                PolicyVersion(
                    policy_id=policy.id,
                    organization_id=self.organization_id,
                    version=policy.current_version + 1,
                    effect=resolved_effect.value,
                    resource=resolved_resource.value,
                    action=resolved_action.value,
                    priority=resolved_priority,
                    conditions=[condition.as_payload() for condition in validated],
                )
            )
            policy.current_version = policy.current_version + 1
            self._flush()
            self.session.commit()
            # An explicit refresh, because sessions here do not expire on commit:
            # without it the version loaded before the write would still be attached
            # to the policy, and the caller would be handed the definition it just
            # replaced.
            self.session.refresh(policy)
        return self.definition_of(policy)

    def set_status(self, policy: Policy, status: PolicyStatus | str) -> bool:
        """Move a policy through its lifecycle. Returns whether anything changed.

        A move the lifecycle table does not allow is a :class:`ConflictError`, not a
        validation failure: the request was well formed and the record says no — the
        same answer the inventory and the registry give for an impossible move.

        Activation passes an extra gate: the *stored* definition is re-validated
        before the status changes, so a policy this build cannot evaluate cannot be
        put into force even if it reached the table another way.
        """
        target = validate_status(status)
        try:
            validate_transition(policy.status, target)
        except ValueError as exc:
            raise ConflictError(str(exc)) from exc
        if policy.status == target.value:
            # Already there: an activation a client retries is a no-op, not an error.
            return False

        if target is PolicyStatus.ACTIVE:
            # Re-read the stored definition rather than trusting the request: what
            # matters is what the record says, not what someone believed it said.
            #
            # A definition this build cannot evaluate is refused as a *conflict*
            # rather than as a malformed request: the request ("activate this") is
            # fine, and the record is what cannot be brought into force. That is also
            # why the failure is not translated into a 4xx-and-forget: the message
            # names what could not be read, and the policy stays out of force.
            try:
                self.definition_of(policy)
            except PolicyDefinitionError as exc:
                raise ConflictError(f"this policy cannot be activated: {exc}") from exc

        with self.writing():
            policy.status = target.value
            self._flush()
            self.session.commit()
            self.session.refresh(policy)
        return True

    def delete(self, policy: Policy) -> None:
        """Remove a policy and, by cascade, its version history.

        A hard delete, like the inventory's: the row *is* the record, and a retained
        "deleted" policy would have to be filtered out by every reader. The caller
        emits the domain event before this runs, so the removal stays observable.
        Retiring is the non-destructive alternative — it keeps the record and stops
        evaluation — and the API documents that choice.

        An explicit, tenant-filtered ``DELETE`` rather than ``session.delete``: the
        statement itself carries the organization boundary, so the row is removed
        only if it belongs to this repository's tenant — the same rule every read
        here obeys, applied to the write that cannot be undone.
        """
        with self.writing():
            self.session.execute(
                delete(Policy)
                .where(Policy.id == policy.id)
                .where(Policy.organization_id == self.organization_id)
            )
            self.session.commit()

    # ── Internals ────────────────────────────────────────────────────────────

    def _filtered(
        self,
        statement: Select[Any],
        *,
        statuses: Sequence[PolicyStatus | str] | None = None,
        effects: Sequence[PolicyEffect | str] | None = None,
        resources: Sequence[Resource | str] | None = None,
        actions: Sequence[Action | str] | None = None,
    ) -> Select[Any]:
        """Join the current version and apply the listing filters.

        The join is a plain ``JOIN`` (not a left join): a policy always has a
        current version — the two are written together — so a policy without one is
        a defect, and it should be visible rather than silently listed as if it had
        an empty definition.
        """
        statement = statement.join(PolicyVersion, _current_version_join())
        if statuses:
            statement = statement.where(
                Policy.status.in_([validate_status(value).value for value in statuses])
            )
        if effects:
            statement = statement.where(
                PolicyVersion.effect.in_([validate_effect(value).value for value in effects])
            )
        if resources:
            statement = statement.where(
                PolicyVersion.resource.in_([resolve_resource(value).value for value in resources])
            )
        if actions:
            statement = statement.where(
                PolicyVersion.action.in_([resolve_action(value).value for value in actions])
            )
        return statement

    def _definition(self, policy: Policy) -> PolicyDefinition:
        """Validate the current version of ``policy`` into an evaluable definition.

        Raises :class:`~aicore_api.core.policy.PolicyDefinitionError` when the stored
        row is not something this build can interpret. That is deliberate:
        evaluation must never quietly skip a policy, because skipping a deny is
        permitting the action.
        """
        row = policy.current_version_row
        if row is None:  # pragma: no cover - the join guarantees a current version
            raise PolicyDefinitionError(
                f"policy {policy.name!r} points at version {policy.current_version}, "
                "which does not exist"
            )
        resolved_resource, resolved_action = validate_target(row.resource, row.action)
        return PolicyDefinition(
            policy_id=policy.id,
            name=policy.name,
            version=row.version,
            priority=validate_priority(row.priority),
            effect=validate_effect(row.effect),
            resource=resolved_resource,
            action=resolved_action,
            conditions=conditions_from_stored(
                row.conditions, source=f"policy {policy.name!r} version {row.version}"
            ),
        )

    def _flush(self) -> None:
        """Flush, translating a constraint violation into the domain error it means."""
        try:
            self.session.flush()
        except IntegrityError as exc:
            self.session.rollback()
            raise _translate_integrity_error(exc) from exc
