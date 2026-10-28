"""The policy record: what an organization's policies say, and what they used to say.

Two tables, and the split is the point.

``policies`` is the **identity and the life** of a policy: what it is called, why it
exists, whether it is in force, and which of its versions is current. It is
tenant-owned (``TenantOwnedMixin``), because a policy is an organization's own
governance decision — there is deliberately no global or shared policy in this
phase, and no way to write one: every row carries a mandatory ``organization_id``
that the isolation guard refuses to let anyone forget.

``policy_versions`` is the **definition**, in full: the target, the effect, the
priority and the conditions, one row per version, **append-only**. Editing a policy
never rewrites a version; it adds one and moves ``policies.current_version``
forward. That is what makes a recorded decision explainable — a decision names
``policy_id`` and ``policy_version``, and the row those name still says exactly what
it said when the decision was made. There is no update path for a version, in this
code or in the API, and no ``updated_at`` column, because a column nothing can
change would be a lie about the schema.

Three structural choices are worth reading before changing this file:

- **A version cannot belong to another organization's policy.**
  ``(organization_id, policy_id)`` references ``policies(organization_id, id)``, so
  a cross-tenant version is unrepresentable rather than merely rejected — the same
  composite-key technique ``agents`` and ``assets`` use. That reference needs
  ``uq_policies_organization_id_id``, which the migration adds on purpose, since
  PostgreSQL can only point a foreign key at a unique set of columns.
- **Deleting a policy deletes its history, and deleting an organization deletes
  nothing.** ``policy_versions`` cascades from ``policies`` (a version whose policy
  is gone is unreachable, so it is an orphan), while ``policies`` itself is
  ``ON DELETE RESTRICT`` from ``organizations`` — removing a tenant is an explicit
  operational procedure, never a side effect.
- **The database enforces the simple invariants and the code enforces the
  vocabulary.** Shape and size of the conditions, bounds on priority, and the
  closed sets of status, effect, resource and action are ``CHECK`` constraints, so
  no writer — migration, data fix, psql — can store a shape the schema does not
  allow. The *semantics* (which operator applies to which field, which values a
  field takes, which targets exist as permissions) live in
  :mod:`aicore_api.core.policy`, are validated on the way in and again on the way
  out, and are asserted equal to these constraint sets by tests. Splitting it that
  way keeps the schema honest without turning a JSONB column into a second,
  unreadable implementation of the language.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKeyConstraint,
    Index,
    Integer,
    String,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PostgreSQLUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from aicore_api.core.permissions import Resource
from aicore_api.core.policy import (
    MAX_CONDITIONS,
    POLICY_DESCRIPTION_MAX_LENGTH,
    POLICY_NAME_MAX_LENGTH,
    POLICY_TARGETS,
    PRIORITY_MAX,
    PRIORITY_MIN,
    PolicyEffect,
    PolicyStatus,
)
from aicore_api.db.base import (
    APP_SCHEMA,
    Base,
    TenantOwnedMixin,
    TimestampMixin,
    UUIDPrimaryKeyMixin,
)

__all__ = [
    "POLICIES_TABLE_COMMENT",
    "POLICY_STATUS_MAX_LENGTH",
    "POLICY_VERSIONS_TABLE_COMMENT",
    "Policy",
    "PolicyVersion",
]

#: Enum-ish columns, ``VARCHAR`` + ``CHECK`` as everywhere else in this schema: a
#: new effect or status stays an ordinary transactional migration, and PostgreSQL
#: still refuses a value the application does not know.
POLICY_STATUS_MAX_LENGTH = 16
POLICY_EFFECT_MAX_LENGTH = 32
POLICY_RESOURCE_MAX_LENGTH = 32
POLICY_ACTION_MAX_LENGTH = 16

POLICIES_TABLE_COMMENT = (
    "Organization policies: the identity, rationale and lifecycle of one policy, "
    "pointing at its current version. Tenant-owned; a policy belongs to exactly "
    "one organization."
)
POLICY_VERSIONS_TABLE_COMMENT = (
    "Append-only policy definitions: target, effect, priority and conditions, one "
    "row per version. A published version is never edited, so a recorded decision "
    "that names a version can always be read back."
)


def resource_values() -> str:
    """The policy-target resources, as the literal list a ``CHECK`` constraint wants.

    Derived from the permission vocabulary rather than written out, so the
    constraint and the targets the code validates against cannot disagree — and so
    that adding a permission is enough to make its resource storable. The migration
    carries its own literals (a migration describes the database at one point in
    time); ``tests/test_policies.py`` compares the two.
    """
    return ", ".join(f"'{resource.value}'" for resource in Resource)


def action_values() -> str:
    """The policy-target actions, as the literal list a ``CHECK`` constraint wants."""
    actions = sorted({action.value for targets in POLICY_TARGETS.values() for action in targets})
    return ", ".join(f"'{action}'" for action in actions)


def _effect_values() -> str:
    return ", ".join(f"'{effect.value}'" for effect in PolicyEffect)


def _status_values() -> str:
    return ", ".join(f"'{status.value}'" for status in PolicyStatus)


#: The target columns carry the *union* of the declared resources and actions,
#: rather than an enumerated list of pairs. A pair such as ``policy.manage`` is
#: therefore refused by the application (``validate_target``) and not by the
#: constraint — deliberately: PostgreSQL can check two small closed sets cheaply,
#: while "this pair is a declared permission" is a fact about the permission
#: catalog, and duplicating that here would be a second copy of it to keep in
#: sync. ``tests/test_policies.py`` asserts both halves, including that the
#: constraint set equals the code vocabulary.
TARGET_RESOURCE_CHECK = f"resource IN ({resource_values()})"
TARGET_ACTION_CHECK = f"action IN ({action_values()})"


class Policy(UUIDPrimaryKeyMixin, TimestampMixin, TenantOwnedMixin, Base):
    """One organization policy, with the version that is currently in force."""

    __tablename__ = "policies"

    #: A human label, unique within the organization. Not an identifier: a policy
    #: is referred to by its id, and the name is what an operator reads in a list.
    name: Mapped[str] = mapped_column(String(POLICY_NAME_MAX_LENGTH), nullable=False)

    #: Why this policy exists. Required, because a policy nobody can explain is a
    #: policy nobody can review — and the reason belongs with the rule, not in a
    #: ticket that outlives its relevance.
    description: Mapped[str] = mapped_column(String(POLICY_DESCRIPTION_MAX_LENGTH), nullable=False)

    #: Where the policy is in its life. Only ``active`` participates in evaluation.
    status: Mapped[str] = mapped_column(
        String(POLICY_STATUS_MAX_LENGTH), nullable=False, server_default=text("'draft'")
    )

    #: Which of this policy's versions is the current definition. Advanced by the
    #: repository in the same transaction that appends the version, so the pointer
    #: and the row it points at cannot disagree.
    current_version: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("1"))

    #: The current definition, loaded with the policy.
    #:
    #: A relationship with an explicit join condition, because the version is not
    #: identified by a foreign key column alone: it is the row whose ``version``
    #: equals ``current_version``. ``viewonly`` because the definition is only ever
    #: written by appending a version, never by editing the relationship.
    current_version_row: Mapped[PolicyVersion | None] = relationship(
        primaryjoin=(
            "and_(Policy.id == foreign(PolicyVersion.policy_id), "
            "Policy.current_version == foreign(PolicyVersion.version))"
        ),
        uselist=False,
        lazy="joined",
        viewonly=True,
    )

    __table_args__ = (
        # One name per policy per organization: two policies with one name would
        # make "the staging guard" ambiguous in every conversation about it — and
        # in every audit record that quotes a name.
        UniqueConstraint("organization_id", "name"),
        # Redundant with the primary key, and added on purpose: PostgreSQL can only
        # point a foreign key at a unique *set* of columns, and
        # ``policy_versions`` references ``(organization_id, id)`` so that a policy
        # and its versions can never belong to different tenants.
        UniqueConstraint("organization_id", "id"),
        CheckConstraint(
            f"char_length(btrim(name)) BETWEEN 1 AND {POLICY_NAME_MAX_LENGTH}",
            name="name_length",
        ),
        CheckConstraint("name = btrim(name)", name="name_normalized"),
        CheckConstraint(
            f"char_length(btrim(description)) BETWEEN 1 AND {POLICY_DESCRIPTION_MAX_LENGTH}",
            name="description_length",
        ),
        CheckConstraint("description = btrim(description)", name="description_normalized"),
        CheckConstraint(f"status IN ({_status_values()})", name="status_valid"),
        CheckConstraint("current_version >= 1", name="current_version_positive"),
        # The evaluation query leads with the tenant and the status, which is also
        # every listing's first filter.
        Index("ix_policies_organization_id_status", "organization_id", "status"),
        {"comment": POLICIES_TABLE_COMMENT},
    )

    def __repr__(self) -> str:
        # The name is a human label an operator chose, not tenant data in the
        # sense that a credential or a person's identity is.
        return (
            f"<Policy id={self.id!s} name={self.name!r} status={self.status!r} "
            f"v{self.current_version}>"
        )


class PolicyVersion(Base):
    """One immutable version of one policy's definition.

    The primary key is ``(policy_id, version)``: a version is identified by the
    policy it belongs to and its number, which is also what makes "no two versions
    of one policy share a number" a property of the schema rather than a rule the
    application remembers.

    There is no ``updated_at``: nothing updates a version. An edit appends the next
    one, which is what lets a decision recorded months ago name the exact definition
    it was made from.
    """

    __tablename__ = "policy_versions"

    policy_id: Mapped[uuid.UUID] = mapped_column(PostgreSQLUUID(as_uuid=True), primary_key=True)
    version: Mapped[int] = mapped_column(Integer, primary_key=True)

    #: Tenant ownership, carried on the version row too. It makes the table
    #: *detectable* as tenant-owned by the isolation guard (which reads the column,
    #: not a registry), and it participates in the composite foreign key below, so a
    #: version row cannot be attached to another organization's policy.
    organization_id: Mapped[uuid.UUID] = mapped_column(
        PostgreSQLUUID(as_uuid=True), nullable=False, index=True
    )

    #: What the policy says when it applies.
    effect: Mapped[str] = mapped_column(String(POLICY_EFFECT_MAX_LENGTH), nullable=False)

    #: What it is about: one ``resource.action`` pair, drawn from the permission
    #: catalog (enforced by the application, constrained to the closed sets here).
    resource: Mapped[str] = mapped_column(String(POLICY_RESOURCE_MAX_LENGTH), nullable=False)
    action: Mapped[str] = mapped_column(String(POLICY_ACTION_MAX_LENGTH), nullable=False)

    #: Ordering within one effect. Bounded so it can be compared and displayed.
    priority: Mapped[int] = mapped_column(Integer, nullable=False)

    #: The conditions, as structured data: an array of
    #: ``{"field", "operator", "value"}`` objects, validated by
    #: :mod:`aicore_api.core.policy` on the way in and on the way out. JSONB because
    #: the shape is a list whose length varies; *not* because anything goes — the
    #: constraints below refuse a scalar, an object and an over-long list, and the
    #: application refuses a field, operator or value that is not in the vocabulary.
    conditions: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB(none_as_null=True), nullable=False
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        # The tenant boundary *and* the composite target, in one constraint: the
        # referenced pair is unique on ``policies`` because the migration adds
        # ``uq_policies_organization_id_id`` before this table.
        ForeignKeyConstraint(
            ["organization_id", "policy_id"],
            [f"{APP_SCHEMA}.policies.organization_id", f"{APP_SCHEMA}.policies.id"],
            ondelete="CASCADE",
        ),
        CheckConstraint("version >= 1", name="version_positive"),
        CheckConstraint(f"effect IN ({_effect_values()})", name="effect_valid"),
        CheckConstraint(TARGET_RESOURCE_CHECK, name="resource_valid"),
        CheckConstraint(TARGET_ACTION_CHECK, name="action_valid"),
        CheckConstraint(
            f"priority BETWEEN {PRIORITY_MIN} AND {PRIORITY_MAX}", name="priority_range"
        ),
        # Structure only: the conditions are an array of at most ``MAX_CONDITIONS``
        # entries. Whether an entry is *valid* is the language's question (see the
        # module docstring), and it is answered by code that both write paths call.
        CheckConstraint("jsonb_typeof(conditions) = 'array'", name="conditions_is_array"),
        CheckConstraint(
            f"jsonb_array_length(conditions) <= {MAX_CONDITIONS}",
            name="conditions_length",
        ),
        # The evaluation query: tenant, then the target, then the ordering hint.
        Index(
            "ix_policy_versions_organization_id_resource_action",
            "organization_id",
            "resource",
            "action",
        ),
        {"comment": POLICY_VERSIONS_TABLE_COMMENT},
    )

    def __repr__(self) -> str:
        return (
            f"<PolicyVersion policy_id={self.policy_id!s} v{self.version} "
            f"{self.effect!r} {self.resource}.{self.action} priority={self.priority}>"
        )
