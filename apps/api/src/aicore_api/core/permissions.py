"""Roles and permissions — the vocabulary authorization is written in.

Two rules shape this module:

1. **Permissions are explicit.** Authorization code asks "does this membership
   hold ``user.manage``?", never "is this user an ADMIN?". Role names are labels
   for humans; permissions are what the backend enforces. A role whose meaning
   changes is a data change in one place, not a hunt through route handlers.

2. **A role is a set of permissions, declared once.** :data:`ROLE_PERMISSIONS` is
   the single source of truth: the migration that seeds the database is asserted
   against it (``tests/test_authorization.py``), so the catalog in code and the
   catalog in PostgreSQL cannot drift apart.

Phase 5 makes the *shape* of a permission explicit. A permission identifier is
``resource.action`` — :class:`Permission` → :class:`Resource` + :class:`Action` —
and both halves are closed vocabularies declared here:

    identity → resource → action → permission → authorization decision

:func:`parse_permission_code` is the only door into that vocabulary, and it
refuses anything that is not a declared ``resource.action`` pair, so a typo or an
invented code cannot travel through the system as an authorization requirement.
The three vocabularies are cross-checked by tests
(``tests/test_permissions.py``): every catalog code parses, every resource and
action is used by at least one permission, and no code exists outside them.

Two resources the phase description names have no namespace of their own, and
that is deliberate: **membership** is governed by ``user.read`` / ``user.manage``
(Phase 2 chose those codes for the member directory and the membership lifecycle)
and the **permission catalog** is read through ``role.read`` (a permission only
means something as part of a role). Renaming a permission code is a migration —
codes are stored in the database, published by the API and asserted by tests — so
Phase 5 documents the mapping instead of churning it.

Scope discipline: the permissions below are exactly those the application can
enforce today — the Phase 2 foundation (organization, membership, role and
read-only oversight), the Phase 3 AI asset inventory, the Phase 4 agent registry,
the Phase 6 policy record and, with Phase 7, the action firewall. Permissions for
agent execution, approvals and incidents are **not** declared yet: they belong to
the phases that implement the resources behind them. A permission with nothing to
guard would be a claim, not a control, and this table would become a document of
intentions rather than a description of the system. There is deliberately no
``agent.execute``, ``agent.suspend``, ``agent.approve``, ``agent.control``,
``policy.execute``, ``policy.approve`` or ``firewall.block``: registering an agent
is not the same capability as running one, writing a policy is not the same
capability as enforcing it, and the one capability Phase 7 adds is the narrowest
one that describes what it does — *run one registered action through the firewall*
(``action.execute``), not "do anything to anything".

Phase 6 adds one resource, and four actions on it. ``policy.read`` /
``policy.create`` / ``policy.update`` / ``policy.delete`` guard the policy record
itself. There is deliberately **no** ``policy.evaluate``: evaluating policies is a
read of them — it stores nothing, changes nothing, and reveals nothing a
``policy.read`` holder cannot already read — so a separate permission for it would
be privilege with no boundary behind it. Enforcement, when it arrives, needs a
permission of its own; that is Phase 7's decision, not this one's.

Phase 7 makes it. The action firewall runs *registered actions* — a closed,
code-level catalogue with one entry — and the capability that guards it is
``action.execute``: a new resource (``action``, the action registry) with one
action on it (``execute``). It is deliberately not ``agent.execute``, which would
claim the ability to run an agent (a later phase's capability, not this one's), and
not a wildcard of any kind. Every other action on the ``action`` resource —
``approve``, ``kill``, ``block``, ``read`` — is absent, because this build can do
none of them. Because a permission is also a *policy target*, ``action.execute`` is
the pair an organization writes a policy against when it wants to constrain what
its members may execute.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from enum import StrEnum
from types import MappingProxyType

__all__ = [
    "RESOURCE_ACTIONS",
    "ROLE_INTENTS",
    "ROLE_PERMISSIONS",
    "Action",
    "Permission",
    "Resource",
    "RoleCode",
    "UnknownPermissionError",
    "all_permissions",
    "parse_permission_code",
    "permissions_for",
    "permissions_for_resource",
    "role_holds",
    "sort_permissions",
]


#: The shape a permission code must have. Identical to the ``CHECK`` constraint on
#: ``aicore.permissions.code`` (asserted equal to the model's pattern by
#: ``tests/test_permissions.py``), so the vocabulary and the database agree on what
#: a code *is* rather than only on which codes exist.
PERMISSION_CODE_PATTERN = r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$"

#: Every code in this build has exactly two segments (``resource.action``). Kept
#: separate from the pattern above because the database is more permissive on
#: purpose: a future phase may introduce a three-segment code in a reviewed
#: migration, while *this* build must not silently accept one it cannot classify.
PERMISSION_CODE_SEGMENTS = 2


class UnknownPermissionError(ValueError):
    """A string that is not a permission this build knows.

    A ``ValueError`` so that callers which already treat catalog mistakes as
    value errors keep working, and a distinct class so that "this code is not in
    the vocabulary" cannot be confused with "this role is unknown".
    """


class Resource(StrEnum):
    """The resource half of a permission: what the capability governs.

    A closed vocabulary, and deliberately a small one: only resources that exist
    *and* have a permission guarding them appear here. ``policy`` arrived with
    Phase 6, because there is now a policy record to guard; ``incident``, ``tool``,
    ``firewall`` and the rest of the roadmap are absent because declaring a
    resource nobody can act on would turn this table into a document of
    intentions — the same rule the permission list itself follows.
    """

    ORGANIZATION = "organization"
    USER = "user"
    ROLE = "role"
    AUDIT = "audit"
    SECURITY = "security"
    ASSET = "asset"
    AGENT = "agent"
    POLICY = "policy"
    #: The action registry itself: the closed catalogue of actions this build can
    #: run. Phase 7 added it, together with :attr:`Action.EXECUTE`.
    ACTION = "action"


class Action(StrEnum):
    """The action half of a permission: what may be done to the resource.

    Only the actions this build can perform. ``execute`` arrived with Phase 7, and
    it means one narrow thing: *run one action from the registered catalogue through
    the action firewall*. There is still no ``approve``, ``block``, ``intercept`` or
    ``kill``, and still no way to start, stop or control an agent at runtime — an
    action vocabulary that listed those would advertise enforcement that does not
    exist.
    """

    READ = "read"
    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"
    MANAGE = "manage"
    EXECUTE = "execute"


def parse_permission_code(code: str) -> tuple[Resource, Action]:
    """Split ``code`` into its resource and action, or refuse it.

    This is the vocabulary's single entry point: a code that is not
    ``resource.action`` over *known* halves raises
    :class:`UnknownPermissionError` instead of travelling into an authorization
    check. Whether the pair is a permission this build actually declares is
    :meth:`Permission.parse`'s stricter question.
    """
    if not isinstance(code, str):
        raise UnknownPermissionError(f"permission code must be a string, got {type(code).__name__}")
    segments = code.split(".")
    if len(segments) != PERMISSION_CODE_SEGMENTS:
        raise UnknownPermissionError(
            f"{code!r} is not a permission code: expected exactly "
            f"{PERMISSION_CODE_SEGMENTS} segments (resource.action)"
        )
    resource_code, action_code = segments
    try:
        resource = Resource(resource_code)
    except ValueError as exc:
        raise UnknownPermissionError(
            f"{code!r} names an unknown resource {resource_code!r}"
        ) from exc
    try:
        action = Action(action_code)
    except ValueError as exc:
        raise UnknownPermissionError(f"{code!r} names an unknown action {action_code!r}") from exc
    return resource, action


class Permission(StrEnum):
    """A capability a membership can be granted.

    Values are stable identifiers: they appear in API responses, in the database
    seed, and eventually in audit records. Renaming one is a migration.
    """

    ORGANIZATION_READ = "organization.read"
    ORGANIZATION_UPDATE = "organization.update"
    USER_READ = "user.read"
    USER_MANAGE = "user.manage"
    ROLE_READ = "role.read"
    ROLE_MANAGE = "role.manage"
    AUDIT_READ = "audit.read"
    SECURITY_READ = "security.read"
    ASSET_READ = "asset.read"
    ASSET_CREATE = "asset.create"
    ASSET_UPDATE = "asset.update"
    ASSET_DELETE = "asset.delete"
    AGENT_READ = "agent.read"
    AGENT_CREATE = "agent.create"
    AGENT_UPDATE = "agent.update"
    AGENT_DELETE = "agent.delete"
    POLICY_READ = "policy.read"
    POLICY_CREATE = "policy.create"
    POLICY_UPDATE = "policy.update"
    POLICY_DELETE = "policy.delete"
    ACTION_EXECUTE = "action.execute"

    @classmethod
    def parse(cls, code: str) -> Permission:
        """The declared permission ``code`` names, or :class:`UnknownPermissionError`.

        Stricter than :func:`parse_permission_code`: ``policy.read`` is a
        well-formed ``resource.action`` pair, but this build declares no such
        permission, so it is refused rather than accepted as a future code.
        """
        parse_permission_code(code)
        try:
            return cls(code)
        except ValueError as exc:
            raise UnknownPermissionError(
                f"{code!r} is not a permission this build declares"
            ) from exc

    @property
    def resource(self) -> Resource:
        """What this permission governs (``agent.update`` → :attr:`Resource.AGENT`)."""
        return parse_permission_code(self.value)[0]

    @property
    def action(self) -> Action:
        """What it allows (``agent.update`` → :attr:`Action.UPDATE`)."""
        return parse_permission_code(self.value)[1]


class RoleCode(StrEnum):
    """The roles an organization member can hold.

    Extensible by adding a code here together with the seeded row and grants in
    the migration that introduces it. :func:`permissions_for` refuses anything it
    does not know, so an unknown role never resolves silently to "no
    permissions" — or, worse, to "all permissions".
    """

    OWNER = "owner"
    ADMIN = "admin"
    SECURITY_ADMIN = "security_admin"
    AI_ADMIN = "ai_admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


#: The role model. Every role's permissions are listed literally — no role is
#: computed from another — so reading this table is reading the whole policy.
#:
#: - OWNER          — full organization administration.
#: - ADMIN          — general administration, stopping short of ``role.manage``
#:                    (deciding who may do what is an ownership decision) and of
#:                    the security/audit reads (oversight is not administration).
#:                    It administers the policy record in full, and with Phase 7
#:                    it may run a registered action through the firewall:
#:                    operating what the organization has is administration's job.
#: - SECURITY_ADMIN — security posture, the audit trail, and *recording* a
#:                    containment decision in the inventory (it may read and
#:                    update assets; it may not create or delete records).
#:                    Enforcing containment at runtime is a later phase with its
#:                    own permission — the inventory state is a record, not an
#:                    action. The registry follows the same rule: it reads agents
#:                    and may record a lifecycle change, but it does not create
#:                    or delete identities. Phase 6 makes one deliberate
#:                    exception for the policy record: writing a policy *is*
#:                    recording a containment decision (a deny, a threshold, an
#:                    approval requirement), which is this role's job — so it may
#:                    read, create and update policies, while deleting one stays
#:                    with the owner and the administrator, exactly as deleting
#:                    an asset or an agent does. Phase 7 adds ``action.execute``:
#:                    examining a posture by running a registered, read-only
#:                    assessment is this role's work, and a policy may still deny
#:                    it, or require an approval, by context.
#: - AI_ADMIN       — AI asset and agent administration: registers agents and
#:                    maintains their records and versions, but does not delete
#:                    them (removing an identity is an administrative decision,
#:                    not a stewardship one). It holds no policy permission and no
#:                    ``action.execute``, on purpose: the parties whose work a
#:                    policy constrains do not write the constraint *or* run the
#:                    actions it governs, and an AI administrator that governs
#:                    itself is not governed.
#: - ANALYST        — reads and analyses security information; no management
#:                    permission at all. Policies are governance configuration, and
#:                    reading them is neither reading AI inventory nor analysing
#:                    findings, so an analyst holds none.
#: - VIEWER         — read-only access to what it is granted, and nothing else.
ROLE_PERMISSIONS: Mapping[RoleCode, frozenset[Permission]] = MappingProxyType(
    {
        # Every permission, by construction: OWNER is the role that can do
        # anything inside the organization it owns.
        RoleCode.OWNER: frozenset(Permission),
        RoleCode.ADMIN: frozenset(
            {
                Permission.ORGANIZATION_READ,
                Permission.ORGANIZATION_UPDATE,
                Permission.USER_READ,
                Permission.USER_MANAGE,
                Permission.ROLE_READ,
                Permission.ASSET_READ,
                Permission.ASSET_CREATE,
                Permission.ASSET_UPDATE,
                Permission.ASSET_DELETE,
                Permission.AGENT_READ,
                Permission.AGENT_CREATE,
                Permission.AGENT_UPDATE,
                Permission.AGENT_DELETE,
                Permission.POLICY_READ,
                Permission.POLICY_CREATE,
                Permission.POLICY_UPDATE,
                Permission.POLICY_DELETE,
                Permission.ACTION_EXECUTE,
            }
        ),
        RoleCode.SECURITY_ADMIN: frozenset(
            {
                Permission.ORGANIZATION_READ,
                Permission.USER_READ,
                Permission.AUDIT_READ,
                Permission.SECURITY_READ,
                Permission.ASSET_READ,
                Permission.ASSET_UPDATE,
                Permission.AGENT_READ,
                Permission.AGENT_UPDATE,
                Permission.POLICY_READ,
                Permission.POLICY_CREATE,
                Permission.POLICY_UPDATE,
                Permission.ACTION_EXECUTE,
            }
        ),
        RoleCode.AI_ADMIN: frozenset(
            {
                Permission.ORGANIZATION_READ,
                Permission.USER_READ,
                Permission.ASSET_READ,
                Permission.ASSET_CREATE,
                Permission.ASSET_UPDATE,
                Permission.AGENT_READ,
                Permission.AGENT_CREATE,
                Permission.AGENT_UPDATE,
            }
        ),
        RoleCode.ANALYST: frozenset(
            {
                Permission.ORGANIZATION_READ,
                Permission.SECURITY_READ,
                Permission.ASSET_READ,
                Permission.AGENT_READ,
            }
        ),
        RoleCode.VIEWER: frozenset(
            {
                Permission.ORGANIZATION_READ,
                Permission.ASSET_READ,
                Permission.AGENT_READ,
            }
        ),
    }
)

#: One-line description of what each role is for, shown in the API and in docs.
ROLE_INTENTS: Mapping[RoleCode, str] = MappingProxyType(
    {
        RoleCode.OWNER: "Full organization administration, including roles.",
        RoleCode.ADMIN: "General organization administration.",
        RoleCode.SECURITY_ADMIN: "Security posture, audit trail and containment.",
        RoleCode.AI_ADMIN: "AI asset and AI platform administration.",
        RoleCode.ANALYST: "Read and analyse AI and security information.",
        RoleCode.VIEWER: "Read-only access to permitted resources.",
    }
)


#: Which actions each resource currently supports, derived from the catalog below
#: rather than declared separately — so a resource cannot advertise an action no
#: permission implements, and a new permission cannot be forgotten here. Read it as
#: the answer to "what can be done to this resource *today*".
RESOURCE_ACTIONS: Mapping[Resource, frozenset[Action]] = MappingProxyType(
    {
        resource: frozenset(
            permission.action for permission in Permission if permission.resource is resource
        )
        for resource in Resource
    }
)


def permissions_for_resource(resource: Resource | str) -> tuple[Permission, ...]:
    """Every permission that governs ``resource``, in declaration order.

    An unknown resource raises, for the same reason an unknown role does: a lookup
    that silently resolves to nothing looks like a resource nobody may touch.
    """
    try:
        resolved = Resource(resource)
    except ValueError as exc:
        raise ValueError(f"unknown resource {resource!r}") from exc
    return tuple(permission for permission in Permission if permission.resource is resolved)


def permissions_for(role: RoleCode | str) -> frozenset[Permission]:
    """The permissions ``role`` grants.

    An unknown role raises rather than resolving to an empty or full set: a
    lookup that silently succeeds on bad input is how a typo becomes a
    permission bug.
    """
    try:
        resolved = RoleCode(role)
    except ValueError as exc:
        raise ValueError(f"unknown role {role!r}") from exc
    return ROLE_PERMISSIONS[resolved]


def all_permissions() -> tuple[Permission, ...]:
    """Every permission, in a stable order (declaration order of the enum)."""
    return tuple(Permission)


def role_holds(role: RoleCode | str, permission: Permission) -> bool:
    """Whether ``role`` grants ``permission``. The whole authorization question."""
    return permission in permissions_for(role)


def sort_permissions(permissions: Iterable[Permission | str]) -> list[str]:
    """Permission codes in a deterministic order, for API responses and tests."""
    return sorted({str(permission) for permission in permissions})
