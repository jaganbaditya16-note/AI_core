"""Explicit authorization vocabulary for AICore.

Permissions are closed, reviewable capabilities. Incident management and human
approval are separate from action execution: approval never grants execution by
itself; the existing firewall remains the final enforcement point.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from enum import StrEnum
from types import MappingProxyType

__all__ = [
    "RESOURCE_ACTIONS", "ROLE_INTENTS", "ROLE_PERMISSIONS", "Action", "Permission",
    "Resource", "RoleCode", "UnknownPermissionError", "all_permissions",
    "parse_permission_code", "permissions_for", "permissions_for_resource",
    "role_holds", "sort_permissions",
]

PERMISSION_CODE_PATTERN = r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$"
PERMISSION_CODE_SEGMENTS = 2

class UnknownPermissionError(ValueError):
    """A permission code outside the closed vocabulary."""

class Resource(StrEnum):
    ORGANIZATION = "organization"
    USER = "user"
    ROLE = "role"
    AUDIT = "audit"
    SECURITY = "security"
    ASSET = "asset"
    AGENT = "agent"
    POLICY = "policy"
    ACTION = "action"
    INCIDENT = "incident"

class Action(StrEnum):
    READ = "read"
    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"
    MANAGE = "manage"
    EXECUTE = "execute"
    APPROVE = "approve"

def parse_permission_code(code: str) -> tuple[Resource, Action]:
    if not isinstance(code, str):
        raise UnknownPermissionError(f"permission code must be a string, got {type(code).__name__}")
    parts = code.split(".")
    if len(parts) != PERMISSION_CODE_SEGMENTS:
        raise UnknownPermissionError(f"{code!r} is not a resource.action permission code")
    try:
        resource = Resource(parts[0])
        action = Action(parts[1])
    except ValueError as exc:
        raise UnknownPermissionError(f"{code!r} uses an unknown resource or action") from exc
    return resource, action

class Permission(StrEnum):
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
    ACTION_APPROVE = "action.approve"
    INCIDENT_READ = "incident.read"
    INCIDENT_CREATE = "incident.create"
    INCIDENT_UPDATE = "incident.update"

    @classmethod
    def parse(cls, code: str) -> "Permission":
        parse_permission_code(code)
        try:
            return cls(code)
        except ValueError as exc:
            raise UnknownPermissionError(f"{code!r} is not declared by this build") from exc

    @property
    def resource(self) -> Resource:
        return parse_permission_code(self.value)[0]

    @property
    def action(self) -> Action:
        return parse_permission_code(self.value)[1]

class RoleCode(StrEnum):
    OWNER = "owner"
    ADMIN = "admin"
    SECURITY_ADMIN = "security_admin"
    AI_ADMIN = "ai_admin"
    ANALYST = "analyst"
    VIEWER = "viewer"

ROLE_PERMISSIONS: Mapping[RoleCode, frozenset[Permission]] = MappingProxyType({
    RoleCode.OWNER: frozenset(Permission),
    RoleCode.ADMIN: frozenset({
        Permission.ORGANIZATION_READ, Permission.ORGANIZATION_UPDATE,
        Permission.USER_READ, Permission.USER_MANAGE, Permission.ROLE_READ,
        Permission.ASSET_READ, Permission.ASSET_CREATE, Permission.ASSET_UPDATE,
        Permission.ASSET_DELETE, Permission.AGENT_READ, Permission.AGENT_CREATE,
        Permission.AGENT_UPDATE, Permission.AGENT_DELETE, Permission.POLICY_READ,
        Permission.POLICY_CREATE, Permission.POLICY_UPDATE, Permission.POLICY_DELETE,
        Permission.ACTION_EXECUTE, Permission.INCIDENT_READ,
    }),
    RoleCode.SECURITY_ADMIN: frozenset({
        Permission.ORGANIZATION_READ, Permission.USER_READ, Permission.AUDIT_READ,
        Permission.SECURITY_READ, Permission.ASSET_READ, Permission.ASSET_UPDATE,
        Permission.AGENT_READ, Permission.AGENT_UPDATE, Permission.POLICY_READ,
        Permission.POLICY_CREATE, Permission.POLICY_UPDATE, Permission.ACTION_EXECUTE,
        Permission.ACTION_APPROVE, Permission.INCIDENT_READ, Permission.INCIDENT_CREATE,
        Permission.INCIDENT_UPDATE,
    }),
    RoleCode.AI_ADMIN: frozenset({
        Permission.ORGANIZATION_READ, Permission.USER_READ, Permission.ASSET_READ,
        Permission.ASSET_CREATE, Permission.ASSET_UPDATE, Permission.AGENT_READ,
        Permission.AGENT_CREATE, Permission.AGENT_UPDATE,
    }),
    RoleCode.ANALYST: frozenset({
        Permission.ORGANIZATION_READ, Permission.SECURITY_READ, Permission.ASSET_READ,
        Permission.AGENT_READ, Permission.INCIDENT_READ,
    }),
    RoleCode.VIEWER: frozenset({Permission.ORGANIZATION_READ, Permission.ASSET_READ, Permission.AGENT_READ}),
})

ROLE_INTENTS: Mapping[RoleCode, str] = MappingProxyType({
    RoleCode.OWNER: "Full organization administration, including security review.",
    RoleCode.ADMIN: "General organization administration.",
    RoleCode.SECURITY_ADMIN: "Security operations, incident management and human approval.",
    RoleCode.AI_ADMIN: "AI asset and agent administration without execution authority.",
    RoleCode.ANALYST: "Read and analyse AI security information and incidents.",
    RoleCode.VIEWER: "Read-only access to permitted inventory.",
})

RESOURCE_ACTIONS: Mapping[Resource, frozenset[Action]] = MappingProxyType({
    resource: frozenset(permission.action for permission in Permission if permission.resource is resource)
    for resource in Resource
})

def permissions_for(role: RoleCode | str) -> frozenset[Permission]:
    try:
        code = RoleCode(role)
    except ValueError as exc:
        raise UnknownPermissionError(f"unknown role {role!r}") from exc
    return ROLE_PERMISSIONS[code]

def permissions_for_resource(role: RoleCode | str, resource: Resource) -> frozenset[Permission]:
    return frozenset(p for p in permissions_for(role) if p.resource is resource)

def role_holds(role: RoleCode | str, permission: Permission | str) -> bool:
    try:
        p = Permission(permission)
    except ValueError:
        return False
    return p in permissions_for(role)

def all_permissions() -> frozenset[Permission]:
    return frozenset(Permission)

def sort_permissions(permissions: Iterable[Permission | str]) -> tuple[Permission, ...]:
    normalized = {Permission(p) for p in permissions}
    return tuple(sorted(normalized, key=lambda p: p.value))
