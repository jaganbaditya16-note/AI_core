"""Closed authorization vocabulary and the Phase 11 least-privilege boundary."""
from __future__ import annotations

import re

import pytest
from sqlalchemy.orm import Session

from aicore_api.core.permissions import (
    PERMISSION_CODE_PATTERN,
    RESOURCE_ACTIONS,
    ROLE_PERMISSIONS,
    Action,
    Permission,
    Resource,
    RoleCode,
    UnknownPermissionError,
    all_permissions,
    parse_permission_code,
    permissions_for,
    permissions_for_resource,
)
from aicore_api.db.models.rbac import CODE_PATTERN as MODEL_CODE_PATTERN
from aicore_api.db.repositories.rbac import RoleCatalog


def test_the_catalog_is_a_validated_resource_action_vocabulary() -> None:
    for permission in Permission:
        resource, action = parse_permission_code(permission.value)
        assert resource is permission.resource
        assert action is permission.action
        assert permission.value.count(".") == 1
        assert re.fullmatch(PERMISSION_CODE_PATTERN, permission.value)


def test_permission_identifiers_are_unique() -> None:
    codes = [permission.value for permission in all_permissions()]
    assert len(codes) == len(set(codes))


def test_every_resource_and_action_is_used_by_the_catalog() -> None:
    assert set(RESOURCE_ACTIONS) == set(Resource)
    used_actions = {action for actions in RESOURCE_ACTIONS.values() for action in actions}
    assert used_actions == set(Action)


def test_permissions_for_resource_is_role_scoped() -> None:
    assert permissions_for_resource(RoleCode.SECURITY_ADMIN, Resource.INCIDENT) == frozenset({
        Permission.INCIDENT_READ,
        Permission.INCIDENT_CREATE,
        Permission.INCIDENT_UPDATE,
    })
    assert permissions_for_resource(RoleCode.SECURITY_ADMIN, Resource.ACTION) == frozenset({
        Permission.ACTION_EXECUTE,
        Permission.ACTION_APPROVE,
    })
    assert permissions_for_resource(RoleCode.AI_ADMIN, Resource.ACTION) == frozenset()


def test_unknown_permission_codes_are_refused() -> None:
    for code in (
        "", "agent", "agent.", ".read", "agent.update.extra", "agent-read",
        "Agent.Read", "agent.Read", "agent.read ", " agent.read", "agent..read",
        "policy.kill", "policy.evaluate", "firewall.block", "tool.invoke",
        "action.kill", "action.block", "action.execute_all", "agent.firewall.block",
    ):
        with pytest.raises(UnknownPermissionError):
            Permission.parse(code)
        with pytest.raises(UnknownPermissionError):
            parse_permission_code(code)


def test_phase11_permission_codes_are_declared_and_parsed() -> None:
    expected = {
        "action.approve": Permission.ACTION_APPROVE,
        "incident.read": Permission.INCIDENT_READ,
        "incident.create": Permission.INCIDENT_CREATE,
        "incident.update": Permission.INCIDENT_UPDATE,
    }
    for code, permission in expected.items():
        assert Permission.parse(code) is permission


def test_only_action_catalogue_has_execute_and_only_action_has_approve() -> None:
    assert {permission.resource for permission in Permission if permission.action is Action.EXECUTE} == {
        Resource.ACTION,
    }
    assert {permission.resource for permission in Permission if permission.action is Action.APPROVE} == {
        Resource.ACTION,
    }


def test_incident_capabilities_are_not_execution_capabilities() -> None:
    assert Permission.INCIDENT_CREATE.action is Action.CREATE
    assert Permission.INCIDENT_READ.action is Action.READ
    assert Permission.INCIDENT_UPDATE.action is Action.UPDATE
    assert Permission.ACTION_APPROVE.resource is Resource.ACTION
    assert Permission.ACTION_APPROVE.action is Action.APPROVE


EXPECTED_ROLE_MATRIX: dict[RoleCode, set[Permission]] = {
    RoleCode.OWNER: set(Permission),
    RoleCode.ADMIN: {
        Permission.ORGANIZATION_READ, Permission.ORGANIZATION_UPDATE,
        Permission.USER_READ, Permission.USER_MANAGE, Permission.ROLE_READ,
        Permission.ASSET_READ, Permission.ASSET_CREATE, Permission.ASSET_UPDATE, Permission.ASSET_DELETE,
        Permission.AGENT_READ, Permission.AGENT_CREATE, Permission.AGENT_UPDATE, Permission.AGENT_DELETE,
        Permission.POLICY_READ, Permission.POLICY_CREATE, Permission.POLICY_UPDATE, Permission.POLICY_DELETE,
        Permission.ACTION_EXECUTE, Permission.INCIDENT_READ,
    },
    RoleCode.SECURITY_ADMIN: {
        Permission.ORGANIZATION_READ, Permission.USER_READ, Permission.AUDIT_READ, Permission.SECURITY_READ,
        Permission.ASSET_READ, Permission.ASSET_UPDATE, Permission.AGENT_READ, Permission.AGENT_UPDATE,
        Permission.POLICY_READ, Permission.POLICY_CREATE, Permission.POLICY_UPDATE, Permission.ACTION_EXECUTE,
        Permission.ACTION_APPROVE, Permission.INCIDENT_READ, Permission.INCIDENT_CREATE, Permission.INCIDENT_UPDATE,
    },
    RoleCode.AI_ADMIN: {
        Permission.ORGANIZATION_READ, Permission.USER_READ, Permission.ASSET_READ, Permission.ASSET_CREATE,
        Permission.ASSET_UPDATE, Permission.AGENT_READ, Permission.AGENT_CREATE, Permission.AGENT_UPDATE,
    },
    RoleCode.ANALYST: {
        Permission.ORGANIZATION_READ, Permission.SECURITY_READ, Permission.ASSET_READ,
        Permission.AGENT_READ, Permission.INCIDENT_READ,
    },
    RoleCode.VIEWER: {
        Permission.ORGANIZATION_READ, Permission.ASSET_READ, Permission.AGENT_READ,
    },
}


def test_the_role_matrix_is_exactly_the_documented_one() -> None:
    assert {role: set(granted) for role, granted in ROLE_PERMISSIONS.items()} == EXPECTED_ROLE_MATRIX


def test_ai_admin_never_holds_approval_or_execution() -> None:
    grants = permissions_for(RoleCode.AI_ADMIN)
    assert Permission.ACTION_APPROVE not in grants
    assert Permission.ACTION_EXECUTE not in grants


def test_security_admin_can_review_without_changing_execution_boundary() -> None:
    grants = permissions_for(RoleCode.SECURITY_ADMIN)
    assert Permission.ACTION_APPROVE in grants
    assert Permission.ACTION_EXECUTE in grants
    assert Permission.INCIDENT_CREATE in grants
    assert Permission.INCIDENT_UPDATE in grants


def test_every_role_grant_is_a_declared_permission() -> None:
    for role_code, granted in ROLE_PERMISSIONS.items():
        assert granted <= set(Permission), role_code
        for permission in granted:
            assert permission.resource in set(Resource)
            assert permission.action in set(Action)


def test_no_role_holds_an_unimplemented_resource_permission() -> None:
    implemented_resources = set(Resource)
    for role_code, granted in ROLE_PERMISSIONS.items():
        for permission in granted:
            assert permission.resource in implemented_resources, f"{role_code}: {permission}"


def test_the_code_pattern_is_shared_with_the_database_model() -> None:
    assert PERMISSION_CODE_PATTERN == MODEL_CODE_PATTERN


def test_the_seeded_catalog_matches_the_runtime_catalog(integration_session: Session) -> None:
    catalog = RoleCatalog(integration_session)
    rows = catalog.list_permissions()
    assert {row.code for row in rows} == {permission.value for permission in Permission}
    seeded = catalog.grants_by_role_code()
    for role_code, granted in seeded.items():
        assert granted == {permission.value for permission in ROLE_PERMISSIONS[role_code]}
