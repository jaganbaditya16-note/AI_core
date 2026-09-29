from __future__ import annotations

from aicore_api.core.firewall import FirewallOutcome, FirewallReason


def test_firewall_outcomes_are_closed() -> None:
    assert {item.value for item in FirewallOutcome} == {"allow", "deny", "require_approval"}


def test_firewall_reason_vocabulary_includes_approved_execution() -> None:
    assert {item.value for item in FirewallReason} == {
        "allowed",
        "approval_accepted",
        "authorization_denied",
        "policy_denied",
        "policy_requires_approval",
        "target_not_found",
        "environment_mismatch",
    }
    assert FirewallReason.APPROVAL_ACCEPTED.value == "approval_accepted"
    assert FirewallReason.POLICY_REQUIRES_APPROVAL.value == "policy_requires_approval"
