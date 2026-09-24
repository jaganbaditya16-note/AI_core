"""The firewall's decision: one typed outcome, and every way it can be wrong.

The firewall is the enforcement boundary, so the properties worth testing are the ones
that make it *boundary-like* rather than advisory:

- there are exactly three outcomes, and only one of them permits execution;
- neither upstream layer can be widened: a Phase 5 denial is a denial whatever Phase 6
  said, a Phase 6 denial is a denial, and ``require_approval`` never becomes an
  execution;
- every ambiguity is a refusal *or* a loud failure — a missing environment fact, a
  target this organization does not have, a decision about a different question;
- the decision is a pure function of its arguments: same values, same decision, no
  clock, no database, no network, no model.

The last section reads the module's own source, because "the enforcement path cannot
reach anything" is a claim about code rather than about one call.
"""

from __future__ import annotations

import ast
import dataclasses
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest

from aicore_api.auth.authorization import AuthorizationDecision, DecisionReason
from aicore_api.auth.policy import EffectiveDecision, EffectiveReason, combine
from aicore_api.core.actions import AGENT_POSTURE_CHECK, ActionRequest, ActionTarget
from aicore_api.core.assets import Environment
from aicore_api.core.firewall import (
    FirewallConfigurationError,
    FirewallDecision,
    FirewallOutcome,
    FirewallReason,
    decide,
)
from aicore_api.core.permissions import Action, Permission, Resource
from aicore_api.core.policy import ConditionField, PolicyDefinition, PolicyEffect
from aicore_api.core.policy_engine import (
    PolicyContext,
    PolicyDecision,
    PolicyDecisionKind,
    evaluate_policies,
)

EVALUATED_AT = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)


# ── The values a decision is made from ───────────────────────────────────────


def _authorization(
    organization_id: uuid.UUID,
    *,
    allowed: bool = True,
    permission: Permission | None = Permission.ACTION_EXECUTE,
    role_code: str = "owner",
    principal_is_owner: bool | None = None,
) -> AuthorizationDecision:
    """Phase 5's answer for one organization, as the pipeline would have produced it."""
    return AuthorizationDecision(
        allowed=allowed,
        reason=DecisionReason.ALLOWED if allowed else DecisionReason.MISSING_PERMISSION,
        permission=permission,
        organization_id=organization_id,
        role_code=role_code,
        membership_id=uuid.uuid4(),
        principal_is_owner=principal_is_owner,
    )


def _policy_decision(
    organization_id: uuid.UUID,
    *,
    effect: PolicyEffect | None = None,
    resource: Resource = Resource.ACTION,
    action: Action = Action.EXECUTE,
) -> PolicyDecision:
    """Phase 6's answer, produced by the real engine rather than by a stub.

    ``effect=None`` means "no policy targets this": the engine is asked about an empty
    catalogue, which is the ``not_applicable`` case. Anything else is a real definition
    evaluated against a real context.
    """
    context = PolicyContext(
        organization_id=organization_id,
        resource=resource,
        action=action,
        facts={ConditionField.ENVIRONMENT: Environment.PRODUCTION.value},
    )
    definitions: list[PolicyDefinition] = []
    if effect is not None:
        definitions.append(
            PolicyDefinition(
                policy_id=uuid.uuid4(),
                version=1,
                name=f"{effect.value.title()} execution",
                priority=100,
                effect=effect,
                resource=resource,
                action=action,
                conditions=(),
            )
        )
    return evaluate_policies(definitions, context, evaluated_at=EVALUATED_AT)


def _request(
    organization_id: uuid.UUID,
    *,
    target_id: uuid.UUID | None = None,
    environment: Environment = Environment.PRODUCTION,
    agent_id: uuid.UUID | None = None,
) -> ActionRequest:
    """A validated request, in the shape the route assembles one."""
    return ActionRequest.build(
        definition=AGENT_POSTURE_CHECK,
        organization_id=organization_id,
        principal_id=uuid.uuid4(),
        membership_id=uuid.uuid4(),
        target_id=target_id or uuid.uuid4(),
        environment=environment,
        arguments={},
        correlation_id="firewall-test-request",
        idempotency_key="firewall-test-key",
        agent_id=agent_id,
    )


def _target(
    request: ActionRequest, *, environment: Environment | None = Environment.PRODUCTION
) -> ActionTarget:
    """The target record, with the facts the API would have derived from the row."""
    facts: dict[ConditionField, object] = {}
    if environment is not None:
        facts[ConditionField.ENVIRONMENT] = environment.value
    return ActionTarget(
        resource=Resource.AGENT,
        identifier=request.target_id,
        facts=facts,  # type: ignore[arg-type]
    )


def _decide(
    *,
    request: ActionRequest,
    authorization: AuthorizationDecision,
    policy: PolicyDecision,
    target: ActionTarget | None,
) -> FirewallDecision:
    """Run the firewall over a combination, as the route does."""
    return decide(
        request=request,
        definition=AGENT_POSTURE_CHECK,
        target=target,
        authorization=authorization,
        policy=combine(authorization, policy),
    )


# ── The outcome vocabulary ───────────────────────────────────────────────────


def test_the_outcome_vocabulary_is_exactly_three_values() -> None:
    """Three outcomes, one of which permits. A fourth would be a decision nobody acts on."""
    assert set(FirewallOutcome) == {
        FirewallOutcome.ALLOW,
        FirewallOutcome.DENY,
        FirewallOutcome.REQUIRE_APPROVAL,
    }
    assert FirewallOutcome.ALLOW.value == "allow"
    assert FirewallOutcome.REQUIRE_APPROVAL.value == "require_approval"


def test_the_reason_vocabulary_is_closed_and_names_the_layer_that_decided() -> None:
    """The refusals are stable codes, and the policy ones are Phase 6's own.

    A client that already reads a dry-run evaluation sees the same vocabulary here,
    which is what makes an execution reportable by the same tooling.
    """
    assert set(FirewallReason) == {
        FirewallReason.ALLOWED,
        FirewallReason.AUTHORIZATION_DENIED,
        FirewallReason.POLICY_DENIED,
        FirewallReason.POLICY_REQUIRES_APPROVAL,
        FirewallReason.TARGET_NOT_FOUND,
        FirewallReason.ENVIRONMENT_MISMATCH,
    }
    assert FirewallReason.POLICY_DENIED.value == "policy_denied"
    assert FirewallReason.POLICY_REQUIRES_APPROVAL.value == "policy_requires_approval"


# ── The decision matrix: CASE A-D of the phase ───────────────────────────────


def test_a_phase_five_allow_with_no_policy_matches_is_an_allow() -> None:
    """CASE A, the no-matching-policy form: authorization alone permits it."""
    organization_id = uuid.uuid4()
    request = _request(organization_id)

    decision = _decide(
        request=request,
        authorization=_authorization(organization_id, principal_is_owner=True),
        policy=_policy_decision(organization_id),
        target=_target(request),
    )

    assert decision.outcome is FirewallOutcome.ALLOW
    assert decision.reason is FirewallReason.ALLOWED
    assert decision.allowed is True
    assert decision.denied is False
    assert decision.requires_approval is False
    assert decision.permission_required == "action.execute"
    assert decision.policy_decision == PolicyDecisionKind.NOT_APPLICABLE.value
    assert decision.effective_reason == EffectiveReason.AUTHORIZATION_GRANT.value
    assert decision.principal_role == "owner"
    assert decision.organization_id == organization_id
    assert decision.target_id == request.target_id
    assert decision.correlation_id == request.correlation_id


def test_an_allow_policy_combined_with_a_phase_five_allow_is_an_allow() -> None:
    """CASE A's other form: a matching ``allow`` does not grant, it declines to object."""
    organization_id = uuid.uuid4()
    request = _request(organization_id)

    decision = _decide(
        request=request,
        authorization=_authorization(organization_id),
        policy=_policy_decision(organization_id, effect=PolicyEffect.ALLOW),
        target=_target(request),
    )

    assert decision.outcome is FirewallOutcome.ALLOW
    assert decision.effective_reason == EffectiveReason.POLICY_ALLOWED.value


def test_a_phase_five_denial_is_final_whatever_the_policy_says() -> None:
    """CASE B: an authorization denial is never widened by a policy.

    Asserted against three policy answers in one test, because the property is about
    all of them: allow, deny and require_approval all produce the same refusal, and
    the reason names Phase 5 rather than the policy layer.
    """
    organization_id = uuid.uuid4()
    request = _request(organization_id)
    denied = _authorization(organization_id, allowed=False)

    for policy in (
        _policy_decision(organization_id),
        _policy_decision(organization_id, effect=PolicyEffect.ALLOW),
        _policy_decision(organization_id, effect=PolicyEffect.REQUIRE_APPROVAL),
    ):
        decision = _decide(
            request=request, authorization=denied, policy=policy, target=_target(request)
        )
        assert decision.outcome is FirewallOutcome.DENY
        assert decision.reason is FirewallReason.AUTHORIZATION_DENIED
        assert decision.allowed is False


def test_a_policy_denial_is_a_denial_even_when_authorization_allowed() -> None:
    """CASE C: a matching ``deny`` beats an authorization allow, always."""
    organization_id = uuid.uuid4()
    request = _request(organization_id)

    decision = _decide(
        request=request,
        authorization=_authorization(organization_id),
        policy=_policy_decision(organization_id, effect=PolicyEffect.DENY),
        target=_target(request),
    )

    assert decision.outcome is FirewallOutcome.DENY
    assert decision.reason is FirewallReason.POLICY_DENIED
    assert decision.denied is True
    assert decision.allowed is False
    assert decision.requires_approval is False
    assert decision.policy_decision == PolicyDecisionKind.DENY.value
    assert decision.effective_reason == EffectiveReason.POLICY_DENIED.value


def test_a_policy_that_requires_approval_never_becomes_an_execution() -> None:
    """CASE D: the third outcome is carried through, and it does not execute.

    ``require_approval`` is neither ``allow`` nor ``deny``: it is the value Phase 6
    produced and this phase has no workflow to resolve. Asserted on the predicates
    because they are what the execution path branches on.
    """
    organization_id = uuid.uuid4()
    request = _request(organization_id)

    decision = _decide(
        request=request,
        authorization=_authorization(organization_id),
        policy=_policy_decision(organization_id, effect=PolicyEffect.REQUIRE_APPROVAL),
        target=_target(request),
    )

    assert decision.outcome is FirewallOutcome.REQUIRE_APPROVAL
    assert decision.reason is FirewallReason.POLICY_REQUIRES_APPROVAL
    assert decision.allowed is False
    assert decision.denied is False
    assert decision.requires_approval is True
    assert decision.policy_decision == PolicyDecisionKind.REQUIRE_APPROVAL.value
    assert decision.effective_reason == EffectiveReason.POLICY_REQUIRES_APPROVAL.value


# ── The referents: target, tenant, environment ───────────────────────────────


def test_a_target_this_organization_does_not_have_is_refused_before_the_policy() -> None:
    """A missing row is not "your policy says no", and the reason says which it is.

    Two policy answers, one refusal: the check is about the request's referents, so it
    does not depend on what the organization's policies happen to say.
    """
    organization_id = uuid.uuid4()
    request = _request(organization_id)

    for policy in (
        _policy_decision(organization_id),
        _policy_decision(organization_id, effect=PolicyEffect.DENY),
    ):
        decision = _decide(
            request=request,
            authorization=_authorization(organization_id),
            policy=policy,
            target=None,
        )
        assert decision.outcome is FirewallOutcome.DENY
        assert decision.reason is FirewallReason.TARGET_NOT_FOUND


def test_an_environment_the_record_does_not_confirm_is_refused() -> None:
    """The request's declared environment is checked, not believed.

    This is the one thing a request states about the world, so it is the one thing the
    firewall verifies against the record — and a record that states no environment at
    all is a refusal rather than a benefit of the doubt.
    """
    organization_id = uuid.uuid4()
    request = _request(organization_id, environment=Environment.PRODUCTION)

    unconfirmed = (
        _target(request, environment=Environment.STAGING),
        _target(request, environment=None),
    )
    for target in unconfirmed:
        decision = _decide(
            request=request,
            authorization=_authorization(organization_id),
            policy=_policy_decision(organization_id),
            target=target,
        )
        assert decision.outcome is FirewallOutcome.DENY
        assert decision.reason is FirewallReason.ENVIRONMENT_MISMATCH


def test_the_declared_environment_is_part_of_the_fingerprint() -> None:
    """Two requests that name different environments are different requests.

    Otherwise a caller could replay a staging execution as a production one, and the
    idempotency ledger would answer with the earlier result.
    """
    organization_id = uuid.uuid4()
    target_id = uuid.uuid4()

    staging = _request(organization_id, target_id=target_id, environment=Environment.STAGING)
    production = _request(organization_id, target_id=target_id, environment=Environment.PRODUCTION)

    assert staging.fingerprint != production.fingerprint


# ── The combinations that must fail loudly ───────────────────────────────────


def test_the_firewall_refuses_to_decide_about_a_different_question() -> None:
    """A wrongly assembled pipeline is a defect, not a denial.

    Every case below is a pair of values that do not describe one request. With a
    refusal, a client would be told "no" for a question nobody asked; with a raise, the
    deployment that assembled it badly is the thing that breaks.
    """
    organization_id = uuid.uuid4()
    request = _request(organization_id)
    target = _target(request)
    authorization = _authorization(organization_id)
    policy = _policy_decision(organization_id)

    def _run(
        *,
        definition: object = AGENT_POSTURE_CHECK,
        request_: ActionRequest = request,
        target_: object = target,
        authorization_: object = authorization,
        policy_: object = policy,
    ) -> FirewallDecision:
        return decide(
            request=request_,
            definition=definition,  # type: ignore[arg-type]
            target=target_,  # type: ignore[arg-type]
            authorization=authorization_,  # type: ignore[arg-type]
            policy=policy_,  # type: ignore[arg-type]
        )

    # The definition is for another action.
    with pytest.raises(FirewallConfigurationError):
        _run(definition=dataclasses.replace(AGENT_POSTURE_CHECK, action_id="agent.other"))
    # The authorization decision is about another organization.
    with pytest.raises(FirewallConfigurationError):
        _run(authorization_=_authorization(uuid.uuid4()))
    # …and about another permission, including "no permission at all".
    for permission in (Permission.AGENT_UPDATE, None):
        with pytest.raises(FirewallConfigurationError):
            _run(authorization_=_authorization(organization_id, permission=permission))
    # The policy decision is about a different question: another organization, then
    # another resource/action pair.
    with pytest.raises(FirewallConfigurationError):
        _run(
            policy_=EffectiveDecision(
                authorization=authorization,
                policy=_policy_decision(uuid.uuid4()),
            )
        )
    with pytest.raises(FirewallConfigurationError):
        _run(
            policy_=EffectiveDecision(
                authorization=authorization,
                policy=_policy_decision(
                    organization_id, resource=Resource.AGENT, action=Action.READ
                ),
            )
        )
    # The target is a different row, or a different kind of row.
    with pytest.raises(FirewallConfigurationError):
        _run(target_=ActionTarget(resource=Resource.AGENT, identifier=uuid.uuid4()))
    with pytest.raises(FirewallConfigurationError):
        _run(target_=ActionTarget(resource=Resource.ASSET, identifier=request.target_id))


def test_a_decision_is_a_pure_function_of_its_arguments() -> None:
    """Same values in, equal decisions out — twice in a row, and out of order.

    The firewall is the last thing between a decision and an execution, so it may not
    depend on anything that could differ between two identical calls.
    """
    organization_id = uuid.uuid4()
    request = _request(organization_id)
    authorization = _authorization(organization_id)
    policy = _policy_decision(organization_id, effect=PolicyEffect.REQUIRE_APPROVAL)

    first = _decide(
        request=request, authorization=authorization, policy=policy, target=_target(request)
    )
    second = _decide(
        request=request, authorization=authorization, policy=policy, target=_target(request)
    )

    assert first == second
    assert first.outcome is second.outcome
    assert first.reason is second.reason


def test_the_decision_never_carries_the_arguments_of_the_request() -> None:
    """A decision names what was decided, not what the caller sent.

    The correlation id, the action and the target are identifiers; the arguments are
    payload, and a decision that rendered them would put a caller's input into a log
    line by way of a ``repr``.
    """
    organization_id = uuid.uuid4()
    request = ActionRequest.build(
        definition=AGENT_POSTURE_CHECK,
        organization_id=organization_id,
        principal_id=uuid.uuid4(),
        membership_id=uuid.uuid4(),
        target_id=uuid.uuid4(),
        environment=Environment.PRODUCTION,
        arguments={"report_detail": "full"},
        correlation_id="firewall-test-request",
        idempotency_key="firewall-test-key",
    )
    decision = _decide(
        request=request,
        authorization=_authorization(organization_id),
        policy=_policy_decision(organization_id),
        target=_target(request),
    )

    assert "report_detail" not in repr(decision)
    assert "full" not in repr(decision)


# ── The enforcement path cannot reach anything ───────────────────────────────

REPO_ROOT = Path(__file__).resolve().parents[3]

#: The modules that decide and execute. Everything a request can cause to *happen*
#: passes through them, so they are held to an explicit allow-list of imports.
ENFORCEMENT_PATH = (
    Path("apps/api/src/aicore_api/core/actions.py"),
    Path("apps/api/src/aicore_api/core/firewall.py"),
    Path("apps/api/src/aicore_api/core/executors.py"),
    Path("apps/api/src/aicore_api/core/execution.py"),
)

#: What these modules may import. Deliberately short: a parser, a digest, a value type,
#: a logger, a timestamp type, the schema library, and this application's own core.
ALLOWED_IMPORTS = frozenset(
    {
        "__future__",
        "abc",
        "collections",
        "collections.abc",
        "dataclasses",
        "datetime",
        "enum",
        "hashlib",
        "json",
        "logging",
        "re",
        "types",
        "typing",
        "uuid",
        "pydantic",
        "aicore_api.core.actions",
        "aicore_api.core.agents",
        "aicore_api.core.assets",
        "aicore_api.core.domain_errors",
        "aicore_api.core.events",
        "aicore_api.core.execution",
        "aicore_api.core.executors",
        "aicore_api.core.firewall",
        "aicore_api.core.permissions",
        "aicore_api.core.policy",
        "aicore_api.core.request_context",
        "aicore_api.auth.authorization",
        "aicore_api.auth.policy",
    }
)

#: Builtins no module on this path may call, by name. ``compile`` is here and
#: ``re.compile`` is not: the check below looks for the *bare* name, which is the
#: builtin that turns a string into code.
FORBIDDEN_CALLS = frozenset(
    {
        "eval",
        "exec",
        "compile",
        "__import__",
        "open",
        "breakpoint",
        "input",
        "globals",
        "locals",
        "vars",
    }
)

#: Attributes that reach a process, a file, a socket or a dynamic import whatever they
#: are attached to (``os.system``, ``subprocess.run``, ``pickle.loads``,
#: ``importlib.import_module``). Matched on the attribute rather than the module so a
#: module already covered by the import allow-list cannot smuggle one in through a
#: local alias.
FORBIDDEN_ATTRIBUTES = frozenset(
    {
        "system",
        "popen",
        "Popen",
        "spawn",
        "spawnl",
        "spawnv",
        "execv",
        "execl",
        "fork",
        "run",
        "call",
        "check_output",
        "import_module",
        "loads",
        "load",
        "urlopen",
    }
)


def _parse(relative: Path) -> ast.Module:
    return ast.parse((REPO_ROOT / relative).read_text(encoding="utf-8"))


def _imported_modules(tree: ast.Module) -> set[str]:
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            modules.add(node.module)
    return modules


@pytest.mark.parametrize("relative", ENFORCEMENT_PATH, ids=lambda path: path.name)
def test_the_enforcement_path_imports_only_what_it_needs(relative: Path) -> None:
    """No subprocess, no shell, no socket, no HTTP client, no filesystem, no queue.

    An allow-list rather than a deny-list, so importing something nobody has thought
    about yet fails here instead of passing quietly. This is the phase's "no arbitrary
    code execution, no outbound network, no filesystem" requirement, asserted where it
    can actually be enforced.
    """
    unexpected = sorted(
        module for module in _imported_modules(_parse(relative)) if module not in ALLOWED_IMPORTS
    )
    assert unexpected == [], f"{relative.name} imports {unexpected}"


@pytest.mark.parametrize("relative", ENFORCEMENT_PATH, ids=lambda path: path.name)
def test_the_enforcement_path_calls_nothing_that_executes_code(relative: Path) -> None:
    """``eval``, ``exec``, ``__import__``, ``open``: none of them, by name.

    Checked against the parsed syntax tree rather than the text, so a docstring that
    says "no ``eval``" is not mistaken for a call to one.
    """
    offenders: list[str] = []
    for node in ast.walk(_parse(relative)):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Name) and node.func.id in FORBIDDEN_CALLS:
            offenders.append(f"{relative.name}:{node.lineno} calls {node.func.id}()")
        if isinstance(node.func, ast.Attribute) and node.func.attr in FORBIDDEN_ATTRIBUTES:
            offenders.append(f"{relative.name}:{node.lineno} reaches .{node.func.attr}()")
    assert offenders == []


@pytest.mark.parametrize(
    "relative",
    (ENFORCEMENT_PATH[0], ENFORCEMENT_PATH[2]),
    ids=lambda path: path.name,
)
def test_the_catalogue_and_the_adapters_never_reach_the_database(relative: Path) -> None:
    """An adapter is not given a session, an engine or a connection — so it cannot have one.

    Asserted structurally as well as by the invocation's shape
    (``test_action_execution.py``): the module cannot import the database layer even if
    a later edit wanted it to, which is what keeps "an adapter cannot read another
    tenant" from depending on the adapter's own restraint.
    """
    database_modules = [
        module
        for module in _imported_modules(_parse(relative))
        if module.startswith(("aicore_api.db", "aicore_api.api"))
    ]
    assert database_modules == []
