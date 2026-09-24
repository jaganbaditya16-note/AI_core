# The action firewall (Phase 7)

> **The Action Firewall is the enforcement boundary. Only `ALLOW` reaches the
> execution adapter.**

Phases 5 and 6 answer questions. Phase 7 is the first phase that *acts* — and this
document is about the single door it acts through, why the door can only open one way,
and what is deliberately still absent behind it.

Every other phase's rule still holds: the deterministic control layer decides. No LLM,
no Nemotron, no Nebius call and no generated text takes part in an authorization or a
policy decision anywhere in this pipeline, and nothing in this phase is advisory.

## The pipeline

One request, in order. Nothing is executed before every step has passed:

| # | Step | What answers | Where |
|---|---|---|---|
| 1 | Authenticate | the bearer token resolves to a principal | Phase 2 |
| 2 | Resolve the tenant | the organization in the path, on a membership of the caller | Phase 2 |
| 3 | Check the permission | `action.execute` for this organization | Phase 5 |
| 4 | Resolve the action | the identifier against the process-wide catalogue | this phase |
| 5 | Resolve the target | the row, **inside this organization** | Phase 3/4 |
| 6 | Resolve the attributed agent | the same, when the request names one | Phase 4 |
| 7 | Build and validate the request | the action's own input schema | this phase |
| 8 | Authorize the instance | Phase 5's `authorize_instance`, with the resolved row in scope | Phase 5 |
| 9 | Build the policy context | server-held facts: environment, status, classification, category, ages, caller role, ownership | Phase 6 |
| 10 | Evaluate policy | the organization's active policies for `action.execute`, combined with the authorization decision | Phase 6 |
| 11 | Decide, then execute **only on `ALLOW`** | the action firewall, then `ActionExecutionService` → one adapter | this phase |

Steps 3 and 8 are the same authorization service asked two different questions: *may
this caller use this permission here*, and *may this caller act on this row*. Nothing
in this phase re-implements either.

A decision that is not `ALLOW` is answered as an **error envelope**, never as a
success with a note attached. The error code names the reason, so a client can switch
on it rather than parse prose.

## The request

`ActionRequest` is the server's view of one request. The client sends only its half:

```jsonc
POST /organizations/{organization_id}/actions/execute
{
  "action": "agent.posture_check",          // a registered identifier
  "target_id": "3f1c1d8e-…",                // the row this organization is acting on
  "environment": "production",              // what the caller believes it is acting in
  "arguments": { "report_detail": "full" }, // validated against the action's schema
  "idempotency_key": "01J8Z0Q2P9H4V6S8T2N4K6M8R1",
  "agent_id": null                          // optional attribution, resolved in-tenant
}
```

The other fields — organization, principal, membership, correlation id, the validated
argument model — are assembled by the server. The body has **no field** for a module, a
function, a script, a command, a URL, an executor, a permission, a role, an
organization or a correlation id, and `extra="forbid"` means attempting one is a 422
rather than a silently ignored key. A request that exists is therefore a request whose
arguments already satisfy its action's schema, which is what keeps "invalid arguments"
a 422 at the boundary instead of a decision somewhere deeper.

`environment` deserves one sentence: it is not evidence. It is *checked* against the
environment the target row is recorded in (a mismatch is `environment_mismatch`, 403),
and the policy layer is evaluated against the **recorded** value, never the declared
one.

## The catalogue

```python
AGENT_POSTURE_CHECK = ActionDefinition(
    action_id="agent.posture_check",
    resource=Resource.AGENT,              # the kind of row it addresses
    description="Assess an agent's recorded posture from its registry facts.",
    argument_model=AgentPostureArguments,  # the input schema, a Pydantic model
    sensitivity=ActionSensitivity.ROUTINE,  # review metadata, not an authorization input
    executor_id="agent_registry",           # the adapter it is bound to
)
DEFAULT_ACTIONS = ActionRegistry((AGENT_POSTURE_CHECK,), executor_ids=("agent_registry",))
```

The registry is the allowlist: immutable, built from code at import time, looked up by
identifier only. Construction is where its internal consistency is checked — duplicate
identifiers, or a definition naming an adapter nothing registered, are startup
failures. Nothing in a request can add to it, and an unknown identifier is a 422 that
lists the catalogue; the identifier is never resolved, imported or interpreted.

One action ships, and it is read-only by construction: `agent.posture_check` classifies
the facts the row already attests and reports findings from a closed set
(`high_risk_classification`, `unclassified_risk`, `production_autonomous_agent`,
`suspended_asset`, `recently_registered`) plus one verdict
(`standard` / `elevated` / `attention`). It opens no connection, reads no clock and
calls nothing. That is the point of a *reference* adapter: the phase proves the
architecture with something that cannot do damage while the architecture is new.

There is deliberately no per-action permission. The authorization question — *may this
person run registered actions here?* — is one question, `action.execute`; the
contextual one — *should this action, on this target, run?* — is a Phase 6 policy
written against that same target.

## The decision

```python
FirewallDecision(
    outcome=FirewallOutcome.ALLOW,        # ALLOW | DENY | REQUIRE_APPROVAL
    reason=FirewallReason.ALLOWED,        # a stable code, never prose
    action_id=..., target_id=..., organization_id=..., correlation_id=..., effective=...,
)
```

The mapping is exhaustive and one-directional:

| Upstream | Firewall |
|---|---|
| Phase 5 denies | `DENY`, `authorization_denied` — final, whatever the policy layer says |
| Target not in this organization | `DENY`, `target_not_found` — answered as a 404, identical for "not yours" and "does not exist" |
| The record does not confirm the declared environment | `DENY`, `environment_mismatch` |
| Phase 6 denies (alone or combined) | `DENY`, `policy_denied` |
| Phase 6 requires approval | `REQUIRE_APPROVAL`, `policy_requires_approval` — **never executed** |
| Phase 6 allow / not applicable, Phase 5 allows | `ALLOW`, `allowed` |

Three properties make that a boundary rather than a report:

- **A typed value, not a convention.** There is no string comparison on the execution
  path, and no caller can "almost" allow something.
- **Neither upstream layer can be widened.** An `ALLOW` from the policy layer means "no
  active policy objected", not "the caller may act", so it only continues *subject to*
  the authorization decision. The combination is Phase 6's own `combine`, reused rather
  than re-derived, so a denial can never become a permit.
- **Ambiguity fails closed.** A missing authorization decision, a decision about a
  different organization or permission, a policy decision about another target, a
  definition that is not the registered one: each raises
  `FirewallConfigurationError` rather than producing a decision. A pipeline wired
  wrongly must not answer "denied" — it must fail loudly.

`decide()` is a pure function of its arguments: no clock, no database, no network, no
model. `tests/test_action_firewall.py` asserts that structurally, by parsing the
enforcement path's own source.

## The adapter boundary

```python
class ActionExecutor(ABC):
    executor_id: ClassVar[str]                      # declared, validated at class creation

    @abstractmethod
    def execute(self, invocation: ActionInvocation) -> ActionOutcome: ...
```

An adapter receives an `ActionInvocation` and nothing else: identifiers, the attested
target, the validated arguments, the environment, the correlation id and the time.
There is no session, no engine, no credential, no filesystem path and no URL in that
shape, so "an adapter cannot reach outside its tenant" is true by construction rather
than by restraint. `ActionOutcome` is equally closed: a summary, a tuple of stable
finding codes, and JSON-representable detail.

Two rules keep the boundary honest:

- **Adapters are reached only through the firewall.** The adapter registry is a request
  dependency, and `tests/test_actions_api.py` asserts that exactly one route in the
  whole application declares it — the execute route, which reaches it through
  `ActionExecutionService`.
- **The service re-checks the decision.** `ActionExecutionService.execute()` refuses
  anything that is not `ALLOW` on its own account, so a future code path that skips the
  firewall does not execute; it fails.

Adding a real adapter later (a ticketing system, an ERP, a mail provider, a cloud API)
means implementing this interface and registering it with an identifier — the
architecture is the extensible part; the catalogue, the request schema, the decisions
and the enforcement do not change. No such adapter exists in this build, and an
adapter that needed arbitrary network destinations or a subprocess would be a change to
this document, not a new file.

## Executing exactly once

The failure mode this phase must survive is mundane: a client sends a request, the
answer is lost, and it retries. The request therefore carries a required
`idempotency_key`, and the ledger claims it:

1. the key is looked up **within the organization**; a completed record with the same
   request fingerprint is returned as-is (`replayed: true`) and the adapter is not
   called again;
2. otherwise the key is reserved with an `INSERT` guarded by
   `UNIQUE (organization_id, idempotency_key)` — no lock, no lease, no distributed
   anything; the database's constraint is the arbiter, and a race is answered "not now"
   rather than by running the action twice;
3. only then is the adapter invoked, and its outcome recorded against the reservation.

A key reused for a *different* request is a 409. A run whose adapter failed keeps its
key: the action may have had effects this build cannot see, so the way forward is a new
request, not a re-run.

**The ledger is not an audit trail.** It records identifiers, a fingerprint, a status
and what the adapter reported — no actor, no role, no rationale and no row for a
refusal. What happened, for whom, whether it was allowed and what it changed is the
Phase 8 trail: a separate table (`aicore.audit_events`), written by a separate writer,
which records the refusals this table deliberately forgets. The two are one decision
sequence seen twice, and neither stands in for the other — see [audit.md](audit.md).
No dashboard and no approval queue exists in either of them.

## The API

One endpoint, and it is the only one in the build that can execute anything:

```
POST /organizations/{organization_id}/actions/execute      →  200
```

```jsonc
{
  "organization_id": "…",
  "action_id": "agent.posture_check",
  "action_sensitivity": "routine",
  "target": { "resource": "agent", "id": "3f1c1d8e-…" },
  "agent_id": null,
  "permission_required": "action.execute",
  "principal_role": "owner",
  "environment": "production",
  "firewall": { "outcome": "allow", "reason": "allowed" },
  "authorization": { "allowed": true, "reason": "role_permission_grant", "permission": "action.execute" },
  "policy": { "decision": "not_applicable", "reason": "no_matching_policy", … },
  "effective": { "decision": "allow", "reason": "authorization_grant", … },
  "executed": true,
  "replayed": false,
  "execution_id": "…",
  "idempotency_key": "…",
  "correlation_id": "…",
  "executed_at": "2026-09-24T12:00:00Z",
  "result": { "summary": "…", "findings": ["unclassified_risk"], "details": {…},
              "adapter": "agent_registry", "digest": "…" }
}
```

Both upstream answers are published side by side on purpose: a client can see whether
the permission or a policy produced the effective answer, and a reviewer can see which
one permitted an execution. The request's arguments are never echoed back.

Every refusal is an error, with a code:

| Status | Code | Meaning |
|---|---|---|
| 401 | `unauthorized` | no usable credential |
| 403 | `forbidden` | the caller lacks `action.execute` (or the membership is not active) |
| 403 | `policy_denied` | an active policy denied this action |
| 403 | `approval_required` | this action requires an approval this build cannot grant — **nothing was executed** |
| 403 | `environment_mismatch` | the record does not confirm the declared environment |
| 404 | `not_found` | no such target in this organization, or no such attributed agent — identical for "not yours" and "does not exist" |
| 409 | `idempotency_conflict` | the key was used for a different request, or a previous attempt did not complete |
| 422 | `unknown_action` | the identifier is not in the catalogue (the response lists it) |
| 422 | `invalid_arguments` | the arguments do not satisfy the action's schema |
| 422 | `validation_error` | the body names a field the server owns, or is otherwise malformed |
| 500 | `execution_failed` | the action was admitted and the adapter could not finish; the key stays claimed |

## Approvals

`REQUIRE_APPROVAL` is a **value**, and the phase stops there: no queue, no approver, no
approve/reject endpoint, no notification, no state to fake. The API says so in the
error it returns, and `tests/test_actions_api.py` asserts that no approval route exists
in the published document. Approval workflows arrive later, with the phase that owns
them; until then "requires approval" means "does nothing until then".

## Security guarantees

- **Only `ALLOW` reaches an adapter**, asserted three times over: the decision is
  typed, the service re-checks it, and the adapter is a dependency of one route.
- **No arbitrary execution.** No `eval()`, no `exec()`, no `pickle`, no subprocess, no
  shell, no dynamic import by name, no arbitrary outbound network call — on the
  enforcement path or anywhere it can reach. `tests/test_action_firewall.py` scans the
  enforcement modules' source for calls that would create one.
- **Tenant isolation.** The target, the attributed agent and the ledger are all
  resolved inside the caller's organization; a foreign row and a missing row produce
  byte-identical refusals. Guessing an identifier from another tenant is not a key to
  it.
- **No request-supplied security facts.** The tenant, the caller, the permission and
  every policy fact come from the credential, the path and the row.
- **Closed input.** Identifiers, idempotency keys, arguments and bodies are all
  validated against closed shapes; injection-shaped and oversized input is refused
  before anything is authorized.
- **Secret hygiene.** Responses carry no credential and no argument echo; error
  messages carry no stack trace, no SQL and no database detail; the ledger stores no
  token and no secret.

## Limitations, stated plainly

- **One action, one adapter.** The catalogue holds `agent.posture_check` because a
  reference implementation is worth more than a speculative one. CRM, ERP, mail,
  database, cloud, ticketing, financial and MCP adapters are the architecture's
  extension points, not this phase's code.
- **No approvals, no workflow, no notification.** `require_approval` does not execute
  and does not queue.
- **No agent execution and no runtime control.** Nothing starts, stops, suspends,
  quarantines or contains an agent; the firewall runs registered actions, and the one
  that exists only reads.
- **No audit/event system, no monitoring, no kill switch, no incidents** — and the
  ledger is explicitly not a substitute for any of them.
- **No LLM anywhere in the path.** Nemotron is an advisory layer in a later phase; it
  does not authorize, evaluate, decide or execute, and no decision here could be
  generated text.
- **Sensitivity is review metadata**, not an enforcement input: it records how much
  care an action warrants and is published in the response; it does not change who may
  run one or whether a policy may deny it.

## Verification

```bash
bash scripts/test-db.sh      # empty database, migrations, drift check, round trip, full suite
bash scripts/verify.sh --full
```

Phase 7's own tests, and what each is for:

| File | What it proves |
|---|---|
| `tests/test_actions.py` | the catalogue, the definition contract, argument schemas, the request model and the fingerprint — pure, no database |
| `tests/test_action_firewall.py` | CASE A–D, every refusal and reason, fail-closed configuration errors, purity, and the structural scan of the enforcement path |
| `tests/test_action_execution.py` | CASE A–G at the service boundary with a **recording adapter**: exactly one call on `ALLOW`, zero calls on everything else; replay, conflict, failure; the ledger's constraints against real PostgreSQL |
| `tests/test_actions_api.py` | CASE A–G over HTTP with a recording adapter installed through the route's own dependency: call counts, every published error, tenant isolation and IDOR, injection-shaped input, the closed body, secret hygiene, and that one route can reach an adapter |
| `tests/test_permissions.py`, `tests/test_authorization.py` | `action.execute` and the `action` resource in the catalog, the role matrix, the seeded rows, and that the route declares the permission it enforces |
| `tests/test_migrations.py`, `tests/test_policies.py` | the new table, the widened policy target constraints, and that the seed equals the code catalog |
