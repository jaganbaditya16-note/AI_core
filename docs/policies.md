# The policy engine (Phase 6)

Phase 6 adds a **context-aware policy layer**: a place to record what an organization
decides about an action in a given situation, and a deterministic evaluator that turns
those records into a decision.

The one sentence that matters most, and the boundary this phase deliberately stops at:

> **The policy engine evaluates. The action firewall enforces.**

Nothing in this repository blocks, approves, suspends, intercepts or executes anything.
Evaluation is a report — a value — and the phase that acts on it is a later one.

## What a policy is

A policy is an organization's own rule about one `resource.action` pair from the
permission catalogue:

```json
{
  "name": "No production agent changes without review",
  "description": "Production agent updates are the change class our auditors care about.",
  "resource": "agent",
  "action": "update",
  "effect": "require_approval",
  "priority": 10,
  "conditions": [
    { "field": "environment", "operator": "equals", "value": "production" }
  ]
}
```

- **`resource` / `action`** — drawn from the closed permission vocabulary. A policy
  targets a capability the application can check, or it is refused. There is no
  `firewall.block`, `incident.create`, `tool.invoke` or `kill.execute`: a policy about
  something nothing enforces would be a claim, not a control.
- **`effect`** — `allow`, `deny` or `require_approval`, required rather than
  defaulted, because the effect *is* the decision.
- **`priority`** — 0–1000, lower first. It orders policies; it never decides which
  effect wins (see [Precedence](#precedence)).
- **`conditions`** — structured data, all of which must hold for the policy to apply.
  An empty list is a blanket rule for the target, which is legitimate and clearer than
  inventing a condition that is always true.
- **`status`** — the lifecycle state. Only `active` is evaluated.

Policies are tenant-owned. There is no global, shared or built-in policy, and no way
to write one: every row carries an `organization_id` that the isolation guard refuses
to let a caller forget.

## The evaluation pipeline

```
identity → permission → POLICY ENGINE → policy decision → effective authorization
                          │
                          ├─ validate the target
                          ├─ load the organization's ACTIVE policies for it
                          ├─ evaluate each policy's conditions against the context
                          ├─ apply precedence
                          └─ return one deterministic decision (a value)
```

1. **Identity and permission come first.** Phase 5 answers *may this principal use
   this permission in this organization?* before any policy is consulted. Phase 6 does
   not replace, wrap or reorder that step.
2. **The engine is handed its input.** It receives definitions and a
   [`PolicyContext`](../apps/api/src/aicore_api/core/policy_engine.py), and returns a
   `PolicyDecision`. It reads no rows, opens no connection, calls no model and reads
   no clock (the evaluation timestamp is an argument).
3. **Both layers are combined in one place.** `combine(authorization, policy)` in
   [`auth/policy.py`](../apps/api/src/aicore_api/auth/policy.py) produces the effective
   answer — and can only ever make it more restrictive.

### The policy decision

The engine answers with one of four values, and the fourth is an abstention rather than a
fifth opinion:

| `decision` | Meaning |
|---|---|
| `allow` | An active policy targeted this resource and action and every one of its conditions matched. |
| `deny` | The same, with a `deny` effect. |
| `require_approval` | The same, with a `require_approval` effect. It is **not** `allowed`. |
| `not_applicable` | No active policy applied: nothing targeted the question, or no policy's conditions matched. |

Only a policy that actually matched can produce `allow`; "I found no rule" is never
reported as permission, which is why `not_applicable` exists. It cannot appear in an
effective decision — the authorization layer always says something — so the effective
answer is always `allow`, `deny` or `require_approval`.

A decision also names the policy and **version** that decided it, the priority, the
conditions that matched (with the values they were compared against), how many policies
were evaluated and how many matched. Precedence is by effect, then priority, then name,
then id — never by the order rows came back from the database — so the same policies and
the same context always produce the same decision, on any database.

### Effective decisions

| authorization | policy | effective |
|---|---|---|
| allow | deny | **deny** |
| allow | require_approval | **require_approval** |
| allow | allow | allow |
| allow | not_applicable | allow |
| deny | *any* | **deny** |

A policy can only restrict. There is no combination that turns a Phase 5 denial into a
permit, and `tests/test_policy_authorization.py` asserts that over the whole cross
product rather than by example.

`require_approval` is a **value only**. Nothing in this build creates an approval
request, notifies an approver, tracks a decision or resolves one: no workflow, no
queue, no UI. It is reported so that the phase that implements approvals has something
to consume, and it is never `allowed` — a request that needs approval is not permitted
yet.

## The condition language

A condition is a field, an operator, and a value. That is the entire language:

```json
{ "field": "risk_classification", "operator": "in", "value": ["high", "critical"] }
```

**There is no expression language.** No arbitrary code, no user-supplied Python, no
`eval()`, no policy-authored SQL, no nesting, no `OR`, no negation of a condition list,
no regex, no free-form field. The engine compares a field against a value with an
operator, and a test asserts structurally that the modules that decide a policy can
reach no database, no transport, no clock and no evaluator.

### Fields

Nine fields, each one answerable from genuinely available context, with a type and — for
the string fields — a closed set derived from the domain's own enums, so a new
environment, category or role becomes usable by existing rather than by editing two
lists:

| Field | Type | Values |
|---|---|---|
| `environment` | string | `development` \| `staging` \| `production` \| `unknown` |
| `asset_type` | string | the seven inventory types |
| `resource_status` | string | `draft` \| `active` \| `suspended` \| `retired` |
| `risk_classification` | string | `low` \| `medium` \| `high` \| `critical` \| `unassessed` |
| `agent_category` | string | the eight agent categories |
| `user_role` | string | `owner` \| `admin` \| `security_admin` \| `ai_admin` \| `analyst` \| `viewer` |
| `is_resource_owner` | boolean | `true` \| `false` |
| `agent_age_days` | number | 0–36500 |
| `asset_age_days` | number | 0–36500 |

Deliberately absent: request source, IP addresses, user or agent identifiers, tool and
model names, free-form metadata, and anything else a caller could simply claim. A field
nobody can supply would be a condition that never matches; a field a caller can assert
would be a condition that can be spoofed.

### Operators

The set is closed, and each operator is refused on a field where it would not mean
anything:

| Operator | Compares against | Refused on |
|---|---|---|
| `equals`, `not_equals` | a single value of the field's type | — |
| `in`, `not_in` | a list of 1–16 such values | boolean fields (a set of booleans is an `equals` in disguise) |
| `less_than`, `less_than_or_equal`, `greater_than`, `greater_than_or_equal` | a number | any non-numeric field |

### Validation, and what happens to an invalid policy

Every write path validates the whole definition — target, effect, priority, every
condition, every value — *before* a row is staged, and activation validates the
**stored** definition rather than trusting the request. So:

- an invalid condition cannot be created,
- an invalid definition cannot be activated,
- a stored row this build cannot interpret (a database edited outside the application)
  raises rather than being skipped. Skipping a policy would silently change what the
  organization's policy says — and **skipping a denial is permitting the action**.

### Missing context never matches

A condition whose field the context does not carry **does not match**, for every
operator including the negated ones. `not_equals` against a fact nobody supplied is not
`true`; it is "this policy does not apply".

The consequence is the safe one: an unevaluatable condition leaves the authorization
decision exactly where Phase 5 put it. It can never *widen* anything, because a policy
can only restrict. A missing security fact is never read as "allowed".

## Precedence

Deterministic, and stated rather than implied:

1. **Effect first:** `deny` > `require_approval` > `allow`. A denial outranks every
   permit, at any priority. No policy can argue its way around another policy's refusal.
2. **Then priority:** among the matching policies with the strongest effect, the lowest
   priority is the one reported as the decider.
3. **Then name, then id:** a tiebreak that exists so the answer is *always* defined.
4. **Never the row order.** The engine sorts its own candidates, and a test evaluates
   every rotation and the reversal of a real list to assert that the decision is
   identical. "Last policy wins" is not a rule here, and neither is "first row wins".

Priority decides *which* matching policy is named and the order matches are reported
in. It cannot change *whether* a request is denied.

## Lifecycle

```
        ┌───────────────► active ◄────────────┐
 draft ─┤                 │  ▲                │
        └──► retired      │  └── disabled ────┘
                          └──────► retired
```

- `draft` — editable, never evaluated. May be activated or retired.
- `active` — in force. May be disabled or retired (asking again is a no-op).
- `disabled` — reversible: may be activated again or retired.
- `retired` — **terminal**. History: it keeps its record, stops being evaluated, and
  cannot be brought back.

Only `active` policies participate in evaluation, and a policy can be created only as
`draft` or `active` — being born disabled or retired would be a quiet way to write a
record that never applies.

This is a **record**, not runtime control. Nothing about a status change starts, stops,
blocks, suspends or contains anything.

## Versioning

A policy is two tables: its **identity and life** (`policies` — the name, the rationale,
the status, the pointer to the current version) and its **definition**
(`policy_versions`, one append-only row per version).

- Editing the definition **appends a version** and moves the pointer. A published
  version is never rewritten or deleted.
- Editing only the name or the description is **not** a version change: a label does not
  change what a policy does.
- An edit that changes nothing appends nothing — a client re-sending the current
  definition is not making a change, and a version number is what a decision is
  attributed to.
- A **lifecycle move** is not a definition change either. `status` lives on the policy
  record, so activating, disabling or retiring a policy leaves its version where it is:
  a decision that names version 3 names the same wording before and after an activation.
- A decision names `policy_id` **and** `policy_version`, so the definition a recorded
  decision was made from can still be read back, exactly as it was.

There is no audit system here: no decision log, no event stream of evaluations, no
history retention policy. The version history is what makes a decision attributable, and
that is all this phase claims.

## Evaluation context

A `PolicyContext` is supplied by the caller and carries only facts that are genuinely
available:

```python
PolicyContext(
    organization_id=...,
    resource=Resource.AGENT,
    action=Action.UPDATE,
    facts={"environment": "production", "agent_age_days": 3},
)
```

- A field that is **absent** is not the same as a field carrying the value `unknown`:
  the first means nothing is known, the second means known to be unknown.
- A fact is a single scalar. `in`/`not_in` compare a fact against a list of values the
  *policy* states, so nothing in a context is a set.
- The context is validated on construction (unknown fields, wrong types and lists are
  refused) and frozen, so it cannot change between the moment a decision is computed and
  the moment it is recorded.

The **dry-run endpoint** takes its facts from the request body, with two exceptions:
`user_role` and `is_resource_owner` are derived from the caller's own membership, and a
request that tries to supply them is refused (422). A client cannot talk its way around
a policy that asks about the caller's role.

## API

| Method | Path | Permission |
|---|---|---|
| `GET` | `/organizations/{organization_id}/policies` | `policy.read` |
| `POST` | `/organizations/{organization_id}/policies` | `policy.create` |
| `GET` | `/organizations/{organization_id}/policies/{policy_id}` | `policy.read` |
| `GET` | `/organizations/{organization_id}/policies/{policy_id}/versions` | `policy.read` |
| `PATCH` | `/organizations/{organization_id}/policies/{policy_id}` | `policy.update` |
| `DELETE` | `/organizations/{organization_id}/policies/{policy_id}` | `policy.delete` |
| `POST` | `/organizations/{organization_id}/policies/evaluate` | `policy.read` |

Conventions are the ones the rest of the API already uses: list endpoints page with
`limit`/`offset` (capped, never unbounded), filters are repeatable and ORed within one
filter, `?total=true` opts into the filtered count, item routes answer 404 for a missing
row *and* for another tenant's, and PATCH distinguishes "omitted" from "set" so that
`conditions: []` means "no conditions" rather than "unchanged". The status codes are
equally conventional: 422 for a body that is wrong (an unknown target, an invalid
condition, a state a policy may not hold), 409 for a request that conflicts with the
record as it stands (a name already taken in this organization, a lifecycle move the
current state does not allow), 404 for a policy that is not this organization's.

There is deliberately **no** `policy.execute`, `policy.approve`, `policy.kill` or
`policy.evaluate` permission: evaluation is a read of the policy record, and no role is
granted the ability to make a policy act.

`POST .../policies/evaluate` is explicitly a **dry run**. It reports the authorization
decision, the policy decision and the effective answer side by side — so a client can
see which layer produced the outcome — and performs no action, records no decision,
creates no approval and writes nothing.

## Who may manage policies

| Role | `policy.read` | `policy.create` | `policy.update` | `policy.delete` |
|---|---|---|---|---|
| owner | ✓ | ✓ | ✓ | ✓ |
| admin | ✓ | ✓ | ✓ | ✓ |
| security_admin | ✓ | ✓ | ✓ | — |
| ai_admin | — | — | — | — |
| analyst | — | — | — | — |
| viewer | — | — | — | — |

The reasoning, stated because a permission table without one is a table nobody can
review:

- **owner / admin** — general administration manages governance records outright.
- **security_admin** — writing a policy *is* recording a containment decision, which is
  this role's job, so it may read, create and update. Deleting one is not: removing the
  record stays with the owner and the administrator, exactly as deleting an asset or an
  agent does.
- **ai_admin** — holds no policy permission, on purpose. The party whose work a policy
  constrains does not write the constraint.
- **analyst / viewer** — policies are governance configuration, not inventory and not
  security findings, so neither reads them.

The matrix is reviewed in code (`core/permissions.py`), in a second literal copy in
`tests/test_permissions.py`, and behaviourally in `tests/test_policy_authorization.py`,
which exercises every role against the real routes.

## Database

Migration `0005_policies` adds two tables. Nothing existing was altered, and nothing was
dropped: the upgrade applies to an empty database and to a Phase 5 one identically, and
the downgrade removes exactly what it added.

```
aicore.policies
  id                uuid pk
  organization_id   uuid not null → organizations(id) on delete restrict
  name              varchar(96) not null          ─┬─ unique (organization_id, name)
  description       varchar(500) not null          │
  status            varchar(16) not null  default 'draft'   CHECK in the four states
  current_version   integer not null default 1              CHECK >= 1
  created_at, updated_at  timestamptz
  unique (organization_id, id)   ← so a version can reference the pair
  index  (organization_id, status)

aicore.policy_versions
  policy_id         uuid pk ─┐
  version           integer pk ─┴─ (policy_id, version)          CHECK version >= 1
  organization_id   uuid not null
                    └─ (organization_id, policy_id) → policies(organization_id, id)
                       on delete CASCADE
  effect            varchar(32) not null   CHECK in (allow, deny, require_approval)
  resource          varchar(32) not null   CHECK in the resource vocabulary
  action            varchar(16) not null   CHECK in the action vocabulary
  priority          integer not null       CHECK between 0 and 1000
  conditions        jsonb not null         CHECK jsonb_typeof = 'array'
                                           CHECK jsonb_array_length <= 8
  created_at        timestamptz not null   ← no updated_at: nothing updates a version
  index (organization_id, resource, action)
```

Three decisions worth reading:

- **A version cannot belong to another organization's policy.** The composite key
  `(organization_id, policy_id)` references `policies(organization_id, id)`, so a
  cross-tenant version is *unrepresentable* rather than merely rejected — the same
  technique `assets` and `agents` use.
- **The database enforces the invariants; the application enforces the vocabulary.**
  Shape and size of the conditions, the bounds and the closed status/effect/resource/
  action sets are `CHECK` constraints, so no writer — migration, data fix, `psql` — can
  store a shape the schema does not allow. Which *operator* belongs with which *field*,
  which values a field accepts and which pairs are permissions are facts about the
  language, and they live in `core/policy.py`. Tests assert the two agree: the constraint
  sets are compared with the code vocabularies, and the numeric bounds with the constants.
- **JSONB holds the condition array and nothing else.** Not one uncontrolled blob: the
  column is constrained to an array of bounded length, and every element is validated on
  the way in and re-validated on the way out.

Deleting a policy deletes its versions by cascade (an orphaned version is unreachable);
deleting an *organization* is refused while any policy exists (`ON DELETE RESTRICT`), so
removing a tenant stays an explicit procedure.

## Example policies

```jsonc
// Nothing in production changes without a human deciding.
{ "name": "Production agent changes need review", "resource": "agent", "action": "update",
  "effect": "require_approval", "priority": 10,
  "conditions": [{ "field": "environment", "operator": "equals", "value": "production" }] }

// Nobody but the owner deletes an asset that is still in service.
{ "name": "Owners delete active assets", "resource": "asset", "action": "delete",
  "effect": "allow", "priority": 100,
  "conditions": [{ "field": "resource_status", "operator": "equals", "value": "active" }] }

// A blanket deny for a target this organization has decided is out of bounds.
{ "name": "No agent deletion in this organization", "resource": "agent", "action": "delete",
  "effect": "deny", "priority": 500, "conditions": [] }

// High-risk records get a stricter rule than everything else.
{ "name": "High-risk assets are read-only in production", "resource": "asset", "action": "update",
  "effect": "deny", "priority": 0,
  "conditions": [
    { "field": "environment", "operator": "equals", "value": "production" },
    { "field": "risk_classification", "operator": "in", "value": ["high", "critical"] }
  ] }
```

## Security semantics, in one place

- A policy **cannot grant**. It cannot add a permission to a role, cannot bypass Phase 5,
  and cannot turn a denial into a permit.
- A policy **cannot target another organization's resource**: policies are tenant-scoped
  at the repository, at the query and at the row.
- A foreign policy id answers **404**, identical to an id that does not exist — no
  existence oracle, no cross-tenant enumeration.
- **Only authorized roles** read or write policies, and the routes enforce that through
  Phase 5 rather than through a check of their own.
- **Nothing arbitrary is interpreted**: no `eval()`, no policy-authored SQL, no
  expression tree, no model call, no network call during evaluation.
- **Nothing is executed.** No action, no interception, no approval, no suspension, no
  incident, no notification. The engine evaluates; the action firewall — a later phase —
  enforces.

## Boundaries (what this phase is not)

- No runtime enforcement, interception, firewall or containment; no kill switch.
- No approval workflow, approver, queue or UI: `require_approval` is a value.
- No suspension as a policy action, and no policy-triggered side effect of any kind.
- No monitoring, anomaly or threat detection, incidents or dependency graph.
- No model provider, no Nemotron, no Nebius, no cloud integration.
- No Control Center UI: this phase ships a backend contract and shared types.
