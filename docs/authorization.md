# Permission model and authorization foundation (Phase 5)

Phase 2 answered "who may do what here?" with a membership, a role and a set of
explicit permissions, checked before a handler runs. Phase 5 makes that answer a
*thing the system can state*:

```
identity → resource → action → permission → authorization decision
```

One question, asked in one place, answered as a value:

> May this principal use this permission in this organization — for this row?

```
authorize(principal, organization, permission[, scope]) → AuthorizationDecision
```

The decision is deterministic, computed from database facts, and carries a
machine-readable reason. Nothing in this path consults a policy engine, a network
service or a model. **Phase 5 is a foundation, not enforcement**: it did not add a
runtime control plane, approvals or a policy language, and no route gained a
capability it did not have. (Phase 6 added the policy language *on top of* this
decision, and Phase 7 added the action firewall that acts on it — neither changed
the vocabulary or the decision itself; see [actions.md](actions.md).)

## The vocabulary

A permission identifier is `resource.action`, and both halves are closed enums in
`aicore_api/core/permissions.py`.

| Resource | Actions available today | What it governs |
| --- | --- | --- |
| `organization` | `read`, `update` | The tenant itself |
| `user` | `read`, `manage` | The member directory and the membership lifecycle |
| `role` | `read`, `manage` | The role catalog — and the permission catalogue, which is read through it |
| `audit` | `read` | The Phase 8 audit trail: read-only, through one endpoint |
| `security` | `read`, `create` | Security posture and findings: the Phase 10 risk reads, and recording an assessment |
| `asset` | `read`, `create`, `update`, `delete` | The AI inventory |
| `agent` | `read`, `create`, `update`, `delete` | The agent registry |

| Action | Means |
| --- | --- |
| `read` | See it |
| `create` | Bring it into existence |
| `update` | Change it |
| `delete` | Remove it |
| `manage` | Administer the lifecycle of the resource as a whole (memberships, roles) |

Two resources the phase was asked to name have **no namespace of their own**, and
that is deliberate:

- **membership** is governed by `user.read` / `user.manage` — Phase 2 chose those
  codes for the member directory and for adding, changing and removing members;
- the **permission catalogue** is read through `role.read`, because a permission
  only means something as part of a role (`GET /permissions` sits beside
  `GET /roles` and requires the same permission).

Renaming a permission code is a migration: codes are stored in the database,
published by the API and asserted by tests. Phase 5 documents the mapping instead
of churning it, which is also why no permission code and no role grant changed.

Reading the vocabulary in code:

```python
from aicore_api.core.permissions import Action, Permission, Resource, permissions_for_resource

Permission.parse("agent.update").resource is Resource.AGENT   # True
Permission.parse("agent.update").action is Action.UPDATE      # True
permissions_for_resource("agent")                             # the four agent.* permissions
Permission.parse("agent.execute")                             # raises UnknownPermissionError
```

### What is deliberately absent

There is no `execute`, `approve`, `kill`, `block`, `intercept` or `control`, and no
`policy.*`, `incident.*`, `tool.*` or `firewall.*`. Those belong to the phases
that implement them; declaring one now would advertise enforcement that does not
exist. Two tests assert the absence rather than trusting it
(`test_the_vocabulary_declares_no_future_phase_action`,
`test_the_vocabulary_declares_no_future_phase_resource`).

### The identifier is validated at every door

- **Format** — the same pattern the database `CHECK` constraint uses
  (`PERMISSION_CODE_PATTERN`; a test asserts it equals the model's `CODE_PATTERN`),
  exactly two segments, lowercase.
- **Membership** — `Permission.parse()` refuses a well-formed code this build does
  not declare, so `policy.read` cannot travel in as "the permission we will need".
- **Routes** — `require_permission(Permission.X)` takes the enum, so a route cannot
  declare a string; the route's requirement is stamped onto its dependency and
  read back by the structural tests.
- **Database** — `aicore.permissions.code` is unique, format-checked, and seeded by
  migration; `test_permissions.py` compares the code catalogue with the seeded rows
  in both directions (a code in one place only fails the suite).

## The decision

```python
@dataclass(frozen=True, slots=True)
class AuthorizationDecision:
    allowed: bool
    reason: DecisionReason          # role_permission_grant, missing_permission, …
    permission: Permission | None   # None when only membership was asked about
    organization_id: uuid.UUID | None
    role_code: str | None
    membership_id: uuid.UUID | None
    instance_organization_id: uuid.UUID | None
    principal_is_owner: bool | None
```

`resource` and `action` are derived properties of `permission`.

| Reason | Means | HTTP |
| --- | --- | --- |
| `role_permission_grant` | Active membership, role grants the permission | 200/201/204 |
| `active_membership` | No permission was asked for; the caller is a member | 200 |
| `missing_membership` | No membership — or no such organization | **404** |
| `membership_not_active` | A member whose membership is suspended | **403** |
| `missing_permission` | Active member, permission not granted | **403** |
| `resource_outside_tenant` | The row belongs to another organization | **404** |
| `unknown_role` | A role this build cannot reason about | **500** (loud defect) |

Three properties the tests assert:

- **Total.** Every input produces ALLOW or DENY, including a role the code does not
  know — it *denies*, so nothing is ever silently permissive. The HTTP boundary
  still raises for that case: a database whose catalog disagrees with the code is a
  deployment defect, and a quiet 403 would hide it.
- **Deterministic and local.** No clock, no randomness, no model, no network
  client: `test_the_decision_path_contains_no_model_call_and_no_network_client`
  scans the decision path's source for all of them, and repeated identical
  questions are asserted to produce identical decisions.
- **Contained.** A denial for a non-member carries no identifier from the tenant
  they asked about (the only id present is the one they supplied), so recording a
  decision cannot leak a foreign tenant.

`authorize()` is the reporting form; `resolve_organization_context()` is the
raising wrapper the routes use, and `OrganizationContext` carries the decision that
produced it — a handler can answer "why was this allowed?" without re-deriving it.

## Instance authorization: permission + tenant + ownership

Holding `asset.update` is not the same as being allowed to update *this* row.
`auth/authorization.py` adds a pure, database-free instance dimension:

```python
authorize(context, permission, scope=ResourceScope(organization_id=…, owner_membership_id=…))
authorize_instance(context, scope, permission=…)      # from an already-resolved context
```

- a row in another organization is denied even for a caller holding the
  permission — tenancy is part of the question, not an assumption about the query
  that loaded the row;
- **ownership is reported, never relied upon**: `principal_is_owner` is `True`,
  `False` or `None` (row with no owner). It never widens an ALLOW in this phase —
  owning a row grants nothing that the role does not already grant, which is
  asserted (`test_ownership_is_reported_and_never_widens_a_decision`);
- ownership integrity stays where Phase 3 put it: the composite foreign key that
  makes a cross-tenant owner *unrepresentable* in the database. Phase 5 does not
  create a second ownership system; `ResourceScope` reads the facts the row already
  carries, and refuses an object that cannot state its organization.

### Routes authorize the row, not only the permission

Every item route (assets and agents: read, update, delete, and the agent identity
lookup) loads its row through a tenant-scoped repository and then asserts it with
`api/scope.py`:

```python
require_instance_scope(context, asset, permission=Permission.ASSET_UPDATE, detail="Asset not found")
```

In a correct build this can only pass — which is the point. It turns a property of
the query into an assertion about the answer, so a repository that loses its tenant
filter (a bug, not a policy) fails closed with the same 404 a missing row gets,
instead of serving another organization's record. Two tests prove the guard is
reachable by making a repository return a foreign row and asserting that every verb
answers 404.

## Denial semantics (unchanged, now explicit)

| Situation | External answer |
| --- | --- |
| No organization / not a member | `404` — identical to each other, byte for byte |
| Row in another organization | `404` — identical to "no such row" |
| Suspended membership | `403` — the caller is a member and can see why |
| Missing permission | `403` — names the permission it requires |
| Client-settable organization | Impossible: the organization comes from the path, the caller from the credential |

The two 404s are the security contract, not a convention: any difference between
"not there" and "not yours" is an enumeration oracle. The instance layer's denials
are mapped by `api/scope.py` so the same rule holds one level down.

## Role matrix

Phase 5 reviewed the matrix against the resources that exist and **kept it** — the
grants below answer capabilities the application can actually enforce, and no role
was widened:

| Permission | owner | admin | security_admin | ai_admin | analyst | viewer |
| --- | :-: | :-: | :-: | :-: | :-: | :-: |
| `organization.read` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `organization.update` | ✅ | ✅ | — | — | — | — |
| `user.read` | ✅ | ✅ | ✅ | ✅ | — | — |
| `user.manage` | ✅ | ✅ | — | — | — | — |
| `role.read` | ✅ | ✅ | — | — | — | — |
| `role.manage` | ✅ | — | — | — | — | — |
| `audit.read` | ✅ | — | ✅ | — | — | — |
| `security.read` | ✅ | — | ✅ | — | ✅ | — |
| `asset.read` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `asset.create` | ✅ | ✅ | — | ✅ | — | — |
| `asset.update` | ✅ | ✅ | ✅ | ✅ | — | — |
| `asset.delete` | ✅ | ✅ | — | — | — | — |
| `agent.read` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `agent.create` | ✅ | ✅ | — | ✅ | — | — |
| `agent.update` | ✅ | ✅ | ✅ | ✅ | — | — |
| `agent.delete` | ✅ | ✅ | — | — | — | — |

Totals as Phase 5 left them: owner 16, admin 13, security_admin 8, ai_admin 8,
analyst 4, viewer 3.

> **Phase 6 extended this catalog** with `policy.read` / `policy.create` /
> `policy.update` / `policy.delete`, granted to owner, admin and (read/create/update
> only) security_admin. **Phase 7 added one more**: `action.execute`, the permission
> that guards the action firewall, held by owner, admin and security_admin — the
> catalog is now **21 permissions, 66 grants**, head `0006_action_firewall`, with the
> per-role totals owner 21, admin 18, security_admin 12, ai_admin 8, analyst 4,
> viewer 3. The matrix in this document is the Phase 5 review and is left as it was
> written; the policy grants are in
> [policies.md](policies.md#who-may-manage-policies) and the action grants — including
> why the AI administrator deliberately does not hold `action.execute` — in
> [actions.md](actions.md).

`test_the_role_matrix_is_exactly_the_documented_one` spells the matrix out a second
time, literally, on purpose: the existing parity test would still pass if somebody
widened a role in the code table *and* the seed at once. This one makes a privilege
change a visible diff.

## Database

Phase 5 reviewed the catalog tables against the requirements and **found no schema
change necessary** — so there was no Phase 5 migration and the head stayed
`0004_agents`. Phase 6 left those tables exactly as they were too: it added its four
policy permissions *as rows* in `0005_policies`, using the invariants below rather
than new ones:

| Requirement | Where it already holds |
| --- | --- |
| Permission code uniqueness | `uq_permissions_code` |
| Permission code format | `ck_permissions_code_format` (`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$`) |
| Role code uniqueness and format | `uq_roles_code`, `ck_roles_code_format` |
| Role-permission uniqueness | `role_permissions` primary key `(role_id, permission_id)` |
| Valid foreign keys | `role_permissions` → `roles` (`CASCADE`) and → `permissions` (`RESTRICT`); `memberships.role_id` → `roles` (`RESTRICT`) |
| Safe deletion | deleting a granted permission is refused; deleting a role with members is refused; deleting a role drops its grants |
| Tenant correctness | the catalog is installation-wide reference data by design; which role a member holds is tenant-owned (`memberships`), so "who may do what here" is always a join from a tenant row |

Nothing was added because nothing was missing: a redundant constraint or an
unused column would be a claim those phases could not justify. Phase 6 consequently
added no catalog *schema* either — only the four permission rows and their grants,
in its own migration (`0005_policies`), which is compared against
`core/permissions.py` by `tests/test_migrations.py`. Phase 7 added one permission and
three grants the same way, in `0006_action_firewall`. The catalog holds **21
permissions, 6 roles, 66 grants**.

## API impact

One additive change, on the endpoint that already published the catalog:

```jsonc
// GET /organizations/{organization_id}/permissions  (role.read)
{
  "organization_id": "…",
  "permissions": [
    {
      "code": "agent.update",
      "resource": "agent",      // ← new: closed vocabulary, published as an enum
      "action": "update",       // ← new
      "description": "Change a registered agent's record, version or lifecycle state."
    }
  ]
}
```

`resource` and `action` are typed as `Resource` and `Action` in the OpenAPI
document, so a client gets the vocabulary from the contract rather than by parsing
strings, and `packages/types` mirrors them as literal unions
(`PermissionResource`, `PermissionAction`).

Everything else is unchanged: no new routes, no new permissions, no new request
fields, and `GET /me` still reports a membership's permissions as codes. There is
deliberately **no permission-mutation API**: who may do what is a reviewed
migration, not a runtime mutation.

## Verification

| Guarantee | Test |
| --- | --- |
| Every permission is a validated `resource.action` pair, unique | `test_permissions.py` |
| An undeclared or malformed code is refused (23 shapes today; 17 when Phase 5 reviewed it, 20 after Phase 6) | `test_an_undeclared_permission_code_is_refused` |
| No future-phase action or resource is declared | `test_the_vocabulary_declares_no_future_phase_*` |
| Code catalogue ≡ seeded rows, both directions | `test_the_seeded_catalog_holds_exactly_the_declared_permissions` |
| The role matrix is exactly the documented one | `test_the_role_matrix_is_exactly_the_documented_one` |
| Allow/deny reasons, including unknown role and suspended membership | `test_authorization_decisions.py` |
| A foreign row is denied; ownership never widens an ALLOW | `test_a_row_in_another_organization_is_denied_even_with_the_permission`, `test_ownership_is_reported_and_never_widens_a_decision` |
| Decisions are deterministic | `test_the_same_question_always_has_the_same_answer` |
| No model call, client, clock or RNG in the decision path | `test_the_decision_path_contains_no_model_call_and_no_network_client` |
| Item routes authorize the row they loaded | `test_an_asset_route_refuses_a_row_that_is_not_in_the_callers_organization`, and the same for agents |
| Route permission matches the route's resource and method | `test_every_tenant_route_declares_one_permission_that_matches_its_resource_and_method` |
| The vocabulary is published, not just documented | `test_the_permission_vocabulary_is_published` |

```bash
bash scripts/test-db.sh     # migrations from an empty database, round trip, full suite
bash scripts/verify.sh      # lint, format, typecheck, tests, secrets, compose
```

## What Phase 5 does not implement

- **No policy engine and no policy language.** Phase 5 decides; the Phase 6 policy
  layer can only further restrict it, and the Phase 7 firewall consumes both. What this
  phase does not do is keep history: authorization writes no row of its own, and the
  Phase 8 trail records a decision only when the pipeline acts on it — see
  [audit.md](audit.md).
- **No runtime enforcement.** Nothing intercepts an action, blocks a tool or stops
  an agent. `status: suspended` remains a record.
- **No approvals, no kill switch.** Those arrive with the phases that implement
  them. The action firewall exists since Phase 7, and it is not a fourth decision
  layer: it consumes this phase's decision object, refuses anything that is not an
  `ALLOW`, and runs a registered action through [actions.md](actions.md).
- **No LLM anywhere in the decision path** — asserted structurally, not by
  intention.
- **No ABAC engine and no attribute rules.** The only context a decision reads is
  the membership, the role, the permission, the tenant and the ownership fact the
  row carries.
- **No permission-mutation API and no custom roles.** Roles are shipped data,
  changed by reviewed migration.
- **The trail records; it never decides.** Phase 8 writes one audit event per action
  decision — including the denials and the approval requirements this layer returns —
  and one per lifecycle change. It takes no part in a decision: a decision is made
  first, then recorded; `audit.read` guards the read side, and nothing can write the
  trail through the API.
