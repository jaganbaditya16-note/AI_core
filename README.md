# AICore

**Enterprise AI Control Plane** — currently at **Phase 8: the audit trail**. Phase 0
delivered the skeleton, Phase 1 the PostgreSQL schema and tenant boundary, Phase 2 the
identity layer on top of it (bearer tokens identify a user, memberships bind them to an
organization with a role, protected routes authorize against explicit permissions),
Phase 3 the AI asset inventory, Phase 4 the agent registry (a stable, server-generated
identity for one of those assets), Phase 5 the authorization foundation (a closed
resource/action vocabulary and a deterministic, structured authorization decision),
Phase 6 the policy engine (org-scoped definitions, a closed condition language, a
deterministic evaluator, versioned history), Phase 7 the action firewall (the enforcement
boundary: only `ALLOW` reaches an adapter) and Phase 8 the audit trail: an append-only,
tenant-scoped record of security-relevant activity, written by the platform and read
through one read-only endpoint.

AICore is intended to let an organization discover the AI running in its
environment, control what that AI is allowed to do, and monitor what it did, with
an intelligence layer (NVIDIA Nemotron via Nebius Token Factory) providing
reasoning and recommendations.

**Discovery is not automatic, and enforcement is one narrow thing.** Nothing in
this repository scans a network or a cloud account: assets are recorded by a person
through the API, or by a future integration through the internal service boundary
described in [`docs/inventory.md`](docs/inventory.md). The policy engine
**evaluates**; since Phase 7 the **action firewall** enforces — for one thing only:
running a registered action from a closed, code-level catalogue, through a pipeline
that authenticates, authorizes, evaluates a policy and decides before any adapter is
called. Only `ALLOW` reaches an adapter. Since Phase 8 that pipeline also **records**:
one append-only event per security-relevant operation, with server-resolved attribution
and a sanitized summary, queryable per organization through one read-only endpoint.
Nothing intercepts an agent, nothing is blocked at runtime, no approval is ever granted,
nothing is monitored and no record is acted on automatically —
[`docs/phase-0-scope.md`](docs/phase-0-scope.md) lists exactly what is absent.

## Architecture direction

```
DISCOVER              CONTROL                  MONITOR
AI inventory          Identity · Permissions   Behaviour · Anomalies
Agent registry        Policy · Action firewall Security · Cost
Model/Tool inventory  Approval · Kill switch   Audit · Incidents
        └──────────────────────┬──────────────────────┘
                               ▼
                          INTELLIGENCE
                    Nemotron · Nebius Token Factory
```

**Core principle:** the model reasons, explains and recommends. **Deterministic
AICore services make the authorization, policy and security decisions.** The LLM
is never the final security authority — which is why the foundation couples
nothing to a model provider.

## Technology stack (locked)

| Layer | Choice |
|---|---|
| Frontend | Next.js 16 (App Router), TypeScript, Tailwind CSS v4, npm |
| Backend | Python 3.11+, FastAPI, Pydantic v2 |
| Database | PostgreSQL 16 (SQLAlchemy 2 + psycopg 3) |
| Infrastructure | Docker, Docker Compose |
| Testing | Pytest, Playwright |
| API | REST + OpenAPI |
| Motion | framer-motion (used minimally — one entrance transition, reduced-motion aware) |

Redis and Supabase are deliberately **not** part of this architecture.

## Repository structure

```
apps/
  web/                  Next.js frontend
    src/app/            overview, /health, /api/health proxy, error/loading/not-found
    src/lib/            server-only config + health client
    src/components/     health panel, motion wrapper
  api/                  FastAPI backend
    src/aicore_api/     main · config · cli · api · auth · core · db · discovery · schemas
    tests/              Pytest suite (unit + PostgreSQL integration)
packages/
  types/                shared API contract types (health, errors, organizations, identity, assets,
                        agents, permissions, policies, actions, audit)
database/
  init/                 one-time bootstrap SQL (schema namespace only)
  migrations/           Alembic environment and revisions
    versions/0001_organizations.py
    versions/0002_identity_and_rbac.py
    versions/0003_assets.py
    versions/0004_agents.py
    versions/0005_policies.py
    versions/0006_action_firewall.py
    versions/0007_audit_events.py
tests/e2e/              Playwright smoke tests
docs/                   architecture, scope, development guide, inventory, agents, authorization, policies, actions, audit, ADRs
infrastructure/         docker-compose.yml
scripts/                dev-db, dev-api, py, migrate, test-db, verify, check-secrets
```

## Local setup

```bash
cp .env.example .env          # then set POSTGRES_PASSWORD
npm install
bash scripts/py.sh -c pass    # creates apps/api/.venv, installs API deps
```

## Start the stack

**1 — PostgreSQL** (no Docker needed):

```bash
bash scripts/dev-db.sh        # prints the AICORE_DATABASE_URL to export
```

or with Docker:

```bash
docker compose --env-file .env -f infrastructure/docker-compose.yml up -d db
```

**2 — Backend:**

```bash
npm run dev:api               # http://127.0.0.1:8000 · docs at /docs
curl http://127.0.0.1:8000/health
# {"status":"ok","service":"aicore-api","version":"0.1.0","environment":"development"}
```

**3 — Frontend:**

```bash
npm run dev                   # http://127.0.0.1:3000
```

Whole stack in containers:

```bash
docker compose --env-file .env -f infrastructure/docker-compose.yml up --build
# web → http://localhost:3000 · api → http://localhost:8000 · db → localhost:5432
```

## Environment variables

All variables are documented in [`.env.example`](.env.example). Nothing is
hardcoded, `.env` is gitignored, and the web container never receives database
credentials.

| Variable | Purpose |
|---|---|
| `POSTGRES_USER` / `POSTGRES_PASSWORD` / `POSTGRES_DB` / `POSTGRES_PORT` | database provisioning (Compose) |
| `AICORE_DATABASE_URL` | API → PostgreSQL (**required**, PostgreSQL-only, never logged) |
| `AICORE_ENVIRONMENT` / `AICORE_DEBUG` / `AICORE_LOG_LEVEL` | runtime mode; `production` rejects debug and wildcard CORS |
| `AICORE_CORS_ALLOW_ORIGINS` | empty by default (same-origin proxy) |
| `AICORE_AUTH_PROVIDER` | credential provider; `api_token` today, external identity providers later |
| `API_INTERNAL_URL` | server-side address the web tier uses to reach the API |
| `API_REQUEST_TIMEOUT_MS` | backend request timeout (250–30000 ms) |
| `NEXT_PUBLIC_API_URL` | optional fallback; anything `NEXT_PUBLIC_*` is public |

## Tests and checks

```bash
npm run lint          npm run typecheck      npm run build
npm run test:api      npm run test:e2e       npm run verify:motion
npm run check:secrets
npm run verify                # lint, types, tests, build, secret scan, LICENSE
bash scripts/verify.sh --full # + live PostgreSQL + E2E where available
```

`bash scripts/test-db.sh` starts a real PostgreSQL, provisions the role and
database, migrates it from empty, checks the schema against the models
(`alembic check`), proves the migration reverses, and runs the whole suite against
it — readiness included.

## Health contract

| Endpoint | Meaning | Failure mode |
|---|---|---|
| `GET /health` | liveness — process is serving; no dependencies touched | never fails while running |
| `GET /health/ready` | readiness — PostgreSQL reachable (`SELECT 1`) | `503` with the failing check named |
| `GET /api/health` (web) | same-origin proxy report for the browser | `503`, structured `errors[]` |

Every non-2xx API response uses one envelope:
`{"error": {"code", "message", "details", "request_id"}}`, and every response
carries `X-Request-ID`.

## Current limitations

- **No sign-up, login or session management.** Credentials are provisioned out of
  band with the CLI (see below); there is no password anywhere in AICore, and the
  frontend is never a security boundary.
- **No user-management API.** Adding members and issuing tokens is an operator
  action. `POST /organizations` remains a development/test provisioning route
  (404 everywhere else), because this phase has no platform-administrator concept
  that could authorize tenant creation.
- **`security.read` has no subject yet.** It is part of the catalog and appears on
  `GET /me`, but there is no security finding to read — no route pretends otherwise.
  (`audit.read` is no longer in that position: since Phase 8 it guards the audit
  trail's read-only endpoint.)
- **No domain tables beyond the tenant root, the identity tables, the asset
  inventory, the agent registry, the policy record, the execution ledger and the audit
  trail.** Incident and monitoring tables arrive in later phases, through migrations.
- **No agent runtime.** An agent registry record names an agent; it does not run
  one. There is no execution, no session, no tool invocation, no credential issued
  to an agent, and `status: suspended` is a recorded state rather than a kill
  switch — see [docs/agents.md](docs/agents.md).
- **No automatic discovery.** Nothing scans a network or a cloud account, and no
  provider is integrated. Assets are registered by a person or by a future
  integration through an internal service boundary — see
  [docs/inventory.md](docs/inventory.md).
- **No runtime enforcement of an agent.** Phase 7 admits one kind of execution —
  a registered action from a closed catalogue, one entry of which is a read-only
  posture assessment — and refuses everything else before an adapter is reached. There
  is still no action interception, no blocking, no approval workflow, no
  suspension-as-a-policy-action, no kill switch, no agent execution and no
  containment: a policy decision that says `require_approval` states that approval is
  required and does nothing further. See [docs/policies.md](docs/policies.md) and
  [docs/actions.md](docs/actions.md).
- **No AI features.** No model provider is integrated; no runtime containment,
  behaviour monitoring or incident handling.
- **The audit trail is a record, not a control.** There is no monitoring dashboard, no
  metrics, no anomaly detection, no baselining, no alerting, no incident management, no
  retention job and no hash chain — a plain SHA-256 chain stored beside the rows it
  covers would be recomputable by anyone who can write them, so the phase implements the
  part that is real without a key-management design and states the deferral:
  [docs/audit.md](docs/audit.md).
- **Local verification caveats:** this sandbox has no Docker and blocks
  Playwright's browser CDN, so Compose is validated as configuration (and in CI)
  and E2E runs in CI or on a developer machine with browser access. Both are
  reported honestly by `scripts/verify.sh` rather than skipped silently.

## What Phase 8 adds

The **audit trail**: the durable, tenant-scoped record of security-relevant activity —
who did what, in which organization, when, against which resource, with what decision,
and what came of it. It observes and records; it never decides or executes, and it
cannot change an answer.

- **One append-only table** — `aicore.audit_events`, with the tenant boundary, closed
  vocabularies, server-generated `id` and `occurred_at`, and no `updated_at` at all.
  `UPDATE`, `DELETE` and `TRUNCATE` are refused by database triggers; the single
  exception is a transaction-local, greppable override that permits deletion only, and
  Phase 8 has no retention policy to use it.
- **One internal writer** — `AuditWriter`, reached through the Phase 3 event seam
  (`emit_event(..., session=session)`). The organization, the person and the membership
  are resolved from the authorized request context, never from a body; an operation
  nobody performed is recorded with no actor rather than a fabricated one.
- **A closed vocabulary with real emit sites** — inventory, agent registry, policy record,
  ingestion and the whole action pipeline. The four axes stay separate: `event_type`
  (what happened), `action` (which operation), `decision` (what was decided) and
  `outcome` (how it ended), reusing Phase 7's vocabulary (`allow` + `success`,
  `deny` + `blocked`, `require_approval` + `not_executed`).
- **Phase 7 integration** — an admitted execution is recorded *before* anything can run
  (fail-closed), the decision is recorded once, naming the layer that produced it, and
  the ending is recorded after the adapter has acted (best-effort, so a failure to write
  can never turn a completed execution into a reported failure). The recording never
  lets a `DENY` execute and never changes decision precedence.
- **Metadata security** — a bounded, flat, sanitized summary. Credential-shaped keys and
  values are redacted, nested or oversized documents are refused, and action arguments
  are never stored: an execution records that it had `N` arguments, not what they were.
- **A read-only query API** — `GET /organizations/{id}/audit-events`, guarded by the
  existing `audit.read`, with twelve filters, mandatory bounded pagination and
  deterministic `occurred_at DESC, id DESC` ordering. Foreign organizations answer
  exactly like missing ones.
- **No new permission and no matrix change** — `audit.read` (owner, security_admin) was
  declared in Phase 2 for this purpose. There is no `audit.update`, `audit.delete` or
  `audit.write`; a permission to change history would defeat the point of keeping it.
- **Migration `0007_audit_events`** — the table, its constraints, six indexes and the
  append-only trigger function, and nothing else. No earlier table is touched.

**The audit trail is not the execution ledger, and it is not a monitoring system.** The
Phase 7 `action_executions` table is an idempotency mechanism and forgets refusals; the
audit trail records them and has no key. And a record is not a control: there is no
anomaly detection, no baseline, no dashboard, no alerting, no incident response and no
containment. A hash chain is deliberately deferred, because a recomputable one would
look like evidence while proving nothing — see [docs/audit.md](docs/audit.md).

Design, event model, metadata boundary, append-only semantics and limitations:
[docs/audit.md](docs/audit.md).

## What Phase 7 adds

The **action firewall**: the enforcement boundary between a decision and anything
actually happening. A request to run one registered action is authenticated,
authorized, evaluated against the organization's policies and decided — and only an
`ALLOW` reaches an adapter.

- **A closed action catalogue** — `ActionDefinition` / `ActionRegistry`: identifier,
  resource type, description, input schema, target requirement and sensitivity, bound
  to an adapter by identifier. One action ships: `agent.posture_check`, a read-only
  assessment. An unknown identifier is a 422 that names the catalogue; nothing is
  imported, resolved or interpreted to answer it.
- **A typed request** — `ActionRequest` carries the tenant, the principal, the
  membership, the optional attributed agent, the action, the target, the validated
  arguments, the environment, the correlation id and an idempotency key. A client
  cannot state the tenant, the caller, the permission, the executor or a command: the
  body has no field for them and refuses extras.
- **One typed decision** — `ALLOW` / `DENY` / `REQUIRE_APPROVAL`, with a stable
  reason. Phase 5's denial and Phase 6's denial both map to `DENY`;
  `require_approval` never executes; a missing target or an environment the record
  does not confirm is a refusal. Mismatched inputs raise rather than decide.
- **An adapter boundary** — one explicit interface, reached only through the
  execution service, which re-checks the decision instead of trusting its caller.
  `tests/test_actions_api.py` asserts structurally that the adapter registry is a
  dependency of exactly one route.
- **Idempotency, not a workflow** — a required key; a retry of the same request
  returns the recorded answer without running the adapter again, a key reused for a
  different request is a 409, and a failed run keeps its key.
- **One new permission** — `action.execute` (owner, admin, security_admin), which is
  also the policy target an organization writes a rule against. No `agent.execute`,
  no wildcard, no per-action permission.
- **Migration `0006_action_firewall`** — the idempotency ledger with the tenant
  boundary, the key uniqueness and the status/outcome/error ties as constraints, plus
  the one permission and the policy target vocabulary widened by one pair.

Design, request model, decision flow and security guarantees:
[docs/actions.md](docs/actions.md).

## What Phase 6 adds

The **context-aware policy engine**: a way for an organization to record what it
decides about an action in a given situation, and a deterministic evaluator that turns
those records into a decision — without ever replacing the authorization layer.

- **Policy definitions, org-scoped** — `resource.action` from the permission catalogue,
  an effect (`allow` / `deny` / `require_approval`), a priority, a status and a list of
  conditions. One tenant per policy; there is no global or shared policy.
- **A closed condition language** — nine fields with typed values and closed sets, and
  eight operators. No expressions, no user code, no `eval()`, no policy-authored SQL,
  no `OR`, no nesting. A value that does not fit its field is refused before the policy
  is stored, and an invalid stored definition cannot be activated.
- **A deterministic evaluator** — `deny` beats `require_approval` beats `allow`,
  then priority, then name and id, and never the order rows arrived in. The engine is a
  pure function of its arguments: no clock, no database, no network, no model call,
  asserted structurally.
- **A policy can only restrict** — the effective answer is the authorization decision
  *and* the policy decision, so a Phase 5 denial can never become a permit, and missing
  context never reads as "allowed".
- **Versioned history** — editing a definition appends a version and never rewrites
  one, so a decision that names a version stays explainable. Labels and rationale are
  not versions; an edit that changes nothing is not a version either.
- **Four policy permissions** — `policy.read` / `create` / `update` / `delete`, granted
  to owner, admin and (for read/create/update) security_admin. No `policy.execute`,
  `policy.approve` or `policy.kill`: evaluation is a read, and no role may make a policy
  act. Phase 6 left the matrix at 20 permissions / 63 grants; Phase 7 took it to
  21 / 66 with `action.execute`.
- **A documented dry run** — `POST .../policies/evaluate` reports the authorization
  decision, the policy decision and the effective answer side by side, and performs no
  action, records nothing and approves nothing.
- **Migration `0005_policies`** — new head; two new tables with the tenant boundary in
  the schema (composite foreign key), closed statuses, effects, targets and bounds as
  `CHECK` constraints, and JSONB only for the structured condition array.

Design, condition language, precedence and boundaries:
[docs/policies.md](docs/policies.md).

## What Phase 5 adds

The **authorization foundation**: authorization is a vocabulary and a decision, not
a string comparison hidden in a handler.

- **A resource/action vocabulary** — every permission is `resource.action`
  (`agent.update` → `agent` + `update`) whose halves come from closed enums:
  resources `organization`, `user`, `role`, `audit`, `security`, `asset`, `agent`
  and actions `read`, `create`, `update`, `delete`, `manage`. Nothing else parses;
  there is no `execute`, `approve`, `kill` or `policy.*` until a phase implements
  one.
- **A deterministic decision object** — `AuthorizationDecision` answers *may this
  principal use this permission in this organization, for this row?* with ALLOW or
  DENY, a machine-readable reason (`role_permission_grant`, `missing_permission`,
  `missing_membership`, `membership_not_active`, `resource_outside_tenant`,
  `unknown_role`), and the identifiers it was made from. No model call, no network
  client, no clock, no randomness — asserted structurally.
- **Instance authorization** — holding `asset.update` is not enough for a row in
  another organization, and every item route additionally authorizes the row it
  loaded, so a repository that lost its tenant filter fails closed with a 404
  instead of serving another tenant's record.
- **Ownership, reported and not relied upon** — a decision says whether the caller
  owns the row; ownership widens nothing in this phase.
- **Unchanged security semantics** — non-members and foreign rows still answer
  404, suspended memberships 403, and the role matrix is reviewed and unchanged
  (owner 16, admin 13, security_admin 8, ai_admin 8, analyst 4, viewer 3).
- **`GET /permissions` publishes the model** — each entry now carries `resource`
  and `action` as closed vocabularies, mirrored in `packages/types`.
- **No migration** — the catalog's constraints (code uniqueness, format checks,
  uniqueness of grants, FK behaviour) were reviewed and already satisfy the
  requirements; the head stays `0004_agents`.

Design, decision semantics and limitations: [docs/authorization.md](docs/authorization.md).

## What Phase 4 adds

The **agent registry**: which agent this is, and whether it is the same agent it
was last week.

- **One stable identity per agent** — `identity_id`, generated by PostgreSQL, never
  derived from a name and never settable by a client. Renaming an agent or shipping
  version 1.3 does not change who the agent is; the display name is pointedly not
  the identity. Identity is unique per organization, so a lookup can never be
  ambiguous across tenants.
- **An extension of the inventory, not a second agent system** — `aicore.agents` is
  one-to-one with an `agent` asset (`asset_id` is unique, and the composite foreign
  key means the agent's record must be in the agent's own organization). Name,
  environment, lifecycle and owner stay on the asset, where Phase 3 already
  constrains them, so there is no second copy to keep in sync.
- **A closed category vocabulary** — `assistant`, `workflow`, `autonomous`,
  `coding`, `customer_support`, `data`, `security`, `other`. Categories describe;
  they never grant.
- **A validated lifecycle** — `draft`, `active`, `suspended`, `retired`, with an
  explicit transition table (`retired` is terminal) and reason-carrying refusals.
  Suspension is registry state: nothing is stopped, revoked or blocked.
- **Version metadata** — `version` plus optional `build_revision` and `framework`,
  so v1.2 and v1.3 are distinguishable while sharing one identity.
- **Registry API** — `GET|POST /organizations/{id}/agents`,
  `GET|PATCH|DELETE /organizations/{id}/agents/{agent_id}` and
  `GET /organizations/{id}/agents/identity/{identity_id}`, with four permissions
  (`agent.read`, `agent.create`, `agent.update`, `agent.delete`) checked by the
  backend. There is deliberately no `agent.execute` or `agent.control`.
- **Audit readiness** — registration, updates and deletion emit domain events
  (`agent.registered`, `agent.updated`, `agent.deleted`).

Design, API usage, security boundaries and current limitations:
[docs/agents.md](docs/agents.md).

## What Phase 3 adds

The AI **inventory**: what an organization knows it has, and what it knows about
each thing.

- **One inventory table, seven asset types** — `agent`, `application`, `model`,
  `tool`, `mcp_server`, `api`, `data_source`, all in `aicore.assets`. The type is a
  column and the type-specific detail lives in validated `metadata`, so list,
  filter, paginate, own, classify and isolate work identically for every type
  instead of being written seven times.
- **Recorded state, not runtime state** — lifecycle (`draft`, `active`,
  `suspended`, `retired`), discovery state (`managed`, `unknown`, `shadow`),
  environment (`development`, `staging`, `production`, `unknown`) and a risk
  classification (`low` … `critical`, `unassessed`) that is **stored only**: no
  scoring, no enforcement, no kill switch.
- **Real ownership** — the owner is a membership in the same organization,
  enforced by a composite foreign key, so a cross-tenant owner is unrepresentable
  in the database rather than rejected by a handler. Application code never
  invents a user.
- **Deterministic deduplication** — `(organization_id, asset_type,
  external_identifier)` is unique when the identifier is present, so re-reporting
  an asset converges on one record. Names are never identifiers.
- **Asset API** — `GET|POST /organizations/{id}/assets`,
  `GET|PATCH|DELETE /organizations/{id}/assets/{asset_id}` and
  `GET /organizations/{id}/assets/owners`: repeatable filters, bounded pagination
  (`limit` ≤ 200, opt-in `total`), and four permissions (`asset.read`,
  `asset.create`, `asset.update`, `asset.delete`) checked by the backend.
- **A discovery seam, not a discovery feature** — `aicore_api.discovery` defines
  the normalise → validate → ownership → record path a future integration calls.
  No cloud or network integration ships, and nothing claims otherwise.
- **Audit readiness** — inventory changes emit domain events
  (`asset.created`, `asset.updated`, `asset.deleted`, `asset.discovered`) through one
  boundary. Phase 8 attached the audit trail to it: an event with a session is a durable
  row as well as a log line, which is exactly the hook this phase left.

Design, API usage and current limitations: [docs/inventory.md](docs/inventory.md).

## What Phase 2 adds

Identity and access control, enforced by the server:

- **Authentication** — bearer API tokens, stored only as SHA-256 hashes, read from
  the `Authorization` header only, revocable and expirable. Credentials are issued
  by `python -m aicore_api.cli`, never over HTTP, and there is no
  development-only authentication path.
- **Roles and permissions** — six roles (`owner`, `admin`, `security_admin`,
  `ai_admin`, `analyst`, `viewer`) built from explicit permissions (eight here;
  twelve after Phase 3 added the four `asset.*` permissions). Code asks for a
  permission, never for a role name, so privilege changes happen in one catalog
  rather than in route handlers.
- **Authorization** — every tenant-scoped route resolves the caller's membership
  in the organization named in the path and checks one required permission before
  the handler runs: `authenticate → identify → resolve organization → verify
  membership → resolve role → resolve permissions → authorize`.
- **Tenant isolation under authentication** — a member of one organization gets
  the same `404` for another organization as for one that does not exist, so
  access refusals leak neither data nor existence.
- **API** — `GET /me` (who am I, which organizations, which roles, which
  permissions) and the authorized organization reads (`GET /organizations/{id}`,
  `/members`, `/roles`, `/permissions`). No more than the phase needs.

Design and rationale: [docs/authentication.md](docs/authentication.md).

## What Phase 1 adds

One table and the boundary every later table inherits:

- **`aicore.organizations`** — the tenant root: UUID key, unique slug, lifecycle
  status, timestamps, all enforced by database constraints.
- **Tenant-owned conventions** — future tables inherit a UUID key, timestamps and
  a non-null `organization_id` foreign key (`ON DELETE RESTRICT`), so a table
  cannot be added without a tenant boundary.
- **An isolation guard** — every statement touching a tenant-owned table is
  refused unless a tenant is bound *and* the statement filters on
  `organization_id`. Tenant context is explicit and request-scoped; there is no
  default tenant to fall back on.
- **Alembic migrations** — a dev dependency, with `bash scripts/migrate.sh`,
  a drift check (`alembic check`) and a proven downgrade path.

Two deliberately narrow exceptions exist so the foundation can be verified: a
minimal `POST /organizations` + `GET /organizations/{id}` persistence path that
answers only in `development` and `test` (it returns 404 elsewhere, and there is
no organization-management API), and a test-only tenant-owned table.

Design and rationale: [docs/database.md](docs/database.md).

## Future phases (high level)

1. ~~Tenants~~ — **Phase 1**. ~~Users, roles, permissions, membership
   enforcement~~ — **Phase 2**.
2. ~~Discovery and inventory~~ — **Phase 3** records it. ~~Agent identity~~ —
   **Phase 4** gives an agent its stable identity. Automatic discovery (cloud,
   network, endpoint integrations), agent execution and the dependency graph are
   later work; nothing in this build observes or runs anything.
3. ~~Authorization foundation~~ — **Phase 5** made permission and decision the
   vocabulary everything else builds on. ~~Policy engine~~ — **Phase 6** evaluates
   context and policy *through* this decision path rather than beside it, and
   reports a decision without acting on one. ~~Action firewall~~ — **Phase 7** became
   the enforcement boundary: a registered action runs only when authorization,
   policy and the firewall all allow it, and only through an adapter. Approvals and
   the kill switch are still to come — they are the remaining places a policy
   decision would be carried out.
4. Monitoring and response: behaviour, anomalies, cost, incidents, approvals and the
   kill switch (making `security.read` mean something, and turning the audit trail from
   a record into something that is read automatically). ``audit.read`` guards the trail
   since **Phase 8**.
5. Intelligence: Nemotron / Nebius as an advisory layer over deterministic
   decisions.

Details and rationale: [`docs/architecture.md`](docs/architecture.md) ·
[`docs/decisions/0001-phase-0-foundation.md`](docs/decisions/0001-phase-0-foundation.md).

## Development tooling

Agent tooling used while building this repository (gstack, Superpowers, ruflo,
21st.dev) is documented in [`TOOLKIT.md`](TOOLKIT.md) and is **not** part of the
AICore runtime: it is excluded from Docker images via `.dockerignore` and is not
a dependency of either application.

## License

See [`LICENSE`](LICENSE).
