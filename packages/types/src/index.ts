/**
 * Shared API contract types.
 *
 * The published surface covers exactly what the API serves: health endpoints,
 * the common error envelope, the organization (tenant) contract, the identity
 * contract (who the caller is, which organizations they belong to, what role they
 * hold and what it grants), the AI asset inventory, the agent registry, the policy
 * engine, the action firewall, and — since Phase 8 — the audit trail.
 *
 * Domain contracts for incidents and everything after them are intentionally NOT
 * defined: those phases are not implemented, and a type published now would be a
 * promise this build does not keep. Neither is a write model for the audit trail,
 * because reading is the only client operation there: the platform records events,
 * a caller only queries them.
 *
 * These types mirror the Pydantic models in `apps/api/src/aicore_api/schemas/`.
 * A backend test (`tests/test_openapi_contract.py`) asserts the two stay aligned.
 */

/* ── Health ──────────────────────────────────────────────────────────────── */

/** Liveness response: `GET /health`. */
export interface HealthResponse {
  status: "ok";
  service: string;
  version: string;
  environment: string;
}

/** A single dependency check inside a readiness response. */
export interface ReadinessCheck {
  name: string;
  status: "ok" | "error";
  detail: string | null;
}

/** Readiness response: `GET /health/ready` (HTTP 503 when any check fails). */
export interface ReadinessResponse {
  status: "ok" | "error";
  checks: ReadinessCheck[];
}

/**
 * Payload returned by the Next.js same-origin proxy (`/api/health`).
 *
 * The browser never talks to the API host directly by default, so this
 * envelope carries the upstream results plus whether the API was reachable.
 */
export interface HealthReport {
  reachable: boolean;
  checkedAt: string;
  api: HealthResponse | null;
  readiness: ReadinessResponse | null;
  errors: string[];
}

/* ── Organizations (Phase 1) ─────────────────────────────────────────────── */

/**
 * Lifecycle of a tenant. The database constrains these values, so an unknown
 * string coming from anywhere is a bug, not a new state.
 */
export type OrganizationStatus = "active" | "suspended" | "archived";

/**
 * A tenant: `GET /organizations/{id}`.
 *
 * Field names mirror the API exactly (snake_case), because this file is a
 * mirror of the published contract rather than a client-side view model.
 */
export interface Organization {
  id: string;
  name: string;
  slug: string;
  status: OrganizationStatus;
  created_at: string;
  updated_at: string;
}

/** Request body for `POST /organizations` (development and test environments only). */
export interface OrganizationCreate {
  name: string;
  slug: string;
}

/* ── Identity and access (Phase 2) ───────────────────────────────────────── */

/**
 * Lifecycle of a person. `suspended` cannot authenticate; the database
 * constrains these values, so an unknown string is a bug rather than a state.
 */
export type UserStatus = "active" | "suspended";

/** Lifecycle of a membership: a suspended grant carries no permissions. */
export type MembershipStatus = "active" | "suspended";

/** A person, as the API describes them. No credential field exists, by design. */
export interface User {
  id: string;
  email: string;
  full_name: string;
  status: UserStatus;
}

/** The tenant a membership belongs to. */
export interface OrganizationSummary {
  id: string;
  name: string;
  slug: string;
  status: OrganizationStatus;
}

/** A role, without its permission set (that is a catalog fact, not a grant). */
export interface RoleSummary {
  code: string;
  name: string;
}

/**
 * One of the caller's memberships.
 *
 * `permissions` is empty when the membership is not active: a suspended grant
 * must never be readable as usable.
 */
export interface Membership {
  organization: OrganizationSummary;
  role: RoleSummary;
  status: MembershipStatus;
  permissions: string[];
}

/** `GET /me` — the authenticated caller and every organization they belong to. */
export interface MeResponse {
  user: User;
  memberships: Membership[];
}

/** One member of an organization, as seen from inside that organization. */
export interface Member {
  user: User;
  role: RoleSummary;
  status: MembershipStatus;
  created_at: string;
}

/** `GET /organizations/{organization_id}/members`. */
export interface MemberListResponse {
  organization_id: string;
  members: Member[];
}

/** A role and the permissions it grants. */
export interface Role {
  code: string;
  name: string;
  description: string;
  permissions: string[];
}

/** `GET /organizations/{organization_id}/roles`. */
export interface RoleListResponse {
  organization_id: string;
  roles: Role[];
}

/**
 * The resource half of a permission identifier: what a capability governs.
 *
 * A closed vocabulary that mirrors `aicore_api.core.permissions.Resource`, and
 * deliberately small: a resource appears here only once a permission guards it.
 */
export type PermissionResource =
  "organization" | "user" | "role" | "audit" | "security" | "asset" | "agent" | "policy" | "action";

/**
 * The action half of a permission identifier: what may be done.
 *
 * `execute` names exactly one capability: run an action from the registered
 * catalogue through the action firewall (`action.execute`). There is deliberately no
 * `agent.execute`, no `approve` and no `block` — this build runs registered actions,
 * and it approves nothing.
 */
export type PermissionAction = "read" | "create" | "update" | "delete" | "manage" | "execute";

/**
 * One capability the application knows how to check.
 *
 * `code` is the identifier (`agent.update`); `resource` and `action` are its two
 * halves, so a client can group capabilities without parsing the string itself.
 */
export interface Permission {
  code: string;
  resource: PermissionResource;
  action: PermissionAction;
  description: string;
}

/** `GET /organizations/{organization_id}/permissions`. */
export interface PermissionListResponse {
  organization_id: string;
  permissions: Permission[];
}

/* ── AI asset inventory (Phase 3) ────────────────────────────────────────── */

/**
 * What kind of AI-related thing an inventory record describes. One closed
 * vocabulary for every type: the type is a column, and the type-specific detail
 * lives in `metadata` rather than in a table per type.
 */
export type AssetType =
  "agent" | "application" | "model" | "tool" | "mcp_server" | "api" | "data_source";

/** Where an asset is deployed. `unknown` is stored honestly, not guessed. */
export type AssetEnvironment = "development" | "staging" | "production" | "unknown";

/** Lifecycle of a record. `suspended` is inventory state only — no containment. */
export type AssetStatus = "draft" | "active" | "suspended" | "retired";

/**
 * How far the asset is accounted for:
 * `managed` — registered in AICore on purpose;
 * `unknown` — observed, ownership not yet established;
 * `shadow` — observed outside the organization's known inventory.
 */
export type DiscoveryState = "managed" | "unknown" | "shadow";

/** Storage only in this phase: nothing scores or enforces it yet. */
export type RiskClassification = "low" | "medium" | "high" | "critical" | "unassessed";

/** Who is accountable for an asset: a user, through their membership. */
export interface AssetOwner {
  membership_id: string;
  user_id: string;
  full_name: string;
  email: string;
}

/** One record in `GET /organizations/{organization_id}/assets`. */
export interface Asset {
  id: string;
  organization_id: string;
  name: string;
  description: string | null;
  asset_type: AssetType;
  status: AssetStatus;
  environment: AssetEnvironment;
  discovery_state: DiscoveryState;
  risk_classification: RiskClassification;
  owner: AssetOwner | null;
  metadata: Record<string, unknown> | null;
  /** Set by the server: a report from an integration is not a manual entry. */
  discovery_source: string;
  /** When an integration last observed it; null for a manually registered asset. */
  last_seen_at: string | null;
  /** An integration's own identifier for the asset, when it has one. */
  external_identifier: string | null;
  created_at: string;
  updated_at: string;
}

/** `GET /organizations/{organization_id}/assets`. */
export interface AssetListResponse {
  organization_id: string;
  items: Asset[];
  count: number;
  limit: number;
  offset: number;
  /** Number of matching assets, or `null` unless the request asked with `?total=true`. */
  total: number | null;
}

/** `GET /organizations/{organization_id}/assets/owners`: who an asset can be assigned to. */
export interface AssetOwnerListResponse {
  organization_id: string;
  owners: AssetOwner[];
}

/* ── Agents (Phase 4) ────────────────────────────────────────────────────── */

/**
 * What kind of agent this is. A description, never a grant: no permission in this
 * build is derived from a category, and no category implies an ability.
 */
export type AgentCategory =
  | "assistant"
  | "workflow"
  | "autonomous"
  | "coding"
  | "customer_support"
  | "data"
  | "security"
  | "other";

/** Runtime identity facts an agent record may carry. Never credentials. */
export interface AgentIdentityMetadata {
  runtime?: string;
  region?: string;
  instance?: string;
}

/** Who owns a registered agent: the same shape as an asset owner. */
export type AgentOwner = AssetOwner;

/**
 * One registered agent: an `agent` asset plus the identity layer over it.
 *
 * `identity_id` is generated by the server and never changes — not when
 * `display_name` changes and not when `version` does. `display_name` is a label;
 * the identity is what later phases will attribute actions to.
 *
 * `status` is registry lifecycle state. It is a record, not a runtime control:
 * nothing in this build starts, stops, blocks or contains an agent.
 */
export interface Agent {
  /** Registry row id. Internal; `identity_id` is the identifier to store. */
  id: string;
  organization_id: string;
  identity_id: string;
  /** The inventory record this identity belongs to. Exactly one per agent. */
  asset_id: string;
  display_name: string;
  description: string | null;
  category: AgentCategory;
  version: string;
  framework: string | null;
  build_revision: string | null;
  status: AssetStatus;
  environment: AssetEnvironment;
  identity_metadata: AgentIdentityMetadata | null;
  owner: AgentOwner | null;
  created_at: string;
  updated_at: string;
}

/** `GET /organizations/{organization_id}/agents`. */
export interface AgentListResponse {
  organization_id: string;
  items: Agent[];
  count: number;
  limit: number;
  offset: number;
  /** Number of matching agents, or `null` unless the request asked with `?total=true`. */
  total: number | null;
}

/* ── Policies (Phase 6) ──────────────────────────────────────────────────── */

/**
 * What a policy says when it applies.
 *
 * `require_approval` is a *value*: this build reports it and performs no approval.
 */
export type PolicyEffect = "allow" | "deny" | "require_approval";

/**
 * Where a policy is in its life. Only `active` participates in evaluation.
 *
 * A policy is created as a `draft` or `active`; `disabled` and `retired` are states
 * it moves to. `retired` is terminal.
 */
export type PolicyStatus = "draft" | "active" | "disabled" | "retired";

/**
 * The facts a condition may be written about.
 *
 * A closed vocabulary, mirrored in `aicore_api.core.policy.ConditionField`. There is
 * no free-form field and no expression language: a condition is a field, an operator
 * and a typed value, all validated before the policy is stored.
 */
export type PolicyConditionField =
  | "environment"
  | "asset_type"
  | "resource_status"
  | "risk_classification"
  | "agent_category"
  | "user_role"
  | "is_resource_owner"
  | "agent_age_days"
  | "asset_age_days";

/**
 * The operators, and all of them.
 *
 * The set-valued operators compare against a list, the ordered ones against a
 * number, and both are refused on a field where they would not mean anything.
 */
export type PolicyConditionOperator =
  | "equals"
  | "not_equals"
  | "in"
  | "not_in"
  | "less_than"
  | "less_than_or_equal"
  | "greater_than"
  | "greater_than_or_equal";

/**
 * One condition: a field, an operator, and the value it is compared against.
 *
 * The value is a string, a boolean, a number, or a list of those for the set
 * operators — never an expression. Every condition must hold for a policy to apply.
 */
export interface PolicyCondition {
  field: PolicyConditionField;
  operator: PolicyConditionOperator;
  value: string | number | boolean | Array<string | number | boolean>;
}

/** One condition that held, with the fact that satisfied it. */
export interface MatchedCondition {
  field: PolicyConditionField;
  operator: PolicyConditionOperator;
  value: string | number | boolean | Array<string | number | boolean>;
  actual: string | number | boolean;
}

/** A policy as the API returns it: the record plus its current definition. */
export interface Policy {
  policy_id: string;
  organization_id: string;
  name: string;
  description: string;
  resource: PermissionResource;
  action: PermissionAction;
  effect: PolicyEffect;
  priority: number;
  status: PolicyStatus;
  /** The current definition's version. A decision names the version it used. */
  version: number;
  conditions: PolicyCondition[];
  created_at: string;
  updated_at: string;
}

/** `GET /organizations/{organization_id}/policies`. */
export interface PolicyListResponse {
  organization_id: string;
  items: Policy[];
  count: number;
  limit: number;
  offset: number;
  /** Number of matching policies, or `null` unless the request asked with `?total=true`. */
  total: number | null;
}

/** One version of a policy's definition. Append-only: a version is never edited. */
export interface PolicyVersion {
  version: number;
  resource: PermissionResource;
  action: PermissionAction;
  effect: PolicyEffect;
  priority: number;
  conditions: PolicyCondition[];
  created_at: string;
}

/** `GET /organizations/{organization_id}/policies/{policy_id}/versions`. */
export interface PolicyVersionListResponse {
  organization_id: string;
  policy_id: string;
  /** Which version is in force now — not necessarily the last item on the page. */
  current_version: number;
  items: PolicyVersion[];
  limit: number;
  offset: number;
  count: number;
  total: number;
}

/**
 * What the policy layer says about one request, on its own.
 *
 * `not_applicable` means no active policy addressed it — a decision, not an absence
 * of one. `allow` here means "no policy objects", never "the caller may act": the
 * effective answer combines this with the authorization decision, and a policy can
 * only make it more restrictive.
 */
export interface PolicyDecision {
  decision: PolicyEffect | "not_applicable";
  reason: "no_matching_policy" | "matching_allow" | "matching_deny" | "matching_require_approval";
  allowed: boolean;
  denied: boolean;
  requires_approval: boolean;
  applicable: boolean;
  policy_id: string | null;
  policy_version: number | null;
  policy_name: string | null;
  priority: number | null;
  matched_conditions: MatchedCondition[];
  matched_policy_count: number;
  evaluated_policies: number;
}

/** Phase 5's answer for the permission the target names. */
export interface PolicyAuthorizationDecision {
  allowed: boolean;
  reason: string;
  permission: string;
}

/** The two layers combined: a policy can restrict an authorization, never widen it. */
export interface EffectivePolicyDecision {
  decision: PolicyEffect;
  reason:
    | "authorization_denied"
    | "policy_denied"
    | "policy_requires_approval"
    | "policy_allowed"
    | "authorization_grant";
  allowed: boolean;
  denied: boolean;
  requires_approval: boolean;
}

/**
 * `POST /organizations/{organization_id}/policies/evaluate`.
 *
 * A **dry run**: it evaluates and reports, and performs no action, no approval and no
 * enforcement. `dry_run` is always `true` and is part of the contract on purpose —
 * the response says what *would* happen and nothing else. Enforcement belongs to the
 * action firewall, which this build does not have.
 *
 * `user_role` and `is_resource_owner` are never accepted in `facts`: they come from
 * the caller's membership, and the endpoint refuses a request that supplies them.
 */
export interface PolicyEvaluateRequest {
  resource: PermissionResource;
  action: PermissionAction;
  facts?: Partial<Record<PolicyConditionField, string | number | boolean>>;
}

export interface PolicyEvaluateResponse {
  dry_run: true;
  organization_id: string;
  resource: PermissionResource;
  action: PermissionAction;
  permission_required: string;
  principal_role: string;
  authorization: PolicyAuthorizationDecision;
  policy: PolicyDecision;
  effective: EffectivePolicyDecision;
  evaluated_at: string;
}

/**
 * The body for creating a policy.
 *
 * `effect` is required rather than defaulted: the effect *is* the decision, and a
 * client that omitted it would be choosing a semantics by accident.
 */
export interface PolicyCreate {
  name: string;
  description: string;
  resource: PermissionResource;
  action: PermissionAction;
  effect: PolicyEffect;
  priority?: number;
  conditions?: PolicyCondition[];
  status?: "draft" | "active";
}

/* ── The action firewall (Phase 7) ──────────────────────────────────────── */

/**
 * The three outcomes the firewall can return, and the whole of its vocabulary.
 *
 * `require_approval` is a *value*: the API returns it (and a correlation id) and
 * executes nothing. There is no approval workflow in this build.
 */
export type FirewallOutcome = "allow" | "deny" | "require_approval";

/**
 * Why the firewall decided what it decided. Stable codes, never prose.
 *
 * `authorization_denied` is Phase 5's answer, `policy_denied` and
 * `policy_requires_approval` are Phase 6's, and the remaining two are about the
 * request's own referents: a target this organization does not have, and an
 * environment the target record does not confirm.
 */
export type FirewallReason =
  | "allowed"
  | "authorization_denied"
  | "policy_denied"
  | "policy_requires_approval"
  | "target_not_found"
  | "environment_mismatch";

/**
 * How much care a registered action warrants, published so the catalogue is
 * reviewable. Not an authorization input: authorization is Phase 5's question and
 * the context is Phase 6's.
 */
export type ActionSensitivity = "routine" | "controlled" | "sensitive";

/** The row an action addresses, inside the caller's organization. */
export interface ActionTarget {
  resource: PermissionResource;
  id: string;
}

/** What the firewall decided about one execution. */
export interface FirewallDecision {
  outcome: FirewallOutcome;
  reason: FirewallReason;
}

/**
 * The body of `POST /organizations/{organization_id}/actions/execute`.
 *
 * The mirror of `ActionExecuteRequest`.
 *
 * Every field here is something the client *knows*: a registered action identifier,
 * a target, the environment it believes it is acting in, validated arguments and an
 * idempotency key. There is no field for an executor, a module, a function, a URL,
 * a command, a permission or an identity — the server takes those from the
 * credential and the path, and a body that tries to state one is refused.
 *
 * `environment` is a statement, not evidence: it is checked against the environment
 * the target row is recorded in, and the policy layer is evaluated against the
 * recorded value.
 */
export interface ActionExecuteRequest {
  action: string;
  target_id: string;
  environment: AssetEnvironment;
  arguments?: Record<string, string | number | boolean | (string | number | boolean)[]>;
  /** Required: a retry after a lost answer must not run the action twice. */
  idempotency_key: string;
  /** The agent this execution is attributed to, when an agent requested it. */
  agent_id?: string | null;
}

/**
 * What the adapter reported.
 *
 * The mirror of `ActionOutcomeRead`. `findings` is a closed set of codes, `details` is
 * structured and adapter-specific,
 * and `digest` is a stable hash of the action, the target and the outcome — so two
 * executions can be compared without comparing prose. It identifies what was done,
 * never who asked.
 */
export interface ActionOutcome {
  summary: string;
  findings: string[];
  details: Record<string, unknown>;
  adapter: string;
  digest: string;
}

/**
 * The result of an executed action.
 *
 * Returned only when the firewall said `allow`: every other outcome is an error whose
 * code names the reason (`policy_denied`, `approval_required`, `unknown_action`, …).
 * `replayed` is true when the idempotency key had already run the identical request —
 * no adapter ran again.
 */
export interface ActionExecutionResponse {
  organization_id: string;
  action_id: string;
  action_sensitivity: ActionSensitivity;
  target: ActionTarget;
  agent_id: string | null;
  permission_required: string;
  principal_role: string;
  environment: AssetEnvironment;
  firewall: FirewallDecision;
  authorization: PolicyAuthorizationDecision;
  policy: PolicyDecision;
  effective: EffectivePolicyDecision;
  executed: true;
  replayed: boolean;
  execution_id: string;
  idempotency_key: string;
  correlation_id: string;
  executed_at: string;
  result: ActionOutcome;
}

/* ── The audit trail (Phase 8) ─────────────────────────────────────────── */

/**
 * Everything the trail may record, and nothing else.
 *
 * The names are stable identifiers in a durable table: `asset.created` is not a
 * display string, it is what a future reader filters on. The action pipeline
 * contributes six, because one request passes through six distinguishable states
 * worth remembering — it was admitted, it was refused, it was held for an approval
 * this build cannot grant, it ran, it was answered from the ledger instead of
 * running again, or it was admitted and failed.
 *
 * `asset.discovered` is the ingestion path's event: an integration reported
 * something, which is a system origin rather than a request.
 */
export type AuditEventType =
  | "asset.created"
  | "asset.updated"
  | "asset.deleted"
  | "asset.discovered"
  | "agent.registered"
  | "agent.updated"
  | "agent.deleted"
  | "policy.created"
  | "policy.updated"
  | "policy.version_published"
  | "policy.status_changed"
  | "policy.deleted"
  | "action.requested"
  | "action.denied"
  | "action.require_approval"
  | "action.executed"
  | "action.replayed"
  | "action.failed";

/** The kind of row an event is about. Closed, like every other vocabulary here. */
export type AuditResourceType = "asset" | "agent" | "policy";

/**
 * Who initiated the event.
 *
 * `human` is an authenticated caller; the person and the membership are resolved by
 * the server from the credential, never from the request. `system` is an operation
 * nobody performed — the ingestion path recording what an integration reported.
 * There is no `agent` actor: an execution attributed to an agent is still a human's
 * request, and the agent appears in `agent_id` instead of being given an identity it
 * does not have.
 */
export type ActorType = "human" | "system";

/** Where the event originated. A worker or a scheduler adds its own value later. */
export type AuditSource = "api" | "ingestion";

/**
 * The decision recorded, in the vocabulary the policy engine and the firewall
 * already publish (`FirewallOutcome`). Null when no decision applies: a system
 * operation answers to no authorization layer, and a request that has only been
 * admitted has not been decided yet.
 */
export type AuditDecision = "allow" | "deny" | "require_approval";

/**
 * What became of the event.
 *
 * `pending` exists for exactly one event type — an admitted execution request, whose
 * ending is unknown when the row is written and may never be known. `replayed` is
 * kept apart from `success` on purpose: a request answered from the ledger is not a
 * second execution, and a trail that called it one would overstate what the system
 * did.
 */
export type AuditOutcome =
  | "success"
  | "failed"
  | "blocked"
  | "not_executed"
  | "replayed"
  | "pending";

/**
 * One recorded event — the mirror of `AuditEventRead`.
 *
 * Every field is named and typed rather than returned straight from the row, so
 * adding a column to the table cannot silently publish it. The four axes stay
 * separate: `event_type` is what happened, `action` is which operation, `decision`
 * is what was decided, `outcome` is how it ended.
 *
 * Nothing here can be claimed by a client. `organization_id`, the actor, the
 * timestamps and the correlation are resolved by the server; there is no request
 * shape in this file, because there is no write endpoint to send one to.
 */
export interface AuditEvent {
  id: string;
  organization_id: string;
  event_type: AuditEventType;
  /** The shape of the row this event was written in. */
  schema_version: number;
  /** The server's clock at the moment of the event, in UTC. */
  occurred_at: string;
  actor_type: ActorType;
  /** The authenticated person; null for a system event. */
  actor_id: string | null;
  /** The membership that carried the role; null for a system event. */
  actor_membership_id: string | null;
  /** The agent an execution was attributed to, when the request named one. */
  agent_id: string | null;
  resource_type: AuditResourceType;
  /** The row the event was about, as it was; null when it is not about one. */
  resource_id: string | null;
  /**
   * The operation: the registered action's identifier for an execution, or the
   * `resource.action` permission for a lifecycle change.
   */
  action: string | null;
  decision: AuditDecision | null;
  outcome: AuditOutcome;
  /** Groups the events of one flow; server-established, never client-claimed. */
  correlation_id: string;
  /** The originating HTTP request; null for an internal path such as ingestion. */
  request_id: string | null;
  source: AuditSource;
  /**
   * Sanitized summary facts. Credential-shaped keys and values are redacted at the
   * write boundary and again on the way out, and action arguments are never stored:
   * an execution records that it carried N arguments, not what they were.
   */
  metadata: Record<string, unknown>;
}

/**
 * `GET /organizations/{organization_id}/audit-events`.
 *
 * Ordered `occurred_at DESC, id DESC`, always paginated: `limit` is bounded and
 * `offset` is capped, so no query can ask for the whole trail. `total` is present
 * only when the caller asked for it; `count` always describes the page itself.
 */
export interface AuditEventListResponse {
  organization_id: string;
  items: AuditEvent[];
  limit: number;
  offset: number;
  count: number;
  total: number | null;
}

/* ── Monitoring (Phase 9) ────────────────────────────────────────────────── */

/**
 * The bounded windows this build measures over, plus an explicit range.
 *
 * Every named window has a fixed length and the server decides *when* it ends: a client
 * chooses which interval to read, never what time it is. `custom` is the escape hatch for
 * an investigation with its own edges, and it is bounded too — a month, and never
 * unbounded, because an open-ended range is priced by how long the organization has
 * existed.
 */
export type MonitoringWindow = "5m" | "15m" | "1h" | "24h" | "7d" | "custom";

/** How finely a series is bucketed: an hour for the day being worked in, a day beyond it. */
export type MonitoringInterval = "hour" | "day";

/**
 * The interval a response measured, as the server resolved it.
 *
 * Both bounds are inclusive and in UTC, and `end` is the server's clock at the moment of
 * the request — so "activity went up" can always be checked against "compared to when".
 */
export interface MonitoringWindowRead {
  name: MonitoringWindow;
  /** Inclusive lower bound, in UTC. */
  start: string;
  /** Inclusive upper bound, in UTC: the server's clock. */
  end: string;
}

/**
 * How the actions that ran in the window ended.
 *
 * `success_rate` and `failure_rate` are `null` when nothing completed: a zero would read
 * as "everything failed", which is the opposite of "nothing ran". Refusals are not in
 * these counts — a request that never ran cannot fail.
 */
export interface ExecutionHealth {
  /** Executions that finished: `succeeded + failed`. */
  completed: number;
  succeeded: number;
  failed: number;
  /** Share of completed executions that succeeded; null when none completed. */
  success_rate: number | null;
  /** Share of completed executions that failed; null when none completed. */
  failure_rate: number | null;
}

/**
 * Refusals in the window, and which layer produced them.
 *
 * A denial is an event Phase 8 recorded — a request was refused and nothing ran — not an
 * incident and not a finding. `by_reason` is the firewall's own vocabulary, and a refusal
 * whose reason could not be read is counted under `unspecified` rather than dropped.
 */
export interface DenialSummary {
  total: number;
  /**
   * Counts keyed by the reason the refusal recorded: `"authorization_denied"`,
   * `"policy_denied"`, `"target_not_found"`, `"environment_mismatch"` or `"unspecified"` —
   * the last being a refusal whose reason could not be read, counted rather than dropped so
   * the breakdown always adds up to `total`. The keys are a closed vocabulary owned by the
   * firewall; a client should treat an unknown key as a reason it does not render yet.
   */
  by_reason: Record<string, number>;
}

/**
 * `GET /organizations/{organization_id}/monitoring/summary`.
 *
 * Every field is a count of events of a stated type within the recorded window: what the
 * action pipeline did, what the inventory and registry changed, and whether the rules
 * moved. There is no score, no severity and no verdict — a spike is a bigger number.
 */
export interface MonitoringSummaryResponse {
  organization_id: string;
  window: MonitoringWindowRead;
  /** Every audit event in the window. */
  total_events: number;
  action_requests: number;
  action_executions: number;
  action_failures: number;
  action_denials: number;
  action_replays: number;
  approval_required: number;
  asset_creations: number;
  asset_updates: number;
  asset_deletions: number;
  asset_discoveries: number;
  agent_registrations: number;
  agent_updates: number;
  agent_deletions: number;
  policy_creations: number;
  policy_updates: number;
  policy_version_publications: number;
  policy_status_changes: number;
  policy_deletions: number;
  /** The five policy counters above, summed. */
  policy_changes: number;
  /** Distinct agents named by at least one event in the window. */
  active_agents: number;
  /** Distinct assets named by at least one event in the window. */
  active_assets: number;
  execution_health: ExecutionHealth;
  denials: DenialSummary;
}

/**
 * One agent's activity in the window.
 *
 * Present only when the agent is named by at least one event: this build measures
 * activity, and it cannot tell an idle agent from one whose requests never happened.
 */
export interface MonitoringAgentRead {
  agent_id: string;
  events: number;
  action_requests: number;
  executions: number;
  failures: number;
  denials: number;
  approval_required: number;
  replays: number;
  /** The newest event's recorded time, in UTC. */
  last_activity_at: string;
}

/**
 * `GET /organizations/{organization_id}/monitoring/agents`.
 *
 * Ordered by event count descending, then by identifier ascending — the second key makes
 * the order total, so paging cannot repeat or skip an agent. `total` is present only when
 * the caller asked for it, because it costs a second query.
 */
export interface MonitoringAgentListResponse {
  organization_id: string;
  window: MonitoringWindowRead;
  items: MonitoringAgentRead[];
  limit: number;
  offset: number;
  count: number;
  total: number | null;
}

/**
 * One registered action's activity in the window.
 *
 * `allowed` counts requests the firewall permitted, whatever came of them, while the rest
 * count events: a request that was allowed and then failed is both `allowed` and `failed`.
 */
export interface MonitoringActionRead {
  action: string;
  requested: number;
  allowed: number;
  denied: number;
  approval_required: number;
  executed: number;
  failed: number;
  replayed: number;
}

/** `GET /organizations/{organization_id}/monitoring/actions`: one row per action that ran. */
export interface MonitoringActionListResponse {
  organization_id: string;
  window: MonitoringWindowRead;
  items: MonitoringActionRead[];
  count: number;
}

/** How the action pipeline answered, by decision. Every value is present, at zero if unseen. */
export interface MonitoringDecisionsRead {
  allow: number;
  deny: number;
  require_approval: number;
}

/**
 * Activity on the policy record itself: the definition, its versions and its state.
 *
 * Counts, never recommendations: the field says a policy was activated, and there is no
 * field a client could read as advice about what to change.
 */
export interface MonitoringPolicyLifecycleRead {
  created: number;
  updated: number;
  version_published: number;
  status_changed: number;
  deleted: number;
  /** The five counts above, summed. */
  changes: number;
}

/**
 * `GET /organizations/{organization_id}/monitoring/policies`.
 *
 * Two different facts, kept apart: `decisions` is what the pipeline answered for requests,
 * `lifecycle` is what changed on the policy record. A denial is counted, never attributed
 * to a named policy — the trail records the decision and its reason, not which policy
 * produced it.
 */
export interface MonitoringPolicyResponse {
  organization_id: string;
  window: MonitoringWindowRead;
  decisions: MonitoringDecisionsRead;
  lifecycle: MonitoringPolicyLifecycleRead;
}

/**
 * One interval of a time series: half-open on the Python side, inclusive both ends in the
 * query, and one interval wide in every case.
 */
export interface TrendBucket {
  /** Inclusive start of the bucket, in UTC. */
  start: string;
  /** Exclusive end of the bucket, in UTC. */
  end: string;
  events: number;
  action_requests: number;
  action_executions: number;
  action_failures: number;
  action_denials: number;
  approval_required: number;
}

/**
 * `GET /organizations/{organization_id}/monitoring/trends`.
 *
 * A complete series: every bucket between the window's first and last, in order, with the
 * quiet ones present as zeros. No smoothing, no interpolation, no moving average — the
 * counts are the counts.
 */
export interface MonitoringTrendResponse {
  organization_id: string;
  window: MonitoringWindowRead;
  interval: MonitoringInterval;
  buckets: TrendBucket[];
  count: number;
}

/* ── Errors ──────────────────────────────────────────────────────────────── */

/**
 * Machine-readable error codes returned by the API.
 *
 * A code is a stable identifier, so a client switches on it rather than matching
 * message text. The action firewall's refusals are the reason the vocabulary is this
 * specific: an action denied by a policy and one awaiting an approval are both 403,
 * and they are not the same answer.
 */
export type ApiErrorCode =
  | "bad_request"
  | "unauthorized"
  | "forbidden"
  | "not_found"
  | "method_not_allowed"
  | "conflict"
  | "payload_too_large"
  | "unsupported_media_type"
  | "validation_error"
  | "rate_limited"
  | "internal_error"
  | "service_unavailable"
  | "unknown_action"
  | "invalid_arguments"
  | "policy_denied"
  | "approval_required"
  | "environment_mismatch"
  | "idempotency_conflict"
  | "execution_failed"
  | `http_${number}`;

/** Error envelope returned for every non-2xx API response. */
export interface ApiErrorResponse {
  error: {
    code: ApiErrorCode;
    message: string;
    details?: unknown;
    requestId?: string;
  };
}
