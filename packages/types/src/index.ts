/**
 * Shared API contract types.
 *
 * The published surface covers exactly what the API serves: health endpoints,
 * the common error envelope, the organization (tenant) contract, the identity
 * contract (who the caller is, which organizations they belong to, what role they
 * hold and what it grants), and — since Phase 3 — the AI asset inventory.
 *
 * Domain contracts for policy, the action firewall, audit records and incidents
 * are intentionally NOT defined: those phases are not implemented, and a type
 * published now would be a promise this build does not keep.
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
  "organization" | "user" | "role" | "audit" | "security" | "asset" | "agent" | "policy";

/**
 * The action half of a permission identifier: what may be done.
 *
 * There is no `execute`, `approve` or `block`: those are runtime control-plane
 * actions, and this build can perform none of them.
 */
export type PermissionAction = "read" | "create" | "update" | "delete" | "manage";

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

/* ── Errors ──────────────────────────────────────────────────────────────── */

/** Machine-readable error codes returned by the API. */
export type ApiErrorCode =
  "not_found" | "method_not_allowed" | "validation_error" | "internal_error" | `http_${number}`;

/** Error envelope returned for every non-2xx API response. */
export interface ApiErrorResponse {
  error: {
    code: ApiErrorCode;
    message: string;
    details?: unknown;
    requestId?: string;
  };
}
