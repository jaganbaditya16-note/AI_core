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

/** One capability the application knows how to check. */
export interface Permission {
  code: string;
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
