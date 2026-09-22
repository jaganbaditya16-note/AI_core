/**
 * Shared API contract types.
 *
 * The published surface covers exactly what the API serves: health endpoints,
 * the common error envelope, the organization (tenant) contract, and — since
 * Phase 2 — the identity contract (who the caller is, which organizations they
 * belong to, what role they hold and what it grants).
 *
 * Domain contracts for AI inventory, policy, the action firewall, audit records
 * and incidents are intentionally NOT defined: those phases are not implemented,
 * and a type published now would be a promise this build does not keep.
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
