# Phase 11 contract coverage

Phase 11 and later security capabilities are tested in dedicated contract/security suites. The existing Phase 1–10 OpenAPI contract suite remains intact and continues to assert the previously published API shapes, negative security boundaries, and shared TypeScript mirror.

The Phase 11 additions include incident and approval schemas and routes, while the action execution surface remains exactly one firewall-backed endpoint. Approval is not execution authority and must never be represented as a client-supplied authorization field.
