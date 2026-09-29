# AICore Phase 1–10 Production Audit

This document records the review boundary for the competition build. It is intentionally
separate from the Phase 10 anomaly methodology and from the Nebius/NVIDIA investigator:
the earlier phases remain the deterministic security foundation.

## Phase-by-phase contract

| Phase | Security/product contract | Review focus |
|---|---|---|
| 1 | PostgreSQL schema and tenant boundary | Composite tenant ownership, foreign keys, migrations, real PostgreSQL tests |
| 2 | Identity, memberships and RBAC | Server-resolved caller identity, organization membership and closed permissions |
| 3 | AI asset inventory | Tenant-scoped CRUD, lifecycle audit events, no arbitrary ownership supplied by clients |
| 4 | Agent registry | Stable server identity for registered agents and tenant isolation |
| 5 | Authorization foundation | Closed resource/action vocabulary and deterministic decisions |
| 6 | Policy engine | Versioned organization policy, bounded condition language and deterministic evaluation |
| 7 | Action firewall | One execution entry point; only `ALLOW` reaches an adapter |
| 8 | Audit trail | Append-only, tenant-scoped, sanitized security record |
| 9 | Monitoring | Bounded PostgreSQL counts over the audit trail; read-only and non-verdict |
| 10 | Anomaly and risk | Agent-specific baseline/observation analysis; deterministic findings; no automatic response |

## Cross-phase invariants

1. **Tenant isolation is server-owned.** A request never gets to choose another organization's
   security context by placing an organization identifier in a payload.
2. **Authentication precedes authorization.** A bearer token identifies a user and the
   membership in the organization path supplies the role and permissions.
3. **Authorization and policy are deterministic.** The model layer is not a security
   authority and cannot widen a permission or policy decision.
4. **Execution has one narrow boundary.** The action firewall is the only route that can
   reach an action adapter. Analytical routes never execute actions.
5. **Audit data is not an application payload store.** Event metadata is bounded and
   sanitized; credentials and action arguments do not belong in the trail.
6. **Monitoring and risk are observations, not controls.** Counts and anomaly findings do
   not mutate policies, permissions, agents or execution state.
7. **Phase 10 has no model dependency.** The statistical detection path remains usable when
   Nebius is unavailable.
8. **Nebius/Nemotron is advisory.** The investigator receives a server-selected, bounded
   detection record and returns structured prose. Its output cannot authorize or execute.
9. **Secrets stay server-side.** Database credentials and the Nebius key are environment
   configuration; the browser never receives the Nebius key.
10. **Production fails closed on unsafe configuration.** PostgreSQL is required, production
    debug is rejected, wildcard production CORS is rejected, and the Nebius endpoint is
    restricted to approved HTTPS hosts.

## Competition-path verification

The final application path should be demonstrated as:

```text
recorded activity
  -> deterministic Phase 10 detection
  -> bounded evidence
  -> NVIDIA Nemotron via Nebius Token Factory
  -> structured investigation
  -> human decision
  -> existing AICore authorization/policy/firewall boundary
  -> execution only when the deterministic controls allow it
```

The model is deliberately not allowed to become an autonomous remediation engine. This
keeps the intelligence layer useful to an operator while preserving the security guarantees
of Phases 1–10.

## Known limits

- AICore does not discover arbitrary cloud accounts or network assets automatically.
- The registered agent is a control-plane identity, not a general-purpose agent runtime.
- Phase 10 detects and explains unusual activity; it does not prove malicious intent.
- The Nebius investigator requires a valid Token Factory credential for live inference.
- Live model quality, latency and cost must be measured against the actual hackathon account
  before submission; mocked inference tests do not establish those production measurements.
- Browser E2E is environment-dependent locally; CI installs Chromium explicitly.

## Release gate

Do not merge the competition branch into the release branch until all of the following are
true:

- PostgreSQL-backed tests pass from an empty schema.
- Alembic reports no schema drift.
- Migration downgrade and re-upgrade pass.
- Ruff, Ruff format and mypy pass.
- Frontend lint, typecheck and production build pass.
- Browser E2E passes in CI.
- Secret scan passes.
- A live Nebius Token Factory inference has been exercised with the NVIDIA Nemotron model
  configured for the submission.
- The public repository contains an open-source license, setup instructions and the required
  Nebius/NVIDIA usage and feedback documentation.
