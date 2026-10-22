# Nebius x NVIDIA Global AI Hackathon — Submission Runbook

This document records the AICore submission path and the checks that must be completed before submitting to Devpost.

## Required platform/model usage

AICore uses a server-only advisory intelligence path through **Nebius Token Factory** and an NVIDIA **Nemotron** model. The model is advisory only: it cannot authorize, approve, execute, mutate policy, or bypass the action firewall.

For hackathon eligibility, the deployed project must make a runtime call to Nebius Token Factory or run on Nebius AI Cloud and must use at least one NVIDIA open-source model. Configuration alone is not evidence of runtime use.

## Demonstration path

The primary demo should be one complete, reproducible workflow:

1. A deterministic AICore detector identifies unusual activity.
2. The operator opens or promotes an incident.
3. A bounded incident context is sent server-side to the Nemotron advisory layer through Nebius Token Factory.
4. Nemotron returns an explanation, evidence interpretation, and recommended next step.
5. A human reviews the recommendation.
6. Any action requiring authorization goes through the existing identity, membership, RBAC, policy, approval, and action-firewall path again.
7. The UI shows the resulting audit trail and the separation between model advice and deterministic enforcement.

The demo must never imply that the model itself is the security authority.

## Security requirements

- Never place Nebius credentials in client-side code or `NEXT_PUBLIC_*` variables.
- Never commit real credentials to Git.
- The browser must call the same-origin Next.js BFF rather than the Nebius API directly.
- Do not send action arguments, credentials, secrets, or unrestricted audit payloads to the model.
- Keep tenant and membership authorization before advisory data retrieval.
- Treat model output as untrusted text/data.
- Model timeouts, malformed responses, provider errors, and missing credentials must fail closed for any control action and must not create an authorization bypass.
- The advisory path must remain read-only with respect to AICore controls.

## Required environment configuration

Set these only in the server environment used for the deployed application:

```text
AICORE_NEBIUS_API_KEY=<secret>
AICORE_NEBIUS_BASE_URL=https://api.tokenfactory.nebius.com/v1
AICORE_NEBIUS_MODEL=<verified Nemotron model ID available to the Token Factory project>
AICORE_INTELLIGENCE_SERVICE_TOKEN=<long random server-to-BFF token, if enabled by the deployment>
```

Do not copy a model identifier into the production configuration until it has been verified against the actual Token Factory account/project.

## Pre-submission verification

### Repository

- Public repository URL works.
- An open-source license is visible at repository level.
- README contains installation and run instructions.
- No secrets, private keys, tokens, or credentials are present in Git history or the current tree.
- The repository contains the source, assets, and instructions required to run the project.

### Backend

- Ruff check passes.
- Ruff format check passes for the configured API scope.
- Mypy passes for the configured API scope.
- Hermetic tests pass.
- Full PostgreSQL tests pass.
- Migration upgrade/downgrade/upgrade passes.
- `alembic check` reports no schema drift.
- Readiness endpoint returns HTTP 200 with a healthy database.
- Cross-tenant, unauthorized, approval, expiry, concurrency, and model-failure paths are covered.

### Frontend

- TypeScript passes.
- ESLint passes.
- Production build passes.
- The browser never receives server-only Nebius credentials.
- Loading, empty, error, timeout, and reduced-motion states are usable.
- Desktop and mobile layouts are checked on the deployed build.

### Live deployment

A successful CI build is not a substitute for a working hosted demo. Before submission, verify the actual public deployment:

1. Open the production URL in a fresh browser session.
2. Verify the application health/readiness path.
3. Exercise the complete incident → advisory → human review → policy/firewall workflow.
4. Verify a real Nebius Token Factory inference request occurs.
5. Verify the browser network panel contains no Nebius API key or server credential.
6. Temporarily test provider failure and confirm the application remains safe and usable.
7. Record the exact model ID and provider configuration used in the final submission notes.

## Three-minute video structure

Keep the video under three minutes and show the product rather than a tutorial:

- **0:00–0:20:** The real problem and who experiences it.
- **0:20–0:45:** AICore detects the abnormal behavior and creates the incident context.
- **0:45–1:30:** Show the Nebius Token Factory + NVIDIA Nemotron advisory step and the useful output.
- **1:30–2:10:** Show human review, approval separation, policy re-evaluation, and the firewall boundary.
- **2:10–2:40:** Show audit/evidence, tenant isolation/security controls, and the failure-safe behavior.
- **2:40–3:00:** State the impact, scalability direction, and explicitly identify Nebius Token Factory and the NVIDIA model used.

The video should include spoken audio explaining the required Nebius and NVIDIA usage, as requested by the hackathon guidance.

## Required Nebius/NVIDIA feedback

The Devpost submission must include concrete feedback on each Nebius/NVIDIA technology actually used:

- What was used and for which task.
- Time from zero to first successful request.
- What worked particularly well.
- What was difficult or should be improved.
- Documentation/onboarding observations with specific tool names.
- Latency, reliability, model behavior, or developer-experience observations where measured.
- Whether the team would build with the tools again and why.

Do not claim measurements that were not actually observed.

## Current verification boundary

CI success demonstrates repository-level correctness for the committed changes. It does **not** prove that live Nebius inference or a public Vercel deployment has been verified. Those claims should only be made after the deployment credentials are configured and the hosted workflow has been exercised end-to-end.
