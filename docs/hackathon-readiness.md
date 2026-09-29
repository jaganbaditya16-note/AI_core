# Nebius x NVIDIA Global AI Hackathon — readiness

This document is a submission checklist, not a claim that the project has already passed every runtime gate.

## Official requirements mapped to AICore

| Requirement | AICore status | Evidence / remaining action |
|---|---|---|
| Working software application | **In progress** | Backend and web application exist; a hosted demo still needs final deployment verification. |
| Runtime call to Nebius Token Factory or Nebius AI Cloud | **Implemented in code; live proof pending** | `core/intelligence.py` calls the Nebius OpenAI-compatible endpoint. Run a real inference with a valid server-side key before submission. |
| At least one NVIDIA open-source model | **Implemented** | Default model: `nvidia/nemotron-3-super-120b-a12b`. |
| One eligible track | **Best Apps and Agents** | The product is an AI security control-plane application with a human-in-the-loop investigation workflow. |
| Public code repository | **Yes** | GitHub repository is public. |
| Open-source license | **Yes** | MIT `LICENSE`. |
| README + setup instructions | **Yes, but must be refreshed before final submission** | README still contains historical Phase 10 wording in places; do not submit until those sections describe the current intelligence layer. |
| Demo URL | **Pending** | Deploy the web/API stack and verify the exact URL used in the submission. |
| Public YouTube demo under 3 minutes | **Pending** | Record only after the hosted runtime path is verified. |
| Nebius/NVIDIA usage explained | **Implemented** | `docs/nebius-nemotron.md`; also describe Token Factory and Nemotron explicitly in the Devpost entry. |
| Required tool feedback | **Pending** | Submit specific feedback about Token Factory and NVIDIA/Nemotron, including onboarding, strengths, weaknesses and whether you would build with it again. |
| Existing-project disclosure | **Required if applicable** | Explain the significant work completed during the submission period if the project predates the hackathon. |

## Judging-oriented engineering goals

The four Stage Two criteria are equally weighted: technological implementation, design, potential impact, and quality of idea. AICore should therefore be demonstrated as a complete product rather than as an API call.

### 1. Technological implementation

The critical proof is a real request path:

`deterministic anomaly -> bounded evidence -> Nebius Token Factory -> NVIDIA Nemotron -> validated advisory result -> human review`

The model must never become the authorization, policy, approval or execution authority.

Before submission, verify:

- real Token Factory inference succeeds from the deployed application;
- the model ID is visible in the application/docs;
- no API key reaches browser code, logs or repository history;
- provider failures return a truthful error instead of fabricated AI output;
- model output is schema-validated and bounded;
- database and tenant authorization tests pass;
- the production build succeeds.

### 2. Design

The final demo should show a complete user journey rather than a static landing page:

1. security finding appears;
2. reviewer opens the finding;
3. reviewer asks for investigation;
4. Nemotron returns observations, hypotheses and reviewer questions;
5. reviewer sees the `advisory only` boundary;
6. any real action remains behind the deterministic AICore firewall.

### 3. Potential impact

The product should be presented around a specific problem: AI systems create security-relevant activity faster than human security teams can manually understand. AICore combines deterministic controls with model-assisted investigation without handing the model the authority to enforce its own conclusions.

Do not claim automatic remediation, autonomous containment, continuous cloud discovery, compliance certification, or production-scale guarantees unless those capabilities are actually implemented and demonstrated.

### 4. Quality of idea

The differentiator is the separation of responsibilities:

- deterministic systems detect and enforce;
- Nemotron investigates and explains;
- humans review and decide.

This is more defensible than allowing an LLM to directly authorize or execute security actions.

## Security and scalability limits to disclose

- The current inference endpoint is synchronous; production scale should move inference to an asynchronous job/queue when investigation latency or traffic grows.
- Provider rate limits and account balance are external dependencies.
- The application must use a secret manager/server environment for `AICORE_NEBIUS_API_KEY`.
- The current product does not claim autonomous agent execution or autonomous containment.
- A public demo should use synthetic or deliberately non-sensitive evidence.
- Any production deployment needs distributed rate limiting, request budgets, observability and provider circuit-breaking beyond the hackathon minimum.

## Cost discipline

The project can be developed and demonstrated using free/open-source software plus Nebius promotional or hackathon credits, but **zero monetary cost is not guaranteed indefinitely**. Nebius Token Factory grants initial credits and may require paid balance for heavy workloads. Do not enable automatic top-ups for the hackathon demo.

Keep prompts small, cap output tokens, avoid unnecessary retries, and use a fast/low-cost model for routine calls if quality testing shows it is sufficient. Use the larger Super model only where its reasoning quality materially improves the investigation.

## Final submission gate

Do not submit until all of these are true:

- [ ] hosted URL works without developer-only setup;
- [ ] real Nebius Token Factory request succeeds;
- [ ] NVIDIA Nemotron model is used at runtime;
- [ ] public repository and MIT license are accessible;
- [ ] README is current and contains exact setup instructions;
- [ ] security/secret scan passes;
- [ ] backend tests pass with PostgreSQL;
- [ ] frontend typecheck/lint/build pass;
- [ ] no secrets are present in Git history or browser bundles;
- [ ] YouTube demo is under three minutes and shows the real product;
- [ ] Devpost feedback is specific and complete;
- [ ] all claims in the submission are demonstrably true.
