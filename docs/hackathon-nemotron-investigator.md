# AICore — Evidence-to-Decision Investigator

## What this adds

AICore already turns agent activity into deterministic anomaly detections. This extension adds a deliberately narrow AI layer: **NVIDIA Nemotron on Nebius Token Factory investigates a recorded detection and produces a bounded brief for a human reviewer**.

The model is not the security authority. It cannot authorize, approve, execute, block, suspend, mutate policy, or change the detection. The deterministic AICore control plane remains the enforcement boundary.

That separation is the product story:

```text
agent activity
    ↓
deterministic baseline + anomaly detection
    ↓
recorded evidence
    ↓
bounded evidence adapter
    ↓
NVIDIA Nemotron 3.5 Lightning
served by Nebius Token Factory
    ↓
structured investigation brief
    ↓
human verifies evidence
    ↓
existing authorization + policy + firewall
```

## Real user problem

Security teams can detect unusual AI-agent behaviour but still spend time answering:

- What exactly changed?
- Which parts are facts versus hypotheses?
- What should a human verify next?
- What should **not** be done yet?
- Can an AI assistant help without becoming an unsafe autonomous security operator?

AICore addresses that gap by turning a deterministic detection into a reviewable investigation brief while preserving a hard boundary between **reasoning** and **authority**.

## Why the model is useful here

A deterministic detector is good at repeatable thresholds and evidence. It is not good at turning several structured signals into a concise investigation narrative.

Nemotron is used for the part where language reasoning adds value:

1. summarize the recorded anomaly;
2. explain why it matters;
3. generate explicitly-labelled hypotheses;
4. propose safe verification checks;
5. suggest non-executable containment considerations;
6. state uncertainty and unsafe next steps.

The model never receives credentials, action arguments, raw audit payloads, or arbitrary tenant rows.

## Safety boundary

The endpoint requires the existing `audit.read` permission and loads the detection through the tenant-scoped repository. A missing or cross-tenant detection is a 404.

The request body is empty. The client cannot supply a risk level, evidence, target, role, policy result, or execution request.

The model output is validated against a strict Pydantic contract. Invalid model output becomes a 503; it is never silently converted into a trusted answer.

The output contains `action_taken: false` by construction. No investigation route calls the action execution service.

## Privacy boundary

Only server-generated anomaly fields are sent to Nebius. The integration applies recursive bounds to strings, lists and mappings before inference. This limits accidental context growth and makes the outbound payload auditable.

The system prompt forbids inventing credentials, commands, IP addresses, users, assets, events, or payloads. The application still treats model output as untrusted text.

Operators must review the evidence and their organization's data-residency and retention requirements before enabling external inference.

## Configuration

Set these server-only variables:

```text
AICORE_NEBIUS_API_KEY=<secret>
AICORE_NEBIUS_BASE_URL=https://api.tokenfactory.us-central1.nebius.com/v1
AICORE_NEBIUS_MODEL=nvidia/Nemotron-3_5-Lightning
AICORE_NEBIUS_TIMEOUT_SECONDS=20
AICORE_NEBIUS_MAX_OUTPUT_TOKENS=900
```

Never use `NEXT_PUBLIC_` for the API key.

The current Nebius documentation lists an OpenAI-compatible Token Factory API and the public NVIDIA Nemotron lineup. The model is configurable so the deployment can move to another supported Nemotron endpoint without changing the safety boundary.

## API

```text
POST /organizations/{organization_id}/risk/detections/{detection_id}/investigation
```

The endpoint returns:

- summary
- why it matters
- hypotheses
- verification checks
- recommended containment considerations
- confidence
- uncertainties
- do-not-do guidance
- model identifier
- correlation ID
- whether input was truncated
- `action_taken: false`

## Demo path

For the three-minute hackathon video, demonstrate one complete story instead of many disconnected screens:

1. Show an agent's normal baseline.
2. Generate or display a recorded anomaly.
3. Open the detection and show its deterministic evidence.
4. Click **Investigate with Nemotron**.
5. Show the structured brief and clearly label it **AI advisory — not authorization**.
6. Point to the verification checklist and uncertainty section.
7. Show that the action path remains behind AICore authorization, policy and firewall checks.
8. Say aloud: **"Nebius Token Factory runs NVIDIA Nemotron; the model explains, AICore decides."**

Do not claim a remediation was executed by the model unless a separately verified, authorized action workflow actually performs it.

## Hackathon requirement mapping

The current official rules require a working software application that runs on Nebius Token Factory or Nebius AI Cloud and uses at least one NVIDIA open-source model. They also require a working demo URL, public repository, README/setup instructions, a public <=3-minute YouTube demo, and specific feedback about Nebius Token Factory/AI Cloud and the NVIDIA model used. The judging criteria are equally weighted: technological implementation, design, potential impact, and quality of idea.

This implementation is designed to make the required technologies visible in the product architecture and demo. **Calling the Token Factory API from an otherwise locally-hosted application is not treated here as proof of the hosting requirement. The final submission should deploy the application on Nebius AI Cloud/Serverless or otherwise verify that its runtime satisfies the platform rule.**

## Customer perspective

### Value

- Converts a noisy anomaly into a reviewable investigation brief.
- Keeps evidence and authorization deterministic.
- Reduces the amount of security context a human must assemble manually.
- Makes uncertainty explicit instead of presenting a confident-looking verdict.

### Trust concerns

- A model can still hallucinate.
- External inference may be inappropriate for sensitive evidence.
- Model latency and availability can vary.
- Recommendations are not automatically validated against the organization's current change plan.

The product addresses these concerns by bounding input, validating output, requiring human review, and keeping the model outside the enforcement path.

## Judge perspective

### Technological implementation

The interesting implementation is not merely "call an LLM." The important boundary is deterministic detection → controlled evidence adapter → Nemotron reasoning → structured output → deterministic security controls.

### Design

The UI should make three states visually distinct:

1. **Fact** — recorded deterministic evidence.
2. **AI hypothesis** — Nemotron interpretation.
3. **Decision** — AICore authorization/policy/firewall result.

Never merge those states into one AI-generated score.

### Potential impact

The initial audience is organizations operating internal AI agents, where anomalous behaviour needs investigation without handing an LLM unrestricted control over production systems.

### Quality of idea

The differentiator is the **authority boundary**: the model is useful precisely because it is not trusted with the final security decision.

## Scalability

The inference adapter is stateless. It can run behind a serverless endpoint and scale horizontally. Detection data remains in PostgreSQL, while each investigation is an independent inference request.

For higher traffic:

- use a queue for asynchronous investigation;
- cache identical investigation inputs by detection fingerprint + model version;
- add per-tenant rate limits;
- use a smaller Nemotron model for high-volume triage and a larger model for escalated cases;
- collect latency, token usage and failure metrics without logging secrets.

## Cost discipline

The application itself uses ordinary open-source Python/Next.js components. Nebius Token Factory is consumption-based. The hackathon materials advertise free Token Factory credits, but **free credits are not the same as unlimited zero-cost production usage**. Keep the demo small, cap output tokens, and stop the deployment when the credits are exhausted.

## Known limitations

- No automatic root-cause proof.
- No autonomous remediation.
- No claim that model recommendations are correct merely because they pass schema validation.
- No persistent AI memory is introduced by this feature.
- No new database table is required for the advisory result.
- Browser E2E and a live hosted endpoint still need to be verified in the target deployment environment before submission.
- The repository must be public and include its open-source license for judging.

## Required hackathon feedback template

The submission should contain concrete feedback rather than generic praise:

### Nebius Token Factory

**Used for:** serving the investigation model for anomaly triage.

**What worked well:** _Fill in measured onboarding time, API compatibility, latency and observed reliability._

**What needs work:** _Name the exact API/console/documentation step and describe the problem._

**Onboarding:** _Record the path from account/credits to first successful inference._

**Would build again:** _State the decision and why, based on observed evidence._

### NVIDIA Nemotron

**Model used:** `nvidia/Nemotron-3_5-Lightning`.

**Used for:** bounded security-investigation reasoning over deterministic anomaly evidence.

**What worked well:** _Record concrete examples from the demo/evaluation set._

**What needs work:** _Record failure cases, schema-following issues, latency or reasoning gaps._

**Would build again:** _State the decision and why, based on observed evidence._

Do not fabricate benchmark numbers or feedback. Measure them during the final demo run.
