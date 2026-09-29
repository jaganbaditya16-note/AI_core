# AICore — Evidence-to-Decision Investigator

## Product

AICore is a security control plane for organizations operating AI agents. The hackathon feature adds a narrow, high-value capability: **NVIDIA Nemotron 3.5 Lightning, served by Nebius Token Factory, turns a deterministic anomaly into a bounded investigation brief for a human operator.**

The product is deliberately split into three trust levels:

```text
OBSERVE
agent activity → deterministic baseline → recorded anomaly/evidence

REASON
bounded + redacted evidence → NVIDIA Nemotron on Nebius Token Factory
                  → structured hypotheses + verification plan

DECIDE
human review → current identity/RBAC → policy → action firewall
                  → only then can an existing action be executed
```

**Nemotron investigates. AICore decides.**

That is the core safety and product distinction. The model is not the security authority and has no tool access.

## Real user problem

AI-agent security teams face a costly gap between detection and decision. A detector can identify an unusual pattern, but a human still has to assemble context, distinguish facts from hypotheses, decide what to verify, and avoid premature remediation.

AICore addresses that gap without handing an LLM production control:

- deterministic systems produce the evidence;
- Nemotron explains and organizes that evidence;
- uncertainty remains visible;
- humans verify the suggested checks;
- the existing authorization, policy and firewall layers remain authoritative.

This makes the AI useful in the exact place where language reasoning adds value while keeping the high-risk decision path deterministic.

## What Nemotron does

Nemotron is used for:

1. concise anomaly explanation;
2. severity interpretation as advisory context, not a policy verdict;
3. explicitly labelled hypotheses;
4. evidence categories used in the reasoning;
5. safe, falsifiable verification checks;
6. non-executable containment considerations;
7. confidence and uncertainty;
8. explicit unsafe actions to avoid.

The model cannot approve, execute, block, delete, suspend, change policy, call tools, or mutate database state.

## Security architecture

### 1. Tenant boundary

The route requires the existing `audit.read` permission and loads the detection through the tenant-scoped repository. A missing or cross-tenant detection is returned as a 404.

The client cannot submit its own risk score, evidence, target, role, policy result or execution request.

### 2. Data minimization

The route constructs an explicit allow-list of detection fields instead of serializing the ORM object. The outbound adapter then:

- recursively redacts credential-shaped keys such as `password`, `token`, `api_key`, `authorization`, cookies and private keys;
- redacts bearer/JWT-like strings;
- limits nesting, strings, mappings and lists;
- enforces a hard 32 KiB serialized input ceiling;
- calculates a SHA-256 digest of the exact bounded representation sent to the model.

The digest is a provenance identifier only; source evidence is never returned through it.

### 3. Prompt-injection boundary

Detection evidence can contain attacker-controlled text. The system prompt therefore explicitly treats the evidence block as **data, not instructions**. The application does not allow evidence to become a system message or tool instruction.

Prompt hardening is defense-in-depth, not a claim that prompt injection can never occur. The more important control is that Nemotron has no authority or tools to act on a successful injection.

### 4. Model-output boundary

Nemotron output must satisfy a strict Pydantic contract. Oversized or credential-shaped output is rejected. Invalid inference is a service failure, never a trusted fallback.

The response has `action_taken: false` by construction.

### 5. SSRF protection

The configured inference endpoint must use HTTPS and one of the approved Nebius Token Factory hosts. Credentials, query strings and fragments are rejected. This prevents a configuration mistake from turning the inference client into a generic internal HTTP client.

### 6. Cost/abuse protection

The process has a bounded inference concurrency guard. Saturation returns HTTP 429 rather than allowing unbounded model calls. Output tokens and timeout are capped by configuration.

This is intentionally a local defense. A production multi-instance deployment should add distributed per-tenant rate limiting at the gateway as well.

### 7. Secret handling

`NEBIUS_API_KEY` is server-side configuration only. It is never a `NEXT_PUBLIC_*` value, never included in model evidence, and never included in the safe configuration summary.

The repository contains placeholders only. Real credentials must be supplied through deployment secrets/environment configuration.

## API

```text
POST /organizations/{organization_id}/risk/detections/{detection_id}/investigation
```

Response includes:

- detection identity/type/risk level;
- summary and severity interpretation;
- hypotheses;
- evidence categories used;
- safe verification checks;
- containment considerations;
- confidence and uncertainty;
- do-not-do guidance;
- model identifier;
- request correlation ID;
- input-boundary indicator;
- SHA-256 evidence digest;
- `action_taken: false`.

Possible operational responses include 401, 403, 404, 429 and 503. The endpoint never converts an inference failure into a fake answer.

## Demo story

The three-minute demo should be one complete customer story:

1. Show normal AI-agent behaviour and the deterministic baseline.
2. Trigger/show one recorded anomalous pattern.
3. Open the evidence generated by AICore.
4. Click **Investigate with Nemotron**.
5. Show three visually separate sections: **Recorded facts**, **AI hypotheses**, and **Human verification**.
6. Highlight the uncertainty and do-not-do sections.
7. Attempt to demonstrate that the investigation response cannot execute an action.
8. Show that an actual action remains behind authentication, RBAC, policy and the action firewall.
9. State clearly: **"Nebius Token Factory runs NVIDIA Nemotron. Nemotron investigates; AICore decides."**

Do not claim autonomous remediation unless a separately verified, authorized action workflow actually performs it.

## Customer perspective

### Value

- Less time turning a detection into a reviewable incident narrative.
- Deterministic evidence remains the source of truth.
- Hypotheses are visibly separated from facts.
- Verification steps are explicit instead of hidden in a model's prose.
- The AI layer can fail without disabling the underlying security control plane.

### Trust concerns and responses

| Customer concern | Design response |
|---|---|
| "Can the model execute something dangerous?" | No tools and no execution path. `action_taken` is always false. |
| "Can tenant data cross boundaries?" | Tenant-scoped repository plus explicit field allow-list. |
| "Can secrets reach the model?" | Recursive sensitive-key/value redaction plus hard payload cap. |
| "Can a malicious detection prompt-inject the model?" | Evidence is isolated as data and the model has no authority. |
| "Can the endpoint be abused for unlimited spend?" | Token/output cap, timeout and bounded concurrency; production gateway rate limiting remains recommended. |
| "What if the model hallucinates?" | Strict schema, explicit hypotheses/uncertainty, human verification, no authority. |
| "What if Nebius is unavailable?" | The core control plane remains usable; investigation fails closed with 503. |

## Judge perspective

### Technological implementation

The value is not another chatbot. The implementation connects a real deterministic security pipeline to a production-oriented NVIDIA model through Nebius while preserving an explicit trust boundary:

**detection → evidence adapter → safety boundary → Nemotron reasoning → structured advisory output → human verification → existing deterministic enforcement.**

### Design

A judge should be able to tell immediately which information is:

- **FACT** — recorded by AICore;
- **AI HYPOTHESIS** — generated by Nemotron;
- **DECISION** — made by a human and enforced by AICore.

Those states should never be collapsed into a single AI score.

### Potential impact

The first customer is an organization running internal AI agents where anomalous behaviour is expensive to investigate and unsafe to hand entirely to an autonomous LLM.

The architecture can generalize to AI-agent operations, internal security operations, model/tool governance and regulated environments, subject to deployment-specific privacy requirements.

### Quality of idea

The differentiator is not claiming that the model is infallible. The product makes the model useful **because it is constrained**: it can reason over evidence but cannot become the authority that acts on its own reasoning.

## Scalability

The inference adapter is stateless and horizontally deployable. The control-plane database remains the source of truth.

For production scale:

- move investigations to an asynchronous queue for long-running analysis;
- use distributed per-tenant rate limits;
- cache only by a deterministic evidence digest + model/version/prompt version;
- use a smaller Nemotron model for routine triage and a larger supported model for escalations;
- record latency/token/error metrics without recording prompts or credentials;
- use dedicated Nebius capacity when isolation or predictable throughput becomes necessary.

Nebius currently documents public and dedicated inference paths and describes Token Factory as an OpenAI-compatible inference platform with autoscaling and production-oriented deployment options. citeturn0search6turn0search10

## Cost discipline

The software stack itself is open-source Python/Next.js infrastructure. Nebius Token Factory inference is usage-priced, so the application deliberately bounds output tokens and concurrency. Current Nebius documentation lists Nemotron 3.5 Lightning at a low per-token public-endpoint price relative to larger Nemotron variants; exact pricing and availability should be rechecked before submission because they can change. citeturn0search2

Do not describe the application as unlimited zero-cost production software merely because hackathon credits may be available.

## Known limitations

- Nemotron does not prove root cause.
- Schema validation does not prove factual correctness.
- Prompt-injection defenses reduce risk but cannot mathematically eliminate model misinterpretation.
- The current concurrency guard is process-local; distributed rate limiting belongs at the gateway.
- Sensitive-data policy is deployment-specific; operators must decide whether the selected evidence is permitted to leave their environment.
- No autonomous remediation is introduced by this feature.
- A live hosted demo and real inference measurement must be verified in the final submission environment.

## Nebius/NVIDIA requirement mapping

The hackathon organizers explicitly require teams to explain what they used Nebius Token Factory/AI Cloud and the NVIDIA model for, what worked, what needs improvement, how onboarding felt, and whether they would build with the tools again. They also explicitly advise teams to hide API keys, name the required technologies in the project description/Built With section, and demonstrate them clearly in the three-minute video. citeturn1search0

Nebius documents an OpenAI-compatible Token Factory API and a current Nemotron catalog including Nemotron 3.5 Lightning, with public inference available for the highlighted model. citeturn0search1turn0search2

### Feedback that must be measured, not invented

**Nebius Token Factory — used for:** serving Nemotron inference for bounded anomaly investigation.

**What worked:** record actual onboarding time, API compatibility, first-token latency, total latency, reliability and model-switching experience.

**What needs work:** name the exact console/API/documentation step and describe the observed issue.

**Onboarding:** record the path from account/credits → API key → first successful request.

**Would build again:** decide from the measured experience, not from generic praise.

**NVIDIA Nemotron — model:** `nvidia/Nemotron-3_5-Lightning`.

**Used for:** security-investigation reasoning over deterministic anomaly evidence.

**What worked:** record concrete examples where the model correctly separated evidence, hypotheses and uncertainty.

**What needs work:** record failure cases, schema-following issues, latency or reasoning gaps.

**Would build again:** decide after evaluating the actual demo workload.

## Final submission safety checklist

Before submission:

- [ ] Public repository contains no real API key or database credential.
- [ ] Secret scan passes.
- [ ] Nebius key exists only in server/deployment secret configuration.
- [ ] Live Nemotron inference succeeds.
- [ ] Cross-tenant investigation is rejected.
- [ ] Credential-like evidence is redacted before inference.
- [ ] Oversized evidence is bounded.
- [ ] Prompt-injection fixture remains non-executable.
- [ ] Invalid model JSON fails closed.
- [ ] Investigation cannot call the action execution path.
- [ ] Existing action firewall tests remain green.
- [ ] Production build and API tests are green.
- [ ] Live hosted demo is verified.
- [ ] Actual Nebius/NVIDIA feedback is measured and written into the submission.
