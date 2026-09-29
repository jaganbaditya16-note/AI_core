# AICore + NVIDIA Nemotron on Nebius

AICore keeps security decisions deterministic and uses NVIDIA Nemotron only as a bounded,
human-in-the-loop investigation assistant.

## Runtime path

`Phase 10 deterministic detection -> server-generated evidence -> Nebius Token Factory -> NVIDIA Nemotron -> advisory explanation -> human review`

The model cannot authorize, execute, approve, deny, suspend or contain anything. Its output
never enters policy evaluation or the action firewall.

## Required configuration

Set these only on the API/server environment:

```text
AICORE_NEBIUS_API_KEY=<secret>
AICORE_NEBIUS_BASE_URL=https://api.tokenfactory.us-central1.nebius.com/v1/
AICORE_NEBIUS_MODEL=nvidia/nemotron-3-super-120b-a12b
AICORE_NEBIUS_TIMEOUT_SECONDS=30
```

The default model is NVIDIA Nemotron 3 Super through the OpenAI-compatible Nebius Token
Factory endpoint. The key is stored as `SecretStr`, never sent to the model, never returned
by the API and never exposed through `NEXT_PUBLIC_*` variables.

## Security boundary

Only deterministic anomaly fields, bounded evidence and an optional 1,000-character human
question are sent. Raw audit metadata, action arguments, credentials, tokens and private
payloads are excluded. Prompt content is explicitly treated as untrusted data to reduce
prompt-injection risk.

A missing or unreachable provider returns `503`; the application does not silently fake an
AI response. This distinction matters for judging and production operations.

## API

```text
POST /organizations/{organization_id}/risk/detections/{detection_id}/investigate
```

The caller must already hold `audit.read`. A foreign-tenant detection is indistinguishable
from a missing detection. The response is marked `advisory_only=true` and includes the model
identifier, confidence and limitations.

## Hackathon demonstration

For the Nebius x NVIDIA Global AI Hackathon, demonstrate a real runtime call to Nebius Token
Factory with the NVIDIA Nemotron model. The recommended story is:

1. Show a deterministic anomaly in AICore.
2. Open the finding and request an investigation.
3. Show the Nemotron explanation, hypotheses and reviewer questions.
4. Show that the model has no execute/approve control.
5. Human review remains the final decision boundary.

The repository must be configured with a real Nebius key only in the deployed server secret
store; never commit it.
