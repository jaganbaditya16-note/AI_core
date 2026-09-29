# AICore

**Proof-Bound AI Security Control Plane** — a deterministic security system with a bounded NVIDIA Nemotron investigation layer served through Nebius Token Factory.

AICore discovers and inventories AI assets, applies explicit authorization and policy, detects anomalous behaviour from its own audit history, opens operational incidents, requests human approvals, and re-checks current policy before an approved action can reach the existing firewall.

## Core principle

> **AI explains security evidence. Deterministic services make security decisions. Humans remain accountable for consequential approval.**

Nemotron never receives credentials, raw action arguments, unrestricted audit metadata, or execution controls. Model output is advisory and bounded. Approval is single-use, tenant-scoped, requester-bound and expiry-bound. The final action must still pass the current authorization, policy and firewall checks.

## Demonstration path

```text
AI activity → deterministic anomaly → bounded evidence → Nemotron investigation
          → incident → human review → current-policy re-check → action firewall
          → execute or block
```

The operations console is available at `/operations`.

## Nebius + NVIDIA

AICore uses **Nebius Token Factory's OpenAI-compatible inference API** with an NVIDIA Nemotron model. The API key is server-side only (`AICORE_NEBIUS_API_KEY`) and is never exposed through `NEXT_PUBLIC_*` configuration. When the key is absent, the intelligence endpoint fails closed with a controlled `503`; it does not fabricate an inference result.

The application intentionally keeps Nemotron outside authorization and execution. This makes the model useful for investigation without making probabilistic output a security boundary.

## Architecture

```text
                 ┌──────────────────────────┐
                 │   Next.js Operations UI  │
                 └────────────┬─────────────┘
                              │
                 ┌────────────▼─────────────┐
                 │       FastAPI API         │
                 └────────────┬─────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        ▼                     ▼                     ▼
 deterministic risk     incidents + RBAC      action firewall
        │                     │                     │
        └──────────┬──────────┘                     │
                   ▼                                │
          bounded evidence                          │
                   │                                │
                   ▼                                │
        Nebius Token Factory                        │
                   │                                │
                   ▼                                │
          NVIDIA Nemotron                          │
                   │                                │
                   ▼                                │
             human review ───── approval ───────────┘
```

## Security model

- Tenant-owned records are accessed through tenant-scoped repositories.
- Incident evidence stores references, not copied event/action payloads.
- Approval rows store the exact action fingerprint and idempotency key, but no action arguments.
- Reviewers cannot approve their own membership's request.
- Approval expires after one hour and can be consumed once.
- Database conditional update is the concurrency arbiter for approval consumption.
- An approval cannot override authorization or a policy denial.
- Current policy is evaluated again at execution time.
- The existing action firewall remains the only execution gate.
- AI administrators do not receive approval authority.
- API keys and database credentials remain server-side.

## Stack

| Layer | Technology |
|---|---|
| Web | Next.js 16, TypeScript, Tailwind CSS v4 |
| API | Python 3.11+, FastAPI, Pydantic v2 |
| Data | PostgreSQL 16, SQLAlchemy 2, Alembic |
| AI | Nebius Token Factory + NVIDIA Nemotron |
| Testing | Pytest, Playwright, Ruff, mypy, TypeScript |
| Runtime | Docker / Docker Compose |

## Repository layout

```text
apps/api/                       FastAPI control plane
  src/aicore_api/core/          authorization, policy, firewall, risk, intelligence
  src/aicore_api/db/models/     tenant, audit, risk, incident, approval models
  src/aicore_api/db/repositories/tenant-scoped persistence
  src/aicore_api/api/routes/    REST endpoints
  tests/                        unit + PostgreSQL security coverage
apps/web/src/app/operations/    judge-facing operations console
database/migrations/            versioned PostgreSQL schema
packages/types/                 shared frontend contracts
docs/                           architecture and hackathon evidence
```

## Local setup

```bash
cp .env.example .env
npm install
bash scripts/py.sh -c pass
npm run dev:api
npm run dev
```

Run PostgreSQL with Docker Compose or the repository's database helper. Apply migrations before exercising incident/approval endpoints.

## Environment

Keep secrets out of Git. Set `AICORE_NEBIUS_API_KEY` only in the server environment when you are ready for live inference. Do not use a `NEXT_PUBLIC_` variable for this key.

## Verification

```bash
npm run lint
npm run typecheck
npm run build
npm run test:api
npm run check:secrets
bash scripts/verify.sh --full
```

The submission should only claim a live Nebius inference path after the key is configured and a real request has been demonstrated. Browser E2E also requires Chromium to be installed.

## Hackathon alignment

This project is intended for the **Best Apps and Agents** track: it is a practical security operations workflow rather than a generic chatbot. The hackathon requires a working application using Nebius Token Factory or AI Cloud and at least one NVIDIA open-source model, plus a public repository, license, setup instructions, working demo and short public demo video. The final submission must also include specific feedback on Nebius/NVIDIA tooling.

## Current limitations

- The Nebius API key is intentionally not stored in the repository and must be configured for live inference.
- The operations console is the judge-facing workflow UI; production authentication/identity management remains deliberately out of scope.
- Incident evidence is reference-only; it does not snapshot arbitrary audit payloads.
- The approval API is an explicit human-review layer. It does not turn approval into blanket execution authority.
- A production deployment should add external identity federation, centralized rate limiting, secret rotation, observability and managed database backups.

## License

MIT — see `LICENSE`.
