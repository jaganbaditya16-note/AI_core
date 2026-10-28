# Anomaly & risk (Phase 10)

> **DETECTION ≠ INCIDENT. RISK ≠ AUTHORIZATION. THERE IS NO AUTOMATIC RESPONSE.**
>
> Phase 10 compares what each agent did in a recent, bounded **observation window** with
> what the same agent did in the **baseline window** immediately before it, and explains —
> with structured evidence — anything that is unusual. It is deterministic, read-only and
> analytical. It does not authorize, execute, invoke the action firewall, block or approve.
> It does not suspend, kill or contain an agent, and does not revoke or modify a
> permission. It does not modify a policy. It does not create an incident, does not send an
> alert, does not notify anyone and does not remediate anything. A risk level is never an
> input to any of those decisions, and no Phase 1–9 code path reads it.

```
DISCOVER → IDENTITY → PERMISSION → POLICY → ACTION FIREWALL → CONTROLLED EXECUTION
        → AUDIT → MONITORING → ANOMALY & RISK
```

Phase 9 counts. Phase 10 asks *is any of it unusual for this agent, and how much should that
matter?* — over the same audit trail, with arithmetic a reviewer can redo by hand. There is
no machine learning, no language model, no external service and no network call anywhere in
the phase.

## What the phase adds

| Piece | Where |
| --- | --- |
| Pure engine: windows, vocabulary, statistics, detection, risk, evidence, fingerprints | `apps/api/src/aicore_api/core/risk.py` |
| Bounded PostgreSQL aggregates over `audit_events` (read-only) | `apps/api/src/aicore_api/db/repositories/risk_history.py` |
| Detection store (insert-only, deduplicated) | `apps/api/src/aicore_api/db/repositories/anomaly_detections.py` |
| Orchestration | `apps/api/src/aicore_api/risk/service.py` |
| Operator command that records detections | `apps/api/src/aicore_api/risk/cli.py` |
| Three read-only routes and their schemas | `api/routes/risk.py`, `schemas/risk.py` |
| Table `aicore.anomaly_detections` | migration `0008_anomaly_detections` |
| TypeScript mirror | `packages/types/src/index.ts` |

The audit trail's schema is unchanged. No permission is added and no role changes.

## Detection ≠ incident

A **detection** is a recorded, explained observation: *this agent, over these windows,
deviated from its own baseline in this way, by this much*. It has no lifecycle — no
acknowledge, assign, resolve, close, suppress or snooze — because those are
incident-management verbs, and this phase does not manage incidents. The table's triggers
refuse `UPDATE` (so a detection cannot be turned into a work item by a data fix either) and
`TRUNCATE`; rows may only be removed with a tenant-scoped `DELETE`, because they are
re-derivable from the trail.

What to do about a detection is a person's decision, taken through the phases that already
own action (the registry, the policy engine, the action firewall). **There is no automatic
response of any kind.**

## Risk ≠ authorization

`risk_level` is information. The action firewall, the policy engine, the executors and the
authorization layer do not import the engine, and an agent classified `critical` has its
next request decided exactly as it would have been before Phase 10 existed
(`tests/test_risk_read_only.py` asserts both: the import graph, and the behaviour).

The Phase 3 asset field `risk_classification` — a human-set label that policies may
reference — is a different thing. Phase 10 never reads or writes it.

## The detection vocabulary

Closed: eight types, each implemented from data the trail really has.

| Detection | Question it answers | Method |
| --- | --- | --- |
| `action_rate_spike` | Far more action requests than usual? | mean + max(3σ, 5) |
| `action_rate_drop` | Far fewer action requests than usual? | mean − max(3σ, 5) |
| `failure_rate_spike` | A much larger share of executions failing? | share difference ≥ 0.25 |
| `denial_rate_spike` | A much larger share of requests refused? | share difference ≥ 0.25 |
| `novel_action` | An action never requested in the baseline? | set difference |
| `novel_resource` | A target never addressed in the baseline? | set difference |
| `unusual_time` | Requests in UTC hours the baseline never used? | zero-baseline hour of day |
| `unusual_frequency` | A burst far denser than the baseline's densest? | peak five-minute bucket |

What the engine reads from each `aicore.audit_events` row: `organization_id`, `event_type`,
`occurred_at`, `agent_id`, `action`, `resource_type`, `resource_id`. It reads
`action.requested` (the request), `action.denied`, `action.executed` and `action.failed`
(what came of it). `action.replayed` and `action.require_approval` are neither denials nor
failures. It **never** reads `metadata`, the actor, the request id or the correlation id —
so no argument, payload, credential or token can reach an analysis, a stored detection or a
response.

## Windows: baseline and observation

| Parameter | Values | Default |
| --- | --- | --- |
| `baseline` | `7d`, `14d`, `30d` | `14d` |
| `observation` | `1h`, `6h`, `24h` | `24h` |
| `as_of` | a whole UTC hour, timezone-aware, not in the future | start of the current UTC hour |

- **Observation** = `[as_of − observation, as_of)`.
- **Baseline** = `[observation_start − baseline, observation_start)`, immediately before it.
- Both are **half-open and adjacent** (`baseline_end == observation_start`). An event at
  exactly `observation_start` is in the observation; an event at exactly `as_of` belongs to
  the next analysis. **The baseline never contains the observation.**
- The default `as_of` is the start of the current hour, so an analysis never assesses an
  interval that is still filling up. A misaligned, naive or future `as_of` is refused (422),
  never silently adjusted.
- The baseline is split into **slots** of the observation's length (e.g. `14d`/`24h` →
  14 slots; `7d`/`1h` → 168). Rate statistics are over per-slot request counts, so the
  observation is compared with like-sized intervals.
- The largest scan is 30 days + 24 hours. There is no "all history" query.

## Cold start and minimum-data rules

An agent is `insufficient_history` — anomaly state `undetermined`, risk `none`, every check
`not_evaluated` with reason `entity_history_insufficient`, `baseline_statistics: null` —
unless **all** of these hold. Every unmet
rule is listed in `insufficient_reasons`.

| Rule | Constant | Value | Reason code |
| --- | --- | --- | --- |
| Some baseline activity | — | ≥ 1 request | `no_baseline_activity` |
| Enough baseline requests | `MIN_BASELINE_EVENTS` | `20` | `baseline_events_below_minimum` |
| Enough history slots | `MIN_HISTORY_SLOTS` | `7` | `history_span_below_minimum` |
| Enough history time | `MIN_HISTORY_SPAN` | `1 day` | `history_span_below_minimum` |
| Activity in enough slots | `MIN_ACTIVE_SLOTS` | `3` | `active_slots_below_minimum` |

- A brand-new agent is **never** anomalous for lack of history, however busy it is.
- **No baseline is fabricated.** History is counted from the agent's *first* baseline slot:
  slots before it are *missing* (the trail cannot tell "idle" from "did not exist yet") and
  are excluded; slots after it with no requests are *zero* and are included.
- An agent with no request in either window is not listed at all.

Individual checks can also decline with `insufficient_data` and a reason, so "could not
tell" is never reported as "nothing unusual":

| Check | Declines when | Reason |
| --- | --- | --- |
| `action_rate_drop` | mean − margin ≤ 0 (the mean is too small for "fewer" to mean anything) | `baseline_mean_below_drop_margin` |
| `failure_rate_spike`, `denial_rate_spike` | baseline sample < `SHARE_MIN_BASELINE_SAMPLE` | `baseline_sample_below_minimum` |
| `failure_rate_spike`, `denial_rate_spike` | observed sample < `SHARE_MIN_OBSERVED_SAMPLE` | `observed_sample_below_minimum` |
| `novel_resource` | distinct baseline targets × `RESOURCE_REUSE_MIN_RATIO` > baseline requests | `baseline_resource_set_unstable` |
| `unusual_time` | baseline active in more than `UNUSUAL_TIME_MAX_ACTIVE_HOURS` UTC hours | `baseline_hours_saturated` |

## Statistical methods

Simple, explainable and exact. Every constant below is `aicore_api.core.risk`'s, and
`tests/test_risk_contract.py` asserts this table and the code agree.

| Constant | Value | Used by |
| --- | --- | --- |
| `RATE_SIGMA` | `3` | rate spike / drop: k in mean ± k·σ |
| `RATE_MIN_DELTA` | `5` | rate spike / drop: absolute floor on the margin |
| `SHARE_DELTA` | `0.25` | failure / denial: minimum rise in share |
| `SHARE_EXTREME_DELTA` | `0.5` | failure / denial: "extreme" rise |
| `SHARE_MIN_OBSERVED_EVENTS` | `3` | failure / denial: minimum observed failures / denials |
| `SHARE_MIN_OBSERVED_SAMPLE` | `5` | failure / denial: minimum observed completions / requests |
| `SHARE_MIN_BASELINE_SAMPLE` | `10` | failure / denial: minimum baseline completions / requests |
| `RESOURCE_REUSE_MIN_RATIO` | `2` | novel resource: requests per distinct baseline target |
| `UNUSUAL_TIME_MIN_EVENTS` | `3` | unusual time: minimum off-hours requests |
| `UNUSUAL_TIME_MAX_ACTIVE_HOURS` | `20` | unusual time: saturation cut-off |
| `BURST_RATIO` | `2` | unusual frequency: multiple of the baseline peak |
| `BURST_MIN_DELTA` | `5` | unusual frequency: absolute floor above the baseline peak |
| `MAX_EVIDENCE_ITEMS` | `16` | longest evidence list (the full count is always stated) |
| `MAX_EVIDENCE_BYTES` | `8192` | largest evidence document |

- **Rate (mean + standard deviation, fixed floor).** Over the agent's history slots, the
  population mean μ and standard deviation σ are computed from exact integer sums
  (`(n·Σx² − (Σx)²) / n²`), so zero variance is an exact equality and rounding can never
  make a variance negative. Margin = `max(RATE_SIGMA × σ, RATE_MIN_DELTA)`. Spike:
  observed > μ + margin. Drop: observed < μ − margin. **Zero variance** does not make one
  extra request a spike: the floor applies, `method` is `mean_stddev_fixed_floor` and the
  z-score is reported as `null` (undefined). Extreme: beyond μ ± 2 × margin.
- **Shares (fixed thresholds).** Failure share = failures ÷ (executions + failures); denial
  share = denials ÷ requests. Detected when observed share − baseline share ≥ `SHARE_DELTA`
  with at least `SHARE_MIN_OBSERVED_EVENTS` observed failures/denials. Extreme at
  `SHARE_EXTREME_DELTA`. An agent that is *always* refused is not a denial spike.
- **Novelty (set difference).** Computed in PostgreSQL; the response carries the count and
  the first `MAX_EVIDENCE_ITEMS` items in sorted order. Targets are `resource_type:uuid`.
- **Time (zero-baseline hour of day, UTC).** Observed requests in hours with no baseline
  activity, at least `UNUSUAL_TIME_MIN_EVENTS`.
- **Frequency (peak bucket — the maximum, i.e. the 100th percentile of five-minute
  counts).** Threshold = `max(BURST_RATIO × baseline_peak, baseline_peak + BURST_MIN_DELTA)`;
  extreme at twice the threshold. Buckets are epoch-aligned and both window edges are whole
  hours, so no bucket straddles the boundary.

Deliberately **not** used: median + MAD, interpolated percentiles and moving averages. The
baseline is a fixed window compared with one observation, so a moving average adds nothing
a mean does not; and with the absolute floors above, mean ± 3σ already resists the
small-sample outliers MAD is usually chosen for, while staying computable from two integer
sums in one bounded aggregate. There is **no opaque scoring**: no weights, no model, no
composite number.

## Risk levels and factors

Five levels only: `none`, `low`, `medium`, `high`, `critical`. There is no numeric risk
score, no weight and no probability — a level is a word derived from stated rules.

**Per detection** — a base level from the type, plus one step when the measurement was
extreme (not applicable to novelty or time):

| Detection | Base level | Base factor |
| --- | --- | --- |
| `action_rate_spike` | `medium` | `activity_spike` |
| `action_rate_drop` | `low` | `activity_drop` |
| `failure_rate_spike` | `low` | `failure_rate_elevated` |
| `denial_rate_spike` | `medium` | `denial_rate_elevated` |
| `novel_action` | `medium` | `novel_action_used` |
| `novel_resource` | `low` | `novel_resource_targeted` |
| `unusual_time` | `low` | `off_hours_activity` |
| `unusual_frequency` | `medium` | `burst_activity` |

Escalation factor `extreme_deviation` adds one step.

**Per agent** — the highest detection level, then `multiple_detection_types` (+1 for two or
more distinct types) and `broad_behaviour_change` (+1 more for four or more), capped at
`critical`. No type starts at `high`: reaching it takes more evidence.

Every level above `none` carries its factors (`code`, `effect` = `base` | `escalation`,
`level` or `steps`, `detection_type`, `count`), so a level can always be re-derived by hand.
An agent with no detection is `none` with no factors.

## Evidence

Every detection carries one evidence document, in one shape:

```json
{
  "engine_version": 1,
  "detection_type": "denial_rate_spike",
  "entity": {"type": "agent", "id": "…"},
  "baseline": {"window": "14d", "start": "…", "end": "…", "slot_seconds": 86400,
               "slots": 14, "history_slots": 14, "active_slots": 14, "requests": 42},
  "observation": {"window": "24h", "start": "…", "end": "…", "requests": 6},
  "measurement": {"baseline_denials": 0, "baseline_requests": 42, "observed_denials": 6,
                  "observed_requests": 6, "baseline_share": 0.0, "observed_share": 1.0,
                  "share_delta": 1.0},
  "comparison": {"method": "share_difference", "operator": "greater_than_or_equal",
                 "threshold": 0.25, "extreme_threshold": 0.5, "…": "…"},
  "risk_factors": [{"code": "denial_rate_elevated", "effect": "base", "level": "medium",
                    "detection_type": "denial_rate_spike"},
                   {"code": "extreme_deviation", "effect": "escalation", "steps": 1,
                    "detection_type": "denial_rate_spike"}]
}
```

That is: what was observed, the baseline used, the observation window, the entity, the
measured values, the comparison that fired, the detection type and the risk factors.
Instants are ISO-8601 UTC, whole seconds. **Redaction is structural**: the engine never
reads metadata, and a second wall (`ensure_safe_evidence`) refuses any string that is not
an identifier, a UUID, a `type:uuid` target or a UTC instant, any list longer than
`MAX_EVIDENCE_ITEMS` and any document larger than `MAX_EVIDENCE_BYTES` — refused, not
trimmed, because such a value could only come from a defect.

## API

All three routes are `GET`, tenant-scoped by the path, and require **`audit.read`** — the
owner and the security administrator. The analyst and every other role get 403; a foreign or unknown organization is
404; no credential is 401; a bad parameter is 422.

| Route | Returns |
| --- | --- |
| `GET /organizations/{organization_id}/risk/analysis` | On-demand analysis of one page of agents (never stored). Parameters: `baseline`, `observation`, `as_of`, `agent_id`, `limit` (1–100, default 50), `offset`, `total`. |
| `GET /organizations/{organization_id}/risk/detections` | Recorded detections, newest first. Filters: `agent_id`, `detection_type`, `risk_level`; `limit` (1–200), `offset`, `total`. |
| `GET /organizations/{organization_id}/risk/detections/{detection_id}` | One recorded detection; another tenant's is 404. |

**Why `audit.read`, and only it.** An analysis is the trail in derived form — agent ids,
action names, targets, times — so it needs the trail's read permission, as Phase 9 reasoned
for monitoring. `security.read` alone would be wrong: the analyst holds it without
`audit.read`, and would be reading history it may not read. One permission per route is
Phase 5's rule, no permission is added and no role changes.

**No spoofing.** There is no request body and no write route (`POST`/`PUT`/`PATCH`/`DELETE`
are 405). Parameters named after engine outputs (`risk_level`, `anomaly_state`, `evidence`,
`baseline_mean`, …) are not inputs on the analysis route and change nothing; every value
is computed by the server.

## Persistence and deduplication

`aicore.anomaly_detections` holds only anomalies: `risk_level` cannot be `none`,
`anomaly_state` can only be `anomalous`, `analysis_status` only `analyzed`. Columns:
organization, `detected_at` (server clock), entity type and id, detection type, analysis
status, anomaly state, risk level, both window names and all four bounds (CHECK: adjacent and
ordered), `evidence` (JSON object, bounded), `risk_factors` (non-empty JSON array, bounded),
`schema_version`, `engine_version` and `fingerprint`.

**Deduplication is deterministic**: `fingerprint` = SHA-256 of engine version, entity,
detection type, both window names and the four bounds — never a measured value — and
`UNIQUE (organization_id, fingerprint)` with `INSERT … ON CONFLICT DO NOTHING`. Recording the
same `as_of` twice inserts nothing the second time; the first recording stands. A different
window or a new engine version is a different assessment and a new row.

Recording is an operator action, never an HTTP request:

```bash
python -m aicore_api.risk.cli record --organization acme \
    [--baseline 14d] [--observation 24h] [--as-of 2026-09-25T10:00:00+00:00]
```

It pages through every agent, inserts each detection and prints a JSON summary
(`agents_analyzed`, `insufficient_history`, `anomalous`, `detections_found`,
`detections_recorded`, `truncated`). Exit codes: 0 ok, 1 unknown organization, 2 invalid
window. Schedule it hourly with the default `as_of` to build a history of findings.

## Performance

- Every statement is tenant-scoped, window-bounded (≤ 30 days + 24 hours) and served by the
  trail's existing `(organization_id, event_type, occurred_at)` index.
- Aggregation happens in PostgreSQL (`GROUP BY`, `count(*) FILTER`, window functions); each
  statement returns one row per agent (hours: at most 24), never events.
- A page of up to 100 agents costs a fixed number of statements whatever its size: one to
  choose the page, six to profile it (`agent_id IN (…)`), and one more only when
  `total=true`. No per-agent query, no N+1.

## Tenant isolation

Every repository requires a tenant at construction and every statement carries
`organization_id = :tenant`; the engine-level guard refuses anything else. The same agent id
in two tenants is two unrelated histories. Cross-tenant reads return nothing (analysis,
list) or 404 (item), and recording one tenant never writes another —
`tests/test_risk_security.py` asserts each.

## Limitations

- **Agents only.** Detections are per agent (`entity_type = agent`); unattributed requests
  and lifecycle events are not agent behaviour and are ignored.
- **UTC hours.** `unusual_time` uses UTC hours of day; there is no per-tenant time zone or
  business calendar.
- **No seasonality.** A weekly pattern is not modelled; a quiet weekend against busy
  weekdays can look like a drop with a short observation window.
- **Whole-hour granularity** for `as_of`; five-minute buckets for bursts.
- **Novelty evidence is a sample** of `MAX_EVIDENCE_ITEMS` items (the count is complete).
- **A detection is not proof of harm.** It is a deviation from this agent's own recent past,
  explained; interpreting it is a person's job.
- **Rule changes are versioned**, not retroactive: `engine_version` is part of every
  fingerprint and row.

## Tests

`test_risk_windows.py`, `test_risk_statistics.py`, `test_risk_detection.py` (pure);
`test_risk_integration.py`, `test_risk_persistence.py`, `test_risk_security.py`,
`test_risk_read_only.py` (PostgreSQL); `test_risk_contract.py` (OpenAPI, TypeScript mirror,
migration vocabulary and this document).
