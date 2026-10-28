# Monitoring (Phase 9)

> **MONITORING ≠ ANOMALY DETECTION ≠ INCIDENT RESPONSE ≠ AI INTELLIGENCE ≠ AUTOMATED
> REMEDIATION.**
>
> It counts. Phase 8's `aicore.audit_events` table is the record of what happened; Phase 9
> answers *how much of it happened* — in a bounded window, per agent, per action, over
> time — with arithmetic over that record and nothing else. There is no baseline, no
> threshold, no score, no severity, no "normal", no incident, no alert, no notification and
> no automated response anywhere in this phase. A spike is a bigger number, and this build
> says nothing more about it than that: deciding whether a number is *bad* is a different
> subject with different vocabulary, and it is not implemented here.
>
> Nor is monitoring a control. It cannot authorize, execute, modify a policy, change a
> permission or suspend an agent. It reads the trail and reports counts, and it holds no
> object that could do otherwise.

Phases 5, 6 and 7 *decide*. Phase 8 remembers. Phase 9 **measures**: the same record, read
in aggregate, with no second event system, no duplicated execution records and no new
table. The invariant the build now satisfies:

```
DISCOVER → IDENTITY → PERMISSION → POLICY → ACTION FIREWALL → CONTROLLED EXECUTION
                                      → AUDIT EVENT → MONITORING
```

The phase adds three modules, five read-only endpoints and no permission: `audit.read` —
declared in Phase 2, held by the owner and the security administrator — already guards read
access to the trail, and a measurement is a sum over rows that permission can already read.
No role's grant set changes.

## Where the numbers come from

One source: `aicore.audit_events`, the Phase 8 trail. Every metric this phase publishes is
a `COUNT` over a bounded slice of it, computed by PostgreSQL.

That is a deliberate architecture, not a shortcut:

- **No second event system.** A monitoring stream written beside the trail would be a
  second account of the same activity, and two accounts eventually disagree. There is one
  record of what happened, and the measurement reads it.
- **No duplicated execution records.** Phase 7's `action_executions` table stays what it
  is: an idempotency ledger that records what *ran* and forgets refusals. Monitoring counts
  the trail, which records both.
- **No new table and no migration.** The database is still at `0007_audit_events`. The
  indexes Phase 8 already built — `(organization_id, occurred_at, id)`,
  `(organization_id, event_type, occurred_at)`, `(organization_id, actor_id, occurred_at)`
  and the rest — are the ones the aggregates use; a test asserts the head revision and the
  absence of any monitoring table.
- **No streaming platform.** No Kafka, no Redis, no Elasticsearch, no metrics database. The
  queries are ordinary SQL over rows that are already there.

Facts are derived, never invented. An event type means what Phase 8 made it mean:
`action.denied` is a refusal that never ran, and monitoring adds a number to it, not a
meaning. The vocabulary is the same and is not extended — there is no monitoring event
type, and monitoring writes no event at all.

## The three modules

```
apps/api/src/aicore_api/
  core/monitoring.py              the vocabulary: windows, counters, buckets, rates (pure)
  db/repositories/monitoring.py   the aggregation: tenant-scoped, window-bounded SQL
  monitoring/service.py           the assembly: what a caller receives
  schemas/monitoring.py           the published shapes
  api/routes/monitoring.py        the five endpoints
```

The split is the design. `core/monitoring.py` is a pure module — no database, no clock, no
request — so the parts that can be wrong subtly (a bucket boundary, a window's width, a
ratio over an empty denominator) are testable in isolation. The counter tables live there
too, and the repository *generates* its SQL from them rather than restating them, which is
what makes "adding a metric" a one-line change instead of a three-file change: a metric
cannot come to mean something different from what it is named.

## Time windows

Every request is measured over a bounded window, resolved by the server before the handler
runs.

| Window | Meaning |
|---|---|
| `5m`, `15m`, `1h`, `24h`, `7d` | that span, ending at the server's clock |
| `custom` | `start_time` and `end_time` from the caller, at most 30 days apart |
| *(absent)* | `24h` — the default |

Four rules, in one place (`resolve_window`), so all five endpoints answer identically:

- **Bounded, always.** There is no `all`, no `forever` and no `since`; a `custom` range is
  refused when it exceeds a month. An open-ended query is priced by how long the
  organization has existed, which is exactly the property a monitoring endpoint must not
  have.
- **The server decides what time it is.** A named window always ends at the server's clock.
  A caller can choose *which* interval to read — that is what `custom` is for — but not
  what "now" is, because a measurement whose present the client picks is not the same
  measurement twice.
- **A mistake is an error, not an empty answer.** A `custom` window with one open end, an
  inverted range, a range longer than a month, a bound sent without `window=custom` and a
  naive (timezone-less) timestamp are all `422` with a message naming the problem. Answering
  a malformed request with zeros would look exactly like a quiet period.
- **Time is unambiguous.** Bounds are inclusive and timezone-aware; timestamps are
  published in UTC; bucketing is floored in UTC on both sides (Python and `date_trunc`), so
  a session timezone cannot shift an event into a neighbouring bucket. Boundaries are
  inclusive at **both** ends, so two adjacent windows overlap by one instant rather than
  losing an event between them.

## The consistency model

Stated exactly, because "monitoring" is a word people fill in with promises this build does
not make:

- **Read committed, per statement.** Each view is a handful of statements in one
  transaction on one connection, reading whatever the trail had committed when each
  statement ran. A concurrent execution admitted between two of those statements is
  invisible to both; one admitted between two *views* is visible in the second call and not
  the first.
- **Eventual by request.** A record becomes visible to monitoring once its writer's
  transaction commits — the same instant it becomes visible to the Phase 8 query API, the
  same scan, the same rows. There is no replication, no second copy and therefore no
  replication lag; there is also no push, no cache and no invalidation to get wrong.
- **No real-time claim.** A read that arrives while a write is in flight does not see that
  write. Nothing in this phase promises sub-second freshness, an exact
  "as of" snapshot across several calls, or a live stream.
- **Two windows are two measurements.** A `5m` window and a `24h` window asked a moment
  apart are computed at two different instants and can differ at their edges. That is why
  every response repeats the window it resolved: a number is only meaningful with the
  interval it was measured over.
- **No snapshot isolation and no repeatable read.** Monitoring takes no long-lived
  snapshot, holds no cursor and keeps no cache, so a second call is a second measurement
  rather than a replay — which is the honest thing to publish for a view whose subject is
  still being written.

## What is measured

Counters are defined once, in `core/monitoring.py`, and every published field comes from
one of them.

### `GET …/monitoring/summary`

| Field | Counts |
|---|---|
| `total_events` | every audit event in the window |
| `action_requests` | `action.requested` — executions admitted to the pipeline |
| `action_executions` | `action.executed` — an adapter ran to completion |
| `action_failures` | `action.failed` |
| `action_denials` | `action.denied` — refused by any layer, nothing ran |
| `action_replays` | `action.replayed` — answered from the idempotency ledger |
| `approval_required` | `action.require_approval` — held for an approval this build lacks |
| `asset_creations` / `asset_updates` / `asset_deletions` / `asset_discoveries` | the four `asset.*` events |
| `agent_registrations` / `agent_updates` / `agent_deletions` | the three `agent.*` events |
| `policy_creations` / `policy_updates` / `policy_version_publications` / `policy_status_changes` / `policy_deletions` | the five `policy.*` events |
| `policy_changes` | those five, summed — derived, never counted separately |
| `active_agents` / `active_assets` | distinct agents and assets *named by* an event in the window |
| `execution_health` | `succeeded`, `failed`, `completed` and two rates (below) |
| `denials` | the refusal total and its breakdown by reason |

The eighteen event-type counters partition the whole Phase 8 vocabulary exactly once, and a
test asserts that: an event type added later fails the suite until it is counted, and a type
counted twice fails it too.

### `GET …/monitoring/agents`

One row per agent named by at least one event in the window, ordered by event count
descending and identifier ascending — the second key makes the order total, so paging cannot
repeat or skip a row. Each row carries `events`, `action_requests`, `executions`,
`failures`, `denials`, `approval_required`, `replays` and `last_activity_at`.

**Attribution, not identity.** An agent appears here because a request named it
(`agent_id` on an execution), which is Phase 7's field and Phase 8's column. A registered
agent that has never been named is absent — and so is any agent with nothing in the window,
because this build can measure what happened and cannot distinguish "idle" from "never
used". Reporting both as a row of zeros would invent that difference. The registry's own
`agent_registrations` counter still counts the registration; the two views answer different
questions.

Nothing here ranks, scores or flags an agent. There is no `anomalous`, no `risk`, no
`suspicious`, and no field in which such a claim could be smuggled.

### `GET …/monitoring/actions`

One row per registered action with activity in the window, ordered by identifier (the
catalogue is closed and code-level, so a stable order matters more than a ranked one):
`requested`, `allowed`, `denied`, `approval_required`, `executed`, `failed`, `replayed`.

Two axes, kept apart. `allowed` counts the **decision** column — requests the firewall
permitted, whatever came of them — while the rest count **event types**. A request that was
allowed and then failed is one `allowed` *and* one `failed`; collapsing them would lose the
fact that it was permitted.

Only the six action-pipeline event types appear. Lifecycle events put the permission they
used (`asset.create`) in the same `action` column, and listing them beside the catalogue
would be the one confusion this view exists to prevent.

### `GET …/monitoring/policies`

Two sections that share a subject and must not share an answer:

- `decisions` — how the pipeline answered requests, in Phase 6's and Phase 7's own words:
  `allow`, `deny`, `require_approval`. All three are always present, at zero if unseen.
- `lifecycle` — changes to the policy record: `created`, `updated`, `version_published`,
  `status_changed`, `deleted`, and their sum `changes`.

Neither recommends anything. There is no field a client could read as advice, and no
proposal anywhere in the response.

### `GET …/monitoring/trends`

A complete series over the window: one bucket per interval (`hour` or `day`), in order,
**including the empty ones as zeros**. A gap and a quiet hour must not look the same to a
reader, so the zeros are stated; and nothing is interpolated or smoothed — no moving
average, no fill-forward, no line drawn through data this build does not have.

Bucket edges are floored in UTC, and a series is capped at **366 buckets**: an hourly
series over a month would be 721 points, and the request is refused with the interval it
should have asked for (`interval=day`) rather than answered with a payload nobody reads.
The longest window this build serves therefore always fits a daily series.

### Execution health

`execution_health` is `completed = succeeded + failed`, with `success_rate` and
`failure_rate`. Only **completed** executions are in the denominator: a refused request
never ran, so counting it as a failure would report the firewall's refusals as an execution
problem, and a replay was answered from the ledger and did not execute either.

When nothing completed, both rates are `null` — never `0.0`, which would read as "every
execution failed". "Nothing ran" and "everything failed" are different statements and are
not allowed to look alike.

## The API

| Endpoint | Answers |
|---|---|
| `GET /organizations/{id}/monitoring/summary` | the window's counts in one response |
| `GET /organizations/{id}/monitoring/agents` | per-agent activity (paged) |
| `GET /organizations/{id}/monitoring/actions` | per-action activity |
| `GET /organizations/{id}/monitoring/policies` | decisions and policy-record activity |
| `GET /organizations/{id}/monitoring/trends` | activity per time bucket |

All five are `GET`, all five require `audit.read`, and none of them accepts a write — every
other method on those paths is a `405`. There is deliberately **no** `/monitoring/activity`
duplicating the Phase 8 trail listing (that endpoint already pages and filters the events
themselves), no `/monitoring/health` returning a verdict, and no endpoint for thresholds,
baselines, comparisons or alert configuration.

Common query parameters:

- `window` (`5m`…`7d`, `custom`) plus `start_time`/`end_time` for a custom range;
- `agents`: `limit` (1–200, default 50), `offset` (≤ 100 000), `agent_id`, `total`;
- `actions`: `action` — matched as a value from a closed pattern, length-bounded;
- `trends`: `interval` (`hour`, `day`).

Every response repeats the resolved window (name, inclusive UTC bounds), so a number is
always attributable to a stated interval. Nothing is returned as a raw row: no event id, no
correlation id, no request id and no metadata appear in any response — a measurement is
counts and times.

## Tenant isolation

Every query is scoped by `organization_id` **before** any filter is applied, and the tenant
always comes from the authorized request context — never from the query string:

- a foreign organization answers exactly like one that does not exist (the same `404`, the
  same body, only the `request_id` differs), so there is no existence oracle;
- a foreign `agent_id` or `action` filter selects nothing, because the tenant scope is
  applied first — the answer never reveals whether the identifier exists elsewhere;
- a `403` (a member without `audit.read`) names nothing about the tenant it refused;
- a test asserts cross-tenant behaviour for every one of the five views, for the summary
  aggregates, the per-agent and per-action filters and the time series.

## RBAC

Monitoring reuses `audit.read` and adds no permission. The reasoning is in the route module
and worth repeating: a measurement is a sum over rows the holder can already read, so a new
`monitoring.read` would guard nothing that is not already guarded — and granting it to a
role that lacks `audit.read` would hand that role the trail's contents in aggregate. The
owner and the security administrator read monitoring for the same reason they read the
trail: oversight. The administrator deliberately does not, and neither does the analyst
(`security.read` stays reserved for findings, which is a later phase's subject).

There is no monitoring write permission because there is no monitoring write: no route
acknowledges an event, silences a signal, records a measurement or changes a threshold.

## Performance

Every query carries three bounds, and a test captures the SQL to prove it:

- **tenant** — `organization_id = :tenant` in every statement;
- **window** — `occurred_at >= :start AND occurred_at <= :end` in every statement;
- **page** — `LIMIT`/`OFFSET` on the per-agent view (capped at 200 rows), and the closed
  action catalogue plus its own row ceiling on the per-action view.

Statements per view, measured against a live database: **summary 3** (counters, distinct
identifiers, refusals by reason), **agents 1** (+1 only when `total` is asked for),
**actions 1**, **policies 2** (lifecycle counters and decision counts), **trends 1**. The
summary is one pass and eighteen `count(*) FILTER (…)` expressions rather than eighteen
queries, and a counter that covers the whole vocabulary compiles to a plain `count(*)` — a
tautological filter is how a counter silently stops covering an event type added later.

Aggregation happens in PostgreSQL, never in a Python loop over rows. No query fetches a row
it then counts, and no query is unbounded: a `start` and an `end` are required keyword
arguments on every repository method, with no default and no `None`, so "everything this
organization ever recorded" is not a query this layer can express.

No cache, no Redis, no materialized view and no pre-aggregation: the numbers are computed
per request from the rows that exist. The indexes are Phase 8's.

## Tests

| File | What it holds |
|---|---|
| `tests/test_monitoring.py` | windows, buckets and rates — pure, no database |
| `tests/test_monitoring_metrics.py` | the counter tables against the vocabulary; the response schemas against the counters; the SQL the definitions generate; the absent verdict vocabulary |
| `tests/test_monitoring_service.py` | the assembly, over a stub repository: zero-filled series, derived totals, safe division |
| `tests/test_monitoring_api.py` | the five endpoints over HTTP: shapes, the window contract, pagination, RBAC, isolation, hostile input, and that a read leaves the trail unchanged |
| `tests/test_monitoring_integration.py` | known activity counted exactly; placement across window and bucket boundaries; the SQL that actually ran; isolation and consistency against live PostgreSQL |
| `tests/test_monitoring_read_only.py` | the imports, the signatures and the behaviour that make monitoring read-only |

The integration tests do not use random data. A window is filled with a stated set — ten
requests, six executions, one failure, two refusals, one approval requirement, and five
lifecycle changes — and the API must report exactly those numbers, attributed to the right
agents and the right action. History is also *placed* (rows written directly, in the shape
the platform writes) so that windows and bucket boundaries can be tested with exact
instants, which no sequence of HTTP calls in the present can produce.

## Limitations, stated plainly

- **No anomaly detection, no baselines, no thresholds, no scoring, no behavioural
  profiling.** A number is a number. Nothing here compares two windows, decides what is
  normal, or ranks anything.
- **No incidents, alerts, notifications or webhooks.** A denial is an observed event, and
  remains one. There is no incident table, no severity, no assignment, no workflow and no
  response — nothing in this phase sends anything anywhere.
- **No recommendations and no policy modification.** Monitoring reports what happened; it
  does not evaluate, propose, draft, rank or suggest a policy, a rule, an exemption or a
  setting — there is no field, no endpoint and no code path that could carry one, and the
  service holds no policy engine to consult.
- **No automated remediation and no containment.** No kill switch, no suspension, no policy
  change and no execution. Monitoring cannot act on what it counts; it holds no executor, no
  firewall, no policy engine and no session, and a test asserts those imports are absent.
- **No LLM, no embeddings and no vector store.** The arithmetic is SQL. No model provider is
  integrated, and no metric is produced or explained by one.
- **Denials are not attributed to a specific policy.** The trail records the decision, the
  reason and the layer (`policy_denied`, `authorization_denied`, `target_not_found`,
  `environment_mismatch`), not which policy produced the decision — so "denials by policy"
  is answered at the level of the layer and the reason, and the breakdown is honest about
  the refusals whose reason could not be read by counting them as `unspecified`.
- **Activity, not inventory.** `active_agents` counts agents *named by an event*, not agents
  that exist; the registry and the inventory answer "what do we have". Nor is a per-agent
  count a statement about behaviour: this build has no runtime in which an agent could
  behave.
- **Boundaries are inclusive at both ends.** Two adjacent windows both include an event at
  exactly their shared instant — a deliberate choice (no holes) that a caller reading two
  windows should know about.
- **No real-time claims.** Monitoring reads committed rows per request. There is no
  streaming, no push, no cache and no promise about how fresh the trail is beyond "what has
  been committed".
- **No retention, archival or export.** The trail grows; monitoring reads a bounded slice of
  it and says nothing about what to keep.
- **No frontend.** The five endpoints are the whole client surface of this phase; this build
  ships no dashboard.
