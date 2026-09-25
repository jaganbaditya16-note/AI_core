# Risk: baselines, deviations and assessments (Phase 10)

> **ANOMALY ≠ INCIDENT. RISK ≠ PROOF OF COMPROMISE. DETECTION ≠ AUTOMATIC RESPONSE.
> ANOMALY ENGINE ≠ AUTHORIZATION ENGINE.**
>
> This phase compares an agent's recent behaviour with that agent's own history and reports
> where the two disagree, in numbers a reader can recompute. A deviation is a statement
> about *data*: this rate is outside this bound, over these two intervals, against this
> baseline. It is not a claim about intent, not a claim that something was compromised, and
> not an incident — this build has no incident, no alert, no notification, no severity, no
> suspension, no containment and no approval, and it holds no object that could produce one.
>
> Nor is it a control. The engine cannot authorize, cannot execute, cannot change a policy
> or a permission, cannot suspend or revoke an agent, and cannot write anything except its
> own record of what it computed. Where Phases 5, 6 and 7 *decide* whether something may
> happen, this phase only describes what already did.

Phase 9 counted the trail. Phase 10 **compares**: the same rows, read over two intervals
that do not overlap, measured against each other, and reported as evidence. The invariant
the build now satisfies:

```
DISCOVER → IDENTITY → PERMISSION → POLICY → ACTION FIREWALL → CONTROLLED EXECUTION
                    → AUDIT EVENT → MONITORING → ANOMALY / RISK → EVIDENCE + ASSESSMENT
```

Reads reuse `security.read`; recording an assessment is guarded by `security.create`, which
Phase 10 grants to the owner and the security administrator. Both codes already existed in
the Phase 2 vocabulary — no new resource and no new action was invented for this phase, and
no role was widened except by that one grant.

## The chain, and why every step is kept

```
OBSERVATION → BASELINE → DEVIATION → EVIDENCE → RISK ASSESSMENT
```

Each step is in the response, because a level without its arithmetic is an opinion:

- **Observation** — what this agent actually did in the observed interval: counts from the
  action pipeline, the clock hours it was active in, how long the interval is, and the
  distinct actions and resources it used.
- **Baseline** — the same measurement over a *different*, earlier interval, expressed as a
  distribution of full hourly buckets: mean, population standard deviation, and the sample
  count behind both.
- **Deviation** — six dimensions, each either measured or refused with a closed reason.
  Every dimension is reported whether or not it fired, so the response says what was looked
  for and not only what was found.
- **Evidence** — for each factor, the observation, the baseline it was compared against, the
  bound or count that was crossed, the window, and the identifiers involved. Both facts and
  interpretations are labelled as such: `observed`, `baseline_mean`, `upper_bound` and
  `items` are measurements; `status`, `anomaly`, `risk_level` and `factors` are the engine's
  reading of them, each reproducible from the measurements beside it.
- **Assessment** — a level from a closed five-value vocabulary, assigned by a published
  table over *factor counts*, never by mapping a score to a label.

There is no score anywhere in this phase. Not a hidden one, not a documented one: no
`risk_score`, no `confidence`, no `severity`, no weights. A client that disagrees with a
level can read the table below and the factors that produced it, which is the test of
whether a level was earned.

## The seven modules

```
apps/api/src/aicore_api/
  core/risk.py                    the vocabulary, windows, baselines, statistics, level table (pure)
  risk/engine.py                  six dimensions over two frames → factors → level (pure)
  risk/service.py                 the assembly: registry page or one agent → assessment; recording
  db/repositories/risk.py         RiskRepository reads the trail; DetectionRepository keeps records
  schemas/risk.py                 the published shapes, and the documents a row stores
  api/routes/risk.py              four reads and one recording, and the window dependency
  risk/__init__.py                the boundary, stated for a reader who starts here
```

The split is the design. `core/risk.py` and `risk/engine.py` are pure — no database, no
clock, no request, no configuration lookup — so the parts that can be wrong subtly (a window
boundary, a zero-variance baseline, a ratio with an empty denominator, the level table) are
testable by stating a baseline as a list of numbers. `risk/service.py` is the only place that
knows both the trail and the registry, and `db/repositories/risk.py` is the only place that
touches the audit table or writes a row. The split is also what makes the phase's central
claim checkable: the engine cannot act, because it holds nothing that could.

## Where the numbers come from

One source: `aicore.audit_events`, the Phase 8 trail. No second event system, no duplicated
execution records, no streaming platform, no model, and no new analytics infrastructure.

- **Action-pipeline vocabulary.** The counts are over the eight event types the action
  pipeline records — request, allow, deny, execute, fail, replay, approval requirement and
  the pipeline's own vocabulary — read from `core/audit.py` rather than retyped, so a type
  added to the pipeline is counted on the day it is added.
- **Aggregation in PostgreSQL.** Every statement is a `SELECT` over a bounded window with
  the tenant bound, and the counts are `count(*)`/`count(*) FILTER (…)` grouped by UTC hour
  in the database. No query fetches rows for Python to count, and none can be asked for
  "everything this organization ever recorded": `start` and `end` are required keyword
  arguments with no default.
- **One audit-read vocabulary.** The engine imports `AuditEventType` and nothing else from
  the trail's modules — no writer, no repository, no reader interface. A phase that could
  not name an event type would not be able to count one.

## Time windows

Every request resolves two intervals before any handler runs.

| Observation | Meaning |
|---|---|
| `5m`, `15m`, `1h`, `24h`, `7d` | that span, ending at the server's clock |
| `custom` | `start_time` and `end_time` from the caller, at most 30 days apart |
| *(absent)* | `24h` — Phase 9's default |

| Baseline | Meaning |
|---|---|
| `24h`, `7d`, `14d`, `30d` | history ending exactly where the observation begins; `7d` by default |

The rules, all enforced in one place (`core/risk.py`):

- **The baseline never contains the observation.** It ends at the observation's start, to
  the microsecond, and the stored rows carry that as a database `CHECK`
  (`baseline_precedes_observation`). A comparison against a window that contains the
  observation would be partly a comparison against itself.
- **The maximum baseline is 30 days** — 720 hourly buckets. There is no `all`, no `forever`
  and no open-ended span: an unbounded baseline is priced by how long the organization has
  existed, and, worse, an agent's first month and its third year are not the same
  distribution.
- **The server decides what time it is.** A named observation window always ends at the
  server's clock. A caller chooses *which* interval to read; not what "now" is. The clock is
  read once per request, so the observation's end, the baseline's end and every timestamp in
  the response describe one instant.
- **A malformed window is an error, never an empty answer.** One open end, an inverted
  range, a range longer than 30 days, a bound sent without `window=custom`, a naive
  timestamp, and a window with *no duration at all* are all `422`. A zero-length window is
  refused specifically because a rate whose divisor is zero is not a measurement.
- **Only full hours become baseline samples.** The buckets are floored in UTC on both sides
  (Python and `date_trunc`), and a partial bucket at either edge of the baseline is dropped:
  it holds less than an hour, and keeping it would make the same baseline depend on the
  second of the day it was computed.
- **Recording demands explicit bounds.** A named window means "the last hour, as of when you
  asked", which is a different interval on every request; recording that would write a new
  record each time somebody looked. `window=custom` with both bounds states the interval, so
  the same interval is the same record.

## The method

Stated in full, because "anomaly detection" is a phrase people fill in with whatever they
hope it does.

### Statistics

For each baseline bucket, the engine keeps the counts. The comparison uses:

| Quantity | Definition |
|---|---|
| `baseline_mean` | the arithmetic mean of the per-hour counts of full baseline buckets |
| `baseline_stddev` | the **population** standard deviation of those counts (`σ`, divided by *n*) |
| `upper_bound` | `mean + deviation_multiple × σ` (default: two standard deviations) |
| `lower_bound` | `max(0, mean − deviation_multiple × σ)` — clamped, because a negative rate does not exist |

Zero-variance and empty-input behaviour is defined rather than special-cased away:

- **A flat baseline has bounds equal to its mean.** If every baseline hour is identical,
  `σ` is `0` and both bounds are the mean. Nothing divides by the spread, so a perfectly
  regular agent is comparable rather than excluded — its threshold is simply tight, and the
  change-ratio rule below is what keeps a tight threshold from being a noisy one.
- **`mean([])` is `0.0` and `population_stddev(<2 samples)` is `0.0`, by definition.** The
  functions are total; the *dimensions* are what refuse to compare, with a reason, when
  those numbers would be meaningless.
- **A baseline mean of zero is never a denominator.** A rate dimension whose baseline is
  entirely zero reports `baseline_no_signal`: an agent with no history has no scale to
  deviate from, and "zero versus zero" is not a finding.
- **A ratio with no denominator is skipped, not counted as zero.** A bucket with no
  completions has no failure *rate*; it is excluded from the baseline's ratio distribution
  and reported in `baseline_samples` as not contributing.

### The six dimensions

| Metric | Measured as | Fires when | Insufficient when |
|---|---|---|---|
| `action_rate` | action requests per hour over the whole observation window | `observed > upper_bound` **and** `observed ≥ rate_change_ratio × mean` (spike), or `observed < lower_bound` **and** `observed ≤ mean ÷ rate_change_ratio` (drop) | fewer than 12 full baseline buckets, fewer than 20 baseline events, or a zero mean |
| `failure_rate` | `failures ÷ (executions + failures)` | `observed > upper_bound` and at least the change ratio | fewer than 8 baseline buckets with a denominator, or fewer than 4 observed completions |
| `denial_rate` | `denials ÷ requests` | as above | fewer than 8 baseline buckets with requests, or fewer than 4 observed requests |
| `novel_action` | an action identifier used in the observation that the baseline never recorded | at least `min_novel_occurrences` (default 1) occurrence | fewer than 20 baseline events, or a baseline with no actions |
| `novel_resource` | a `(resource_type, resource_id)` pair the baseline never recorded | as above | as above |
| `unusual_time` | events in a UTC clock hour the agent was never active in | at least `min_novel_occurrences` occurrence | fewer than 20 baseline events, fewer than 4 distinct baseline hours, or a baseline with no hours |

Two rules are worth stating plainly.

**A rate deviation needs both a crossed bound and a real change.** Three standard deviations
around a small mean is a small number: an agent that averages two requests an hour with a
spread of 0.2 has an upper bound of 2.4, and crossing it at 2.7 means nothing. So a
deviation also requires a change of at least `rate_change_ratio` (default 2×) against the
mean. Both numbers are in the factor, so the two conditions can be checked separately.

**The rate is the window's rate, not a bucket's.** The observed quantity is the window's
total request count divided by its length in hours, including a fractional window: a
15-minute observation with 30 requests is a rate of 120/hour, compared against hourly
baseline buckets. The engine does not correct for the smaller sample a short window has,
which makes short windows *harder* to fire, not easier — the conservative direction.

### The level table

`assess_risk_level` is five rows, evaluated in order, over the *counts* of factors — no
score, no weights, and no row that cannot be reached:

| Rule | Level |
|---|---|
| 3 or more strong factors, at least one extreme | `critical` |
| 2 or more strong factors | `high` |
| 1 strong factor, extreme, and at least one weak factor | `high` |
| 1 strong factor, and the deviation is extreme *or* corroborated by a weak factor | `medium` |
| 2 or more weak factors | `medium` |
| exactly one factor of either kind | `low` |
| none | `none` |

The four **strong** factors are the rate deviations —
`action_rate_spike`, `action_rate_drop`, `failure_rate_spike`, `denial_rate_spike`. The
three **weak** ones are the first-use observations — `novel_action`, `novel_resource`,
`unusual_time` — which are context rather than magnitude. A factor is **extreme** when a
rate deviation sits at least `extreme_multiple` (default 3×) past its own bound: above
`3 × upper_bound` for a spike, or below `mean ÷ 3` for a drop. A bound of zero has no
multiple to take, so it is never extreme, and first-use factors are never extreme by
construction.

What the levels mean, in the build's own language: `low` is "one measurement moved outside
its baseline"; `medium` is "that movement is large, or a second, weaker observation agrees";
`high` is "several independent measurements moved, or one moved a long way"; `critical` is
"several moved and at least one is far outside". None of them says an agent *is* anything.
Levels are per assessment, they are not comparable between agents, and they are not a
queue, a ticket or a priority.

### Cold start

An agent with a short or empty baseline is `insufficient_data` — never `anomaly: true`,
never a level above `none`. The response says which condition stopped each dimension
(`baseline_too_short`, `baseline_empty`, `baseline_no_signal`,
`baseline_insufficient_samples`, `observation_insufficient_samples`, `baseline_no_hours`,
`baseline_no_history`), so a reader can tell "we did not look" from "we looked and it was
fine". Both are recorded when they are recorded, because `no row` would otherwise mean two
different things.

## Evidence

Every factor carries the numbers it was computed from — `observed`, `baseline_mean`,
`baseline_stddev`, `upper_bound`, `lower_bound`, `threshold_multiple`,
`threshold_occurrences`, `baseline_samples`, `observation_samples` — plus, for the first-use
dimensions, the identifiers themselves: `items[]` of `{kind, value, occurrences}` with
`kind` from the closed vocabulary `action | resource | hour`. A resource item also names its
`resource_type`, because two resource kinds can share an identifier.

Every dimension carries its own evidence too, whether it fired or not, and every response
states the thresholds in force (`parameters`) — a bound whose multiple is not published
cannot be checked.

**Nothing here is arbitrary JSON.** Every field is a scalar, a stated time, a closed
enumeration or a list of these same models, in the response and in the stored row alike; the
stored documents are re-validated through the same Pydantic models when they are read back,
so a stored record and a computed one cannot drift into different shapes. The database
enforces the bound as well: the evidence document is an object of at most 32 KiB, the
factors an array of at most 16 KiB, and a stored record's `factors` must be non-empty
exactly when its status is `deviating`.

## Privacy

The engine reads counts, identifiers and clock hours. It never reads a request's arguments, a
metadata document, a correlation identifier, an actor, a reason or a payload — a test
captures the SQL and asserts none of those columns is selected — and it could not publish one
if it did: there is no field in the response, and no column in the storage, that could hold
one. An agent's own `identity_metadata` is not part of an assessment, and nothing the agent
or the caller sent is echoed back: the only client-supplied values that reach a request are
an agent identifier, two timestamps and the names of the windows they belong to.

No secrets, no credentials, no tokens, no raw action arguments, no customer records, no
documents: the phase's subject is *how much* and *when*, and the schema has no room for
anything else. A test plants a canary secret in the database and asserts it appears in
neither an assessment nor a stored record.

## The API

| Route | Method | Purpose |
|---|---|---|
| `/organizations/{organization_id}/risk/agents` | `GET` | assess one page of the registry, each agent against its own baseline |
| `/organizations/{organization_id}/risk/agents/{agent_id}` | `GET` | assess one registered agent |
| `/organizations/{organization_id}/risk/detections` | `GET` | list recorded assessments, newest first, with filters |
| `/organizations/{organization_id}/risk/detections/{detection_id}` | `GET` | read one recorded assessment |
| `/organizations/{organization_id}/risk/analysis` | `POST` | assess one agent over explicit bounds and record it |

- **Four reads and one write.** The write accepts exactly one field — `agent_id` — and
  `extra="forbid"` turns an attempt to add anything else into a `422`. There is no threshold
  parameter, no baseline parameter, no level, no anomaly flag, no confidence, no window and
  no organization: every analytical value is derived server-side.
- **Every read states its windows.** The page carries the observation interval, the baseline
  label and `generated_at`; each item carries both intervals, its dimensions, its factors and
  the thresholds in force.
- **Bounded, always.** The observation window is at most 30 days, the baseline at most 30
  days, assessments page at 25 by default and 100 at most, records at 50 by default and 200
  at most, and the offset is capped at 100 000. `total` is returned only when asked for,
  because it costs a second pass.
- **Ordered by the registry and the clock, never by findings.** The page is ordered the way
  the registry lists agents (newest registration first) and the record feed by `detected_at`
  descending with the identifier breaking ties. Nothing ranks: a page that reordered itself
  by level would make paging skip and repeat rows.
- **A foreign identifier is a 404** — literally the same answer as an identifier that does
  not exist, with the same message and the same shape. Both are tested against a second
  tenant that really holds the record in question.
- **Recording is idempotent.** The same agent, the same observation window and the same
  baseline are one record: the second request returns `200` with `recorded: false` and the
  identifier of the record that exists, and the first returns `201`. A different window or a
  different baseline is a different record.

## RBAC

| Route | Permission | owner | security_admin | analyst | admin |
|---|---|:-:|:-:|:-:|:-:|
| the four reads | `security.read` | ✅ | ✅ | ✅ | — |
| `POST …/risk/analysis` | `security.create` | ✅ | ✅ | — | — |

Nothing was invented for this phase: `security.read` is Phase 2's code for reading security
information, and `security.create` is the same vocabulary's write action, granted to the
owner and the security administrator by `0008`. An analyst reads findings and may not record
one; the general administrator holds neither code and gets `403` on every risk route, which
is asserted rather than assumed. There is no `risk.*`, `anomaly.*`, `incident.*` or
`firewall.*` permission, and no route that could remediate, suppress, acknowledge or act.

## Persistence

One table, one migration, and one write path.

```
aicore.anomaly_detections     revision 0008_anomaly_risk
```

- **What a row is.** One recorded assessment of one entity over one closed observation
  window against one named baseline: the windows, the status, the anomaly flag, the level,
  the head detection type, the measurement document and the factors — plus `schema_version`,
  which is part of the identity rather than decoration.
- **Deterministic dedup, enforced by the database.** The identity of an assessment is a
  unique constraint on
  `(organization_id, entity_type, entity_id, observation_start, observation_end,
  `baseline_start, baseline_end, schema_version)`, and an `INSERT … ON CONFLICT DO NOTHING`
  makes a repeated analysis a no-op *in the database*, not in a handler that checked first.
  Two simultaneous requests for the same closed window produce one row.
- **Append-only.** Triggers refuse `UPDATE` outright and `DELETE` unless the transaction has
  set a named, transaction-local retention reason; `TRUNCATE` is refused too. A finding that
  could be edited after the fact would be worth less than no finding at all, and the API
  offers no route that could try.
- **The conclusion cannot contradict the measurements.** `CHECK` constraints assert that a
  `deviating` status implies `anomaly`, that `anomaly` implies a level above `none`, that the
  head detection type is present exactly when the status is `deviating`, that the factors are
  non-empty exactly then, that the named baseline span equals the interval it resolved to,
  and that the baseline ends at or before the observation begins.
- **Nothing else moved.** The migration adds one table, two indexes, one permission grant and
  the append-only guard. It does not alter a Phase 1–9 table, does not touch a policy, does
  not write an audit event, and does not change `0007`.

## Determinism, and what "idempotent" means here

The engine is a pure function of two frames and a parameter set: no clock, no randomness, no
configuration lookup, no database handle. The same two windows produce the same assessment,
in the same field order, with the same factor order (which is why the head detection type is
stable), and a test asserts it by computing the same assessment twice. Recording adds one
thing the engine does not have — the clock that stamps `detected_at` — and nothing else; a
recorded row is byte-identical in its evidence to the assessment that produced it, and
re-asking for the same closed window returns that row rather than computing a new one.

## Performance

Every statement carries three bounds:

- **tenant** — `organization_id = :tenant` in every statement, enforced by the same tenancy
  guard every other phase uses;
- **window** — `occurred_at >= :start AND occurred_at <= :end`, with no default and no
  `None`;
- **population** — the registry page's agents (at most 100), or the one agent named.

The aggregate is *per window*, not per agent: one page of 25 agents costs the same six
statements as one agent, which a test asserts by capturing the SQL the application's engine
actually sends. The indexes are Phase 8's — `(organization_id, occurred_at, id)`,
`(organization_id, actor_id, occurred_at)`, `(organization_id, event_type, occurred_at)` —
and the two new ones serve the record feed and one entity's history.

## Tests

| File | What it holds |
|---|---|
| `tests/test_risk_statistics.py` | windows, baselines, buckets, the level table and the statistics — pure, no database |
| `tests/test_risk_engine.py` | the six dimensions over hand-built frames: every rule, the cold start, the levels, the fixed order |
| `tests/test_risk_api.py` | the reads over HTTP: shapes, window refusals, counts against seeded activity, RBAC-free isolation of one agent's data |
| `tests/test_risk_recording.py` | the one write: idempotence, the database-enforced identity, append-only refusals, what a client may not state |
| `tests/test_risk_isolation.py` | the tenant boundary against a second, real organization: 404s, filters, pagination, no leak of an identifier |
| `tests/test_risk_privacy.py` | a canary secret that must not appear anywhere; the columns the aggregate never selects; the verdict vocabulary that must not occur |
| `tests/test_risk_no_action.py` | the phase cannot act: imports, declared methods, fingerprints of every table before and after an analysis, and an execution that must still be permitted |
| `tests/test_risk_integration.py` | known activity measured exactly; the statements that ran; window bounds; the single insert |
| `tests/test_risk_contract.py` | the published surface: routes, query parameters, response fields, vocabularies, forbidden words, and this document |

No test uses random data. Windows are pinned to whole hours and filled with counts stated in
the test, so a response must equal arithmetic a reader can check — and a change in the engine
shows up as a changed number rather than a passing suite.

## Limitations, stated plainly

- **A deviation is arithmetic, not evidence of intent.** The engine knows how many, how
  often and in which hour; it does not know why, and it never speculates. Nothing in this
  build is a claim that an agent is compromised, malicious or under attack.
- **No incidents, no alerts, no notifications.** There is no incident table, no severity, no
  acknowledgement, no assignment, no suppression, no escalation and no webhook. A detection
  is a row a reader can fetch; nothing sends anything anywhere.
- **No automated response and no containment.** No kill switch, no suspension, no
  revocation, no policy change, no execution. The engine holds no executor, no firewall, no
  policy engine and no session, and a test asserts those imports are absent.
- **No LLM, no embeddings, no vector store, no model provider.** The arithmetic is SQL and
  Python, and the explanation is the numbers that produced it.
- **No governance**: no approval workflow, no dependency graph, no supply-chain analysis, no
  frontend, no SIEM, no message broker and no metrics database.
- **One entity type.** Baselines are per agent (`entity_type = 'agent'`, a value of a closed
  vocabulary with one member today). Assets, policies and organizations have no baseline,
  and the schema refuses a row that claims otherwise.
- **No seasonality and no periodicity.** A baseline is one mean and one spread over at most
  30 days. An agent that is legitimately busier on Mondays will look unusual on Mondays;
  that is the intended reading of a single-distribution comparison, and a reader who needs
  per-hour-of-day models is asking for a different phase.
- **No correction for small samples.** A five-minute window is compared against hourly
  buckets without a variance correction, so a short window needs a larger multiple to fire.
  This is conservative by design and stated rather than hidden.
- **Thresholds are deployment configuration.** The nine parameters have documented defaults
  and are validated at startup; there is no endpoint that reads or sets them, because a
  client that could tune the detector would be choosing its own answers.
- **No retention policy.** Detections accumulate until an operator removes them, which is
  the only way past the append-only guard.
- **No frontend.** Five endpoints are the whole client surface of this phase.
