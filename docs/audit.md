# The audit trail (Phase 8)

> **The Action Execution Ledger is not the audit trail.**
>
> Phase 7's `aicore.action_executions` table is an execution and idempotency mechanism:
> one row per idempotency key, so a retry can be recognized. It records what *ran*. It has
> no actor, no decision, no policy and no refusal — a denied request never touches it.
>
> Phase 8's `aicore.audit_events` table is the application-level record of
> security-relevant activity: who did what, in which organization, when, against which
> resource, with what decision, and what came of it. **The audit trail is not anomaly
> detection, baseline analysis, incident management or alerting.** It is a record.
> Phase 9 *reads* it — [monitoring.md](monitoring.md) counts this trail in bounded windows
> and reports the numbers — and reading to count is all that happens: nothing here judges
> a number, and everything that would act on one — baselines, anomalies, incidents,
> alerting, dashboards, containment — belongs to a later phase and does not exist here.

Phases 5, 6 and 7 *decide*. Phase 8 remembers. It adds one table, one internal writer,
one read-only endpoint and no new permission: `audit.read` was declared in Phase 2 for
exactly this purpose, and no role's grant total changes.

The invariant the whole build now satisfies:

```
DISCOVER → IDENTITY → PERMISSION → POLICY → ACTION FIREWALL → CONTROLLED EXECUTION
                                      → AUDIT EVENT → QUERYABLE SECURITY HISTORY
                                      → MONITORING (Phase 9: the same record, counted)
```

Audit observes. It never authorizes, never decides, never executes and never changes an
answer — it runs *after* the decision and cannot alter it.

## The record

`aicore.audit_events`, one row per event. Every column is either server-resolved or
constrained; none is ever taken from a request body.

| Column | Meaning |
|---|---|
| `id` | UUID, `gen_random_uuid()` — the database's, never the caller's |
| `organization_id` | the tenant, from the authorized path context, `ON DELETE RESTRICT` |
| `event_type` | the closed vocabulary below |
| `schema_version` | the shape of the row; `1` in this build, `CHECK`-constrained |
| `occurred_at` | `now()`, timezone-aware — the server's clock, never a supplied value |
| `actor_type` | `human` or `system` |
| `actor_id` | the authenticated person; `NULL` for a system event |
| `actor_membership_id` | the membership that carried the role; `NULL` for a system event |
| `agent_id` | the agent an execution was attributed to, when the request named one |
| `resource_type` | `asset`, `agent` or `policy` |
| `resource_id` | the row the event is about, kept as a value — it may since be deleted |
| `action` | the operation: a registered action's id, or the `resource.action` permission |
| `decision` | `allow` / `deny` / `require_approval`; `NULL` when nothing was decided |
| `outcome` | what became of the event (below) |
| `correlation_id` | groups the events of one flow; server-established |
| `request_id` | the originating HTTP request; `NULL` for an internal path |
| `source` | `api` or `ingestion` |
| `metadata` | a bounded, sanitized summary — never a payload |

### The four axes are separate, never overloaded

`event_type` says *what happened*, `action` says *what operation it was*, `decision` says
*what the deterministic layer answered*, `outcome` says *how it ended*. The Phase 7
vocabulary is reused rather than reinvented:

| Event | Decision | Outcome |
|---|---|---|
| `action.executed` | `allow` | `success` |
| `action.replayed` | `allow` | `replayed` |
| `action.failed` | `allow` | `failed` |
| `action.denied` | `deny` | `blocked` |
| `action.require_approval` | `require_approval` | `not_executed` |
| `action.requested` | `NULL` (nothing decided yet) | `pending` |

A test asserts `AuditDecision`'s values equal the firewall's outcome vocabulary, so a
fourth firewall outcome cannot appear without a failure.

### The closed vocabulary

Emit sites exist for every value below, and a value nothing emits is absent:

| Group | Event types | Emitted by |
|---|---|---|
| Inventory (Phase 3) | `asset.created`, `asset.updated`, `asset.deleted` | the inventory routes |
| Ingestion | `asset.discovered` | the discovery path, **`source = ingestion`, actor `system`** |
| Agent registry (Phase 4) | `agent.registered`, `agent.updated`, `agent.deleted` | the registry routes |
| Policy record (Phase 6) | `policy.created`, `policy.updated`, `policy.version_published`, `policy.status_changed`, `policy.deleted` | the policy routes |
| Action pipeline (Phase 7) | `action.requested`, `action.denied`, `action.require_approval`, `action.executed`, `action.replayed`, `action.failed` | the execution route |

A lifecycle row's `action` is the `resource.action` permission that guarded the
operation (`asset.create`, `agent.update`, `policy.delete`, …), because that is what was
done; a pipeline row's `action` is the registered action's own identifier
(`agent.posture_check`), because that is what ran. `LIFECYCLE_ACTIONS` is the mapping, and
a test asserts every value in it is a permission this build declares.

## Attribution

Attribution is resolved by the server and cannot be claimed:

- The **organization** comes from the path and the caller's verified membership.
- The **person** is the principal the bearer token resolved to.
- The **membership** is the one that carried the role in that organization — both are
  recorded, because one person belongs to many organizations and a membership alone does
  not name an actor.
- The **agent** is recorded in `agent_id`, separately from the actor. An execution
  attributed to an agent is still a person's request: the trail can say *this person asked
  for this, on behalf of that agent* without inventing an identity for a component that
  holds no credential of its own.
- An operation nobody performed — ingestion — is recorded as `actor_type = 'system'` with
  **no** user and **no** membership. Inventing an actor for it would be worse than
  recording that none existed.

Three constraints make partial or invented attribution unrepresentable in the table
itself: a `human` row must name both identifiers, a `system` row must name neither, and a
`source = 'api'` row must carry a request id while an internal row must not.

**No request body can supply any of it.** The lifecycle and execution request models are
`extra="forbid"`, so a body carrying `actor_id`, `organization_id`, `event_type`,
`occurred_at`, `source`, `decision`, `outcome`, `correlation_id`, `role_code` or
`permissions` is a 422 — the field does not exist, rather than being ignored.

## Writing: one writer, one transaction

Every event is written through `AuditWriter`, the only code in the application that
touches the table:

```text
emit_event(DomainEvent(...))                  → a structured log line
emit_event(DomainEvent(...), session=session) → that *and* one audit row
AuditWriter.record(...)                       → one row, attributed to the authorized caller
AuditWriter.record_system(...)                → one row, attributed to nobody
```

- **The session is the switch.** No session, no row: a migration, a data fix or a unit
  test gets a log line and nothing else, because it has no request, no actor and no tenant
  to attribute anything to.
- **The timestamp is the database's.** Python may stamp an event for its log line; the
  row's `occurred_at` is PostgreSQL's `now()`.
- **Transactional consistency.** The row is written on the session the request is already
  using and committed with it. A change that rolls back leaves no event, and a failure to
  record before a change refuses the change (the `action.requested` row is fail-closed: an
  execution nobody can account for is worse than one that did not happen).
- **Post-decision events never change the answer.** Events recorded *after* a decision —
  the refusal, the executed outcome, the failure — are written best-effort and a failure is
  logged at ERROR: by then the adapter has already run, and raising would turn a completed
  execution into a reported failure and invite a retry of something that already happened.
- **No client can create one.** There is no write endpoint, no request model for an event
  and no permission that grants one.

### What is deliberately *not* an event

- **Reads.** Listing the trail, evaluating a policy, reading an asset: none of it changes
  anything, and an event per read would make the trail a request log with different
  retention questions.
- **Attempts refused before the operation.** A request refused by a route's permission
  dependency (a 403 on `POST /assets`, an analyst calling `actions/execute`) leaves no
  event: nothing was admitted, nothing was decided, nothing happened. The action pipeline
  is the one place a refusal is itself an event — the request *was* admitted, resolved and
  decided — and it records exactly one refusal naming the layer that produced it
  (`policy_denied`, `authorization_denied`, `target_not_found`, `environment_mismatch`,
  `policy_requires_approval`).
- **Authentication failures.** `auth` events are absent on purpose. A failed bearer token
  does not resolve to a user and *cannot* be attributed to an organization: the
  organization in the path is not verified for that caller, so recording "authentication
  failed in organization X" would write a claim the system cannot support — and it would
  turn an unauthenticated endpoint into an existence oracle over tenant ids. Where an
  authenticated caller's operation is refused, that refusal is recorded (see above);
  where the credential itself fails, there is nobody to attribute it to. This is a stated
  limitation, not an oversight.

## Append-only, enforced by the database

Two triggers — row-level for `UPDATE`/`DELETE`, statement-level for `TRUNCATE` — call one
function that raises `RestrictViolation`, with a message that names what was refused.
Application code cannot rewrite an event, and neither can a data fix or a future script.

One exception exists, and it is deliberately awkward:

```sql
SET LOCAL aicore.audit_retention = '<reason>'   -- transaction-local, greppable
```

- it must be asked for in code, by name, with a reason (`audit_retention_override`);
- it is transaction-local, so it cannot leak into the next request that borrows the
  connection and cannot be configured globally;
- it permits `DELETE` **only** — `UPDATE` is refused whatever the setting says, because no
  maintenance operation needs to rewrite history.

Phase 8 has exactly one caller: the test fixtures, which must remove a tenant's events
before they can remove the tenant (the tenant foreign key is `RESTRICT`). **There is no
retention in Phase 8** — no route, no job, no policy, no TTL.

### Tamper evidence: the hash chain is deferred on purpose

The phase allows a hash chain only if ordering and concurrency can be guaranteed cleanly,
and forbids a superficial one. Neither condition is met, so `previous_hash`/`event_hash`
are **not** implemented:

- A plain SHA-256 chain stored in the same database is recomputable by anyone who can
  write the table — update the row, recompute the chain, and the "proof" agrees with the
  tampered record. A chain that looks like evidence while being recomputable is *worse*
  than no chain, because it invites reliance it cannot support.
- A chain that is real needs a key the database does not hold (HMAC with a key held
  outside the database, or signatures with key management), which is a key-management
  design this phase does not own.
- Verification also needs a defined order. Rows are written by concurrent requests, so the
  chain position would have to come from a sequence — serializing writes or accepting
  gaps — and that is a design decision about availability, not a column to add.

What is implemented instead is the part that is real without a key: a schema that cannot
represent an edit, a closed vocabulary, server-resolved attribution, and the override
above that turns deletion into an explicit, greppable act. The deferral is stated here
rather than implied by an absent column.

## Metadata security

`metadata` is a **summary**, never a payload, and one function
(`core.audit.sanitize_metadata`) is the boundary both on write and on read:

- **shape**: a flat mapping of scalars and lists of scalars, at most 32 keys, 256
  characters per string, 16 items per list, 4096 bytes serialized (the table's `CHECK`
  allows a larger ceiling as a backstop, and a test asserts the application's bound is the
  smaller of the two);
- **keys**: a lowercase identifier shape, so `grep` works and a reader can rely on them;
- **redaction**: keys whose segments say *secret* (`token`, `secret`, `password`,
  `authorization`, `cookie`, `session`, `credential`, …) and values that look like
  credentials (`Bearer …`, a JWT, a PEM header) become `[redacted]` — kept as a visible
  marker rather than dropped, because a record that says something sensitive was present is
  more useful than a silent omission. `idempotency_key` is deliberately not a credential:
  it is the only link between a trail row and the ledger row that answers "did this run
  twice?";
- **refusals**: nested values, oversized values or a document that exceeds the bound are
  rejected loudly rather than trimmed — an event whose summary was silently truncated would
  misreport what happened;
- **no automatic argument storage**: an execution records `argument_count`, never the
  arguments, and no call site stores a request body, a header, a token or a stack trace.
  A test writes a secret-shaped value straight into the table and asserts the API returns
  it redacted, so the read boundary holds even for rows a migration wrote.

## Correlation and timestamps

Both come from the existing request context — no second middleware:

- `request_id` is the `X-Request-ID` the request layer accepted (or generated). A caller
  supplying one is not impersonating anything: it is the request id, echoed back in the
  response header, and the layer sanitizes it against a fixed alphabet first.
- `correlation_id` groups the events of one flow. The action pipeline passes the
  firewall's correlation id, which is the request's own; the writer accepts a supplied one
  only if it is a value the request layer could have produced, and replaces anything else
  with the request's id rather than dropping the event.

One request that produces several events — a registration that also creates an inventory
record, an execution that is admitted and then runs — produces several rows sharing one
correlation id. Two requests never share one.

## The query API

```
GET /organizations/{organization_id}/audit-events
```

Read-only, `audit.read`, and the *only* method on that path. Filters: `event_type`,
`actor_type`, `actor_id`, `agent_id`, `resource_type`, `resource_id`, `action`,
`decision`, `outcome`, `correlation_id`, `start_time`, `end_time` (repeatable filters are
ORed within themselves, different filters are ANDed). Pagination is mandatory:
`limit` (1–200, default 50) and `offset` (≤ 100 000), with `count` for the page and an
opt-in `total` for the filtered set. Ordering is deterministic:
`occurred_at DESC, id DESC`.

```jsonc
{
  "organization_id": "…",
  "items": [
    {
      "id": "…",
      "organization_id": "…",
      "event_type": "action.denied",
      "schema_version": 1,
      "occurred_at": "2026-09-24T09:15:04.512345+00:00",
      "actor_type": "human",
      "actor_id": "…",
      "actor_membership_id": "…",
      "agent_id": null,
      "resource_type": "agent",
      "resource_id": "…",
      "action": "agent.posture_check",
      "decision": "deny",
      "outcome": "blocked",
      "correlation_id": "…",
      "request_id": "…",
      "source": "api",
      "metadata": { "reason": "policy_denied", "firewall_outcome": "deny",
                    "effective_reason": "policy_denied", "policy_decision": "deny",
                    "permission_required": "action.execute", "principal_role": "owner",
                    "idempotency_key": "…" }
    }
  ],
  "limit": 50, "offset": 0, "count": 1, "total": null
}
```

The response is an **explicit schema**, not a row passed through: adding a column to the
table cannot silently publish it, and the metadata is re-sanitized on the way out. The
query is tenant-scoped by construction — the organization comes from the path, the caller's
membership is verified before the handler runs, and every statement filters on it — so a
filter can only narrow what the caller could already see, and a foreign organization is
indistinguishable from one that does not exist (byte-identical 404).

### RBAC

`audit.read` is required, held by **owner** and **security_admin** only. The administrator
deliberately does not hold it — "oversight is not administration" — and neither does an
analyst, whose job is reading security findings rather than the history of who did what.
There is no `audit.update`, no `audit.delete` and no `audit.write`: a permission to change
history would defeat the point of keeping it. The role matrix and its grant totals are
unchanged by this phase.

## Relationship to the Phase 7 ledger

| | `action_executions` (Phase 7) | `audit_events` (Phase 8) |
|---|---|---|
| Answers | "did this run twice?" | "who did what, when, and what came of it?" |
| Key | the idempotency key, unique per organization | none — an append-only sequence |
| Refusals | nothing is written | one row naming the layer that refused |
| Attribution | none | actor type, person, membership, agent |
| Decision | none | the decision the pipeline recorded |
| Mutability | status moves to executed/failed | nothing moves; the table refuses edits |
| Read by | the execution service | an operator, through a read-only endpoint |

They are different tables with different columns and different lifetimes, and neither is a
substitute for the other. An execution writes to both, and that duplication is the point:
one is a mechanism, the other is a record.

## Migration

`0007_audit_events` adds the table, its constraints, six indexes and the append-only
trigger function. It adds no permission, no role grant and no change to any earlier table,
and it does not touch any other migration. The indexes are the ones the endpoint's filters
actually need:

| Index | For |
|---|---|
| `(organization_id, occurred_at DESC, id DESC)` | the default page and its ordering |
| `(organization_id, event_type, occurred_at)` | filtering by type |
| `(organization_id, actor_id, occurred_at)` | "what did this person do?" |
| `(organization_id, correlation_id)` | one flow's events |
| `(organization_id, resource_type, resource_id)` | one resource's history |
| `(organization_id)` | the tenant sweep the other four fall back on |

`downgrade` drops the guard, the indexes and the table — and **the rows go with it**. That
is different from Phase 7's ledger, whose downgrade refuses rather than deleting today's
executions: an audit trail is history, and a revision that cannot read or write it should
not leave a table no revision owns. An operator who needs the history takes a dump first.

## Tests

| File | What it proves |
|---|---|
| `tests/test_audit.py` | the vocabulary, the closed event list, actor rules, refusal shapes, the model without a database — pure |
| `tests/test_audit_api.py` | the endpoint: the record compared field by field against the request that caused it, every filter asserted to *narrow*, pagination, ordering, authorization per role, tenant isolation, malformed input, and the response boundary (secrets redacted, unreadable summaries emptied) |
| `tests/test_audit_immutability.py` | append-only against real PostgreSQL: `UPDATE`/`DELETE`/`TRUNCATE` refused, the override's shape (delete-only, one transaction, needs a reason), no repository mutation, no write route, and every `CHECK` refusing what the application cannot produce |
| `tests/test_audit_integration.py` | the emission points end to end: every lifecycle operation, ingestion, and the action pipeline for allow/deny/require_approval/executed/replayed/failed/conflict with a recording adapter proving call counts; attribution and no-spoofing; correlation; metadata never carrying arguments; the ledger and the trail being different tables |
| `tests/test_actions_api.py`, `tests/test_migrations.py`, `tests/test_authorization_decisions.py`, `tests/test_authorization.py` | the ledger is not a trail, the migration chain and live table set, and that the new route declares `audit.read` |

```bash
bash scripts/verify.sh --full   # lint, format, types, unit, API and database suites
bash scripts/test-db.sh         # empty database → migrations → drift check → round trip → full suite
```

## Limitations, stated plainly

- **No hash chain.** Explained above: deferred until a keyed design exists, because a
  recomputable chain would be worse than none.
- **No authentication events.** A failed credential has no organization and no actor to
  attribute it to; inventing one would create an existence oracle. Refusals that *do* have
  an authenticated caller and a verified organization are recorded.
- **No retention, no archival, no export.** The trail grows; the override that permits
  deletion exists for fixtures and is documented as such.
- **Refusals before admission are not events.** A 403 from a route's permission dependency
  is a refusal of an attempt, not a record of an operation — the trail records what the
  platform did.
- **No anomaly detection, baselines, alerting, dashboards, incidents, kill switch or
  containment.** Phase 9 counts this trail — see [monitoring.md](monitoring.md) — and
  counting is as far as that goes: a number is reported, never judged, and nothing reads
  the trail automatically in order to act on it.
- **No SIEM/Kafka/Redis/Elasticsearch integration, no LLM summarization.** The endpoint is
  REST and tenant-scoped, and the trail is queried, not streamed.
- **One table, one writer, one endpoint.** Assets, agents and policies are the resources
  this build has; models, tools, data sources and incidents arrive in their own phases
  with their own vocabulary.
