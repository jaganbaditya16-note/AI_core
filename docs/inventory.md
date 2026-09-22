# AI asset discovery and inventory (Phase 3)

Phase 3 answers one question, for one organization at a time:

> What AI-related things does this organization know it has, and what do we know
> about each of them?

It is the first half of the **DISCOVER** pillar, in the same sense as Phase 2: the
records are real, the tenant boundary is real, the authorization is real — and the
*runtime* decisions that will eventually use this inventory (policy, containment,
monitoring) are not implemented. `suspended` is a status a record can hold; it
stops nothing.

## What this phase is, and what it is not

**It is** a per-organization inventory of AI assets with a validated shape, a
documented deduplication rule, an API to read and change it, and an internal
service boundary through which a future discovery integration registers what it
observes.

**It is not** automatic discovery. There is no network scan, no cloud provider
integration, no agent that watches anything. Nothing in this phase observes your
infrastructure. An asset appears in the inventory because a person called
`POST /assets`, or because an *integration* called
`register_discovered_asset()` — and no such integration ships in this phase. The
seam exists, is tested through, and is honest about the direction the data flows.

Two claims are therefore deliberately absent from this document and from the API:
that assets are found automatically, and that an inventory is a security control.
It is an inventory.

## One table, seven types

Every asset is one row in `aicore.assets`, whatever its type:

| Type | What it covers |
| --- | --- |
| `agent` | An autonomous agent (framework, version) |
| `application` | An application that uses AI (repository, identifier) |
| `model` | A model (provider, model identifier, version) |
| `tool` | A callable tool (tool identifier, endpoint) |
| `mcp_server` | A Model Context Protocol server (server identifier, endpoint) |
| `api` | An AI-related API (endpoint, provider) |
| `data_source` | A data source feeding AI systems (classification placeholder) |

One table rather than seven is a decision, not a shortcut. List, filter, paginate,
count, assign an owner, change a lifecycle state and enforce tenant isolation are
identical for all seven types; seven tables would mean seven copies of all of it,
and a union query for the one thing an inventory must do first. What differs
between types is *metadata*, and that is where the differences live.

Adding a type is a deliberate change: a value in the `AssetType` vocabulary, a
migration for the check constraint, an entry in `METADATA_MODELS`, and a mirror in
`packages/types`. `test_every_type_has_a_metadata_contract_and_there_is_no_permissive_fallback`
fails until all of them agree.

## Field by field

| Field | Notes |
| --- | --- |
| `id` | UUID, assigned by the database |
| `organization_id` | The tenant. Not null, `ON DELETE RESTRICT` |
| `name` | Display name. **Not** an identifier — see below |
| `description` | Optional free text |
| `asset_type` | One of the seven values above |
| `status` | `draft`, `active`, `suspended`, `retired` |
| `environment` | `development`, `staging`, `production`, `unknown` |
| `discovery_state` | `managed`, `unknown`, `shadow` |
| `risk_classification` | `low`, `medium`, `high`, `critical`, `unassessed` — storage only |
| `owner_membership_id` | Optional. A membership **in this organization** (see Ownership) |
| `metadata` | Per-type, validated, JSONB. Optional |
| `discovery_source` | Server-set: `manual`, or `integration:<source>` |
| `last_seen_at` | When an integration last observed it; null for manual records |
| `external_identifier` | The integration's own identifier for the asset, if it has one |
| `created_at`, `updated_at` | Set by the application, never by the client |

The five vocabularies are `VARCHAR` + `CHECK` constraints, not PostgreSQL `ENUM`
types: adding a value is an ordinary migration rather than an `ALTER TYPE` that
cannot run inside a transaction, and the values are compared as the strings they
are. Unknown values are refused by the database *and* by Pydantic — the API is not
the only door into the table.

### Lifecycle

`draft` → `active` → `suspended` → `retired`, in any order a person needs. Nothing
is irreversible except deletion, which removes the row. `retired` is how an asset
that no longer exists should normally leave the inventory: it keeps the history of
what the organization knew. `DELETE` exists because a mistyped record is not
history.

`suspended` is inventory state. There is no kill switch, no containment, and no
runtime effect of any kind in this phase.

### Discovery state

- `managed` — known and registered in AICore on purpose. This is the default for
  a manual registration, and the only state the API assigns by itself.
- `unknown` — recorded, but ownership and management are not yet established. This
  is what an integration's report gets: observing an asset is not the same as
  someone having taken responsibility for it.
- `shadow` — observed outside the organization's known inventory.

The distinction is a judgement, so it is data, not a derived flag: a scan that
finds something can label it `shadow`, and a person can promote a record to
`managed` through `PATCH`. Three states are enough to be honest about what is
known; a fourth would be a workflow this phase does not have.

## Ownership

`owner_membership_id` is a composite foreign key:
`(organization_id, owner_membership_id) → memberships(organization_id, id)`, with
`ON DELETE RESTRICT`.

A plain foreign key to `users.id` would allow an asset in organization A to be
owned by a user who is not a member of A. The composite key makes that
*unrepresentable in the database*, not merely rejected by the handler. The RESTRICT
means a membership that still owns assets cannot be removed while it owns them:
the inventory refuses to lose its last record of who was accountable.

The API accepts an **owner user id** (`owner_user_id`) and resolves it to the
membership in the organization named in the path. A user id from another
organization, or a user who is not a member — or whose membership is suspended —
is refused with `422` and a message that says which rule was broken. Application
code never creates users: an owner must already exist as an active member.

## Metadata

`metadata` is a JSONB object, per-type validated, `8 KiB` when serialized, and
`NULL` rather than `{}` when nothing was recorded (`jsonb_typeof(metadata) =
'object'` is a check constraint, so a JSON scalar cannot be stored).

```jsonc
// asset_type: "model"
{"provider": "openai", "model_identifier": "gpt-4o-mini", "version": "2024-07-18"}

// asset_type: "application"
{"application_identifier": "claims-triage", "repository_url": "https://git.example/claims"}
```

Each type has its own Pydantic model with `extra="forbid"`: a field that belongs
to another type is a `422`, not a silently stored key. Unknown keys are not a
feature the inventory needs, and accepting them would mean an integration could
write a schema nobody validates and every later reader would have to trust.

This is the reason there is no column per metadata field: a `model` has a
`provider`, an `mcp_server` does not, and seven tables of nullable columns would
encode that as a schema rather than as data.

## Deduplication

The rule is explicit and deterministic:

> Two assets in the same organization with the same `asset_type` and the same
> non-null `external_identifier` are the same asset. Everything else may repeat.

Enforced by a **partial** unique index — `(organization_id, asset_type,
external_identifier) WHERE external_identifier IS NOT NULL` — because a manual
registration has no external identifier and many may legitimately be null.

Names are never identifiers. Two different teams may both have a "Support Bot",
and no rule about names could tell that from a duplicate. `external_identifier` is
whatever the reporting integration already uses to distinguish assets; the
inventory does not invent one.

The consequence for repeated discovery is the useful one: re-reporting the same
external identifier converges on one row (`created: false`, observed fields
refreshed) instead of accumulating a near-duplicate row per scan. See
`test_a_discovered_asset_is_recorded_once_and_refreshed_afterwards`.

## The API

Six routes, all under `/organizations/{organization_id}`, all requiring an API
token and a permission:

| Route | Permission |
| --- | --- |
| `GET /assets` | `asset.read` |
| `POST /assets` | `asset.create` |
| `GET /assets/owners` | `asset.read` |
| `GET /assets/{asset_id}` | `asset.read` |
| `PATCH /assets/{asset_id}` | `asset.update` |
| `DELETE /assets/{asset_id}` | `asset.delete` |

Listing:

```bash
curl -s "http://localhost:8000/organizations/$ORG/assets?asset_type=model&environment=production&total=true&limit=50" \
  -H "Authorization: Bearer $AICORE_TOKEN"
```

Filters — `asset_type`, `status`, `environment`, `discovery_state`,
`risk_classification`, `owner_membership_id` — are repeatable and are **ORed within
one parameter, ANDed across parameters**. Values outside a vocabulary are a `422`
with the offending location, not an empty page.

| Parameter | Default | Limits |
| --- | --- | --- |
| `limit` | `50` | `1`–`200` |
| `offset` | `0` | `0`–`100000` |
| `total` | off | Adds the filtered count (`COUNT(*)`), so listing stays one query |

There is no unbounded listing: the limit is capped, the offset is capped, and the
count is opt-in. Items are ordered newest-first by `created_at`, `id`, so pages do
not overlap and a page does not silently shrink when a joined row is missing.

Writing:

```bash
curl -s -X POST "http://localhost:8000/organizations/$ORG/assets" \
  -H "Authorization: Bearer $AICORE_TOKEN" -H 'Content-Type: application/json' \
  -d '{"name": "Claims Triage Agent", "asset_type": "agent",
       "environment": "production", "owner_user_id": "<user-uuid>",
       "metadata": {"framework": "langgraph", "version": "0.2.5"}}'
```

`PATCH` is field-set-aware: an omitted field is unchanged, `null` clears a nullable
field (an empty `metadata` object is stored as `NULL`). `id`, `organization_id`,
`created_at`, `updated_at` and `discovery_source` are not client-settable and are
refused if sent.

Refusals follow the existing contract — `{"error": {"code", "message", "details",
"request_id"}}` with, in particular: `401` without a usable token, `403` when the
role lacks the permission or the membership is suspended, `404` for an asset that
does not exist **or belongs to another organization**, `409` on a duplicate
external identifier, and `422` for anything the schema refuses. An asset that
belongs to another organization is answered exactly like one that does not exist
(same status, same body, same headers), because a difference would be an
enumeration oracle.

`GET /assets/owners` lists the active members an asset can be assigned to, so a
client never has to guess a user id. It is capped and ordered, and never exposes
another organization's members.

## Authorization

Four permissions, and no others:

| Permission | owner | admin | security_admin | ai_admin | analyst | viewer |
| --- | :-: | :-: | :-: | :-: | :-: | :-: |
| `asset.read` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `asset.create` | ✅ | ✅ | — | ✅ | — | — |
| `asset.update` | ✅ | ✅ | ✅ | ✅ | — | — |
| `asset.delete` | ✅ | ✅ | — | — | — | — |

`security_admin` may read the inventory and update a record (recording what was
found) but not create or delete one; `ai_admin` stewards the inventory but cannot
delete; nobody but `owner` and `admin` can delete. Reading is the widest grant
because an inventory nobody can see is not an inventory.

Authorization happens in the backend, before the handler runs: each route declares
`Depends(require_permission(Permission.ASSET_*))`, resolves the caller's membership
in the organization named in the path, and checks the permission. A permission is
never inferred from a role name in application code, and `packages/types` reflects
the contract — it does not enforce it.

No other permission was added in this phase. There is no `agent.execute`,
`agent.suspend`, `policy.*`, `firewall.*` or `incident.*` — those are later phases,
and a permission that guards nothing would be a promise this build does not keep.

## Tenant isolation

Four independent layers, all tested:

1. **The database** — non-null `organization_id`, `ON DELETE RESTRICT`, and a
   composite key that makes a cross-tenant owner unrepresentable.
2. **The repository** — `AssetRepository` cannot be constructed without an
   organization, and every statement it builds is filtered to it.
3. **The tenancy guard** — a session-level guard refuses any statement touching a
   tenant-owned table that is not bound to a tenant, or that does not filter on
   `organization_id`. A missing filter is an exception, not a wider query.
4. **The API** — an asset is looked up *within* the caller's organization, so a
   foreign id and an unknown id are the same `404`.

A user who is not a member of the organization in the path gets `404` for the
organization itself — indistinguishable from an organization that does not exist —
because a `403` would confirm the tenant exists.

## The discovery ingestion foundation

`aicore_api.discovery` is the internal service boundary a future integration calls.
It is not an integration, and it is not reachable over HTTP.

```
discovery source ─► normalize ─► validate ─► organization ownership ─► inventory record
  DiscoveredAsset     (registry)   (Pydantic)   (active membership)      (Asset)
```

```python
from aicore_api.discovery import DiscoveredAsset, register_discovered_asset

result = register_discovered_asset(
    session,
    organization_id,
    DiscoveredAsset(
        source="estate-scan",                     # becomes "integration:estate-scan"
        external_identifier="estate://mcp/files",  # the deduplication key
        name="Files MCP Server",
        asset_type="mcp_server",
        discovery_state="shadow",
        asset_metadata={"server_identifier": "files", "endpoint": "https://mcp.example/files"},
    ),
)
result.created  # True the first time, False when the report refreshed an existing row
```

The rules the service enforces, and the reasons they are rules:

- **The source is named.** An asset observed by something says so
  (`discovery_source = "integration:<source>"`), and a record without a source is
  refused. A discovery path that cannot say who discovered it is not auditable.
- **The metadata contract still applies.** A report is validated by the same
  per-type model as a manual registration; an integration cannot write a shape the
  API would refuse.
- **An owner is never invented.** A report may name an owner, and only an active
  member of that organization can be one.
- **The lifecycle is not the integration's to set.** A report creates `active` /
  `unknown` / `unassessed`; re-reporting refreshes what was *observed* (`name`,
  `description`, `metadata`, `last_seen_at`, `discovery_source`) and never
  overwrites the organization's judgement — its owner, status or risk
  classification.
- **The write is idempotent, decided in the database.** Registration is an
  `INSERT … ON CONFLICT DO NOTHING` followed by a scope-limited refresh, so two
  concurrent collectors converge on one row instead of racing a read-then-write.

`register_discovered_asset` is written against a `Session`, so the caller owns the
transaction. A future ingestion job can therefore commit a whole batch, or roll
back, without this module deciding for it.

## Audit readiness

Phase 3 does not build the audit system (Phase 8), and it does not add a second,
competing one. It does emit domain events at the four points where an inventory
change is worth auditing later — `asset.created`, `asset.updated`, `asset.deleted`
and `asset.discovered` — through `aicore_api.core.events`, which today writes one
structured log line per event and records nothing else.

That gives the later audit phase a single boundary to attach to, and it keeps the
promise honest now: an event is a hook, not a record. Nothing in this phase claims
that asset changes are audited.

## Verification

What each guarantee is checked by:

| Guarantee | Test |
| --- | --- |
| Every type, with its own metadata, stored and read back | `test_assets.py`, `test_assets_api.py` |
| The five vocabularies are closed in PostgreSQL | `test_the_database_refuses_a_value_outside_a_documented_vocabulary` |
| A cross-tenant owner is unrepresentable | `test_an_owner_from_another_organization_is_refused_by_the_database` |
| An owner who still owns assets cannot be removed | `test_an_owner_who_still_owns_assets_cannot_be_removed_from_the_organization` |
| Deduplication converges, names do not deduplicate | `test_an_external_identifier_is_unique_per_organization_and_type`, `test_names_are_not_identifiers` |
| Filters, ordering, bounded pages, opt-in total | `test_assets_api.py` (`filters`, `pagination`) |
| Foreign asset ≡ unknown asset (IDOR) | `test_a_foreign_asset_is_indistinguishable_from_an_unknown_one` |
| Role matrix per method, and 401 without a token | `test_assets_api.py` (authorization) |
| Route → permission map is exactly as documented | `test_every_asset_route_declares_the_permission_it_enforces` |
| The migration matches the models, and reverses | `test_migrations.py`, `scripts/test-db.sh` |

```bash
bash scripts/test-db.sh     # migrations from an empty database, drift, full suite
bash scripts/verify.sh      # lint, format, typecheck, unit tests, secrets, compose
```

## Current limitations

Stated plainly, because an inventory that overstates itself is worse than a small
one:

- **No automatic discovery.** No cloud provider, network or endpoint integration
  exists. Nothing observes anything. Manual registration and the internal service
  boundary are the only two ways in.
- **No runtime effect.** `suspended` and `retired` change a record; they do not
  change any system. There is no policy, firewall, kill switch or monitor.
- **Risk classification is storage.** Five values, no scoring, no engine.
- **No history.** An update overwrites the previous value; there is no revision
  table and no audit record (that is Phase 8).
- **No dependency graph.** Assets do not reference each other yet.
- **No bulk operations.** One asset per request.
- **No count caching or full-text search.** `?total=true` is a `COUNT(*)`;
  `name` is filtered by exact match only.
- **Deletion is immediate and permanent.** `ON DELETE RESTRICT` protects the
  owner, not history: `DELETE` removes the row.
