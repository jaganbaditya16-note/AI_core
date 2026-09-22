# Authentication and authorization (Phase 2)

Phase 1 answered *which tenant owns this row?* Phase 2 answers *who is calling,
and what may they do here?* — and answers it on the server, before a handler runs.

Three claims this document exists to support:

1. every protected operation requires an authenticated user, an active membership
   in the organization named in the request, and an explicit permission that the
   membership's role grants;
2. a credential never decides anything by itself — it identifies a person, and
   the person's membership decides;
3. a member of one organization can never read, change, or even confirm the
   existence of another organization's data.

## Authentication: what a request carries

A request is authenticated with a **bearer API token**:

```bash
curl -H "Authorization: Bearer aicore_9f2c…" http://127.0.0.1:8000/me
```

- the token is read from the `Authorization` header **only** — never from a query
  string, a cookie or a body field (query strings end up in logs and referrers,
  and cookies are attached by a browser to requests the user did not intend);
- only a **SHA-256 hash** of the token is stored. The plaintext exists once, in
  the output of the command that issued it. There is no endpoint, no repository
  method and no administrative path that can read a credential back out;
- a token carries a prefix (`aicore_…`) so a leaked string is recognisable in a
  log and revocable, and it is 256 bits of CSPRNG output — SHA-256 over that is
  sufficient; there is nothing to brute-force and no need for a slow password
  hash;
- **there are no passwords anywhere in AICore**, and no password column, so there
  is no plaintext credential to protect and nothing to rotate after a breach.
  Human sign-in, when it arrives, belongs to an external identity provider which
  holds the credential — not to this application.

A token may expire (`expires_at`), be revoked (`revoked_at` — a timestamp, not a
deletion, so the record of what existed survives), or die with its user
(`ON DELETE CASCADE`). Revocation and suspension take effect on the next request.

Every failure — no header, a malformed header, an unknown token, a revoked token,
an expired token, a suspended user — produces the same `401` with the same body.
The client is told how to authenticate (`WWW-Authenticate: Bearer`) and nothing
else; distinguishing the cases would tell an attacker which tokens and which
accounts exist.

### Where the credentials come from

Nothing issues credentials over HTTP. Phase 2 has no sign-up and no
user-management API — creating the first organization, user and token is a
*provisioning* action, so it belongs to whoever holds database access:

```bash
export AICORE_DATABASE_URL=postgresql+psycopg://aicore:…@localhost:5432/aicore

bash scripts/py.sh -m aicore_api.cli bootstrap \
  --email owner@example.com --full-name "Ada Lovelace" \
  --organization-name "Acme Corporation" --organization-slug acme

bash scripts/py.sh -m aicore_api.cli create-api-token --email owner@example.com --name laptop
bash scripts/py.sh -m aicore_api.cli add-member --organization acme --email analyst@example.com --role analyst
```

The token is printed once and cannot be recovered — only revoked and replaced.
There is deliberately **no development-only authentication path**: a test that
authenticated differently from production would prove nothing about production.

### Provider abstraction

Credential validation sits behind one seam:

```
Credentials → AuthenticationProvider.authenticate() → Principal | None
```

`AICORE_AUTH_PROVIDER` (default `api_token`) selects the implementation from a
registry; routes never name a provider, and no business logic contains a
hardcoded one. Adding an external identity provider later means adding a class and
a registry entry — the authorization layer consumes a `Principal` and is
unaffected. A provider that raises or cannot reach its store yields *no*
principal, never a default one.

## The role model

Six roles, chosen so that each corresponds to a job rather than to a level of
seniority:

| Role | Purpose | Permissions |
|---|---|---|
| `owner` | Full administration of the organization it owns | all eight |
| `admin` | General organization administration | `organization.read`, `organization.update`, `user.read`, `user.manage`, `role.read` |
| `security_admin` | Security, audit, incidents, containment, security configuration | `organization.read`, `user.read`, `audit.read`, `security.read` |
| `ai_admin` | Administration of AI assets and the AI platform | `organization.read`, `user.read` |
| `analyst` | Read and analyse AI and security information | `organization.read`, `security.read` |
| `viewer` | Read-only access to permitted resources | `organization.read` |

The catalog lives in one place: `aicore_api/core/permissions.py`. It is seeded
into the database by migration `0002_identity_and_rbac`, and a test compares the
two copies against the live rows, so a role cannot silently lose a capability in a
deployment. `ai_admin` gaining inventory-management permissions is a Phase 3
change: no permission exists for a resource that does not exist yet.

## The permission model

Permissions are explicit strings, grouped by area, and are the *only* thing
application code may ask for:

| Permission | Means |
|---|---|
| `organization.read` | See the organization itself |
| `organization.update` | Change the organization itself |
| `user.read` | See who belongs to the organization |
| `user.manage` | Add, remove and change memberships |
| `role.read` | See the role and permission catalog |
| `role.manage` | Change which permissions a role grants |
| `audit.read` | Read the audit trail |
| `security.read` | Read security findings and posture |

Code asks `require_permission(Permission.USER_READ)`. It never asks *"is this
user an ADMIN?"* — a role check in a handler is a second, unauditable definition
of who may do what, and a test scans the application modules to keep them out.
Some permissions currently guard nothing because their subject does not exist
yet (`audit.read`, `security.read`: there is no audit record to read, and no
security finding to see). They are the vocabulary the next phases will enforce,
they are already visible on `GET /me`, and no endpoint pretends otherwise.

Roles are not permissions, and neither is a superset assumption: `viewer` is a
subset of every other role, but `security_admin` and `ai_admin` are *incomparable*
— a security administrator cannot manage the AI platform and an AI administrator
cannot read security data. An unknown role code raises rather than resolving to
"no permissions": failing open in an authorization path is unacceptable, and an
empty set silently authorizes nothing while looking successful.

## The authorization flow

```
credentials → identify user → resolve organization → verify membership
            → resolve role → resolve permissions → check required permission → handler
```

Implemented in `aicore_api/auth/`:

| Module | Responsibility |
|---|---|
| `tokens.py` | Token format, generation, hashing (no database imports) |
| `principal.py` | `Principal` — who is calling, and nothing else |
| `providers.py` | Credentials → principal; the swappable seam |
| `authorization.py` | Principal + organization → role → permissions |
| `dependencies.py` | How a route states what it requires |

A protected route declares its requirement in its signature, so the requirement
is part of the contract rather than a line inside the handler:

```python
@router.get("/{organization_id}/members", response_model=MemberListResponse)
def list_members(
    context: ReadMembers,          # Annotated[OrganizationContext, Depends(require_permission(...))]
    session: SessionDep,
) -> MemberListResponse: ...
```

By the time the function body runs, the caller is authenticated, is an active
member of that organization, and holds `user.read` there. The handler cannot
forget the check, because it never performs it.

Failure modes, and why each is the right one:

| Situation | Response | Reasoning |
|---|---|---|
| No credential, unknown/revoked/expired token, suspended user | `401` | Indistinguishable, so probing reveals nothing |
| Active member, role lacks the permission | `403` | The tenant is theirs; the operation is not |
| Membership suspended | `403` | The relationship exists, the authorization does not |
| Not a member — whether or not the organization exists | `404` | A `403` would confirm another tenant exists |
| Malformed organization id | `422` | Validation, before any query |

## Tenant isolation

The organization is taken **from the request path**, and the caller from the
credential. The two are intersected: the path supplies the tenant whose data is
wanted, and the credential determines whether the caller has any standing in it.
There is no organization id in a body field to trust, no "current organization"
the client can set, and no client-side selection that matters — a user who
belongs to two organizations sees two memberships in `GET /me`, and each request
names the one it means.

The data layer keeps its Phase 1 guarantees: every statement touching a
tenant-owned table is refused unless a tenant is bound *and* the statement filters
on `organization_id` (see [database.md](database.md)). Phase 2 adds exactly one
documented cross-tenant read: `memberships_for_user`, which answers "which
organizations does this person belong to?" for the authenticated principal's own
id — a question that cannot be answered from inside one tenant. It takes a
reasoned escape hatch, `cross_tenant_read(...)`, applies to reads only, and
`grep -rn cross_tenant_read` lists every place that can see across tenants.

The tests attack this rather than assume it: a member of one organization asking
for another's id, directory, roles and permission catalog receives the same
`404` as a random UUID, down to the error body; a suspended membership is refused
on every route; and an unknown role fails closed. See
`apps/api/tests/test_authorization.py`.

## What this phase does not do

Stated here so the boundary is as visible as the implementation:

- **no sign-up, login, password reset or session UI** — credentials are
  provisioned out of band, and the frontend is never a security boundary;
- **no user-management API** — `POST /organizations` remains a development/test
  provisioning route (404 elsewhere), because Phase 2 has no
  platform-administrator concept that could authorize tenant creation;
- **no permission for anything that does not exist** — no agent, model, tool,
  policy, firewall or incident permissions;
- **no PostgreSQL Row Level Security** — the design is documented and the schema
  is prepared for it, but it is not enabled (see [database.md](database.md));
- **no audit records** — `audit.read` is a permission whose subject arrives in a
  later phase. Authorization decisions are logged as structured request logs, not
  as an audit trail this phase does not have.

## Local testing

- **Unit and API tests** — `npm run test:api` (hermetic, no database) and
  `bash scripts/test-db.sh` (real PostgreSQL, migrations, drift check, round trip,
  the whole suite).
- **Identities in tests** are real: `apps/api/tests/identity_fixture.py` creates a
  committed user, organization, membership and token through the repositories,
  and removes them afterwards. A bug in the repositories fails those tests; it
  cannot quietly satisfy them.
- **Manually**, the same path an operator would take:

  ```bash
  bash scripts/dev-db.sh                       # start PostgreSQL, print the URL
  bash scripts/migrate.sh upgrade head         # create the schema
  bash scripts/py.sh -m aicore_api.cli bootstrap --email me@example.com \
      --full-name "Me" --organization-name "Local" --organization-slug local
  curl -H "Authorization: Bearer <printed token>" http://127.0.0.1:8000/me
  ```
