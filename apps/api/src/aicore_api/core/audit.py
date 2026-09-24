"""The audit vocabulary: what an event can say, and what it may never carry.

Phase 8 answers a question the earlier phases deliberately left open. Phases 5, 6 and
7 *decide* — authorization, policy, firewall — and Phase 7 acts on one of those
decisions. None of them remembers. This module is the vocabulary half of the memory: a
closed set of event types, of actors, of decisions and outcomes, plus the boundary that
keeps metadata from becoming a place where secrets are stored by accident.

Three rules are encoded here rather than trusted to callers.

**The vocabulary is closed.** An event type outside :class:`AuditEventType` cannot be
written, and the database refuses it a second time through a ``CHECK`` constraint. That
mirrors the permission catalog: a vocabulary that lists events nothing emits advertises
history that does not exist, so the types below are exactly the operations this build
performs — the lifecycle operations of Phases 3, 4 and 6, the ingestion path, and the
action pipeline of Phase 7.

**Attribution is a classification, not a claim.** :class:`AuditActor` distinguishes a
person who acted through the API from a system operation nobody performed. It has no
constructor that accepts an arbitrary identifier: a human actor must name both the
person and the membership the server resolved, and a system actor names nobody. The
database enforces the same tie, so a row that says "a person did this" without saying
who cannot exist.

**Metadata is a summary, never a payload.** Requirement 10 of the phase is a rule about
*every* event, so it is enforced in one place: :func:`sanitize_metadata` bounds the
shape of what may be stored, refuses anything that is not a small flat mapping of
scalars, and redacts values whose key or shape says "this is a credential". Action
arguments are the clearest case: an execution records how many arguments the request
carried, never what they were, and the tests assert that a secret-shaped value cannot
reach the table through any path.

What this module deliberately does not do: it does not decide, it does not execute, it
does not read the database, and it does not know what a policy is. It is the shape of a
record.
"""

from __future__ import annotations

import json
import re
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Any

from aicore_api.core.actions import canonical_json

__all__ = [
    "AUDIT_SCHEMA_VERSION",
    "LIFECYCLE_ACTIONS",
    "MAX_METADATA_BYTES",
    "MAX_METADATA_KEYS",
    "REDACTED",
    "ActorType",
    "AuditActor",
    "AuditDecision",
    "AuditError",
    "AuditEventType",
    "AuditMetadataError",
    "AuditOutcome",
    "AuditResourceType",
    "AuditSource",
    "resolve_event_type",
    "sanitize_metadata",
]

#: The shape of a stored event. Bumped when a column is added or its meaning changes,
#: so a reader can tell which shape it is looking at without guessing from NULLs. The
#: column is constrained to the values this build writes: an older application reading a
#: newer row is a deployment problem, and it should be loud rather than silent.
AUDIT_SCHEMA_VERSION = 1


class AuditEventType(StrEnum):
    """Everything that may be recorded, and nothing else.

    The names are stable identifiers — they appear in a durable table that later phases
    will read, so renaming one is a migration of records rather than a refactor. They
    are also the names the phases before this one already used for their domain events,
    which is what makes the trail continuous with the log lines that came before it.

    The action pipeline contributes six, because one request passes through six
    distinguishable states worth remembering: it was admitted, it was refused, it was
    held for an approval this build cannot grant, it ran, it was answered from the
    idempotency ledger instead of running again, or it was admitted and failed.
    """

    # ── The inventory (Phase 3) ──────────────────────────────────────────────
    ASSET_CREATED = "asset.created"
    ASSET_UPDATED = "asset.updated"
    ASSET_DELETED = "asset.deleted"
    #: Recorded by the ingestion path rather than by a request: an integration
    #: reported something, which is a system origin and therefore a system actor.
    ASSET_DISCOVERED = "asset.discovered"

    # ── The agent registry (Phase 4) ─────────────────────────────────────────
    AGENT_REGISTERED = "agent.registered"
    AGENT_UPDATED = "agent.updated"
    AGENT_DELETED = "agent.deleted"

    # ── The policy record (Phase 6) ──────────────────────────────────────────
    POLICY_CREATED = "policy.created"
    POLICY_UPDATED = "policy.updated"
    POLICY_VERSION_PUBLISHED = "policy.version_published"
    POLICY_STATUS_CHANGED = "policy.status_changed"
    POLICY_DELETED = "policy.deleted"

    # ── The action pipeline (Phase 7) ────────────────────────────────────────
    #: An execution request that reached the decision pipeline: the action resolved
    #: from the catalogue and the request was validated against it. Recorded before
    #: anything is decided, so an execution can never be invisible.
    ACTION_REQUESTED = "action.requested"
    #: The firewall refused it. The reason is in the metadata (``authorization_denied``,
    #: ``policy_denied``, ``target_not_found``, ``environment_mismatch``), which keeps
    #: one refusal one event instead of one per layer that could have produced it.
    ACTION_DENIED = "action.denied"
    #: A policy asked for an approval this build cannot grant. Nothing ran.
    ACTION_REQUIRE_APPROVAL = "action.require_approval"
    #: The adapter ran and reported an outcome.
    ACTION_EXECUTED = "action.executed"
    #: The request was allowed and answered from the ledger: the same key, the same
    #: request, an outcome that was already recorded. Distinct from ``ACTION_EXECUTED``
    #: on purpose — a replay is not a second execution, and a trail that called it one
    #: would overstate what the system did.
    ACTION_REPLAYED = "action.replayed"
    #: The adapter was reached and did not complete the action.
    ACTION_FAILED = "action.failed"


#: The operation each lifecycle event represents, as the ``resource.action`` permission
#: code that guards it. A trail row for "an asset was created" is only useful if it can
#: also say *what was done* — and the operation that was done is exactly the permission
#: the route required before it did it.
#:
#: The two vocabularies are deliberately different kinds of thing: the event type is the
#: name of a fact, the action is the name of a capability. Keeping the mapping here, next
#: to the event types, means a reader can see both at once — and
#: ``test_audit.py`` asserts every value below is a permission this build declares, so a
#: code that no longer exists cannot linger as a fine-sounding string.
#:
#: The execution events are absent on purpose: for those, ``action`` is not a permission
#: but the *registered action's own identifier* (``agent.posture_check``), because that is
#: what was run. A lifecycle event has no such identifier — the operation is the
#: permission.
LIFECYCLE_ACTIONS: Mapping[AuditEventType, str] = MappingProxyType(
    {
        AuditEventType.ASSET_CREATED: "asset.create",
        AuditEventType.ASSET_UPDATED: "asset.update",
        AuditEventType.ASSET_DELETED: "asset.delete",
        # An integration reporting something it saw creates an inventory record; there is
        # no separate "discover" permission, and inventing one would be a permission for a
        # capability nothing checks.
        AuditEventType.ASSET_DISCOVERED: "asset.create",
        AuditEventType.AGENT_REGISTERED: "agent.create",
        AuditEventType.AGENT_UPDATED: "agent.update",
        AuditEventType.AGENT_DELETED: "agent.delete",
        # A policy's definition is written with ``policy.update`` whatever changes: the
        # version history records *what it says now*, and the route that publishes a
        # version requires the same permission as the route that edits metadata.
        AuditEventType.POLICY_CREATED: "policy.create",
        AuditEventType.POLICY_UPDATED: "policy.update",
        AuditEventType.POLICY_VERSION_PUBLISHED: "policy.update",
        AuditEventType.POLICY_STATUS_CHANGED: "policy.update",
        AuditEventType.POLICY_DELETED: "policy.delete",
    }
)


class AuditResourceType(StrEnum):
    """The kind of row an event is about.

    Closed for the same reason the permission vocabulary is: a value that is not in the
    list is a claim no reader can act on. It grows in the phase that introduces the
    resource, together with the ``CHECK`` constraint that admits it.
    """

    ASSET = "asset"
    AGENT = "agent"
    POLICY = "policy"


class ActorType(StrEnum):
    """Who initiated the event.

    Two values, because two origins exist. ``HUMAN`` is an authenticated caller acting
    through the API — the person is named by the credential, never by the request.
    ``SYSTEM`` is an operation nobody performed: the ingestion path recording what an
    integration reported. ``agent`` and ``service`` are deliberately absent: nothing in
    this build can initiate a request as an agent or a service, and a vocabulary that
    named them would describe actors that do not exist.

    Note what is *not* a second actor type: an execution attributed to an agent is still
    a human's request. The agent is recorded in ``agent_id``, which is exactly the
    structured distinction requirement 4 asks for — the trail can say "this person asked
    for this, on behalf of that agent" without inventing an identity for a component
    that has no credential of its own.
    """

    HUMAN = "human"
    SYSTEM = "system"


class AuditSource(StrEnum):
    """Where the event originated.

    ``API`` is an authenticated request handled by this application; ``INGESTION`` is
    the discovery path, which records what an integration reported. A worker, a
    scheduler or an agent runtime adds its own value in the phase that introduces it.
    """

    API = "api"
    INGESTION = "ingestion"


class AuditDecision(StrEnum):
    """The decision an event records, in the vocabulary Phases 6 and 7 already use.

    Declared once more here rather than imported from either layer, because the stored
    column must be closed independently of the code that produced it — a test asserts
    the two vocabularies have the same values, so they cannot drift apart silently.
    ``None`` is a legitimate value for an event that records no decision: a system
    operation answers to no authorization layer, and a request that has only been
    admitted has not been decided yet.
    """

    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


class AuditOutcome(StrEnum):
    """What became of the event.

    ``PENDING`` exists for exactly one event type — an admitted execution request, whose
    outcome is not known when it is recorded and may never be known if the process dies
    mid-flight. That row is the point: an execution that left no trace of having been
    requested would be worse than one whose ending is missing.
    """

    #: It happened and finished as intended.
    SUCCESS = "success"
    #: It was admitted and did not finish.
    FAILED = "failed"
    #: It was refused before anything happened.
    BLOCKED = "blocked"
    #: It was refused for now, pending an approval this build cannot grant.
    NOT_EXECUTED = "not_executed"
    #: It was answered from a recorded outcome instead of running again.
    REPLAYED = "replayed"
    #: It was admitted and has not been decided yet.
    PENDING = "pending"


class AuditError(RuntimeError):
    """The audit subsystem was asked to record something it cannot represent.

    Subclasses ``RuntimeError`` deliberately: every cause of this is a defect in the
    code that built the event, never something a client sent, so it must surface as a
    server fault rather than a 4xx. A build that silently dropped events it found
    inconvenient would be worse than one that refuses loudly.
    """


class AuditMetadataError(AuditError):
    """Metadata is not a small flat mapping of scalars, or it is outsized.

    Raised rather than trimmed: an event whose metadata was silently truncated would
    misreport what happened, and a caller that passed a nested payload has a bug the
    boundary should surface rather than hide.
    """


def resolve_event_type(value: AuditEventType | str) -> AuditEventType:
    """Coerce ``value`` to a declared event type, or refuse it.

    The database refuses an undeclared type as well; this exists so the failure happens
    where the mistake is, with a message naming the vocabulary, instead of as a
    constraint violation inside a request.
    """
    try:
        return AuditEventType(value)
    except ValueError as exc:
        declared = ", ".join(sorted(event_type.value for event_type in AuditEventType))
        raise AuditError(
            f"{value!r} is not a declared audit event type; declared: {declared}"
        ) from exc


@dataclass(frozen=True, slots=True)
class AuditActor:
    """Who caused an event, as the server resolved them.

    Constructed from an authenticated membership (a person) or by stating that no person
    was involved (a system operation). There is no constructor that takes a bare
    identifier, which is what makes "the caller cannot claim to be someone else" a
    property of the type rather than a review habit.
    """

    type: ActorType
    #: The authenticated person. ``None`` for a system actor.
    user_id: uuid.UUID | None = None
    #: The membership that carried the role in this organization. ``None`` for a system
    #: actor — a system operation holds no membership.
    membership_id: uuid.UUID | None = None

    def __post_init__(self) -> None:
        if self.type is ActorType.HUMAN:
            if self.user_id is None or self.membership_id is None:
                raise AuditError(
                    "a human actor must name both the person and the membership the server "
                    "resolved; an event attributed to a person who cannot be named is not "
                    "attribution"
                )
        elif self.user_id is not None or self.membership_id is not None:
            raise AuditError(
                "a system actor names nobody: attributing an operation no person performed to "
                "a user would invent an actor"
            )

    # ── The two ways an actor exists ─────────────────────────────────────────

    @classmethod
    def human(cls, *, user_id: uuid.UUID, membership_id: uuid.UUID) -> AuditActor:
        """An authenticated person, as the credential and the membership identify them."""
        return cls(type=ActorType.HUMAN, user_id=user_id, membership_id=membership_id)

    @classmethod
    def system(cls) -> AuditActor:
        """An operation nobody performed: ingestion, a migration, a future worker."""
        return cls(type=ActorType.SYSTEM)

    @property
    def is_human(self) -> bool:
        """Whether a person initiated this event."""
        return self.type is ActorType.HUMAN

    def __repr__(self) -> str:
        """Identify the actor without rendering an identifier a log does not need."""
        return f"<AuditActor {self.type.value}>"


# ── Metadata: the boundary that keeps payloads out of the trail ───────────────

#: How many keys one event may carry. The events this build writes have a handful; the
#: bound exists so metadata cannot become a document.
MAX_METADATA_KEYS = 32

#: The longest key, value and list this build will store.
MAX_METADATA_KEY_LENGTH = 64
MAX_METADATA_STRING_LENGTH = 256
MAX_METADATA_LIST_ITEMS = 16

#: The serialized size of the whole mapping. The database enforces a larger ceiling as a
#: backstop; this is the bound the application applies before the row is built.
MAX_METADATA_BYTES = 4096

#: What a value becomes when its key or its shape says "this is a credential". Kept as a
#: visible marker rather than dropped: a record that says something sensitive was present
#: is more useful than one that silently omits it.
REDACTED = "[redacted]"

#: Keys are snake-case-ish identifiers, so a key that is not one is a caller's mistake
#: rather than a legitimate label.
_KEY_PATTERN = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")

#: Control characters in a value — every one, including the tab and the newline. No
#: legitimate summary needs one, a value that carries one is either a payload or an attempt
#: at log injection, and a refusal is a clearer answer than a value that would later be
#: re-rendered across two lines of a log file.
_CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f]")

#: Key segments that mean "secret". Segmentation is on ``_``/``-``/``.`` so that
#: ``access_token`` is caught while ``idempotency_key`` — an opaque request identifier,
#: not a credential — is not.
_SENSITIVE_KEY_SEGMENTS = frozenset(
    {
        "apikey",
        "authorization",
        "bearer",
        "credential",
        "credentials",
        "cookie",
        "cookies",
        "jwt",
        "pass",
        "passwd",
        "password",
        "pwd",
        "salt",
        "secret",
        "secrets",
        "session",
        "signature",
        "token",
        "tokens",
    }
)

#: Whole key names that are secrets even though their segments are not (``api_key`` has
#: the innocent segment ``key``). Matched on the normalized key.
_SENSITIVE_KEY_NAMES = frozenset(
    {
        "accesskey",
        "apikey",
        "clientsecret",
        "privatekey",
        "secretkey",
        "signingkey",
    }
)

#: Values that are credentials whatever their key says. Deliberately few and specific:
#: a pattern that matched ordinary text would redact legitimate summaries.
_SENSITIVE_VALUE_PATTERNS = (
    re.compile(r"^bearer\s+\S", re.IGNORECASE),
    re.compile(r"^eyJ[A-Za-z0-9_-]{8,}\."),
    re.compile(r"^-----BEGIN "),
)

_SCALAR_TYPES = (str, bool, int, float)
_SENSITIVE_SEGMENT_SPLIT = re.compile(r"[._-]")


def _is_sensitive_key(key: str) -> bool:
    """Whether a key name says "the value under here is a credential"."""
    normalized = key.lower()
    collapsed = normalized.replace("_", "").replace("-", "").replace(".", "")
    if collapsed in _SENSITIVE_KEY_NAMES:
        return True
    return bool(_SENSITIVE_KEY_SEGMENTS & set(_SENSITIVE_SEGMENT_SPLIT.split(normalized)))


def _is_sensitive_value(value: str) -> bool:
    """Whether a value looks like a credential whatever it is called."""
    return any(pattern.search(value) for pattern in _SENSITIVE_VALUE_PATTERNS)


def _sanitize_value(key: str, value: object) -> Any:
    """One metadata value, validated and redacted if it looks sensitive."""
    if isinstance(value, float) and (value != value or value in {float("inf"), float("-inf")}):
        raise AuditMetadataError(f"metadata value for {key!r} is not a finite number")
    if isinstance(value, str):
        if len(value) > MAX_METADATA_STRING_LENGTH:
            raise AuditMetadataError(
                f"metadata value for {key!r} is longer than {MAX_METADATA_STRING_LENGTH} "
                "characters; a summary is not a payload"
            )
        if _CONTROL_CHARACTERS.search(value):
            raise AuditMetadataError(f"metadata value for {key!r} contains control characters")
        return REDACTED if _is_sensitive_value(value) else value
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        items = list(value)
        if len(items) > MAX_METADATA_LIST_ITEMS:
            raise AuditMetadataError(
                f"metadata list for {key!r} holds more than {MAX_METADATA_LIST_ITEMS} items"
            )
        return [_sanitize_value(key, item) for item in items]
    raise AuditMetadataError(
        f"metadata value for {key!r} is a {type(value).__name__}; this build stores scalars "
        "and lists of scalars, so that metadata stays a summary rather than a payload"
    )


def sanitize_metadata(metadata: Mapping[str, Any] | None) -> dict[str, Any]:
    """The one place metadata becomes storable.

    Every audit write goes through here, so "no secrets in the trail" and "no payloads in
    the trail" are properties of the boundary rather than promises each call site makes.
    A key that names a credential, or a value that looks like one, is replaced by
    :data:`REDACTED`; a shape that is not a small flat mapping of scalars is refused.

    The result is a plain ``dict`` of JSON-safe values, so it can be handed to JSONB, to
    a response model or to a test without further defence.
    """
    if metadata is None:
        return {}
    if not isinstance(metadata, Mapping):
        raise AuditMetadataError(
            f"metadata must be a mapping, got {type(metadata).__name__}; an audit event "
            "carries structured facts, not a value"
        )
    if len(metadata) > MAX_METADATA_KEYS:
        raise AuditMetadataError(
            f"metadata holds {len(metadata)} keys; at most {MAX_METADATA_KEYS} are stored"
        )

    sanitized: dict[str, Any] = {}
    for key, value in metadata.items():
        if not isinstance(key, str) or not _KEY_PATTERN.match(key):
            raise AuditMetadataError(
                f"metadata key {key!r} is not a lowercase identifier; keys are a closed shape "
                "so a reader can rely on them"
            )
        sanitized[key] = REDACTED if _is_sensitive_key(key) else _sanitize_value(key, value)

    rendered = canonical_json(sanitized)
    if len(rendered.encode("utf-8")) > MAX_METADATA_BYTES:
        raise AuditMetadataError(
            f"metadata serializes to more than {MAX_METADATA_BYTES} bytes; an event records "
            "what happened, not the data it happened to"
        )
    return sanitized


def metadata_as_json(metadata: Mapping[str, Any]) -> str:
    """A deterministic rendering of metadata, for logs and for tests.

    Not used to store: the column is JSONB, and PostgreSQL is the one that renders it
    there. This exists so a log line and an assertion agree on the same bytes.
    """
    return json.dumps(metadata, sort_keys=True, separators=(",", ":"), default=str)
