"""The action vocabulary: what this control plane may be asked to *do*.

Phase 5 answers "may this caller use this permission?", Phase 6 answers "does the
context satisfy the organization's policy?". Phase 7 adds the step that actually
does something, and this module is the list of things it may do — a closed,
explicitly registered catalogue written as code.

**There is no "execute anything" path, and none can be built from a request.** An
action is an :class:`ActionDefinition`: an identifier, a description of what it
does, the resource type it addresses, the *input schema* its arguments are validated
against, how sensitive it is, and which executor runs it. A request names an
identifier; the registry either has it or the request is refused. Nothing in a
request can name a module, a function, a class, a URL or a command — the mapping
from identifier to executor is made here, in reviewable source, and there is no
``importlib``, no ``getattr`` on a dotted path and no plugin discovery anywhere in
this package. That is the whole reason the vocabulary is a module rather than a
table: a row that says "call this" is an arbitrary-code field, and a literal is not.

**Arguments are validated twice, in two different ways.** The generic bounds refuse
anything that is not a flat mapping of small scalar values — no nested objects, no
``None``, no oversized strings or lists — so no request can smuggle a structure into
the execution path. Then the action's own input schema (a Pydantic model with
``extra="forbid"`` and ``strict=True``) decides which keys it has and what they
mean. An unknown key, a wrong type or a value outside a closed set is an
:class:`ActionArgumentError`, which the API answers as a 422 — before anything is
authorized, evaluated or executed.

**The policy context is derived, never supplied.** The one fact a request states
about the world is the *environment* it believes it is acting in, and that statement
is not evidence: it is verified against the environment the addressed record is
stored in, and a mismatch is refused. The facts a policy is evaluated against come
from the resolved target record and from the Phase 5 decision — see
:class:`ActionTarget` and :mod:`aicore_api.core.firewall`.

**One permission, deliberately.** Every registered action is guarded by
``action.execute``. A per-action permission would double the catalogue for no
boundary: the *authorization* question ("may this person run registered actions in
this organization?") is one question, and the *contextual* question ("should this
particular action, on this particular target, be run?") is Phase 6's, answered
through a policy on the ``action.execute`` target. ``agent.execute`` was rejected on
purpose: this phase runs registered actions, it does not run agents.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from aicore_api.core.assets import Environment
from aicore_api.core.permissions import Action, Permission, Resource
from aicore_api.core.policy import ConditionField, ContextValue
from aicore_api.core.request_context import is_safe_request_id

__all__ = [
    "ACTION_ID_MAX_LENGTH",
    "ACTION_ID_PATTERN",
    "AGENT_POSTURE_CHECK",
    "DEFAULT_ACTIONS",
    "IDEMPOTENCY_KEY_MAX_LENGTH",
    "IDEMPOTENCY_KEY_PATTERN",
    "MAX_ACTION_ARGUMENTS",
    "MAX_ACTION_DESCRIPTION_LENGTH",
    "MAX_ARGUMENT_KEY_LENGTH",
    "MAX_ARGUMENT_LIST_LENGTH",
    "MAX_ARGUMENT_STRING_LENGTH",
    "ActionArgumentError",
    "ActionDefinition",
    "ActionDefinitionError",
    "ActionError",
    "ActionRegistry",
    "ActionRequest",
    "ActionSensitivity",
    "ActionTarget",
    "AgentPostureArguments",
    "ExecutionStatus",
    "UnknownActionError",
    "canonical_json",
    "default_action_registry",
]

#: An action identifier has the shape of a permission code — dotted, lower case, one
#: or more segments — because it is read, logged and quoted by people who need to
#: recognize it. Two segments at minimum: a bare word would be a name, not a name for
#: *something*.
ACTION_ID_PATTERN = r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$"
ACTION_ID_MAX_LENGTH = 64
_ACTION_ID = re.compile(ACTION_ID_PATTERN)
ACTION_ID_MIN_SEGMENTS = 2

#: The idempotency key is an opaque token a client chooses, kept in the same
#: conservative allow-list as a correlation id: it is stored, compared and echoed,
#: never interpreted, and never used to build a query or a path.
IDEMPOTENCY_KEY_PATTERN = r"^[A-Za-z0-9._:-]{1,128}$"
IDEMPOTENCY_KEY_MAX_LENGTH = 128
_IDEMPOTENCY_KEY = re.compile(IDEMPOTENCY_KEY_PATTERN)

MAX_ACTION_DESCRIPTION_LENGTH = 200

#: Bounds on the argument payload, before any action's own schema sees it. They are
#: bounds on *work* — how many keys, how long a value, how many list items — and they
#: apply to every action, including the ones a later phase registers.
MAX_ACTION_ARGUMENTS = 16
MAX_ARGUMENT_KEY_LENGTH = 64
MAX_ARGUMENT_STRING_LENGTH = 512
MAX_ARGUMENT_LIST_LENGTH = 16

_SCALAR_TYPES = (bool, int, float)


class ActionError(ValueError):
    """Base class for an action request or definition this build refuses.

    A :class:`ValueError`, like the rest of the domain layer, and answered by the API
    as a 422: a request naming an action that does not exist, or arguments its schema
    does not accept, is a request that cannot be satisfied — not a denial, and never
    something that reaches an executor.
    """


class ActionDefinitionError(ActionError):
    """A registry entry this build cannot serve.

    Raised while the catalogue is *built*, so a mistake is a startup failure rather
    than a request that behaves strangely: an identifier that is not an
    ``action.identifier``, a duplicate, an input schema that would accept unknown
    keys, or an executor nothing registered.
    """


class UnknownActionError(ActionError):
    """A request names an action that is not registered.

    The catalogue is not a secret — it is the list of things a client may ask for —
    so the refusal names the identifiers that do exist. Guessing is not the intended
    way to discover the vocabulary.
    """


class ActionArgumentError(ActionError):
    """The arguments do not satisfy the action's input schema.

    Deliberately specific about *where* and *why*, and deliberately silent about
    *what*: the message is built from the error location and the schema's own wording,
    never from the value a caller sent. A request body is attacker-chosen input, and
    an error message that quotes it is how a value ends up in a log.
    """


class ExecutionStatus(StrEnum):
    """How an admitted execution ends. The idempotency ledger's vocabulary.

    Declared here, beside the action vocabulary, rather than in the service that writes
    it: the ledger's table carries the same three values in a ``CHECK`` constraint, and
    the model layer has to be able to import them without importing the execution
    service — which depends on the authorization layer, and therefore on the models.
    A status this build cannot account for is refused by both layers.

    ``RESERVED`` is the claim that makes idempotency work: the key is taken and the
    action has not run. ``EXECUTED`` records an outcome that can be replayed. ``FAILED``
    records that the adapter was reached and could not finish — and is deliberately
    *not* retryable under the same key, because the action may have had effects this
    build cannot see.
    """

    RESERVED = "reserved"
    EXECUTED = "executed"
    FAILED = "failed"


class ActionSensitivity(StrEnum):
    """How much care an action warrants, recorded so it can be reviewed.

    Not an authorization input — authorization is Phase 5's question and context is
    Phase 6's — and not a scoring model: it is the sentence a reviewer needs when
    reading the catalogue ("what class of thing does this touch?"). The action this
    phase ships is :attr:`ROUTINE`, and a test asserts the whole catalogue is, because
    a phase whose claim is "nothing is changed yet" should not register an action that
    touches the world.
    """

    #: Reads and reports on data this system already holds. No side effects.
    ROUTINE = "routine"
    #: Changes a record inside this system. Reversible, and nothing else notices.
    CONTROLLED = "controlled"
    #: Changes something outside this system — a ticket, a message, a deployment.
    SENSITIVE = "sensitive"


def canonical_json(payload: Mapping[str, Any]) -> str:
    """A deterministic JSON rendering of ``payload``, for fingerprints and digests.

    Sorted keys and no whitespace, so two equal payloads render one string however
    they were built. Used to compare a request with itself across retries and to
    digest an outcome, which is why it must never depend on insertion order.
    """
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def _type_name(value: object) -> str:
    """A readable name for a value's type, for a message that must not quote it."""
    return type(value).__name__


def _validate_argument_value(key: str, value: object) -> None:
    """Refuse an argument value that is not a small, flat scalar.

    The rule is about shapes, not meanings: a string, a boolean, a number, or a list
    of those. A nested object is refused because the execution path has no use for one
    and every use for a payload; ``None`` is refused because an argument is a value
    that is being set, and "set it to nothing" is expressed by omitting it.
    """
    if value is None:
        raise ActionArgumentError(
            f"argument {key!r} must be a value, not null; omit it to leave it unset"
        )
    if isinstance(value, Mapping):
        raise ActionArgumentError(
            f"argument {key!r} is a {_type_name(value)}; this build accepts flat scalar values only"
        )
    if isinstance(value, (list, tuple)):
        if len(value) > MAX_ARGUMENT_LIST_LENGTH:
            raise ActionArgumentError(
                f"argument {key!r} lists {len(value)} values; the limit is "
                f"{MAX_ARGUMENT_LIST_LENGTH}"
            )
        for item in value:
            _validate_argument_value(key, item)
        return
    if isinstance(value, str):
        if len(value) > MAX_ARGUMENT_STRING_LENGTH:
            raise ActionArgumentError(
                f"argument {key!r} is longer than {MAX_ARGUMENT_STRING_LENGTH} characters"
            )
        return
    if isinstance(value, _SCALAR_TYPES):
        return
    raise ActionArgumentError(
        f"argument {key!r} is a {_type_name(value)}; this build accepts strings, booleans, "
        "numbers and lists of those"
    )


def validate_argument_payload(arguments: Mapping[str, Any]) -> None:
    """Apply the generic bounds to a raw argument mapping.

    Separate from the per-action schema because it is the same rule for every action,
    present and future: a flat mapping of at most :data:`MAX_ACTION_ARGUMENTS` small
    values whose keys are short strings.
    """
    if not isinstance(arguments, Mapping):
        raise ActionArgumentError(f"arguments must be a mapping, got {_type_name(arguments)}")
    if len(arguments) > MAX_ACTION_ARGUMENTS:
        raise ActionArgumentError(
            f"{len(arguments)} arguments were supplied; the limit is {MAX_ACTION_ARGUMENTS}"
        )
    for key, value in arguments.items():
        if not isinstance(key, str) or not key or len(key) > MAX_ARGUMENT_KEY_LENGTH:
            raise ActionArgumentError(
                "every argument name must be a non-empty string of at most "
                f"{MAX_ARGUMENT_KEY_LENGTH} characters"
            )
        _validate_argument_value(key, value)


def _argument_message(error: Mapping[str, Any]) -> str:
    """Render one Pydantic error as a message that never quotes the input value."""
    location = "/".join(str(part) for part in error.get("loc", ()) if part != "__root__")
    message = str(error.get("msg", "is not a value this action accepts"))
    if message.startswith("Value error, "):
        message = message[len("Value error, ") :]
    return f"argument {location}: {message}" if location else message


def format_validation_error(exc: ValidationError) -> str:
    """A refusal naming the first problem, in the schema's own words."""
    errors = exc.errors()
    if not errors:
        return "unknown arguments"
    return "; ".join(_argument_message(error) for error in errors[:3])


@dataclass(frozen=True, slots=True)
class ActionDefinition:
    """One registered action: everything the build needs to admit and run it.

    A value, not a row. ``executor_id`` names an adapter the executor registry
    resolves — never a module path, a dotted function name or an import string, and
    never anything a request can influence. ``argument_model`` is the input schema: a
    strict Pydantic model with ``extra="forbid"``, checked here and again by the
    registry, so an action cannot be registered that would silently drop the keys it
    does not recognize.
    """

    action_id: str
    description: str
    target_resource: Resource
    sensitivity: ActionSensitivity
    argument_model: type[BaseModel]
    executor_id: str
    #: Whether the target must already exist in the organization. True for every
    #: action this phase registers: an action about a row nobody has is not an action,
    #: and a future "create"-style action can relax it explicitly.
    requires_existing_target: bool = True

    def __post_init__(self) -> None:
        if not isinstance(self.action_id, str) or not _ACTION_ID.match(self.action_id):
            raise ActionDefinitionError(
                f"{self.action_id!r} is not an action identifier; the shape is "
                f"{ACTION_ID_PATTERN} (e.g. 'agent.posture_check')"
            )
        if len(self.action_id) > ACTION_ID_MAX_LENGTH:
            raise ActionDefinitionError(
                f"{self.action_id!r} is longer than {ACTION_ID_MAX_LENGTH} characters"
            )
        if self.action_id.count(".") + 1 < ACTION_ID_MIN_SEGMENTS:
            raise ActionDefinitionError(
                f"{self.action_id!r} is a bare name; an action identifier names what it acts "
                "on first (e.g. 'agent.posture_check')"
            )
        if (
            not isinstance(self.description, str)
            or not self.description
            or len(self.description) > MAX_ACTION_DESCRIPTION_LENGTH
        ):
            raise ActionDefinitionError(
                f"action {self.action_id!r} needs a description of at most "
                f"{MAX_ACTION_DESCRIPTION_LENGTH} characters: a catalogue entry nobody can "
                "read is not reviewable"
            )
        if not isinstance(self.target_resource, Resource):
            raise ActionDefinitionError(
                f"action {self.action_id!r} must name a target resource from the permission "
                "vocabulary"
            )
        if not isinstance(self.sensitivity, ActionSensitivity):
            raise ActionDefinitionError(
                f"action {self.action_id!r} must declare a sensitivity classification"
            )
        if not isinstance(self.executor_id, str) or not _ACTION_ID.match(self.executor_id):
            raise ActionDefinitionError(
                f"action {self.action_id!r} names executor {self.executor_id!r}; an executor "
                "identifier has the same shape as an action identifier"
            )
        if not isinstance(self.argument_model, type) or not issubclass(
            self.argument_model, BaseModel
        ):
            raise ActionDefinitionError(
                f"action {self.action_id!r} must carry a Pydantic model as its input schema"
            )
        if self.argument_model.model_config.get("extra") != "forbid":
            raise ActionDefinitionError(
                f"action {self.action_id!r} has an input schema that accepts unknown keys; "
                'declare model_config = ConfigDict(extra="forbid") so a typo is refused '
                "rather than ignored"
            )

    @property
    def permission(self) -> Permission:
        """The permission that guards this action: ``action.execute``, always.

        One gate for the whole catalogue, on purpose — see the module docstring.
        """
        return Permission.ACTION_EXECUTE

    @property
    def policy_target(self) -> tuple[Resource, Action]:
        """The ``resource.action`` pair an organization writes a policy against."""
        return Resource.ACTION, Action.EXECUTE

    def parse_arguments(self, arguments: Mapping[str, Any]) -> BaseModel:
        """Validate ``arguments`` against this action's schema, or refuse them.

        The generic bounds run first, then the schema, so a payload of the wrong
        *shape* is refused before a schema that expects a small flat mapping sees it.
        """
        validate_argument_payload(arguments)
        try:
            return self.argument_model.model_validate(dict(arguments))
        except ValidationError as exc:
            raise ActionArgumentError(
                f"action {self.action_id!r} was given arguments it does not accept: "
                f"{format_validation_error(exc)}"
            ) from exc

    def __repr__(self) -> str:
        return (
            f"<ActionDefinition {self.action_id!r} target={self.target_resource.value} "
            f"sensitivity={self.sensitivity.value} executor={self.executor_id!r}>"
        )


class ActionRegistry:
    """The allowlist: every action this build will admit, and nothing else.

    Immutable once built, and looked up by identifier only. Building it is also where
    the catalogue's internal consistency is checked — duplicate identifiers, or a
    definition that names an executor nothing registered, are refused here rather
    than discovered by a request.
    """

    def __init__(
        self,
        definitions: Iterable[ActionDefinition] = (),
        *,
        executor_ids: Iterable[str] = (),
    ) -> None:
        ordered: list[ActionDefinition] = []
        by_id: dict[str, ActionDefinition] = {}
        for definition in definitions:
            if not isinstance(definition, ActionDefinition):
                raise ActionDefinitionError(
                    f"the action registry holds ActionDefinition values, got "
                    f"{_type_name(definition)}"
                )
            if definition.action_id in by_id:
                raise ActionDefinitionError(
                    f"two actions are registered as {definition.action_id!r}; the identifier is "
                    "how a request names one, so it has to name exactly one"
                )
            by_id[definition.action_id] = definition
            ordered.append(definition)
        known_executors = frozenset(executor_ids)
        for definition in ordered:
            if known_executors and definition.executor_id not in known_executors:
                raise ActionDefinitionError(
                    f"action {definition.action_id!r} names executor {definition.executor_id!r}, "
                    "which nothing registered; an action whose adapter does not exist could be "
                    "authorized and never run"
                )
        self._definitions = MappingProxyType(by_id)
        self._order = tuple(definition.action_id for definition in ordered)

    def get(self, action_id: object) -> ActionDefinition | None:
        """The definition ``action_id`` names, or ``None``."""
        if not isinstance(action_id, str):
            return None
        return self._definitions.get(action_id)

    def resolve(self, action_id: str) -> ActionDefinition:
        """The definition ``action_id`` names, or :class:`UnknownActionError`."""
        definition = self.get(action_id)
        if definition is None:
            raise UnknownActionError(
                f"{action_id!r} is not an action this build has registered; the catalogue is: "
                f"{', '.join(self._order) or '(empty)'}"
            )
        return definition

    def action_ids(self) -> tuple[str, ...]:
        """Every registered identifier, in registration order."""
        return self._order

    def definitions(self) -> tuple[ActionDefinition, ...]:
        """Every registered definition, in registration order."""
        return tuple(self._definitions[action_id] for action_id in self._order)

    def executor_ids(self) -> frozenset[str]:
        """The executors the registered actions name: the allowlist, one level down."""
        return frozenset(definition.executor_id for definition in self.definitions())

    def __contains__(self, action_id: object) -> bool:
        return self.get(action_id) is not None

    def __len__(self) -> int:
        return len(self._order)

    def __repr__(self) -> str:
        return f"<ActionRegistry {', '.join(self._order) or 'empty'}>"


@dataclass(frozen=True, slots=True)
class ActionTarget:
    """The row an action addresses, as the firewall and the policy layer see it.

    ``facts`` is the Phase 6 field vocabulary filled from the stored row — the same
    facts a dry-run evaluation would be given, derived from data the server already
    holds and never from the request. A field the record cannot attest is *absent*
    rather than guessed, because a condition on an absent field never matches.
    """

    resource: Resource
    identifier: uuid.UUID
    facts: Mapping[ConditionField, ContextValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.resource, Resource):
            raise ActionError("an action target must name a resource from the vocabulary")
        if not isinstance(self.identifier, uuid.UUID):
            raise ActionError("an action target must be identified by a UUID")
        resolved: dict[ConditionField, ContextValue] = {}
        for raw_field, value in self.facts.items():
            try:
                resolved[ConditionField(raw_field)] = value
            except ValueError as exc:
                raise ActionError(f"{raw_field!r} is not a policy context field") from exc
        object.__setattr__(self, "facts", MappingProxyType(resolved))

    @property
    def environment(self) -> Environment | None:
        """The recorded environment of the target, when the record states one.

        Read from the attested facts rather than passed alongside them: one value in
        one place, so a target cannot describe two different environments.
        """
        value = self.facts.get(ConditionField.ENVIRONMENT)
        if not isinstance(value, str):
            # Absent, or not a string: either way this target does not state a usable
            # environment, and the firewall treats "cannot confirm" as a refusal.
            return None
        try:
            return Environment(value)
        except ValueError:
            return None

    def __repr__(self) -> str:
        return (
            f"<ActionTarget {self.resource.value} id={self.identifier!s} facts={len(self.facts)}>"
        )


@dataclass(frozen=True, slots=True)
class ActionRequest:
    """A validated request to run one registered action, as the server sees it.

    The HTTP body is the client's *half* of this: it names an action, a target, an
    environment, arguments, an idempotency key and optionally the agent the execution
    is attributed to. The server adds who is asking, which organization they are
    asking in, which membership they are acting through, and the correlation id of the
    request. None of those is a field a client may send, so none of them can be
    spoofed: the request the firewall decides on is assembled from the credential and
    the path, and the request layer refuses a body that tries to state them.

    A request that exists is a request whose arguments already satisfy its action's
    schema (see :meth:`build`), so the firewall and the executor never have to ask
    whether they are looking at a well-formed request — which is what keeps "invalid
    arguments" a 422 at the boundary instead of a decision somewhere deeper.
    """

    organization_id: uuid.UUID
    principal_id: uuid.UUID
    membership_id: uuid.UUID
    action_id: str
    target_id: uuid.UUID
    environment: Environment
    arguments: BaseModel
    correlation_id: str
    idempotency_key: str
    agent_id: uuid.UUID | None = None

    def __post_init__(self) -> None:
        for name in ("organization_id", "principal_id", "membership_id", "target_id"):
            if not isinstance(getattr(self, name), uuid.UUID):
                raise ActionError(f"{name} must be a UUID")
        if self.agent_id is not None and not isinstance(self.agent_id, uuid.UUID):
            raise ActionError("agent_id must be a UUID when it is present")
        if not isinstance(self.action_id, str) or not _ACTION_ID.match(self.action_id):
            raise ActionError(f"{self.action_id!r} is not an action identifier")
        if not isinstance(self.environment, Environment):
            raise ActionError("environment must be a value from the environment vocabulary")
        if not isinstance(self.arguments, BaseModel):
            raise ActionError("arguments must be the action's validated input model")
        if not is_safe_request_id(self.correlation_id):
            raise ActionError("correlation_id must be a safe request identifier")
        if not isinstance(self.idempotency_key, str) or not _IDEMPOTENCY_KEY.match(
            self.idempotency_key
        ):
            raise ActionError(
                "idempotency_key must be 1-128 characters from A-Z, a-z, 0-9, '.', '_', ':' or '-'"
            )

    @classmethod
    def build(
        cls,
        *,
        definition: ActionDefinition,
        organization_id: uuid.UUID,
        principal_id: uuid.UUID,
        membership_id: uuid.UUID,
        target_id: uuid.UUID,
        environment: Environment,
        arguments: Mapping[str, Any],
        correlation_id: str,
        idempotency_key: str,
        agent_id: uuid.UUID | None = None,
    ) -> Self:
        """Assemble and validate a request against the definition it names."""
        return cls(
            organization_id=organization_id,
            principal_id=principal_id,
            membership_id=membership_id,
            action_id=definition.action_id,
            target_id=target_id,
            environment=environment,
            arguments=definition.parse_arguments(arguments),
            correlation_id=correlation_id,
            idempotency_key=idempotency_key,
            agent_id=agent_id,
        )

    @property
    def fingerprint(self) -> str:
        """A stable digest of *what was asked for*, for idempotency comparisons.

        Covers the action, the target, the environment, the attributed agent and the
        validated arguments — and deliberately not the caller, the correlation id or
        when it arrived: two requests carrying one idempotency key are the same request
        only if they ask for the same thing, and a caller retrying after a token
        rotation is still retrying the same request.
        """
        payload = {
            "action": self.action_id,
            "target": str(self.target_id),
            "environment": self.environment.value,
            "agent_id": None if self.agent_id is None else str(self.agent_id),
            "arguments": self.arguments.model_dump(mode="json"),
        }
        return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()

    def __repr__(self) -> str:
        """Identify the request without rendering the arguments it carries."""
        return (
            f"<ActionRequest {self.action_id!r} target={self.target_id!s} "
            f"environment={self.environment.value} key={self.idempotency_key}>"
        )


class AgentPostureArguments(BaseModel):
    """The input schema of ``agent.posture_check``.

    One field, and its strictness is the point: ``extra="forbid"`` refuses a key this
    action does not have, ``strict=True`` refuses a string where a boolean is
    expected, and the closed ``Literal`` bounds the values. A caller cannot ask this
    action for something it does not do, because there is nowhere to put such a
    request.
    """

    model_config = ConfigDict(extra="forbid", strict=True)

    report_detail: Literal["summary", "full"] = Field(
        default="summary",
        description=(
            "``summary`` reports the assessment; ``full`` also reports the recorded facts "
            "it was derived from. Nothing else changes: the action reads and reports."
        ),
    )


#: The one action this phase registers. Read-only by construction: it assesses facts
#: the organization already stores about one of its agents, and its executor never
#: touches the database — the target's facts are resolved before the firewall runs, so
#: there is nothing for the executor to query, write, fetch or call.
AGENT_POSTURE_CHECK = ActionDefinition(
    action_id="agent.posture_check",
    description=(
        "Assess the recorded posture of one registered agent: the facts this system holds "
        "about it, and the conditions in those facts that warrant attention. Reads and "
        "reports; changes nothing."
    ),
    target_resource=Resource.AGENT,
    sensitivity=ActionSensitivity.ROUTINE,
    argument_model=AgentPostureArguments,
    executor_id="agent_registry",
)

#: The catalogue. A literal, reviewed like any other source in this package.
DEFAULT_ACTIONS = ActionRegistry((AGENT_POSTURE_CHECK,), executor_ids=("agent_registry",))


def default_action_registry() -> ActionRegistry:
    """The action catalogue this build serves.

    A function rather than a bare constant at the call sites, so the wiring is one
    replaceable seam: a test, or a later phase with more actions, replaces the whole
    registry rather than mutating one.
    """
    return DEFAULT_ACTIONS
