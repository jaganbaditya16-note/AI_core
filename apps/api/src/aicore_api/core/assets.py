"""The AI asset vocabulary: what an asset is, and how its metadata is validated.

Phase 3 answers "what AI assets does this organization know about?". Answering it
needs one shared vocabulary, because the alternative — a table, a schema and a set
of rules per asset type — turns seven similar things into seven systems that drift
apart. So there is **one** asset model (``db/models/asset.py``) and this module
supplies the closed sets and the type-specific metadata validation that keep it
honest.

Three decisions are made here rather than in a migration or a route:

1. **The controlled vocabularies are Python ``StrEnum``s**, stored in PostgreSQL as
   ``VARCHAR`` + ``CHECK``. Adding a value is then an ordinary migration instead of
   an ``ALTER TYPE`` that cannot run in the transaction consuming it, and the
   database still refuses anything outside the set.
2. **Type-specific metadata is validated, not schemaless.** Each asset type has a
   Pydantic model with ``extra="forbid"``, so a typo in a metadata key is a
   rejected request rather than a silently stored field nothing will ever read.
   The models are deliberately small: the fields named in the phase, with bounded
   lengths.
3. **An unknown asset type has no metadata contract, and therefore no valid
   metadata.** :func:`metadata_model_for` raises instead of falling back to "any
   dictionary" — the fallback is how a permissive path appears beside a strict one.

What is *not* here: risk assessment, policy, or anything that decides what an asset
may do. ``RiskClassification`` is a stored label with no behaviour attached; the
risk engine that interprets it belongs to a later phase, and saying otherwise would
be a claim this build does not honour.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from enum import StrEnum
from types import MappingProxyType
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

__all__ = [
    "ASSET_TYPE_LABELS",
    "MANUAL_DISCOVERY_SOURCE",
    "METADATA_MAX_BYTES",
    "METADATA_MODELS",
    "AssetStatus",
    "AssetType",
    "DiscoveryState",
    "Environment",
    "RiskClassification",
    "metadata_model_for",
    "normalize_external_identifier",
    "normalize_name",
    "validate_metadata",
]


class AssetType(StrEnum):
    """What kind of AI-related thing this is.

    One type per row, and the type is part of the asset's identity: it selects the
    metadata contract and it participates in the uniqueness rule, so it can never
    be changed by an update (see ``schemas/assets.py``).
    """

    AGENT = "agent"
    APPLICATION = "application"
    MODEL = "model"
    TOOL = "tool"
    MCP_SERVER = "mcp_server"
    API = "api"
    DATA_SOURCE = "data_source"


class AssetStatus(StrEnum):
    """Lifecycle of an inventory record.

    Inventory lifecycle only. ``SUSPENDED`` records that an asset is not meant to
    be in service; it does **not** stop anything from running. Runtime
    containment is a later phase, and a status field that pretended to enforce
    would be the most dangerous kind of fake control.
    """

    DRAFT = "draft"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    RETIRED = "retired"


class DiscoveryState(StrEnum):
    """How the asset came to be known.

    - ``MANAGED`` — registered on purpose and accounted for.
    - ``UNKNOWN`` — recorded, but ownership or management status is not settled.
    - ``SHADOW`` — observed outside the organization's known inventory or
      governance process.

    The distinction is a property of the *record*, not a claim about the world:
    nothing here detects a shadow asset. Phase 3 gives integrations and operators
    a place to record one.
    """

    MANAGED = "managed"
    UNKNOWN = "unknown"
    SHADOW = "shadow"


class Environment(StrEnum):
    """Where the asset lives. ``UNKNOWN`` is first-class, not a missing value."""

    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"
    UNKNOWN = "unknown"


class RiskClassification(StrEnum):
    """A stored label, unassessed until a later phase says otherwise.

    There is no scoring, no weighting and no interpretation in Phase 3: the field
    exists so inventory can carry an operator's judgement, and ``UNASSESSED`` is
    the honest default.
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    UNASSESSED = "unassessed"


#: One-line descriptions of what each type is for, used by the documentation and
#: by the tests that assert every type has both a label and a metadata contract.
ASSET_TYPE_LABELS: Mapping[AssetType, str] = MappingProxyType(
    {
        AssetType.AGENT: "An autonomous or semi-autonomous AI agent.",
        AssetType.APPLICATION: "An application that uses AI capabilities.",
        AssetType.MODEL: "A model, whether hosted, local or consumed as a service.",
        AssetType.TOOL: "A tool or function an agent or application can call.",
        AssetType.MCP_SERVER: "A Model Context Protocol server exposing tools or resources.",
        AssetType.API: "An AI-related API an application integrates with.",
        AssetType.DATA_SOURCE: "A data source that feeds AI systems.",
    }
)

#: The ``discovery_source`` recorded for a record a person registered through the
#: API. Integrations report under ``integration:<name>`` instead, so "who recorded
#: this?" is answerable from the row itself.
MANUAL_DISCOVERY_SOURCE = "manual"

#: Bounded metadata. Metadata is inventory context, not a document store: a cap
#: keeps one asset from turning into an unbounded blob that a list query drags
#: through memory, and it makes "malformed metadata" a rejected request.
METADATA_MAX_BYTES = 8 * 1024

#: Identifier-shaped strings: printable, no control characters, bounded length.
_IDENTIFIER_MAX_LENGTH = 512
_IDENTIFIER_PATTERN = re.compile(r"^[^\x00-\x1f\x7f]+$")


class _MetadataBase(BaseModel):
    """Common rules for every asset type's metadata.

    ``extra="forbid"`` is the important one: it turns a mis-typed key into a 422
    at the boundary instead of a field nobody reads. Blank strings are rejected
    outright — an empty ``provider`` is not information.
    """

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    @field_validator("*", mode="after")
    @classmethod
    def _reject_blank_or_unprintable(cls, value: Any) -> Any:
        if isinstance(value, str):
            if not value:
                raise ValueError("must not be blank")
            if not _IDENTIFIER_PATTERN.match(value):
                raise ValueError("must not contain control characters")
        return value


class ModelMetadata(_MetadataBase):
    """A model: who provides it, which one it is, which version."""

    provider: str | None = Field(default=None, max_length=_IDENTIFIER_MAX_LENGTH)
    model_identifier: str | None = Field(default=None, max_length=_IDENTIFIER_MAX_LENGTH)
    version: str | None = Field(default=None, max_length=_IDENTIFIER_MAX_LENGTH)


class ApplicationMetadata(_MetadataBase):
    """An application that uses AI."""

    application_identifier: str | None = Field(default=None, max_length=_IDENTIFIER_MAX_LENGTH)
    repository_url: str | None = Field(default=None, max_length=_IDENTIFIER_MAX_LENGTH)


class ToolMetadata(_MetadataBase):
    """A callable tool."""

    tool_identifier: str | None = Field(default=None, max_length=_IDENTIFIER_MAX_LENGTH)
    endpoint: str | None = Field(default=None, max_length=_IDENTIFIER_MAX_LENGTH)


class ApiMetadata(_MetadataBase):
    """An AI-related API."""

    endpoint: str | None = Field(default=None, max_length=_IDENTIFIER_MAX_LENGTH)
    provider: str | None = Field(default=None, max_length=_IDENTIFIER_MAX_LENGTH)


class McpServerMetadata(_MetadataBase):
    """A Model Context Protocol server."""

    server_identifier: str | None = Field(default=None, max_length=_IDENTIFIER_MAX_LENGTH)
    endpoint: str | None = Field(default=None, max_length=_IDENTIFIER_MAX_LENGTH)


class AgentMetadata(_MetadataBase):
    """An agent: the framework it is built on, and its version."""

    framework: str | None = Field(default=None, max_length=_IDENTIFIER_MAX_LENGTH)
    version: str | None = Field(default=None, max_length=_IDENTIFIER_MAX_LENGTH)


class DataSourceMetadata(_MetadataBase):
    """A data source feeding AI systems.

    ``classification`` is a free-form placeholder: data-classification schemes are
    organization-specific, and inventing a taxonomy here would be exactly the kind
    of premature policy this phase avoids. It is validated as a bounded string,
    not interpreted.
    """

    classification: str | None = Field(default=None, max_length=_IDENTIFIER_MAX_LENGTH)


#: The metadata contract per asset type. Adding an asset type means adding a model
#: here — which is why :func:`metadata_model_for` has no permissive fallback.
METADATA_MODELS: Mapping[AssetType, type[_MetadataBase]] = MappingProxyType(
    {
        AssetType.AGENT: AgentMetadata,
        AssetType.APPLICATION: ApplicationMetadata,
        AssetType.MODEL: ModelMetadata,
        AssetType.TOOL: ToolMetadata,
        AssetType.MCP_SERVER: McpServerMetadata,
        AssetType.API: ApiMetadata,
        AssetType.DATA_SOURCE: DataSourceMetadata,
    }
)


def metadata_model_for(asset_type: AssetType | str) -> type[_MetadataBase]:
    """The metadata model for ``asset_type``.

    Raises :class:`ValueError` for an unknown type rather than returning a
    permissive model: "we do not know this type" must not become "anything goes".
    """
    try:
        resolved = AssetType(asset_type)
    except ValueError as exc:
        raise ValueError(f"unknown asset type {asset_type!r}") from exc
    return METADATA_MODELS[resolved]


def normalize_name(name: str) -> str:
    """Trim a name and collapse internal whitespace.

    Names are for humans and are *not* identities: two assets may share one, and
    nothing is looked up by name. Normalizing here keeps ``" Acme  Agent "`` and
    ``"Acme Agent"`` from looking like different names in a listing.
    """
    return " ".join(name.split())


def normalize_external_identifier(identifier: str | None) -> str | None:
    """Normalize the stable identifier an integration reports, or ``None``.

    Trimming only — **not** case folding. Identifiers are opaque strings chosen by
    whatever system produced them (an ARN, a URL, a vendor's registry id), and
    silently lowercasing one could merge two genuinely different assets. The
    uniqueness rule is therefore exact-match after trimming, and the docstring in
    ``docs/inventory.md`` tells integrations to canonicalize before reporting.
    """
    if identifier is None:
        return None
    normalized = identifier.strip()
    if not normalized:
        raise ValueError("external_identifier must not be blank")
    if len(normalized) > _IDENTIFIER_MAX_LENGTH:
        raise ValueError(f"external_identifier must be at most {_IDENTIFIER_MAX_LENGTH} characters")
    if not _IDENTIFIER_PATTERN.match(normalized):
        raise ValueError("external_identifier must not contain control characters")
    return normalized


def validate_metadata(
    asset_type: AssetType | str, payload: Mapping[str, Any] | None
) -> dict[str, Any] | None:
    """Validate ``payload`` against ``asset_type``'s contract and normalize it.

    Returns the metadata to store (``None`` when nothing was supplied), or raises
    :class:`ValueError` describing the first problem. Callers translate that into a
    422: metadata that does not match its type is a malformed request, not a
    server error.

    Unknown keys are rejected rather than dropped — silently discarding a field an
    integration reports is how a collector looks like it is working while
    recording nothing.
    """
    if payload is None:
        return None
    if not isinstance(payload, Mapping):
        raise ValueError("metadata must be an object")

    model = metadata_model_for(asset_type)
    try:
        validated = model.model_validate(dict(payload))
    except Exception as exc:  # pydantic ValidationError; message is safe to pass on
        raise ValueError(f"metadata does not match a {asset_type} asset: {exc}") from exc

    stored = validated.model_dump(exclude_none=True)
    if not stored:
        return None
    encoded = json.dumps(stored, separators=(",", ":"), sort_keys=True)
    if len(encoded.encode("utf-8")) > METADATA_MAX_BYTES:
        raise ValueError(f"metadata must be at most {METADATA_MAX_BYTES} bytes when serialized")
    return stored
