"""Discovery: how an asset that something else found becomes an inventory record.

Phase 3 builds the *boundary*, not the collectors. No cloud provider is queried,
no network is scanned, and nothing in this package claims otherwise: an
integration that observes AI assets in some environment (an AWS account, a
Kubernetes cluster, an MCP registry, a CI pipeline) is future work, and when it
arrives it will call the function this package exposes.

Why the boundary exists now anyway: without it, phase 3's inventory would only
ever be written by a human through the API, and the first collector would have to
re-derive the rules for identity, provenance, validation, deduplication and
tenancy from scratch — probably in a different way, which is how one inventory
becomes two. So the rules are written down once, in
:mod:`aicore_api.discovery.registry`, and both the API and any future collector go
through them.

The honest boundary is visible in the schema: a record written through the API is
``discovery_source='manual'`` and has no ``last_seen_at``; a record written by
:func:`~aicore_api.discovery.registry.register_discovered_asset` carries the name
of the integration that reported it and the time it was observed. A client cannot
set either field.
"""

from __future__ import annotations

from aicore_api.discovery.registry import (
    DiscoveredAsset,
    DiscoveryResult,
    register_discovered_asset,
)

__all__ = ["DiscoveredAsset", "DiscoveryResult", "register_discovered_asset"]
