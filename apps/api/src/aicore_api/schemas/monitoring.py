"""Monitoring contract: the measurements the API publishes, and nothing speculative.

Phase 9's read surface is five endpoints, and these are their shapes. Three rules shape
them.

**Every field is a number or a stated time.** There is no score, no label, no severity and
no status word. A response says how many events of a kind happened in a window, and when
the window was — because ``{"system_health": "GOOD"}`` would be this build asserting a
judgement it has no basis for, and publishing a word nobody can compute is worse than
publishing nothing.

**Nothing here is derived from a row the caller cannot read.** Every number comes from the
organization's own audit trail, aggregated; the per-agent and per-action views name
identifiers the caller already sees in that trail. There is no field that would reveal
another tenant's existence, and a foreign identifier simply has no rows — the list comes
back empty rather than answering "that one exists, but not here".

**The window is part of the answer, not an input echo.** Each response repeats the
resolved window it measured, including the server's clock at the moment of the request, so
"events went up" can always be checked against "compared to when". A measurement without
its interval is a number nobody can act on.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, Field

from aicore_api.core.monitoring import MonitoringWindow, TimeInterval

__all__ = [
    "DenialSummaryRead",
    "ExecutionHealthRead",
    "MonitoringActionListResponse",
    "MonitoringActionRead",
    "MonitoringAgentListResponse",
    "MonitoringAgentRead",
    "MonitoringDecisionsRead",
    "MonitoringPolicyLifecycleRead",
    "MonitoringPolicyResponse",
    "MonitoringSummaryResponse",
    "MonitoringTrendResponse",
    "MonitoringWindowRead",
    "TrendBucketRead",
]


class MonitoringWindowRead(BaseModel):
    """The interval a response measured, as resolved by the server.

    ``name`` is the window the caller asked for (``5m`` … ``7d``, or ``custom``) and the
    bounds are what that resolved to, inclusive, in UTC. A client that renders a chart can
    label it from this rather than from its own clock, which is the only way the label and
    the data can be guaranteed to agree.
    """

    name: MonitoringWindow = Field(description="The window the request named.")
    start: datetime = Field(description="Inclusive lower bound, in UTC.")
    end: datetime = Field(description="Inclusive upper bound, in UTC: the server's clock.")


class ExecutionHealthRead(BaseModel):
    """How the actions that ran in the window ended.

    ``success_rate`` and ``failure_rate`` are ``null`` when nothing completed: a zero would
    read as "everything failed", and the absence of executions is a different statement.
    Refusals and replays are not in these counts — a request that never ran cannot fail.
    """

    completed: int = Field(description="Executions that finished: succeeded + failed.")
    succeeded: int = Field(description="``action.executed`` events in the window.")
    failed: int = Field(description="``action.failed`` events in the window.")
    success_rate: float | None = Field(
        description="Share of completed executions that succeeded; null when none completed."
    )
    failure_rate: float | None = Field(
        description="Share of completed executions that failed; null when none completed."
    )


class DenialSummaryRead(BaseModel):
    """Refusals in the window, and which layer produced them.

    A denial is an event Phase 8 recorded, not an incident and not a finding: a request was
    refused and nothing ran. The breakdown by reason is the firewall's own closed
    vocabulary, so a refusal that recorded no readable reason is counted under
    ``unspecified`` rather than dropped.
    """

    total: int = Field(description="``action.denied`` events in the window.")
    by_reason: dict[str, int] = Field(
        description=(
            "Counts keyed by the reason the refusal recorded: ``authorization_denied``, "
            "``policy_denied``, ``target_not_found``, ``environment_mismatch`` or "
            "``unspecified``."
        )
    )


class MonitoringSummaryResponse(BaseModel):
    """``GET /monitoring/summary``: the window's counts in one response.

    Every field is a count of events of a stated type in the recorded window. The action
    fields answer "what did the pipeline do?", the inventory and registry fields answer
    "what changed?", and the policy fields answer "did the rules move?" — three questions,
    one window, no interpretation.
    """

    organization_id: uuid.UUID
    window: MonitoringWindowRead

    total_events: int = Field(description="Every audit event in the window.")
    action_requests: int = Field(description="Executions admitted to the pipeline.")
    action_executions: int = Field(description="Actions an adapter ran to completion.")
    action_failures: int = Field(description="Admitted actions whose adapter failed.")
    action_denials: int = Field(description="Requests refused by any layer.")
    action_replays: int = Field(description="Requests answered from the idempotency ledger.")
    approval_required: int = Field(description="Requests held for an approval this build lacks.")

    asset_creations: int
    asset_updates: int
    asset_deletions: int
    asset_discoveries: int = Field(description="Assets the ingestion path recorded.")
    agent_registrations: int
    agent_updates: int
    agent_deletions: int

    policy_creations: int
    policy_updates: int
    policy_version_publications: int
    policy_status_changes: int
    policy_deletions: int
    policy_changes: int = Field(description="The five policy counters above, summed.")

    active_agents: int = Field(
        description="Distinct agents named by at least one event in the window."
    )
    active_assets: int = Field(
        description="Distinct assets named by at least one event in the window."
    )

    execution_health: ExecutionHealthRead
    denials: DenialSummaryRead


class MonitoringAgentRead(BaseModel):
    """One agent's activity in the window.

    Present only when the agent is named by at least one event in the window: this build
    measures activity, and it cannot tell an idle agent from one whose requests never
    happened, so it does not report the difference as zeros.
    """

    agent_id: uuid.UUID
    events: int = Field(description="Every event attributed to this agent.")
    action_requests: int
    executions: int
    failures: int
    denials: int
    approval_required: int
    replays: int
    last_activity_at: datetime = Field(description="The newest event's recorded time, in UTC.")


class MonitoringAgentListResponse(BaseModel):
    """``GET /monitoring/agents``: one page, most active first.

    Ordered by event count descending, then by identifier ascending — the second key is
    what makes the order total, so paging cannot repeat or skip an agent. ``total`` is
    present only when the caller asked for it, because it costs a second pass.
    """

    organization_id: uuid.UUID
    window: MonitoringWindowRead
    items: list[MonitoringAgentRead]
    limit: int
    offset: int
    count: int = Field(description="Rows in this page.")
    total: int | None = Field(
        default=None, description="Agents with activity in the window; null unless requested."
    )


class MonitoringActionRead(BaseModel):
    """One registered action's activity in the window.

    ``allowed`` counts requests the firewall permitted (the decision axis) while the rest
    count events: a request that was allowed and then failed is both ``allowed`` and
    ``failed``, which is the pair the two axes exist to keep apart.
    """

    action: str = Field(description="The registered action's identifier.")
    requested: int
    allowed: int = Field(description="Requests the firewall permitted, whatever came of them.")
    denied: int
    approval_required: int
    executed: int
    failed: int
    replayed: int


class MonitoringActionListResponse(BaseModel):
    """``GET /monitoring/actions``: one row per action with activity in the window.

    Bounded by construction: the set of actions is the code-level catalogue, and a row
    appears only when the window contains something to report about it.
    """

    organization_id: uuid.UUID
    window: MonitoringWindowRead
    items: list[MonitoringActionRead]
    count: int


class MonitoringDecisionsRead(BaseModel):
    """How the action pipeline answered, by decision, in the window.

    Every declared decision is present, at zero if it never occurred: "no approvals were
    required" and "approvals were not measured" must not look the same.
    """

    allow: int = Field(description="Requests permitted by authorization, policy and firewall.")
    deny: int = Field(description="Requests refused outright.")
    require_approval: int = Field(description="Requests held for an approval this build lacks.")


class MonitoringPolicyLifecycleRead(BaseModel):
    """Activity on the policy record itself: the definition, its versions and its state."""

    created: int
    updated: int
    version_published: int
    status_changed: int
    deleted: int
    changes: int = Field(description="The five counts above, summed.")


class MonitoringPolicyResponse(BaseModel):
    """``GET /monitoring/policies``: what policies did, and what was done to them.

    The two halves are different facts and are kept apart: ``decisions`` counts what the
    pipeline answered for requests, ``lifecycle`` counts changes to the policy record.
    Neither recommends anything — this endpoint reports, it does not propose.
    """

    organization_id: uuid.UUID
    window: MonitoringWindowRead
    decisions: MonitoringDecisionsRead
    lifecycle: MonitoringPolicyLifecycleRead


class TrendBucketRead(BaseModel):
    """One interval of a time series.

    Half-open on the Python side and inclusive at both ends in the query, the two agree
    because the bucket's start is included and the next bucket's start is the boundary the
    query's upper bound cuts at. A bucket with no events is present and zero.
    """

    start: datetime = Field(description="Inclusive start of the bucket, in UTC.")
    end: datetime = Field(description="Exclusive end of the bucket, in UTC.")
    events: int
    action_requests: int
    action_executions: int
    action_failures: int
    action_denials: int
    approval_required: int


class MonitoringTrendResponse(BaseModel):
    """``GET /monitoring/trends``: a complete, zero-filled series over the window.

    Every bucket between the window's first and last is present, in order, so a chart can
    draw the series directly and a reader can tell a quiet interval from missing data.
    No smoothing, no interpolation, no moving average: the counts are the counts.
    """

    organization_id: uuid.UUID
    window: MonitoringWindowRead
    interval: TimeInterval = Field(description="How wide each bucket is.")
    buckets: list[TrendBucketRead]
    count: int = Field(description="How many buckets the series has.")
