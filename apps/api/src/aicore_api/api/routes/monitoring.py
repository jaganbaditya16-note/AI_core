"""Monitoring routes: five endpoints that count, and that is the whole surface.

Phase 9 answers "what is happening?" from the audit trail. Every route here is a ``GET``,
every one is guarded by ``audit.read``, and none of them can change anything — there is no
route that writes a measurement, silences a signal, acknowledges an event or acts on what
it counts. Monitoring observes; the layers below it decide and act.

**Why ``audit.read`` rather than a monitoring permission.** A measurement is a sum over
rows the caller can already read: anyone holding ``audit.read`` can compute every number
these endpoints return by paging the trail. Inventing ``monitoring.read`` would therefore
guard nothing that is not already guarded, and granting it to a role that lacks
``audit.read`` would hand that role the trail's contents in aggregate. So the phase adds no
permission and changes no role — the owner and the security administrator read monitoring
for the same reason they read the trail, and nobody else does. ``security.read`` stays
reserved for findings, which is a later phase's subject.

**Why the window is a dependency.** Every endpoint needs the same decision — which interval
is this? — and a caller who gets it wrong should get the same 422 from all five. Resolving
it once, before any handler runs, is what makes that true, and it is also what keeps the
repository unable to see an unbounded request: by the time a handler runs, the window exists.

**What is deliberately absent.** No ``/monitoring/activity`` duplicating the audit listing:
the trail already has a bounded, paginated, filtered read endpoint, and a second one with a
different default window would be two answers to one question. No ``/monitoring/health``
returning a verdict: "is this healthy?" is a judgement, and this phase measures. No
thresholds, no baselines, no comparison endpoint, no alert configuration — those are
different subjects with different vocabulary, and none of them is half-built here.
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from aicore_api.auth.authorization import OrganizationContext
from aicore_api.auth.dependencies import SessionDep, require_permission
from aicore_api.core.actions import ACTION_ID_MAX_LENGTH, ACTION_ID_PATTERN
from aicore_api.core.monitoring import (
    DEFAULT_WINDOW,
    MonitoringWindow,
    MonitoringWindowError,
    ResolvedWindow,
    TimeInterval,
    resolve_window,
)
from aicore_api.core.permissions import Permission
from aicore_api.db.repositories.monitoring import MonitoringRepository
from aicore_api.monitoring.service import MonitoringService
from aicore_api.schemas.monitoring import (
    DenialSummaryRead,
    ExecutionHealthRead,
    MonitoringActionListResponse,
    MonitoringActionRead,
    MonitoringAgentListResponse,
    MonitoringAgentRead,
    MonitoringDecisionsRead,
    MonitoringPolicyLifecycleRead,
    MonitoringPolicyResponse,
    MonitoringSummaryResponse,
    MonitoringTrendResponse,
    MonitoringWindowRead,
    TrendBucketRead,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/organizations", tags=["monitoring"])

#: Monitoring is a read of the audit trail, so it requires the permission that already
#: guards reading it. Checked before the handler runs, so a caller without it learns
#: nothing — not even whether the organization has any activity at all.
ReadMonitoring = Annotated[OrganizationContext, Depends(require_permission(Permission.AUDIT_READ))]

#: The same ceiling the other listings use. It is what makes "no unbounded page" a property
#: of the endpoint rather than a hope about its callers.
_MAX_OFFSET = 100_000

_RESPONSES: dict[int | str, dict[str, Any]] = {
    401: {"description": "Missing or invalid credentials"},
    403: {"description": "The caller lacks the audit.read permission"},
    404: {"description": "The organization does not exist or the caller is not a member"},
    422: {
        "description": (
            "The window is malformed (a naive timestamp, an inverted or oversized range), "
            "the interval is too fine for it, or a filter value is outside its vocabulary"
        )
    },
}


def resolve_monitoring_window(
    window: Annotated[
        MonitoringWindow,
        Query(description="A named window, or 'custom' with start_time and end_time"),
    ] = DEFAULT_WINDOW,
    start_time: Annotated[
        datetime | None,
        Query(description="Inclusive lower bound; required with window=custom, timezone-aware"),
    ] = None,
    end_time: Annotated[
        datetime | None,
        Query(description="Inclusive upper bound; required with window=custom, timezone-aware"),
    ] = None,
) -> ResolvedWindow:
    """Turn the query string into a window, or refuse the request.

    The server's clock is read here and nowhere else, once per request: a handler never
    decides what "now" is, so every endpoint resolves the same window for the same request
    and two endpoints called together describe the same interval.

    A window this build will not measure is a 422 naming the reason — an inverted range, a
    range longer than a month, a bound sent without ``window=custom`` — rather than an empty
    result. Answering a mistake with zeros would look exactly like a quiet period.
    """
    try:
        return resolve_window(
            window=window,
            start_time=start_time,
            end_time=end_time,
            now=datetime.now(UTC),
        )
    except MonitoringWindowError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc


WindowDep = Annotated[ResolvedWindow, Depends(resolve_monitoring_window)]


def _service(context: OrganizationContext, session: Session) -> MonitoringService:
    """The monitoring service for one request: this tenant's trail, read through one session.

    Constructed per request rather than shared, and always with the organization the
    authorized context resolved — never a value from the query string, the body or a header.
    """
    return MonitoringService(MonitoringRepository(session, context.organization_id))


def _window_read(window: ResolvedWindow) -> MonitoringWindowRead:
    """The resolved window as the response states it."""
    return MonitoringWindowRead(name=window.name, start=window.start, end=window.end)


@router.get(
    "/{organization_id}/monitoring/summary",
    response_model=MonitoringSummaryResponse,
    summary="Count what happened in the organization's window",
    responses=_RESPONSES,
)
def read_monitoring_summary(
    context: ReadMonitoring, session: SessionDep, window: WindowDep
) -> MonitoringSummaryResponse:
    """The window's counts: what the pipeline did, what changed and what was refused.

    One response, one window, no interpretation — see the schema for what each counter
    means. A quiet window returns zeros rather than an empty body, because "nothing
    happened" is a measurement too.
    """
    summary = _service(context, session).summary(window)
    counters = summary.counters
    return MonitoringSummaryResponse(
        organization_id=context.organization_id,
        window=_window_read(window),
        total_events=summary.total_events,
        action_requests=counters["action_requests"],
        action_executions=counters["action_executions"],
        action_failures=counters["action_failures"],
        action_denials=counters["action_denials"],
        action_replays=counters["action_replays"],
        approval_required=counters["approval_required"],
        asset_creations=counters["asset_creations"],
        asset_updates=counters["asset_updates"],
        asset_deletions=counters["asset_deletions"],
        asset_discoveries=counters["asset_discoveries"],
        agent_registrations=counters["agent_registrations"],
        agent_updates=counters["agent_updates"],
        agent_deletions=counters["agent_deletions"],
        policy_creations=counters["policy_creations"],
        policy_updates=counters["policy_updates"],
        policy_version_publications=counters["policy_version_publications"],
        policy_status_changes=counters["policy_status_changes"],
        policy_deletions=counters["policy_deletions"],
        policy_changes=summary.policy_changes,
        active_agents=summary.active_agents,
        active_assets=summary.active_assets,
        execution_health=ExecutionHealthRead(
            completed=summary.execution_health.completed,
            succeeded=summary.execution_health.succeeded,
            failed=summary.execution_health.failed,
            success_rate=summary.execution_health.success_rate,
            failure_rate=summary.execution_health.failure_rate,
        ),
        denials=DenialSummaryRead(
            total=counters["action_denials"], by_reason=dict(summary.denial_reasons)
        ),
    )


@router.get(
    "/{organization_id}/monitoring/agents",
    response_model=MonitoringAgentListResponse,
    summary="Count what each agent did in the organization's window",
    responses=_RESPONSES,
)
def read_monitoring_agents(
    context: ReadMonitoring,
    session: SessionDep,
    window: WindowDep,
    agent_id: Annotated[
        uuid.UUID | None,
        Query(description="Narrow the page to one agent; a foreign or unknown id has no rows"),
    ] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0, le=_MAX_OFFSET)] = 0,
    total: Annotated[
        bool, Query(description="Include the filtered total; costs a second query")
    ] = False,
) -> MonitoringAgentListResponse:
    """One page of agents with activity in the window, most active first.

    Ordered by event count descending and identifier ascending, so the order is total and a
    page cannot repeat or skip a row. An agent that appears in no event is absent rather than
    reported as a row of zeros: this build measures what was recorded, and "idle" is not
    something the trail can state.

    ``agent_id`` narrows the page. An identifier from another organization selects nothing —
    the query is tenant-scoped before the filter is applied, so a foreign id is simply an id
    with no rows here, and the response says nothing about whether it exists elsewhere.
    """
    page = _service(context, session).agents(
        window, limit=limit, offset=offset, agent_id=agent_id, total=total
    )
    return MonitoringAgentListResponse(
        organization_id=context.organization_id,
        window=_window_read(window),
        items=[
            MonitoringAgentRead(
                agent_id=item.agent_id,
                events=item.events,
                action_requests=item.action_requests,
                executions=item.executions,
                failures=item.failures,
                denials=item.denials,
                approval_required=item.approval_required,
                replays=item.replays,
                last_activity_at=item.last_activity_at,
            )
            for item in page.items
        ],
        limit=limit,
        offset=offset,
        count=len(page.items),
        total=page.total,
    )


@router.get(
    "/{organization_id}/monitoring/actions",
    response_model=MonitoringActionListResponse,
    summary="Count what each registered action did in the organization's window",
    responses=_RESPONSES,
)
def read_monitoring_actions(
    context: ReadMonitoring,
    session: SessionDep,
    window: WindowDep,
    action: Annotated[
        str | None,
        Query(
            pattern=ACTION_ID_PATTERN,
            max_length=ACTION_ID_MAX_LENGTH,
            description="Narrow the page to one registered action",
        ),
    ] = None,
) -> MonitoringActionListResponse:
    """One row per registered action with activity in the window, ordered by identifier.

    Bounded by construction rather than by a page size: the set of actions is the closed,
    code-level catalogue, and a row appears only when the window contains something to report
    about it. Ordering is alphabetical, which is stable — a count order would reshuffle the
    page every time a request arrived.

    Only requests that reached the pipeline appear. An action that was never invoked has no
    row, and an event on a lifecycle route (whose ``action`` column holds a permission code
    like ``asset.create``) is not an action execution and is not listed.
    """
    items = _service(context, session).actions(window, action=action)
    return MonitoringActionListResponse(
        organization_id=context.organization_id,
        window=_window_read(window),
        items=[
            MonitoringActionRead(
                action=item.action,
                requested=item.requested,
                allowed=item.allowed,
                denied=item.denied,
                approval_required=item.approval_required,
                executed=item.executed,
                failed=item.failed,
                replayed=item.replayed,
            )
            for item in items
        ],
        count=len(items),
    )


@router.get(
    "/{organization_id}/monitoring/policies",
    response_model=MonitoringPolicyResponse,
    summary="Count policy activity and policy decisions in the organization's window",
    responses=_RESPONSES,
)
def read_monitoring_policies(
    context: ReadMonitoring, session: SessionDep, window: WindowDep
) -> MonitoringPolicyResponse:
    """What the policies decided, and what was done to the policy record.

    Two questions that share a subject and must not share an answer. ``decisions`` counts how
    the pipeline answered requests — the same three words Phase 6 and Phase 7 already use.
    ``lifecycle`` counts changes to the policy record itself: a creation, a new version, an
    activation, a deletion.

    Neither is a recommendation. This endpoint reports that a policy was activated; it does
    not suggest one, and there is no field in this response a client could read as advice.
    A denial is counted, never attributed to a named policy — the trail records the decision
    and its reason, not which policy produced it (see docs/monitoring.md).
    """
    activity = _service(context, session).policies(window)
    return MonitoringPolicyResponse(
        organization_id=context.organization_id,
        window=_window_read(window),
        decisions=MonitoringDecisionsRead(
            allow=activity.decisions.get("allow", 0),
            deny=activity.decisions.get("deny", 0),
            require_approval=activity.decisions.get("require_approval", 0),
        ),
        lifecycle=MonitoringPolicyLifecycleRead(
            created=activity.creations,
            updated=activity.updates,
            version_published=activity.version_publications,
            status_changed=activity.status_changes,
            deleted=activity.deletions,
            changes=activity.changes,
        ),
    )


@router.get(
    "/{organization_id}/monitoring/trends",
    response_model=MonitoringTrendResponse,
    summary="Count activity per time bucket over the organization's window",
    responses=_RESPONSES,
)
def read_monitoring_trends(
    context: ReadMonitoring,
    session: SessionDep,
    window: WindowDep,
    interval: Annotated[
        TimeInterval, Query(description="How wide each bucket is")
    ] = TimeInterval.HOUR,
) -> MonitoringTrendResponse:
    """A complete series over the window: every bucket, in order, zeros included.

    Bucket edges are floored in UTC, so an hour means the same thing whatever the database
    or the caller's locale says, and a bucket with no events is returned as zero rather than
    omitted — a gap would be indistinguishable from missing data.

    The interval has to fit the window: at most
    :data:`~aicore_api.core.monitoring.MAX_BUCKETS` buckets are served, and a request for
    more is refused with the interval it should have asked for. That is what keeps one
    request from returning a series nobody reads.
    """
    try:
        buckets = _service(context, session).trends(window, interval=interval)
    except MonitoringWindowError as exc:
        # Raised by the bucket arithmetic, not by the window: a span that fits a month can
        # still be too fine an interval for it.
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc
    return MonitoringTrendResponse(
        organization_id=context.organization_id,
        window=_window_read(window),
        interval=interval,
        buckets=[
            TrendBucketRead(
                start=bucket.start,
                end=bucket.end,
                events=bucket.events,
                action_requests=bucket.action_requests,
                action_executions=bucket.action_executions,
                action_failures=bucket.action_failures,
                action_denials=bucket.action_denials,
                approval_required=bucket.approval_required,
            )
            for bucket in buckets
        ],
        count=len(buckets),
    )
