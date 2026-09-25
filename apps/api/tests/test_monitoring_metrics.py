"""What each metric counts, frozen: the counters, the schema, and the absent vocabulary.

Every number Phase 9 publishes is defined once, in
:mod:`aicore_api.core.monitoring`, and every one of them is checked here — the counter
tables against the Phase 8 vocabulary they count, and the response models against the
counter tables. That is what makes "this metric still means what it is named" a property
of the build rather than a promise in a docstring: adding a counter without publishing it,
or publishing a field that counts something else, fails in this file.

The last group is the one this phase exists to be careful about. Monitoring counts; it
does not judge. There is no score, no baseline, no threshold and no severity anywhere in
its public surface, and the tests below assert that absence by name — because the failure
mode worth guarding against is not a wrong number, it is a plausible-sounding field like
``risk_score`` appearing later and being read as a verdict this system cannot support.
"""

from __future__ import annotations

import inspect
from collections import Counter

import pytest
from sqlalchemy.dialects import postgresql

from aicore_api.core import monitoring as core_monitoring
from aicore_api.core.audit import AuditDecision, AuditEventType
from aicore_api.core.monitoring import (
    ACTION_ACTIVITY_COUNTERS,
    ACTION_DECISION_COUNTERS,
    AGENT_ACTIVITY_COUNTERS,
    POLICY_CHANGE_TYPES,
    SUMMARY_COUNTERS,
    TREND_COUNTERS,
    UNSPECIFIED_REASON,
    TimeInterval,
)
from aicore_api.db.repositories.monitoring import (
    MAX_ACTION_ROWS,
    _count_expressions,
    _decision_expressions,
)
from aicore_api.monitoring import service as monitoring_service
from aicore_api.schemas import monitoring as monitoring_schemas

#: Vocabulary that would mean monitoring had grown a verdict. Checked against the names
#: this phase publishes — not against its prose, which discusses these subjects only to
#: say that it does not implement them.
VERDICT_WORDS = (
    "risk",
    "score",
    "anomal",
    "incident",
    "alert",
    "severity",
    "threat",
    "suspect",
    "baseline",
    "remediat",
    "recommend",
    "contain",
    "suspend",
    "kill",
    "malicious",
    "abnormal",
    "unusual",
)

PHASE_9_MODULES = (
    core_monitoring,
    monitoring_service,
    monitoring_schemas,
)


def _published_names(module: object) -> list[str]:
    """Every public name a Phase 9 module declares."""
    return [name for name in dir(module) if not name.startswith("_")]


def _response_fields(model: type) -> set[str]:
    return set(model.model_fields)


# ── The counter tables against the vocabulary they count ──────────────────────


def test_every_summary_counter_counts_declared_event_types() -> None:
    declared = set(AuditEventType)
    for name, event_types in SUMMARY_COUNTERS.items():
        assert event_types, name
        assert set(event_types) <= declared, name


def test_the_summary_counters_partition_the_event_vocabulary() -> None:
    """Every event type is counted exactly once, by exactly one metric.

    Not "at least once": a type counted by two counters would be reported twice in a
    summary whose whole point is that the numbers add up, and a type counted by none would
    be invisible. Adding an event type to Phase 8 breaks this file until it is counted.
    """
    counted = [
        event_type for event_types in SUMMARY_COUNTERS.values() for event_type in event_types
    ]
    assert Counter(counted) == Counter(AuditEventType)
    assert len(counted) == len(SUMMARY_COUNTERS) == 18


def test_the_policy_change_counter_is_derived_from_its_parts() -> None:
    lifecycle = {
        name: event_types
        for name, event_types in SUMMARY_COUNTERS.items()
        if name.startswith("policy_")
    }
    declared = {event_type for event_types in lifecycle.values() for event_type in event_types}
    assert declared == set(POLICY_CHANGE_TYPES)
    assert len(lifecycle) == len(POLICY_CHANGE_TYPES) == 5


def test_every_trend_series_is_a_summary_metric_with_the_same_definition() -> None:
    """A trend line cannot come to mean something other than the summary field beside it."""
    for name, event_types in TREND_COUNTERS.items():
        assert name in SUMMARY_COUNTERS
        assert SUMMARY_COUNTERS[name] == event_types
    assert set(TREND_COUNTERS) == {
        "action_requests",
        "action_executions",
        "action_failures",
        "action_denials",
        "approval_required",
    }


def test_the_action_counters_cover_the_action_pipeline_exactly_once() -> None:
    pipeline = {
        event_type for event_type in AuditEventType if event_type.value.startswith("action.")
    }
    counted = [
        event_type
        for event_types in ACTION_ACTIVITY_COUNTERS.values()
        for event_type in event_types
    ]
    assert Counter(counted) == Counter(pipeline)
    assert set(ACTION_ACTIVITY_COUNTERS) == {
        "requested",
        "denied",
        "approval_required",
        "executed",
        "failed",
        "replayed",
    }


def test_the_action_counters_agree_with_the_summary_on_the_same_events() -> None:
    """``denied`` per action and ``action_denials`` in the summary count the same type."""
    assert ACTION_ACTIVITY_COUNTERS["denied"] == SUMMARY_COUNTERS["action_denials"]
    assert ACTION_ACTIVITY_COUNTERS["executed"] == SUMMARY_COUNTERS["action_executions"]
    assert ACTION_ACTIVITY_COUNTERS["failed"] == SUMMARY_COUNTERS["action_failures"]
    assert ACTION_ACTIVITY_COUNTERS["replayed"] == SUMMARY_COUNTERS["action_replays"]


def test_the_decision_counter_uses_the_declared_decision_vocabulary() -> None:
    """``allowed`` is the decision axis, not an event type — and it is a Phase 6 value."""
    assert ACTION_DECISION_COUNTERS == {"allowed": AuditDecision.ALLOW}
    assert all(isinstance(value, AuditDecision) for value in ACTION_DECISION_COUNTERS.values())


def test_the_agent_counters_use_the_same_two_axes_as_the_action_view() -> None:
    assert set(AGENT_ACTIVITY_COUNTERS["events"]) == set(AuditEventType)
    assert AGENT_ACTIVITY_COUNTERS["denials"] == ACTION_ACTIVITY_COUNTERS["denied"]
    assert AGENT_ACTIVITY_COUNTERS["executions"] == ACTION_ACTIVITY_COUNTERS["executed"]
    assert set(AGENT_ACTIVITY_COUNTERS) == {
        "events",
        "action_requests",
        "executions",
        "failures",
        "denials",
        "approval_required",
        "replays",
    }


def test_the_counter_tables_cannot_be_edited_at_runtime() -> None:
    """The definitions are the contract; nothing gets to change one while the server runs."""
    for table in (
        SUMMARY_COUNTERS,
        ACTION_ACTIVITY_COUNTERS,
        AGENT_ACTIVITY_COUNTERS,
        TREND_COUNTERS,
        ACTION_DECISION_COUNTERS,
    ):
        with pytest.raises(TypeError):
            table["injected"] = ("whatever",)  # type: ignore[index]


def test_every_counter_name_is_reported_by_a_read_of_the_phase() -> None:
    """The definitions and the records the service returns are one set of names."""
    assert set(monitoring_service.AgentActivity.__dataclass_fields__) == (
        {"agent_id", "last_activity_at"} | set(AGENT_ACTIVITY_COUNTERS)
    )
    assert set(monitoring_service.ActionActivity.__dataclass_fields__) == (
        {"action"} | set(ACTION_ACTIVITY_COUNTERS) | set(ACTION_DECISION_COUNTERS)
    )
    assert set(monitoring_service.TrendBucket.__dataclass_fields__) == (
        {"start", "end", "events"} | set(TREND_COUNTERS)
    )
    policy_fields = {
        "decisions",
        "creations",
        "updates",
        "version_publications",
        "status_changes",
        "deletions",
    }
    assert set(monitoring_service.PolicyActivity.__dataclass_fields__) == policy_fields
    # The summary's counters travel in one mapping rather than as thirty fields; the test
    # below closes the other end, by requiring the route to read every one of them.
    assert set(monitoring_service.Summary.__dataclass_fields__) == {
        "total_events",
        "counters",
        "active_agents",
        "active_assets",
        "execution_health",
        "denial_reasons",
    }


def test_the_summary_route_publishes_every_metric_the_table_defines() -> None:
    """A counter nothing reads is a metric the API silently stopped reporting."""
    from aicore_api.api.routes import monitoring as monitoring_routes

    source = inspect.getsource(monitoring_routes)
    missing = [name for name in SUMMARY_COUNTERS if f'counters["{name}"]' not in source]
    assert missing == []


# ── The response models against the counters ──────────────────────────────────


def test_the_summary_response_publishes_every_counter_and_nothing_else() -> None:
    assert _response_fields(monitoring_schemas.MonitoringSummaryResponse) == (
        {
            "organization_id",
            "window",
            "total_events",
            "policy_changes",
            "active_agents",
            "active_assets",
            "execution_health",
            "denials",
        }
        | set(SUMMARY_COUNTERS)
    )


def test_the_agent_response_publishes_the_agent_counters() -> None:
    assert _response_fields(monitoring_schemas.MonitoringAgentRead) == (
        {"agent_id", "last_activity_at"} | set(AGENT_ACTIVITY_COUNTERS)
    )


def test_the_action_response_publishes_both_axes() -> None:
    assert _response_fields(monitoring_schemas.MonitoringActionRead) == (
        {"action"} | set(ACTION_ACTIVITY_COUNTERS) | set(ACTION_DECISION_COUNTERS)
    )


def test_the_trend_bucket_publishes_the_series_it_is_a_bucket_of() -> None:
    assert _response_fields(monitoring_schemas.TrendBucketRead) == (
        {"start", "end", "events"} | set(TREND_COUNTERS)
    )


def test_the_policy_response_keeps_decisions_and_lifecycle_apart() -> None:
    assert _response_fields(monitoring_schemas.MonitoringPolicyResponse) == {
        "organization_id",
        "window",
        "decisions",
        "lifecycle",
    }
    assert _response_fields(monitoring_schemas.MonitoringDecisionsRead) == {
        decision.value for decision in AuditDecision
    }
    assert _response_fields(monitoring_schemas.MonitoringPolicyLifecycleRead) == {
        "created",
        "updated",
        "version_published",
        "status_changed",
        "deleted",
        "changes",
    }


def test_the_window_is_repeated_in_every_response_that_measured_one() -> None:
    """A count without its interval is a number nobody can compare to anything."""
    for model in (
        monitoring_schemas.MonitoringSummaryResponse,
        monitoring_schemas.MonitoringAgentListResponse,
        monitoring_schemas.MonitoringActionListResponse,
        monitoring_schemas.MonitoringPolicyResponse,
        monitoring_schemas.MonitoringTrendResponse,
    ):
        assert "window" in _response_fields(model)
        assert "organization_id" in _response_fields(model)


def test_every_published_counter_is_an_integer() -> None:
    """Rates are the only fractions, and only the two of them are nullable."""
    groups = {
        monitoring_schemas.MonitoringSummaryResponse: (
            set(SUMMARY_COUNTERS)
            | {"total_events", "policy_changes", "active_agents", "active_assets"}
        ),
        monitoring_schemas.MonitoringAgentRead: set(AGENT_ACTIVITY_COUNTERS),
        monitoring_schemas.MonitoringActionRead: (
            set(ACTION_ACTIVITY_COUNTERS) | set(ACTION_DECISION_COUNTERS)
        ),
        monitoring_schemas.TrendBucketRead: set(TREND_COUNTERS) | {"events"},
        monitoring_schemas.ExecutionHealthRead: {"completed", "succeeded", "failed"},
        monitoring_schemas.MonitoringPolicyLifecycleRead: {
            "created",
            "updated",
            "version_published",
            "status_changed",
            "deleted",
            "changes",
        },
        monitoring_schemas.MonitoringDecisionsRead: {decision.value for decision in AuditDecision},
    }
    for model, names in groups.items():
        fields = model.model_fields
        for name in names:
            assert fields[name].annotation is int, f"{model.__name__}.{name}"

    health = monitoring_schemas.ExecutionHealthRead.model_fields
    assert health["success_rate"].annotation == (float | None)
    assert health["failure_rate"].annotation == (float | None)
    denials = monitoring_schemas.DenialSummaryRead.model_fields
    assert denials["total"].annotation is int
    assert denials["by_reason"].annotation == dict[str, int]


# ── The vocabulary that must not appear ───────────────────────────────────────


@pytest.mark.parametrize("word", VERDICT_WORDS)
def test_no_published_name_carries_a_verdict(word: str) -> None:
    """No metric, model or field name in this phase judges the activity it reports."""
    for module in PHASE_9_MODULES:
        offenders = [name for name in _published_names(module) if word in name.lower()]
        assert offenders == [], (module.__name__, word, offenders)


@pytest.mark.parametrize("word", VERDICT_WORDS)
def test_no_response_field_carries_a_verdict(word: str) -> None:
    for module in PHASE_9_MODULES:
        for _, model in inspect.getmembers(module, inspect.isclass):
            fields = getattr(model, "model_fields", None)
            if not fields or model.__module__ != module.__name__:
                continue
            offenders = [name for name in fields if word in name.lower()]
            assert offenders == [], (model.__name__, word, offenders)


def test_the_undefined_reason_is_a_stated_value_and_not_an_event_type() -> None:
    """An unreadable reason is a bucket in a breakdown, not a fact invented about a row."""
    assert UNSPECIFIED_REASON == "unspecified"
    assert UNSPECIFIED_REASON not in {event_type.value for event_type in AuditEventType}
    assert UNSPECIFIED_REASON not in {decision.value for decision in AuditDecision}


def test_the_intervals_are_the_two_the_contract_states() -> None:
    assert [interval.value for interval in TimeInterval] == ["hour", "day"]


def test_the_action_view_has_a_row_ceiling_of_its_own() -> None:
    """The one grouped query without a caller-supplied limit still has a bound."""
    assert MAX_ACTION_ROWS == 200


# ── The SQL the definitions generate ──────────────────────────────────────────


def _compile(expression: object) -> str:
    """The SQL one expression stands for, with its values rendered rather than bound.

    Literal binds are what make the assertions below about the *definition* — which event
    types a counter names — rather than about SQLAlchemy's parameter style.
    """
    return str(
        expression.compile(  # type: ignore[attr-defined]
            dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True}
        )
    )


def test_a_counter_covering_every_event_type_is_a_plain_count() -> None:
    """Writing the filter out would be a tautology that silently stops matching later."""
    [expression] = _count_expressions({"events": tuple(AuditEventType)})
    sql = _compile(expression)
    assert sql == "count(*)"
    assert "filter" not in sql.lower()


def test_a_counter_over_a_subset_filters_by_the_event_types_it_names() -> None:
    [expression] = _count_expressions({"denials": (AuditEventType.ACTION_DENIED,)})
    assert expression.name == "denials"
    sql = _compile(expression)
    assert "count(*)" in sql
    assert "FILTER (WHERE" in sql
    assert AuditEventType.ACTION_DENIED.value in sql


def test_every_summary_counter_compiles_to_exactly_one_expression() -> None:
    expressions = _count_expressions(SUMMARY_COUNTERS)
    assert len(expressions) == len(SUMMARY_COUNTERS)
    assert [expression.name for expression in expressions] == list(SUMMARY_COUNTERS)
    compiled = " ".join(_compile(expression) for expression in expressions)
    # Which is a single aggregate row: twelve plain counts and six filtered ones, all over
    # the same scan — not eighteen queries.
    assert compiled.count("count(*)") == len(SUMMARY_COUNTERS)


def test_the_allowed_counter_filters_on_the_decision_axis() -> None:
    [expression] = _decision_expressions(ACTION_DECISION_COUNTERS)
    sql = _compile(expression)
    assert expression.name == "allowed"
    assert "count(*)" in sql
    assert "FILTER (WHERE" in sql
    assert AuditDecision.ALLOW.value in sql


def test_the_repository_touches_no_table_other_than_the_trail() -> None:
    """Monitoring measures the record; it has no second source and no side table.

    Asserted over the compiled statements the module builds, which is where a second table
    would have to appear. The one exception is the subquery ``count_agents`` wraps, which
    is the same trail read again.
    """
    from aicore_api.db.repositories import monitoring as repository_module

    source = inspect.getsource(repository_module)
    for other_table in (
        "ActionExecution",
        "PolicyVersion",
        "Policy(",
        "Agent(",
        "Asset(",
        "Permission(",
        "Membership(",
    ):
        assert other_table not in source, other_table
    assert source.count("AuditEvent") > 10
    assert "delete(" not in source and "update(" not in source
    # …and the one statement that is not built by ``_windowed`` is still over the trail.
    assert "from aicore_api.db.models.audit_event import AuditEvent" in source


def test_the_repository_imports_the_counter_tables_rather_than_restating_them() -> None:
    """A metric's name, definition and SQL come from one place — the tables above."""
    from aicore_api.db.repositories import monitoring as repository_module

    source = inspect.getsource(repository_module)
    for table in (
        "SUMMARY_COUNTERS",
        "ACTION_ACTIVITY_COUNTERS",
        "AGENT_ACTIVITY_COUNTERS",
        "TREND_COUNTERS",
        "ACTION_DECISION_COUNTERS",
    ):
        assert f"{table}," in source or f"{table})" in source, table
    # The event types are never listed again as literals in this module.
    for event_type in AuditEventType:
        if event_type is AuditEventType.ACTION_DENIED:
            continue
        assert f'"{event_type.value}"' not in source, event_type


def test_the_trend_bucket_is_floored_in_utc_in_sql_too() -> None:
    """The database's floor and Python's must agree, including under another TimeZone."""
    from aicore_api.db.repositories import monitoring as repository_module

    source = inspect.getsource(repository_module)
    assert "func.timezone(" in source
    assert "'UTC'" in source or '"UTC"' in source


def test_the_repository_has_no_write_surface() -> None:
    """Read-only by construction: there is no method here that could change the trail."""
    from aicore_api.db.repositories.monitoring import MonitoringRepository

    declared = {
        name
        for name in dir(MonitoringRepository)
        if not name.startswith("_") and callable(getattr(MonitoringRepository, name))
    }
    assert declared == {
        "action_activity",
        "active_identifiers",
        "agent_activity",
        "count_agents",
        "decision_counts",
        "denial_reasons",
        "execute",
        "summary",
        "trend",
        "writing",
    }
    verbs = ("append", "create", "update", "delete", "insert", "write", "record", "emit")
    for method in MonitoringRepository.__mro__:
        for name in getattr(method, "__dict__", {}):
            assert not any(verb in name.lower() for verb in verbs), name
