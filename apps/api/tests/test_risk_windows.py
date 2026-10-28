"""Phase 10 windows: bounded, adjacent, aligned — and the baseline never sees the observation.

Pure tests of :func:`aicore_api.core.risk.resolve_analysis_windows` and
:class:`~aicore_api.core.risk.AnalysisWindows`. No database.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import pytest

from aicore_api.core.risk import (
    BASELINE_SPANS,
    DEFAULT_BASELINE_WINDOW,
    DEFAULT_OBSERVATION_WINDOW,
    OBSERVATION_SPANS,
    AnalysisWindows,
    BaselineWindow,
    ObservationWindow,
    RiskError,
    RiskWindowError,
    floor_to_hour,
    resolve_analysis_windows,
)

NOW = datetime(2026, 9, 25, 10, 37, 12, 345678, tzinfo=UTC)
HOUR = datetime(2026, 9, 25, 10, tzinfo=UTC)


def test_the_window_vocabularies_are_closed() -> None:
    assert [window.value for window in BaselineWindow] == ["7d", "14d", "30d"]
    assert [window.value for window in ObservationWindow] == ["1h", "6h", "24h"]
    assert set(BASELINE_SPANS) == set(BaselineWindow)
    assert set(OBSERVATION_SPANS) == set(ObservationWindow)
    assert max(BASELINE_SPANS.values()) == timedelta(days=30)
    assert max(OBSERVATION_SPANS.values()) == timedelta(hours=24)


def test_defaults_are_fourteen_days_against_the_last_complete_day() -> None:
    windows = resolve_analysis_windows(now=NOW)

    assert windows.baseline is DEFAULT_BASELINE_WINDOW is BaselineWindow.FOURTEEN_DAYS
    assert windows.observation is DEFAULT_OBSERVATION_WINDOW
    assert windows.as_of == windows.observation_end == HOUR
    assert windows.observation_start == HOUR - timedelta(hours=24)
    assert windows.baseline_end == windows.observation_start
    assert windows.baseline_start == windows.observation_start - timedelta(days=14)


def test_the_default_as_of_is_the_start_of_the_current_hour_never_a_partial_hour() -> None:
    windows = resolve_analysis_windows(observation="1h", now=NOW)
    assert windows.observation_end == HOUR
    assert windows.observation_end <= NOW
    assert windows.observation_start == HOUR - timedelta(hours=1)


@pytest.mark.parametrize("baseline", list(BaselineWindow))
@pytest.mark.parametrize("observation", list(ObservationWindow))
def test_the_baseline_ends_exactly_where_the_observation_starts(
    baseline: BaselineWindow, observation: ObservationWindow
) -> None:
    windows = resolve_analysis_windows(baseline=baseline, observation=observation, now=NOW)

    assert windows.baseline_end == windows.observation_start
    assert windows.baseline_end - windows.baseline_start == BASELINE_SPANS[baseline]
    assert windows.observation_end - windows.observation_start == OBSERVATION_SPANS[observation]
    # Half-open intervals that touch: no instant is in both.
    assert not (windows.baseline_start <= windows.observation_start < windows.baseline_end)
    assert windows.slots * windows.slot == BASELINE_SPANS[baseline]
    assert windows.slot == OBSERVATION_SPANS[observation]


@pytest.mark.parametrize(
    ("baseline", "observation", "slots"),
    [
        ("7d", "1h", 168),
        ("7d", "24h", 7),
        ("14d", "6h", 56),
        ("30d", "24h", 30),
        ("30d", "1h", 720),
    ],
)
def test_slot_counts(baseline: str, observation: str, slots: int) -> None:
    windows = resolve_analysis_windows(baseline=baseline, observation=observation, now=NOW)
    assert windows.slots == slots
    assert windows.slot_seconds == int(
        OBSERVATION_SPANS[ObservationWindow(observation)].total_seconds()
    )


def test_an_explicit_past_as_of_is_honoured() -> None:
    as_of = datetime(2026, 9, 1, 0, tzinfo=UTC)
    windows = resolve_analysis_windows(as_of=as_of, now=NOW)
    assert windows.observation_end == as_of


def test_an_as_of_in_another_timezone_is_normalised_to_utc() -> None:
    ist = timezone(timedelta(hours=5, minutes=30))
    as_of = datetime(2026, 9, 25, 14, 30, tzinfo=ist)  # 09:00 UTC
    windows = resolve_analysis_windows(as_of=as_of, now=NOW)
    assert windows.observation_end == datetime(2026, 9, 25, 9, tzinfo=UTC)
    assert windows.observation_end.tzinfo == UTC


def test_the_current_hour_itself_is_an_acceptable_as_of() -> None:
    assert resolve_analysis_windows(as_of=HOUR, now=NOW).observation_end == HOUR


@pytest.mark.parametrize(
    ("as_of", "message"),
    [
        (datetime(2026, 9, 25, 9), "timezone-aware"),
        (datetime(2026, 9, 25, 9, 30, tzinfo=UTC), "whole UTC hour"),
        (datetime(2026, 9, 25, 9, 0, 1, tzinfo=UTC), "whole UTC hour"),
        (datetime(2026, 9, 25, 9, 0, 0, 1, tzinfo=UTC), "whole UTC hour"),
        (datetime(2026, 9, 25, 11, tzinfo=UTC), "not be later"),
        (datetime(2027, 1, 1, tzinfo=UTC), "not be later"),
    ],
)
def test_an_unusable_as_of_is_refused_not_adjusted(as_of: datetime, message: str) -> None:
    with pytest.raises(RiskWindowError, match=message):
        resolve_analysis_windows(as_of=as_of, now=NOW)


@pytest.mark.parametrize(("field", "value"), [("baseline", "90d"), ("observation", "5m")])
def test_a_window_outside_the_vocabulary_is_refused(field: str, value: str) -> None:
    with pytest.raises(RiskWindowError, match="must be one of"):
        options: dict[str, Any] = {field: value}
        resolve_analysis_windows(now=NOW, **options)


def test_a_naive_clock_is_refused() -> None:
    with pytest.raises(RiskWindowError):
        resolve_analysis_windows(now=datetime(2026, 9, 25, 10))


def test_window_errors_are_risk_errors_so_routes_answer_422() -> None:
    assert issubclass(RiskWindowError, RiskError)
    assert issubclass(RiskError, ValueError)


def _windows(**overrides: object) -> AnalysisWindows:
    fields: dict[str, object] = {
        "baseline": BaselineWindow.SEVEN_DAYS,
        "observation": ObservationWindow.ONE_HOUR,
        "baseline_start": HOUR - timedelta(days=7, hours=1),
        "baseline_end": HOUR - timedelta(hours=1),
        "observation_start": HOUR - timedelta(hours=1),
        "observation_end": HOUR,
    }
    fields.update(overrides)
    return AnalysisWindows(**fields)  # type: ignore[arg-type]


def test_windows_can_be_constructed_directly_when_consistent() -> None:
    assert _windows().slots == 168


def test_an_overlapping_baseline_cannot_exist() -> None:
    with pytest.raises(RiskWindowError, match="neither overlap"):
        _windows(
            baseline_start=HOUR - timedelta(days=7),
            baseline_end=HOUR - timedelta(minutes=30),
        )


def test_a_gap_before_the_observation_cannot_exist() -> None:
    with pytest.raises(RiskWindowError, match="neither overlap"):
        _windows(
            baseline_start=HOUR - timedelta(days=7, hours=2),
            baseline_end=HOUR - timedelta(hours=2),
        )


def test_bounds_that_disagree_with_the_named_window_cannot_exist() -> None:
    with pytest.raises(RiskWindowError, match="baseline bounds"):
        _windows(baseline_start=HOUR - timedelta(days=8, hours=1))
    with pytest.raises(RiskWindowError, match="observation bounds"):
        _windows(observation_end=HOUR + timedelta(hours=1))


def test_naive_bounds_cannot_exist() -> None:
    with pytest.raises(RiskWindowError, match="timezone-aware"):
        _windows(observation_end=datetime(2026, 9, 25, 10))


def test_floor_to_hour() -> None:
    assert floor_to_hour(NOW) == HOUR
    assert floor_to_hour(HOUR) == HOUR
    with pytest.raises(RiskWindowError):
        floor_to_hour(datetime(2026, 9, 25, 10, 5))
